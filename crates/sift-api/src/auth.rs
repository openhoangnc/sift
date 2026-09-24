//! Web session authentication.
//!
//! The contract the browser sees matches the Go implementation: a POST to
//! `/control/login` sets an `agh_session` cookie holding a hex token, and
//! `/control/logout` clears it and redirects to `/login.html`.  HTTP Basic
//! credentials are accepted too, which is what the API's scripted users rely
//! on.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ahash::AHashMap;
use parking_lot::{Mutex, MutexGuard};
use tokio::sync::Semaphore;

/// The name of the session cookie.
pub const COOKIE_NAME: &str = "agh_session";

/// The bucket `sessions.db` stores sessions in.
///
/// The name carries a version: upstream changed the record layout once and
/// used a new bucket rather than migrating.
const BUCKET: &[u8] = b"sessions-2";

/// One logged-in session.
#[derive(Clone, Debug)]
pub struct Session {
    /// The user the session belongs to.
    pub user: String,
    /// When the session stops being valid.
    pub expires: SystemTime,
}

/// The session store.
///
/// Sessions are persisted to `sessions.db` in the layout the Go build uses, so
/// a restart does not sign everyone out and either build can read the other's
/// file: a 16-byte token as the key, and a four-byte expiry, a two-byte name
/// length and the name as the value.
#[derive(Default)]
pub struct Sessions {
    /// The live sessions, by token.
    by_token: Mutex<AHashMap<String, Session>>,
    /// Where the sessions are stored, if anywhere.
    path: Option<PathBuf>,
}

impl Sessions {
    /// Creates an empty, unsaved store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Opens the store backed by a file, loading whatever it holds.
    ///
    /// A missing or unreadable file starts an empty store: losing sessions is
    /// an inconvenience, while refusing to start is an outage.
    pub fn open(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let by_token = load(&path).unwrap_or_default();

        Self {
            by_token: Mutex::new(by_token),
            path: Some(path),
        }
    }

    /// Creates a session for a user and returns its token.
    pub fn create(&self, user: &str, ttl: Duration) -> String {
        let token = new_token();
        self.by_token.lock().insert(
            token.clone(),
            Session {
                user: user.to_string(),
                expires: SystemTime::now() + ttl,
            },
        );
        self.persist();

        token
    }

    /// Looks up a session, dropping it if it has expired.
    pub fn get(&self, token: &str) -> Option<Session> {
        let mut map = self.by_token.lock();
        let s = map.get(token)?.clone();
        if s.expires <= SystemTime::now() {
            map.remove(token);

            return None;
        }

        Some(s)
    }

    /// Removes a session.
    pub fn remove(&self, token: &str) {
        self.by_token.lock().remove(token);
        self.persist();
    }

    /// Drops every expired session.
    pub fn sweep(&self) {
        let now = SystemTime::now();
        let before = self.by_token.lock().len();
        self.by_token.lock().retain(|_, s| s.expires > now);
        if self.by_token.lock().len() != before {
            self.persist();
        }
    }

    /// The number of live sessions.
    pub fn len(&self) -> usize {
        self.by_token.lock().len()
    }

    /// Reports whether no session is live.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Writes the store out, if it is backed by a file.
    ///
    /// A write failure is logged rather than propagated: a session that is
    /// only in memory still works until the next restart.
    pub fn persist(&self) {
        let Some(path) = &self.path else {
            return;
        };

        let mut bucket: sift_bolt::write::BucketData = BTreeMap::new();
        for (token, s) in self.by_token.lock().iter() {
            let Some(key) = token_bytes(token) else {
                continue;
            };
            bucket.insert(key, encode(s));
        }

        let mut buckets = BTreeMap::new();
        buckets.insert(BUCKET.to_vec(), bucket);

        if let Err(e) = sift_bolt::write_file(path, &buckets, sift_bolt::DEFAULT_PAGE_SIZE) {
            tracing::warn!(path = %path.display(), error = %e, "saving sessions");
        }
    }
}

/// Reads the stored sessions, dropping the expired ones.
fn load(path: &Path) -> Option<AHashMap<String, Session>> {
    let db = sift_bolt::Db::open(path).ok()?;
    let buckets = db.buckets().ok()?;
    let bucket = buckets.get(BUCKET)?;

    let now = SystemTime::now();
    let mut out = AHashMap::new();
    for (key, value) in bucket {
        let Some(s) = decode(value) else {
            continue;
        };
        if s.expires <= now {
            continue;
        }

        out.insert(hex(key), s);
    }

    Some(out)
}

/// Encodes a session the way the Go build stores it.
fn encode(s: &Session) -> Vec<u8> {
    let expire = s
        .expires
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .min(u64::from(u32::MAX)) as u32;

    let name = s.user.as_bytes();
    let mut out = Vec::with_capacity(6 + name.len());
    out.extend_from_slice(&expire.to_be_bytes());
    out.extend_from_slice(&(name.len().min(usize::from(u16::MAX)) as u16).to_be_bytes());
    out.extend_from_slice(name);

    out
}

/// Decodes a stored session.
fn decode(data: &[u8]) -> Option<Session> {
    if data.len() < 6 {
        return None;
    }

    let expire = u32::from_be_bytes(data[..4].try_into().ok()?);
    let name_len = usize::from(u16::from_be_bytes(data[4..6].try_into().ok()?));
    let name = data.get(6..6 + name_len)?;

    Some(Session {
        user: String::from_utf8_lossy(name).into_owned(),
        expires: UNIX_EPOCH + Duration::from_secs(u64::from(expire)),
    })
}

/// Parses a hex token back into the raw bytes used as the database key.
fn token_bytes(token: &str) -> Option<Vec<u8>> {
    if !token.len().is_multiple_of(2) {
        return None;
    }

    (0..token.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(token.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Renders raw token bytes as the hex form the cookie carries.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }

    s
}

/// Generates a fresh session token, hex-encoded as upstream does.
fn new_token() -> String {
    let bytes: [u8; 16] = rand::random();
    let mut s = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }

    s
}

/// Builds the `Set-Cookie` value for a new session.
pub fn session_cookie(token: &str, ttl: Duration) -> String {
    let secs = ttl.as_secs();

    format!("{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={secs}")
}

/// Builds the `Set-Cookie` value that clears the session.
pub fn clear_cookie() -> String {
    format!("{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
}

/// Extracts the session token from a `Cookie` header.
pub fn token_from_cookies(header: &str) -> Option<&str> {
    header.split(';').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;

        (k.trim() == COOKIE_NAME).then(|| v.trim())
    })
}

/// Decodes an HTTP Basic `Authorization` header into a name and password.
pub fn basic_credentials(header: &str) -> Option<(String, String)> {
    use base64::Engine as _;

    let b64 = header
        .strip_prefix("Basic ")
        .or_else(|| header.strip_prefix("basic "))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let text = String::from_utf8(raw).ok()?;
    let (user, pass) = text.split_once(':')?;

    Some((user.to_string(), pass.to_string()))
}

/// Verifies a password against a bcrypt hash.
///
/// Returns false rather than an error on a malformed hash: a broken hash must
/// not let anyone in.
pub fn verify_password(password: &str, hash: &str) -> bool {
    bcrypt::verify(password, hash).unwrap_or(false)
}

/// Hashes a password with the cost upstream uses.
pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    bcrypt::hash(password, 10)
}

/// How long a failed attempt is remembered before the count lapses.
///
/// Upstream's `failedAuthTTL`.  The window runs from the *first* failure, not
/// the last, so a slow trickle of guesses never accumulates into a block.
const FAILED_AUTH_TTL: Duration = Duration::from_secs(60);

/// One client's failed attempts.
#[derive(Clone, Copy)]
struct Failed {
    /// How many there have been.
    count: u32,
    /// When the record lapses -- and, once the count is spent, when the block
    /// lifts.  The two share a field because upstream's do.
    until: SystemTime,
}

/// How many passwords may be checked at once for everyone the connection
/// guard judges.
///
/// A bcrypt check at upstream's cost is 50-300 ms of a core, and it is the one
/// thing a stranger who knows nothing can make this process spend a core on.
/// Two bounds what a burst of guesses from everywhere at once can take, and
/// the checks run on the blocking pool rather than on the runtime that also
/// answers DNS.  A source the guard spares does not wait for one: see
/// [`Lane::Local`].
const VERIFIERS: usize = 2;

/// How long a check waits for a verifier before it is answered busy.
///
/// Waiting rather than refusing at once is for scripts: a dashboard polling
/// the API with Basic credentials sends several requests together, each one a
/// check, and turning all but two of them away would break it where upstream,
/// which checks them all in parallel, does not.  The queue is first come,
/// first served, and the wait is bounded, so a flood can make a sign-in slow
/// or busy but never hold one forever.
const VERIFIER_WAIT: Duration = Duration::from_secs(5);

/// How often lapsed records are swept out of the table.
///
/// Sweeping on every lookup made each attempt walk the whole table under the
/// one lock every attempt takes.  A lapsed record is also treated as absent
/// whenever it is looked up, so how late the sweep runs changes what the
/// table holds, never what it answers.
const SWEEP_EVERY: Duration = Duration::from_secs(10);

/// The most clients the throttle remembers at once.
///
/// About 2 MB at the most.  Upstream's table has no bound; this one does, so a
/// guessing run spread over a great many sources costs a fixed amount of
/// memory.
///
/// A full table makes room by forgetting the clients that block nobody --
/// those whose record has lapsed, and then those still short of the limit,
/// the oldest first -- down to [`EVICT_TO`].  It never forgets one serving a
/// block: that is exactly what a run from many addresses would be for.  When
/// every client in it is serving a block there is no room, and a newcomer
/// from the internet is refused as if the verifiers were busy, without being
/// checked; one on this network is counted past the bound.  It used to
/// be let through uncounted instead, and a source that kept the table full --
/// unknown names are counted without hashing anything, so eighty thousand
/// requests in a quarter of an hour from a /48 would do -- then left every
/// other source on the internet unlimited guesses.
const MAX_TRACKED: usize = 16_384;

/// What a full table is brought down to when it makes room.
///
/// A quarter at a time, so that a table kept full is walked once per four
/// thousand newcomers rather than once for each.
const EVICT_TO: usize = MAX_TRACKED - MAX_TRACKED / 4;

/// How often a table full of clients serving a block is looked at again for
/// room.
///
/// Nothing in such a table lapses for minutes, and a success makes room
/// without a look; walking sixteen thousand records under the lock every
/// sign-in takes, for every newcomer, is what a flood of them would
/// otherwise cost.
const RECHECK_FULL: Duration = Duration::from_secs(1);

/// How often a table full of clients serving a block is said to be so.
const WARN_FULL_EVERY: Duration = Duration::from_secs(60);

/// Tracks failed login attempts per client, to slow down guessing.
///
/// Upstream's `authRateLimiter`, including the part that reads like a bug and
/// is not: until the count reaches the threshold, every failure keeps the
/// *first* one's deadline, so the attempts have to arrive within a minute of
/// each other to add up.  Reaching the threshold replaces that deadline with
/// the full block.
///
/// Three things differ, each deliberately:
///
/// - **A client is its source, not its address.**  An IPv6 client is its /64,
///   which is what one subscriber is handed and every address in which is
///   free to them; keyed per address, each of those 2^64 addresses came with
///   five fresh guesses.  An IPv4 address is its own client, and one mapped
///   into IPv6 is the IPv4 address it is.  Upstream keys on the address
///   string.  This is the same unit `sift_dns::probe` judges connections by.
/// - **An attempt is counted before its password is checked** (see
///   [`LoginLimiter::check`]) and handed back if it was right.  Counted after,
///   as upstream counts, every guess sent at once passes the threshold check
///   before any of them has failed, and the limit holds only for a client
///   polite enough to wait for each answer.
/// - **The table is bounded**, and swept every [`SWEEP_EVERY`] rather than on
///   every lookup.  See [`MAX_TRACKED`] for what a full one does.
///
/// And one thing is added: a bound on how many passwords are checked at once
/// for the internet, which [`Lane`] explains.
pub struct LoginLimiter {
    /// The clients that have failed recently, by source.
    attempts: Mutex<AHashMap<String, Failed>>,
    /// Failures allowed before the block starts.
    max: u32,
    /// How long the block lasts.
    block: Duration,
    /// When the table is next swept, in seconds since the Unix epoch.  Only
    /// read or written with `attempts` locked.
    next_sweep: AtomicU64,
    /// Until when a table found full of clients serving a block is taken to
    /// still be, in seconds since the Unix epoch.  Only read or written with
    /// `attempts` locked.
    full_until: AtomicU64,
    /// When a full table was last said to be, in seconds since the Unix
    /// epoch.  Only read or written with `attempts` locked.
    warned_full: AtomicU64,
    /// The password checks that may run at once for [`Lane::Shared`].
    verifiers: Arc<Semaphore>,
    /// How long a check waits for one of them.
    verifier_wait: Duration,
}

/// How a password check is queued and counted: as the internet's, or as
/// upstream does it for everyone.
///
/// Everyone the connection guard judges waits its turn for one of the
/// [`VERIFIERS`], because a check is a core's worth of work a stranger can
/// ask for, and is counted before its check.  A source the guard spares --
/// one on this network, or listed in `ratelimit_whitelist` -- does neither:
/// its check starts at once, as every check does upstream.  Home Assistant
/// and the like poll the API with Basic credentials, a check per request and
/// ten requests together; on a small board where one check takes a second
/// or two, the queue made part of every such burst wait out
/// [`VERIFIER_WAIT`] and be answered 429, and a flood of guesses from the
/// internet made all of it so.
///
/// Counting before the check only holds together with the queue: it is the
/// queue that keeps a burst of right answers from being counted all at once,
/// ahead of the first of them handing its attempt back.  Without it, ten
/// right answers at once spent five attempts and blocked the hub for a
/// quarter of an hour.  So a spared source is counted as upstream counts
/// everyone: after the check, and only when the password was wrong.  The
/// limit still applies to it, and a burst of wrong guesses sent together can
/// all be checked before any is counted, exactly as upstream allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    /// Wait for one of the [`VERIFIERS`], for up to [`VERIFIER_WAIT`], and
    /// count the attempt before checking it.
    Shared,
    /// Check at once, and count the attempt once it has failed.
    Local,
}

/// What checking a password under the throttle came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The password is right.
    Accepted,
    /// The name or the password is wrong, and the attempt has been counted.
    Rejected,
    /// The client has spent its attempts and must wait this long; nothing
    /// was checked.
    Blocked(Duration),
    /// Nothing was checked and nothing was counted, because every verifier
    /// stayed busy for as long as a check waits for one -- or because the
    /// client is new and the table has no room to count it in.  Both ask
    /// the client to come back in a moment.
    Busy,
}

impl LoginLimiter {
    /// Creates a limiter allowing `max` failures before a `block`-long pause.
    ///
    /// A zero in either switches it off, as upstream's `emptyRateLimiter`
    /// does when `auth_attempts` or `block_auth_min` is zero.  The bound on
    /// checks running at once stays on regardless: it is about what a check
    /// costs, not about who is guessing.
    pub fn new(max: u32, block: Duration) -> Self {
        Self {
            attempts: Mutex::new(AHashMap::new()),
            max,
            block,
            next_sweep: AtomicU64::new(0),
            full_until: AtomicU64::new(0),
            warned_full: AtomicU64::new(0),
            verifiers: Arc::new(Semaphore::new(VERIFIERS)),
            verifier_wait: VERIFIER_WAIT,
        }
    }

    /// Builds the limiter the configuration asks for.
    pub fn from_config(cfg: &sift_config::Config) -> Self {
        Self::new(
            cfg.auth_attempts,
            Duration::from_secs(u64::from(cfg.block_auth_min) * 60),
        )
    }

    /// Reports whether this limiter throttles anything at all.
    pub fn is_enabled(&self) -> bool {
        self.max > 0 && !self.block.is_zero()
    }

    /// How long the client must wait before trying again.
    ///
    /// Zero means it may try now, which covers every client that has not yet
    /// spent its attempts.
    pub fn blocked_for(&self, client: &str) -> Duration {
        if !self.is_enabled() {
            return Duration::ZERO;
        }

        let key = source(client);
        let now = SystemTime::now();
        let mut m = self.table(now);

        self.left(&mut m, &key, now)
    }

    /// Records a failed attempt, if there is room to.
    ///
    /// For a failure that is already decided.  An attempt still to be checked
    /// goes through [`Self::begin`], which refuses a newcomer there is no
    /// room for rather than letting it be checked uncounted.
    pub fn record_failure(&self, client: &str) {
        self.failed(client, Lane::Shared);
    }

    /// Clears a client's failures after a successful login.
    pub fn record_success(&self, client: &str) {
        self.attempts.lock().remove(source(client).as_ref());
    }

    /// Counts an attempt as a failure before it is checked, or says why it
    /// may not go ahead: [`Verdict::Blocked`] for a client that has spent its
    /// attempts, [`Verdict::Busy`] for a newcomer on [`Lane::Shared`] the
    /// table has no room for.
    ///
    /// The check and the count are one step under one lock, so however many
    /// attempts arrive at once, no more than the threshold get past it.  An
    /// attempt that turns out right is handed back by [`Self::record_success`],
    /// which clears the client's record as a successful sign-in always has.
    pub fn begin(&self, client: &str, lane: Lane) -> Result<(), Verdict> {
        if !self.is_enabled() {
            return Ok(());
        }

        let key = source(client);
        let now = SystemTime::now();
        let mut m = self.table(now);

        let left = self.left(&mut m, &key, now);
        if !left.is_zero() {
            return Err(Verdict::Blocked(left));
        }

        self.count(&mut m, &key, now, lane)
            .map_err(|NoRoom| Verdict::Busy)
    }

    /// Checks a password against the stored hash, under the throttle.
    ///
    /// `hash` is `None` for a name that is not a user, which is refused and
    /// counted without hashing anything, as upstream's `newCookie` does.  The
    /// caller clones the hash out from under the config lock before calling
    /// this, because the check takes long enough that holding a read lock
    /// through it would stall every writer -- a settings change, a pause
    /// ending -- behind a stranger's guess.
    ///
    /// On [`Lane::Shared`] the order is what makes the count hold:
    ///
    /// 1. a client that has spent its attempts is turned away before it
    ///    queues for anything;
    /// 2. the check waits, first come first served, for one of the
    ///    [`VERIFIERS`], and gives up after [`VERIFIER_WAIT`];
    /// 3. only then is the attempt counted -- after the wait, so that
    ///    requests queued behind a verifier are not counted against their
    ///    client while they wait, which is what would lock out a script that
    ///    sends a handful of correctly signed requests at once -- or refused,
    ///    if the client is new and there is no room to count it;
    /// 4. the hash runs on the blocking pool, holding the verifier, so a
    ///    client that hangs up mid-check does not free a verifier while the
    ///    check it started is still running.
    ///
    /// On [`Lane::Local`] a client that has spent its attempts is turned away
    /// just the same, and the rest is upstream's: the hash runs at once, and
    /// only a wrong password is counted, once it is known to be wrong.
    pub async fn check(
        &self,
        client: &str,
        lane: Lane,
        password: String,
        hash: Option<String>,
    ) -> Verdict {
        let left = self.blocked_for(client);
        if !left.is_zero() {
            return Verdict::Blocked(left);
        }

        let Some(hash) = hash else {
            return match self.begin(client, lane) {
                Ok(()) => Verdict::Rejected,
                Err(refused) => refused,
            };
        };

        let ok = match lane {
            Lane::Shared => {
                let wait = self.verifiers.clone().acquire_owned();
                let Ok(Ok(permit)) = tokio::time::timeout(self.verifier_wait, wait).await else {
                    return Verdict::Busy;
                };

                if let Err(refused) = self.begin(client, lane) {
                    return refused;
                }

                // Counted already, if it is wrong.
                verify(password, hash, Some(permit)).await
            }
            Lane::Local => {
                let ok = verify(password, hash, None).await;
                if !ok {
                    self.failed(client, lane);
                }

                ok
            }
        };

        if !ok {
            return Verdict::Rejected;
        }

        self.record_success(client);

        Verdict::Accepted
    }

    /// [`Self::record_failure`], for a client in `lane`.
    fn failed(&self, client: &str, lane: Lane) {
        if !self.is_enabled() {
            return;
        }

        let key = source(client);
        let now = SystemTime::now();
        let mut m = self.table(now);
        let _ = self.count(&mut m, &key, now, lane);
    }

    /// The table, swept of lapsed records if it is time to.
    fn table(&self, now: SystemTime) -> MutexGuard<'_, AHashMap<String, Failed>> {
        let mut m = self.attempts.lock();

        // Due, or the clock has been set back past the last schedule, which
        // would otherwise put the next sweep off by however far it went.
        let secs = unix_secs(now);
        let next = self.next_sweep.load(Ordering::Relaxed);
        if secs >= next || next > secs + SWEEP_EVERY.as_secs() {
            self.next_sweep
                .store(secs + SWEEP_EVERY.as_secs(), Ordering::Relaxed);
            m.retain(|_, f| f.until > now);
        }

        m
    }

    /// How long `key` is blocked for, forgetting its record if it lapsed.
    fn left(&self, m: &mut AHashMap<String, Failed>, key: &str, now: SystemTime) -> Duration {
        let Some(f) = live(m, key, now) else {
            return Duration::ZERO;
        };
        if f.count < self.max {
            return Duration::ZERO;
        }

        f.until.duration_since(now).unwrap_or(Duration::ZERO)
    }

    /// Adds one failure to `key`'s record: upstream's `incLocked`.
    ///
    /// Fails, counting nothing, for a newcomer on [`Lane::Shared`] to a table
    /// with no room for it; see [`MAX_TRACKED`].  One on [`Lane::Local`] is
    /// counted past the bound instead: a table the internet has filled must
    /// not stop the operator signing in from their own network, and the
    /// sources on it are too few to matter to its size.
    fn count(
        &self,
        m: &mut AHashMap<String, Failed>,
        key: &str,
        now: SystemTime,
        lane: Lane,
    ) -> Result<(), NoRoom> {
        if live(m, key, now).is_none()
            && m.len() >= MAX_TRACKED
            && let Err(full) = self.make_room(m, now)
            && lane == Lane::Shared
        {
            return Err(full);
        }

        let f = m.entry(key.to_string()).or_insert(Failed {
            count: 0,
            until: now + FAILED_AUTH_TTL,
        });
        f.count += 1;

        // Spending the last attempt is what starts the block; the failures
        // before it only set how long they have to arrive within.
        if f.count >= self.max {
            f.until = now + self.block;
        }

        Ok(())
    }

    /// Brings a full table down to [`EVICT_TO`] by forgetting clients that
    /// block nobody, or fails when every one of them is serving a block.
    ///
    /// Lapsed records go first, and are all that goes when they are enough.
    /// Then the records still short of the limit, oldest first -- by when
    /// their first failure lapses, which is the order they began in.  Their
    /// clients lose a count that had at most a minute left to run, and is
    /// the one thing a client with a failure or two to its name has here.
    fn make_room(&self, m: &mut AHashMap<String, Failed>, now: SystemTime) -> Result<(), NoRoom> {
        // Found full a moment ago -- unless the clock has since been set
        // back, which would otherwise leave it found full for however far.
        let secs = unix_secs(now);
        let until = self.full_until.load(Ordering::Relaxed);
        if secs < until && until <= secs + RECHECK_FULL.as_secs() {
            return Err(NoRoom);
        }

        m.retain(|_, f| f.until > now);
        if m.len() < MAX_TRACKED {
            return Ok(());
        }

        let excess = m.len() - EVICT_TO;
        let mut counting: Vec<SystemTime> = m
            .values()
            .filter(|f| f.count < self.max)
            .map(|f| f.until)
            .collect();
        if counting.len() <= excess {
            m.retain(|_, f| f.count >= self.max);
        } else {
            // The `excess`-th oldest, and how many at exactly that age go
            // along with every one older than it.
            let (_, &mut cutoff, _) = counting.select_nth_unstable(excess - 1);
            let mut ties = excess - counting.iter().filter(|&&u| u < cutoff).count();
            m.retain(|_, f| {
                if f.count >= self.max || f.until > cutoff {
                    return true;
                }
                if f.until < cutoff {
                    return false;
                }

                // Exactly as old as the cutoff: only as many go as are
                // still needed.
                if ties == 0 {
                    return true;
                }
                ties -= 1;

                false
            });
        }

        if m.len() < MAX_TRACKED {
            return Ok(());
        }

        self.full_until
            .store(secs + RECHECK_FULL.as_secs(), Ordering::Relaxed);
        let warned = self.warned_full.load(Ordering::Relaxed);
        if warned == 0 || warned > secs || secs >= warned + WARN_FULL_EVERY.as_secs() {
            self.warned_full.store(secs, Ordering::Relaxed);
            tracing::warn!(
                blocked = m.len(),
                "refusing sign-ins from new sources: every source the throttle can remember is serving a block"
            );
        }

        Err(NoRoom)
    }

    /// How many failures the client's source has on record, lapsed or not.
    #[cfg(test)]
    pub(crate) fn failures(&self, client: &str) -> u32 {
        self.attempts
            .lock()
            .get(source(client).as_ref())
            .map_or(0, |f| f.count)
    }

    /// Makes a check give up at once when no verifier is free, so a test of
    /// being busy does not have to wait out [`VERIFIER_WAIT`].
    #[cfg(test)]
    pub(crate) fn impatient(mut self) -> Self {
        self.verifier_wait = Duration::ZERO;

        self
    }

    /// The verifiers, so a test can hold them.
    #[cfg(test)]
    pub(crate) fn verifiers(&self) -> Arc<Semaphore> {
        self.verifiers.clone()
    }
}

/// Why an attempt was not counted: the client is new, and the table is full
/// of clients serving a block.
struct NoRoom;

/// Checks a password on the blocking pool, holding `permit` until the check
/// is done.
///
/// The permit travels with the hash, so a client that hangs up mid-check
/// does not free a verifier while the check it started is still running.
async fn verify(
    password: String,
    hash: String,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> bool {
    tokio::task::spawn_blocking(move || {
        let ok = verify_password(&password, &hash);
        drop(permit);

        ok
    })
    .await
    .unwrap_or(false)
}

/// `key`'s record, unless it has lapsed, in which case it is forgotten.
///
/// Upstream sweeps lapsed records before every lookup; doing it for the one
/// record being looked up answers the same without walking the table.
fn live<'a>(
    m: &'a mut AHashMap<String, Failed>,
    key: &str,
    now: SystemTime,
) -> Option<&'a mut Failed> {
    if m.get(key).is_some_and(|f| f.until <= now) {
        m.remove(key);
    }

    m.get_mut(key)
}

/// Seconds since the Unix epoch, for the sweep's schedule.
fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// The source a client address is throttled as.
///
/// An IPv4 address is its own source, and one mapped into IPv6 is the IPv4
/// address it is.  An IPv6 address is its /64: a subscriber is handed at
/// least that much, and can send from a fresh address in it every time for
/// nothing, so keying by address gave every one of them a fresh set of
/// attempts.  The request handlers pass the connection guard's own key --
/// `routes::throttle_key`, which also judges this host's own /64 one address
/// at a time -- and this is the same rule applied to whatever else arrives,
/// which a key already made passes through unchanged.
///
/// Anything that is not an address -- the empty string a request with no
/// peer carries -- is kept as it is.
fn source(client: &str) -> Cow<'_, str> {
    match client.parse::<IpAddr>().map(|ip| ip.to_canonical()) {
        Ok(IpAddr::V4(a)) => Cow::Owned(a.to_string()),
        Ok(IpAddr::V6(a)) => {
            let net = Ipv6Addr::from_bits(a.to_bits() & (u128::MAX << 64));

            Cow::Owned(format!("{net}/64"))
        }
        Err(_) => Cow::Borrowed(client),
    }
}

/// The refusal a client that has spent its attempts gets.
///
/// `Retry-After` is whole seconds, and `left` is truncated to them rather
/// than rounded, which is what upstream's `int(left.Seconds())` does too.
pub fn too_many_attempts(left: Duration) -> axum::response::Response {
    use axum::response::IntoResponse as _;

    (
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        [(axum::http::header::RETRY_AFTER, left.as_secs().to_string())],
        "too many login attempts",
    )
        .into_response()
}

/// The refusal a sign-in gets when every verifier stayed busy, or when its
/// client is new and the throttle has no room to count it.
///
/// The same status and header as a spent client gets, because it asks the
/// same of the client -- come back later -- and a client that already handles
/// one handles both; only the wait differs.  The login page shows the text as
/// it shows any refusal, and nothing was counted against the client.
pub fn verifiers_busy() -> axum::response::Response {
    use axum::response::IntoResponse as _;

    (
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        [(axum::http::header::RETRY_AFTER, "1")],
        "too many sign-ins are being checked at once; try again in a moment",
    )
        .into_response()
}

/// Who the gate found a request to be from.
///
/// Inserted as a request extension once the gate has let a request through,
/// so a handler that needs the name reads it rather than checking the
/// credentials a second time -- which, for Basic credentials, would be a
/// second bcrypt for the same request.
#[derive(Clone, Debug)]
pub struct SignedIn(pub String);

#[cfg(test)]
mod tests {
    #[test]
    fn sessions_survive_a_restart() {
        // A restart that signs everyone out is a visible regression, and the
        // file has to be the one the Go build reads.
        let dir = std::env::temp_dir().join(format!("sift-sessions-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sessions.db");

        let token = {
            let s = Sessions::open(&path);
            let t = s.create("admin", Duration::from_secs(3600));
            assert_eq!(s.len(), 1);

            t
        };

        let again = Sessions::open(&path);
        assert_eq!(again.len(), 1, "the session should be read back");
        assert_eq!(again.get(&token).map(|s| s.user).as_deref(), Some("admin"));

        again.remove(&token);
        let third = Sessions::open(&path);
        assert!(third.is_empty(), "a logout is persisted too");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_expired_session_is_not_loaded() {
        let dir = std::env::temp_dir().join(format!("sift-sessions-exp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sessions.db");

        {
            let s = Sessions::open(&path);
            // A zero TTL is already in the past by the time it is written.
            s.create("admin", Duration::from_secs(0));
        }

        assert!(Sessions::open(&path).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_database_starts_empty_rather_than_failing() {
        let path = std::env::temp_dir().join("sift-sessions-does-not-exist.db");
        std::fs::remove_file(&path).ok();

        assert!(Sessions::open(&path).is_empty());
    }

    #[test]
    fn the_stored_record_matches_the_go_layout() {
        // Four bytes of expiry, two of name length, then the name.
        let s = Session {
            user: "admin".into(),
            expires: UNIX_EPOCH + Duration::from_secs(0x1234_5678),
        };
        let data = encode(&s);

        assert_eq!(&data[..4], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(&data[4..6], &[0x00, 0x05]);
        assert_eq!(&data[6..], b"admin");

        let back = decode(&data).unwrap();
        assert_eq!(back.user, "admin");
        assert_eq!(back.expires, s.expires);
    }

    #[test]
    fn a_short_record_is_rejected() {
        assert!(decode(&[0, 0, 0]).is_none());
        assert!(
            decode(&[0, 0, 0, 0, 0, 9, b'a']).is_none(),
            "name too short"
        );
    }

    #[test]
    fn tokens_round_trip_between_hex_and_bytes() {
        let t = new_token();
        let bytes = token_bytes(&t).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(hex(&bytes), t);
        assert!(token_bytes("abc").is_none(), "an odd length is not hex");
    }

    use super::*;

    #[test]
    fn sessions_expire() {
        let s = Sessions::new();
        let t = s.create("admin", Duration::from_secs(60));
        assert_eq!(s.get(&t).unwrap().user, "admin");

        let expired = s.create("admin", Duration::from_millis(0));
        assert!(s.get(&expired).is_none(), "a zero TTL is already expired");
    }

    #[test]
    fn sessions_can_be_removed() {
        let s = Sessions::new();
        let t = s.create("admin", Duration::from_secs(60));
        s.remove(&t);
        assert!(s.get(&t).is_none());
        assert!(s.is_empty());
    }

    #[test]
    fn tokens_are_unique_hex() {
        let s = Sessions::new();
        let a = s.create("admin", Duration::from_secs(60));
        let b = s.create("admin", Duration::from_secs(60));
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn the_cookie_matches_upstreams_attributes() {
        let c = session_cookie("deadbeef", Duration::from_secs(3600));
        assert!(c.starts_with("agh_session=deadbeef;"));
        assert!(c.contains("Path=/"));
        assert!(c.contains("HttpOnly"));
        assert!(c.contains("SameSite=Lax"));
        assert!(c.contains("Max-Age=3600"));

        assert!(clear_cookie().contains("Max-Age=0"));
    }

    #[test]
    fn parses_the_session_token_from_a_cookie_header() {
        assert_eq!(token_from_cookies("agh_session=abc123"), Some("abc123"));
        assert_eq!(
            token_from_cookies("other=x; agh_session=abc123; more=y"),
            Some("abc123")
        );
        assert_eq!(token_from_cookies("other=x"), None);
    }

    #[test]
    fn parses_basic_credentials() {
        // "admin:test123"
        let h = "Basic YWRtaW46dGVzdDEyMw==";
        assert_eq!(
            basic_credentials(h),
            Some(("admin".to_string(), "test123".to_string()))
        );
        assert_eq!(basic_credentials("Bearer xyz"), None);
        assert_eq!(basic_credentials("Basic !!!not-base64!!!"), None);
    }

    #[test]
    fn verifies_a_real_bcrypt_hash() {
        // The exact hash used by the reference instance for "test123".
        let hash = "$2a$10$dDdZ0lFNF2/tZvNUkV6GR.aMdxqI8P3u0GYPnEiNB5sGNS0Xm26XO";
        assert!(verify_password("test123", hash));
        assert!(!verify_password("wrong", hash));
        assert!(!verify_password("test123", "not-a-hash"));
    }

    #[test]
    fn hashes_round_trip() {
        let h = hash_password("hunter2").unwrap();
        assert!(verify_password("hunter2", &h));
        assert!(!verify_password("hunter3", &h));
    }

    #[test]
    fn the_login_limiter_blocks_after_repeated_failures() {
        let l = LoginLimiter::new(3, Duration::from_secs(900));
        assert!(l.blocked_for("1.2.3.4").is_zero());

        // The attempts themselves are allowed; spending the last one is what
        // starts the block.
        for _ in 0..2 {
            l.record_failure("1.2.3.4");
            assert!(l.blocked_for("1.2.3.4").is_zero());
        }
        l.record_failure("1.2.3.4");

        let left = l.blocked_for("1.2.3.4");
        assert!(
            left > Duration::from_secs(890) && left <= Duration::from_secs(900),
            "the block should run for about the configured time, not {left:?}"
        );

        // A different client is unaffected.
        assert!(l.blocked_for("5.6.7.8").is_zero());

        l.record_success("1.2.3.4");
        assert!(l.blocked_for("1.2.3.4").is_zero());
    }

    #[test]
    fn failures_short_of_the_threshold_lapse_on_their_own() {
        // Upstream keeps the *first* failure's one-minute deadline until the
        // count is spent, so a trickle of guesses never adds up. Reaching
        // back past that deadline is what a slow attacker does, and the
        // record has to be gone by then.
        let l = LoginLimiter::new(3, Duration::from_secs(900));
        l.record_failure("1.2.3.4");

        let lapsed = SystemTime::now() - Duration::from_secs(1);
        l.attempts.lock().get_mut("1.2.3.4").unwrap().until = lapsed;

        assert!(l.blocked_for("1.2.3.4").is_zero());
        assert!(
            l.attempts.lock().is_empty(),
            "a lapsed record should be swept, not counted towards a block"
        );
    }

    #[test]
    fn a_zero_in_either_bound_switches_the_limiter_off() {
        // Upstream's `emptyRateLimiter`, which it installs when
        // `auth_attempts` or `block_auth_min` is zero.
        for l in [
            LoginLimiter::new(0, Duration::from_secs(900)),
            LoginLimiter::new(3, Duration::ZERO),
        ] {
            assert!(!l.is_enabled());
            for _ in 0..10 {
                l.record_failure("1.2.3.4");
            }
            assert!(l.blocked_for("1.2.3.4").is_zero());
        }
    }

    #[test]
    fn the_limiter_takes_its_bounds_from_the_configuration() {
        let mut cfg = sift_config::Config::default();
        assert_eq!(cfg.auth_attempts, 5, "upstream's default");
        assert_eq!(cfg.block_auth_min, 15, "upstream's default, in minutes");

        let l = LoginLimiter::from_config(&cfg);
        assert!(l.is_enabled());
        for _ in 0..5 {
            l.record_failure("1.2.3.4");
        }
        assert!(l.blocked_for("1.2.3.4") > Duration::from_secs(890));

        cfg.auth_attempts = 0;
        assert!(!LoginLimiter::from_config(&cfg).is_enabled());
    }

    #[test]
    fn a_slash_64_is_one_client_and_an_ipv4_address_is_its_own() {
        // Every address in a /64 belongs to whoever was handed it, and was
        // otherwise a fresh set of attempts each.
        let l = LoginLimiter::new(3, Duration::from_secs(900));
        l.record_failure("2001:db8:1:2::1");
        l.record_failure("2001:db8:1:2:aaaa::2");
        l.record_failure("2001:db8:1:2:ffff:ffff:ffff:ffff");

        assert!(!l.blocked_for("2001:db8:1:2::99").is_zero(), "the same /64");
        assert!(l.blocked_for("2001:db8:1:3::1").is_zero(), "the next one");

        // An IPv4 client reaching a dual-stack socket is the address it is,
        // and its neighbour is somebody else.
        for _ in 0..3 {
            l.record_failure("::ffff:192.0.2.1");
        }
        assert!(!l.blocked_for("192.0.2.1").is_zero());
        assert!(l.blocked_for("192.0.2.2").is_zero());

        // A success anywhere in the /64 clears it, as a success always has.
        l.record_success("2001:db8:1:2::abc");
        assert!(l.blocked_for("2001:db8:1:2::1").is_zero());

        // What is not an address is kept as it is.
        assert_eq!(source(""), "");
        assert_eq!(source("2001:db8::1"), "2001:db8::/64");
        assert_eq!(source("::ffff:10.0.0.1"), "10.0.0.1");
    }

    #[test]
    fn an_attempt_is_counted_before_it_is_checked() {
        // `begin` is the threshold check and the count in one step, so
        // however many arrive together no more than the limit get past.
        let l = LoginLimiter::new(3, Duration::from_secs(900));

        for n in 1..=3 {
            assert!(
                l.begin("192.0.2.1", Lane::Shared).is_ok(),
                "attempt {n} may go ahead"
            );
            assert_eq!(l.failures("192.0.2.1"), n);
        }

        let Err(Verdict::Blocked(left)) = l.begin("192.0.2.1", Lane::Shared) else {
            panic!("the fourth is turned away");
        };
        assert!(left > Duration::from_secs(890));
        assert_eq!(l.failures("192.0.2.1"), 3, "a refusal is not an attempt");

        // Off means off.
        let off = LoginLimiter::new(0, Duration::from_secs(900));
        for _ in 0..10 {
            assert!(off.begin("192.0.2.1", Lane::Shared).is_ok());
        }
    }

    /// A limiter at upstream's defaults, shared between tasks.
    fn shared_limiter() -> Arc<LoginLimiter> {
        Arc::new(LoginLimiter::new(5, Duration::from_secs(900)))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn guesses_sent_at_once_are_checked_no_more_than_the_limit_allows() {
        let l = shared_limiter();
        let hash = bcrypt::hash("right", 4).unwrap();

        let tasks: Vec<_> = (0..20)
            .map(|_| {
                let (l, hash) = (l.clone(), hash.clone());
                tokio::spawn(async move {
                    l.check("192.0.2.1", Lane::Shared, "wrong".to_string(), Some(hash))
                        .await
                })
            })
            .collect();

        let mut rejected = 0;
        for t in tasks {
            match t.await.unwrap() {
                Verdict::Rejected => rejected += 1,
                Verdict::Blocked(_) => {}
                other => panic!("unexpected {other:?}"),
            }
        }

        assert_eq!(rejected, 5, "five checked, fifteen turned away");
        assert_eq!(l.failures("192.0.2.1"), 5, "and each counted once");
    }

    #[tokio::test]
    async fn a_right_password_hands_its_attempt_back() {
        let l = shared_limiter();
        let hash = bcrypt::hash("right", 4).unwrap();

        for _ in 0..4 {
            assert_eq!(
                l.check(
                    "192.0.2.1",
                    Lane::Shared,
                    "wrong".into(),
                    Some(hash.clone())
                )
                .await,
                Verdict::Rejected
            );
        }
        // The fifth attempt spends the last one while it is being checked,
        // and a right answer gives it back along with the rest.
        assert_eq!(
            l.check(
                "192.0.2.1",
                Lane::Shared,
                "right".into(),
                Some(hash.clone())
            )
            .await,
            Verdict::Accepted
        );
        assert_eq!(l.failures("192.0.2.1"), 0);

        // An unknown name is refused without hashing anything, and counted.
        assert_eq!(
            l.check("192.0.2.1", Lane::Shared, "right".into(), None)
                .await,
            Verdict::Rejected
        );
        assert_eq!(l.failures("192.0.2.1"), 1);
    }

    #[tokio::test]
    async fn a_check_that_cannot_get_a_verifier_is_busy_and_costs_nothing() {
        let l = LoginLimiter::new(5, Duration::from_secs(900)).impatient();
        let hash = bcrypt::hash("right", 4).unwrap();

        let held = l
            .verifiers()
            .acquire_many_owned(VERIFIERS as u32)
            .await
            .unwrap();
        assert_eq!(
            l.check(
                "192.0.2.1",
                Lane::Shared,
                "right".into(),
                Some(hash.clone())
            )
            .await,
            Verdict::Busy
        );
        assert_eq!(l.failures("192.0.2.1"), 0, "nothing was checked");

        drop(held);
        assert_eq!(
            l.check("192.0.2.1", Lane::Shared, "right".into(), Some(hash))
                .await,
            Verdict::Accepted
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_client_that_hangs_up_does_not_free_a_verifier_early() {
        // The verifier travels with the hash onto the blocking pool.  Were it
        // released with the request instead, a client could start a check,
        // hang up, and start another, each costing a core that the bound
        // never saw.
        let l = shared_limiter();
        let hash = bcrypt::hash("right", 12).unwrap();

        let task = {
            let l = l.clone();
            tokio::spawn(async move {
                l.check("192.0.2.1", Lane::Shared, "wrong".into(), Some(hash))
                    .await
            })
        };
        while l.failures("192.0.2.1") == 0 {
            tokio::task::yield_now().await;
        }
        task.abort();
        let _ = task.await;

        assert_eq!(
            l.verifiers().available_permits(),
            VERIFIERS - 1,
            "the abandoned check still holds its verifier"
        );

        // And gives it back when the hash finishes.
        let started = std::time::Instant::now();
        while l.verifiers().available_permits() < VERIFIERS {
            assert!(started.elapsed() < Duration::from_secs(10));
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(l.failures("192.0.2.1"), 1, "and it counted, as it began");
    }

    #[test]
    fn the_table_is_swept_on_a_schedule_rather_than_on_every_lookup() {
        let l = LoginLimiter::new(3, Duration::from_secs(900));
        l.record_failure("192.0.2.1");
        l.record_failure("192.0.2.2");

        let lapsed = SystemTime::now() - Duration::from_secs(1);
        l.attempts.lock().get_mut("192.0.2.2").unwrap().until = lapsed;

        // The first lookup swept, and the next sweep is some way off: a
        // lookup of somebody else leaves the lapsed record where it is...
        assert!(l.blocked_for("192.0.2.3").is_zero());
        assert_eq!(l.attempts.lock().len(), 2);

        // ...though it is treated as gone the moment it is looked up.
        assert!(l.blocked_for("192.0.2.2").is_zero());
        assert_eq!(l.attempts.lock().len(), 1);

        // Once the sweep is due, it walks the whole table.
        l.attempts.lock().get_mut("192.0.2.1").unwrap().until = lapsed;
        l.next_sweep.store(0, Ordering::Relaxed);
        assert!(l.blocked_for("192.0.2.3").is_zero());
        assert!(l.attempts.lock().is_empty());
    }

    /// Fills the table to [`MAX_TRACKED`] with `record(i)` for each `i`.
    ///
    /// A lookup first, which sweeps and puts the next sweep some seconds off,
    /// so that whatever is forgotten afterwards is forgotten to make room.
    fn fill(l: &LoginLimiter, record: impl Fn(usize) -> Failed) {
        let _ = l.blocked_for("192.0.2.254");

        let mut m = l.attempts.lock();
        for i in m.len()..MAX_TRACKED {
            m.insert(format!("filler-{i}"), record(i));
        }
    }

    /// A record serving a block of fifteen minutes from now.
    fn blocking(max: u32) -> Failed {
        Failed {
            count: max,
            until: SystemTime::now() + Duration::from_secs(900),
        }
    }

    #[test]
    fn a_full_table_forgets_nobody_serving_a_block() {
        // Forgetting a client to make room would be a way to lift its block
        // by guessing from enough other addresses.
        let l = LoginLimiter::new(3, Duration::from_secs(900));
        for _ in 0..3 {
            l.record_failure("192.0.2.1");
        }
        fill(&l, |_| blocking(3));
        assert_eq!(l.attempts.lock().len(), MAX_TRACKED);

        assert_eq!(l.begin("198.51.100.1", Lane::Shared), Err(Verdict::Busy));
        assert_eq!(l.failures("198.51.100.1"), 0, "not tracked");
        assert_eq!(l.attempts.lock().len(), MAX_TRACKED);

        assert!(!l.blocked_for("192.0.2.1").is_zero(), "still blocked");

        // Somebody already in it is still counted.
        l.record_failure("filler-7");
        assert_eq!(l.attempts.lock().get("filler-7").unwrap().count, 4);
    }

    #[tokio::test]
    async fn a_newcomer_to_a_table_full_of_blocks_is_refused_not_waved_through() {
        // Let through uncounted, as it once was, a newcomer had as many
        // guesses as the verifiers could check.
        let l = LoginLimiter::new(5, Duration::from_secs(900));
        let hash = bcrypt::hash("right", 4).unwrap();
        fill(&l, |_| blocking(5));

        assert_eq!(
            l.check(
                "198.51.100.1",
                Lane::Shared,
                "wrong".into(),
                Some(hash.clone())
            )
            .await,
            Verdict::Busy
        );
        assert_eq!(
            l.check("198.51.100.1", Lane::Shared, "wrong".into(), None)
                .await,
            Verdict::Busy,
            "an unknown name is not waved through either"
        );
        assert_eq!(l.failures("198.51.100.1"), 0);
        assert_eq!(l.attempts.lock().len(), MAX_TRACKED);

        // A table the internet filled does not lock out this network: a
        // source on it is checked, and counted past the bound.
        assert_eq!(
            l.check(
                "192.168.1.10",
                Lane::Local,
                "wrong".into(),
                Some(hash.clone())
            )
            .await,
            Verdict::Rejected
        );
        assert_eq!(l.failures("192.168.1.10"), 1);
        assert_eq!(
            l.check("192.168.1.11", Lane::Local, "wrong".into(), None)
                .await,
            Verdict::Rejected
        );
        assert_eq!(l.failures("192.168.1.11"), 1);
        assert_eq!(l.attempts.lock().len(), MAX_TRACKED + 2);

        // A success makes room at once, without waiting to look again.
        l.record_success("filler-9");
        l.record_success("192.168.1.10");
        l.record_success("192.168.1.11");
        assert_eq!(
            l.check("198.51.100.1", Lane::Shared, "right".into(), Some(hash))
                .await,
            Verdict::Accepted
        );
    }

    #[test]
    fn a_lapsed_record_makes_room_for_a_newcomer() {
        let l = LoginLimiter::new(3, Duration::from_secs(900));
        let lapsed = SystemTime::now() - Duration::from_secs(1);
        fill(&l, |i| {
            if i == 5 {
                Failed {
                    count: 1,
                    until: lapsed,
                }
            } else {
                blocking(3)
            }
        });

        assert_eq!(l.begin("198.51.100.1", Lane::Shared), Ok(()));
        assert_eq!(l.failures("198.51.100.1"), 1, "counted");
        assert!(!l.attempts.lock().contains_key("filler-5"));
        assert_eq!(
            l.attempts.lock().len(),
            MAX_TRACKED,
            "the lapsed record alone made the room"
        );
    }

    #[test]
    fn records_short_of_the_limit_make_room_oldest_first() {
        let l = LoginLimiter::new(3, Duration::from_secs(900));
        let now = SystemTime::now();

        // A quarter are blocks about to lift -- older than any count, and
        // still never forgotten -- and the rest are counts of every age.
        fill(&l, |i| {
            if i % 4 == 0 {
                Failed {
                    count: 3,
                    until: now + Duration::from_secs(30),
                }
            } else {
                Failed {
                    count: 1,
                    until: now + Duration::from_secs(31) + Duration::from_millis(i as u64),
                }
            }
        });

        assert_eq!(l.begin("198.51.100.1", Lane::Shared), Ok(()));
        assert_eq!(l.failures("198.51.100.1"), 1);

        let m = l.attempts.lock();
        assert_eq!(m.len(), EVICT_TO + 1, "a quarter made room at once");
        assert!(
            (0..MAX_TRACKED)
                .step_by(4)
                .all(|i| m.contains_key(&format!("filler-{i}")))
        );
        assert!(!m.contains_key("filler-1"), "the oldest count went");
        assert!(m.contains_key(&format!("filler-{}", MAX_TRACKED - 1)));

        // Exactly the oldest: every count still there is younger than every
        // one that went.
        let kept = (0..MAX_TRACKED)
            .filter(|i| i % 4 != 0)
            .filter(|i| m.contains_key(&format!("filler-{i}")));
        let youngest_gone = (0..MAX_TRACKED)
            .filter(|i| i % 4 != 0 && !m.contains_key(&format!("filler-{i}")))
            .max()
            .unwrap();
        assert!(kept.clone().all(|i| i > youngest_gone));
        assert_eq!(kept.count(), EVICT_TO - MAX_TRACKED / 4);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_source_on_this_network_is_never_told_the_verifiers_are_busy() {
        let l = Arc::new(LoginLimiter::new(5, Duration::from_secs(900)).impatient());
        let hash = bcrypt::hash("right", 4).unwrap();
        let held = l
            .verifiers()
            .acquire_many_owned(VERIFIERS as u32)
            .await
            .unwrap();

        assert_eq!(
            l.check(
                "192.0.2.1",
                Lane::Shared,
                "right".into(),
                Some(hash.clone())
            )
            .await,
            Verdict::Busy,
            "the internet waits its turn"
        );

        // Ten at once, as a home automation hub polls.
        let tasks: Vec<_> = (0..10)
            .map(|_| {
                let (l, hash) = (l.clone(), hash.clone());
                tokio::spawn(async move {
                    l.check("192.168.1.10", Lane::Local, "right".into(), Some(hash))
                        .await
                })
            })
            .collect();
        for t in tasks {
            assert_eq!(t.await.unwrap(), Verdict::Accepted);
        }

        // Still counted as everyone is: the limit is upstream's.
        for _ in 0..5 {
            assert_eq!(
                l.check(
                    "192.168.1.10",
                    Lane::Local,
                    "wrong".into(),
                    Some(hash.clone())
                )
                .await,
                Verdict::Rejected
            );
        }
        assert!(matches!(
            l.check("192.168.1.10", Lane::Local, "right".into(), Some(hash))
                .await,
            Verdict::Blocked(_)
        ));

        drop(held);
    }

    #[test]
    fn the_busy_refusal_asks_for_a_second() {
        let r = verifiers_busy();
        assert_eq!(r.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            r.headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("1")
        );
    }

    #[test]
    fn the_refusal_carries_the_seconds_left() {
        let r = too_many_attempts(Duration::from_millis(899_900));
        assert_eq!(r.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            r.headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            // Truncated, as upstream's `int(left.Seconds())` truncates.
            Some("899")
        );
    }
}
