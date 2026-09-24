//! Shutting out a source that connects and never asks anything.
//!
//! An encrypted listener reachable from the internet is scanned, and every
//! visit costs a TLS handshake -- the most expensive thing an unauthenticated
//! stranger can make this process do.  They arrive as fast as whatever is
//! doing it reconnects: one source dialling the DoT port by address was enough
//! to fill the log twice a second with rustls' complaint about the IP address
//! it had put in the SNI extension, and to pay for a signature each time.
//!
//! The rate limiter next door cannot help, and must not be made to.  It is a
//! defence against *datagram* amplification and deliberately leaves a
//! connection alone: a client that completed a handshake cannot have spoofed
//! its address, and limiting streams by rate cut off every client behind one
//! busy address -- a NAT, an office, a phone hotspot -- which is the bug
//! `ratelimit_diff.py` now guards against.
//!
//! What separates a scanner from a busy client is not the rate, it is that a
//! real client *asks something*.  A DoT client opens a connection in order to
//! send a query; a scanner handshakes, learns what it came for, and leaves.
//! So only connections that asked nothing at all are counted here, a single
//! answered query clears an address's record, and the count decays: a monitor
//! that opens a connection a minute to see whether the port is up never
//! reaches the threshold, while a scanner reaches it in seconds.  A busy NAT
//! is answering queries by definition, so it cannot be shut out.
//!
//! Two kinds of connection are not reported here at all, by the listeners'
//! choice rather than the guard's: one whose every question was turned away
//! because the server was busy, which says nothing either way about its
//! source; and one that closed the moment it opened without sending a byte,
//! which cost nothing -- an uptime monitor checking that a port is open does
//! exactly that, and used to be banned for it.  One that holds the
//! connection open in silence before leaving is still a strike: holding it
//! is the cost.
//!
//! Two deliberate limits on what this counts:
//!
//! - **A local address is never shut out.**  The threat is the public
//!   internet, and a liveness check from the LAN that connects and closes is
//!   the shape this looks for without being the thing it is for.  "Local" is
//!   one notion wherever the guard is asked: loopback, private, link-local
//!   and unique-local addresses, and `Config::local_networks`, the
//!   operator's `dns.private_networks`.  This host's own IPv6 /64s are
//!   deliberately *not* local; see the next list.
//! - **An unvalidated QUIC address is never counted.**  A QUIC initial packet
//!   can carry a forged source, so counting one would let a spoofer lock a
//!   victim out of DoQ.  The caller records a wasted connection only once the
//!   handshake has proved the address, which is also why nothing here is
//!   reachable from the UDP path at all.  `crate::quic` is where that rule is
//!   written down for both QUIC listeners.
//!
//! Five more things it does, each because a scanner that had learned the
//! first version could walk around it:
//!
//! - **An IPv6 source is its /64.**  A subscriber is handed at least a /64,
//!   and a scanner can send from a fresh address in it every time for
//!   nothing, so strikes, penalties and the counts below are all kept per
//!   /64.  An IPv4 address is its own source, and one mapped into IPv6 is
//!   judged as the IPv4 address it is.  The exemptions are still judged on
//!   the full address, and an answered query from anywhere in the /64 clears
//!   it: a household with one real client in it is a household with a client.
//!
//!   The exception is this host's own /64s, `Config::host_networks`, where
//!   each address is its own source, as an IPv4 address is.  A router that
//!   advertises the server's global address to its LAN has every device in
//!   the house reach it from the server's own /64, and judged as that /64
//!   they would share one allowance of connections and queries, and one
//!   device's mistake would be a ban for all of them.  They are not
//!   exempted instead, because the same deployment on a rented server is
//!   the one this guard exists for, and there the /64 is often not the
//!   server's alone: Linode, DigitalOcean and others hand their customers
//!   addresses out of a /64 they share, and exempting it would exempt the
//!   neighbours.
//! - **A repeat offender is refused for longer each time.**  Scanners come
//!   back.  Each penalty within a day of the last one ending is twice the one
//!   before, up to `max_penalty`, and a source that stays away for a day is
//!   forgiven.  An answered query still forgives everything at once, so a
//!   client that was misconfigured and has been fixed is simply a client
//!   again -- once any penalty it is serving has run out.
//! - **A penalty is served in full.**  Nothing a source asks while it is
//!   refused lifts the refusal, and it can still be asking: a penalty turns
//!   away new connections, not the ones already open.  A scanner held a DNS
//!   connection open, earned a penalty on the web port by asking for
//!   `/.env`, asked one real question on the connection it had kept and
//!   closed it -- and the report of that answer wiped the penalty and the
//!   offence behind it, so the escalation above never built up.
//! - **Some requests settle the question.**  Nothing but an attacker asks a
//!   DNS server's web interface for `/.env`, so `condemn` refuses a source on
//!   the spot rather than waiting for it to run out of strikes.
//! - **What the internet may hold at once is bounded.**  Not by rate -- see
//!   above -- but by what is open *now*: the connections one source has, the
//!   connections every source has, and the handshakes in progress.  Reaching
//!   one of those is being busy, which is not being hostile, so it is never a
//!   strike and never an offence, and it is logged at most once a minute so
//!   that a flood cannot become a flood of the log.  The allowance for one
//!   source is generous enough for a NAT full of phones that each hold a DoT
//!   connection open.
//!
//! The table of sources is bounded too, because remembering offenders for a
//! day means holding them longer than the ten minutes this used to: past
//! `MAX_TRACKED`, a source with nothing but strikes is given up before one
//! with a record, and one with a record before one serving a penalty.  A scan
//! from a million addresses costs a fixed amount of memory, not a million
//! entries.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ahash::AHashMap;
use parking_lot::{Mutex, RwLock};

/// How the guard decides, and for how long.
#[derive(Clone, Debug)]
pub struct Config {
    /// Connections that ask nothing, within `window`, before a source is shut
    /// out.  Zero switches the guard off -- the limits below included.
    pub strikes: u32,
    /// The span the strikes are counted over.
    pub window: Duration,
    /// How long a source is refused the first time it runs out of strikes.
    pub penalty: Duration,
    /// The longest a repeat offender is refused for.
    ///
    /// Each offence before the last one is forgiven is refused for twice as
    /// long as the one before it, starting from `penalty`, until it reaches
    /// this.  It never shortens the first penalty, whatever it is set to.
    pub max_penalty: Duration,
    /// How long a source must stay out of trouble, counted from the end of
    /// its last penalty, before its offences are forgotten.
    pub forgive: Duration,
    /// Whether an address on this network is left alone.
    ///
    /// The threat is the public internet, and a liveness check from the LAN
    /// that connects and closes is the shape this looks for without being the
    /// thing it is for.  Only the tests turn it off, so the refusal can be
    /// driven over loopback.
    pub exempt_local: bool,
    /// Addresses that are never shut out.
    ///
    /// This is `ratelimit_whitelist`: an operator who has already said an
    /// address is exempt from one defence means it, and reusing the setting
    /// keeps the config file exactly what the Go build writes.
    pub allowlist: Vec<IpAddr>,
    /// Networks that are this network too, as addresses and prefix lengths,
    /// beyond the ones every host has: loopback, private, link-local and
    /// unique-local addresses are local whatever this holds.  Consulted only
    /// while `exempt_local` is on.
    ///
    /// The binary fills it with `dns.private_networks`, or the resolver's
    /// own defaults when that is empty -- which is what brings in
    /// `100.64.0.0/10`, the shared space a carrier-grade NAT and Tailscale
    /// both hand out.
    pub local_networks: Vec<(IpAddr, u8)>,
    /// This host's own IPv6 /64s, as [`host_networks`] finds them, in which
    /// each address is judged as a source of its own rather than as the /64.
    ///
    /// Not an exemption: an address in one of these is struck, refused and
    /// held to its allowances like any other source, only on its own.  A
    /// household reaching the server by its global address comes from the
    /// server's /64, and should not be one shared allowance; but on a rented
    /// server that /64 can be shared with other customers, and exempting it
    /// would exempt them.  Each entry must be a /64 or longer, since an
    /// address in one is told apart by its low 64 bits.
    pub host_networks: Vec<(IpAddr, u8)>,
    /// Connections from judged sources that may be open at once, across every
    /// listener sharing the guard.  Zero means no limit.
    pub max_connections: usize,
    /// Connections one source may have open at once.  Zero means no limit.
    pub max_per_source: usize,
    /// TLS and QUIC handshakes from judged sources that may be in progress at
    /// once.  Zero means no limit.
    pub max_handshakes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // Six in a minute is far more than a client or a monitor makes,
            // and a scanner at two a second reaches it in three seconds.
            strikes: 6,
            window: Duration::from_secs(60),
            penalty: Duration::from_secs(600),
            // Doubling from ten minutes reaches a day at the ninth offence,
            // and a day is as long as refusing anyone is worth: past it the
            // entry is only memory, and the scanner has moved on or will be
            // back to earn another one.
            max_penalty: Duration::from_secs(24 * 3600),
            // Scanners come back on a schedule -- hourly, daily -- so a day
            // after release is long enough to still recognise one that is
            // still at it, while a household whose one misconfigured device
            // tripped the guard once is back to a clean record by the next
            // day even if it never asks anything in between.
            forgive: Duration::from_secs(24 * 3600),
            exempt_local: true,
            allowlist: Vec::new(),
            local_networks: crate::resolver::default_private_networks(),
            host_networks: Vec::new(),
            // Far more than one small server needs, and small enough that
            // what the internet can hold open stays a few thousand sockets
            // and buffers rather than whatever the kernel allows.
            max_connections: 4096,
            // A NAT full of phones, each holding a DoT connection open, fits;
            // one address cannot take the whole budget.
            max_per_source: 64,
            // A handshake is the one thing here that costs real CPU, and it
            // finishes in milliseconds for a client that means it.
            max_handshakes: 256,
        }
    }
}

/// Why `Guard::open` turned a connection away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The source is serving a penalty.
    Banned,
    /// A limit on what may be open at once has been reached.  This says
    /// nothing against the source.
    Busy,
}

/// What the guard has seen, for diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Stats {
    /// Sources with anything held against them: strikes, a penalty, or
    /// offences not yet forgiven.
    pub tracked: usize,
    /// Of those, the ones being refused right now.
    pub banned: usize,
    /// Connections from judged sources open right now, across every listener.
    pub open: usize,
    /// Sources with at least one of those open.
    pub sources: usize,
    /// Handshakes from judged sources in progress right now.
    pub handshakes: usize,
    /// Connections turned away since start because their source was being
    /// refused.
    pub refused_banned: u64,
    /// Connections and handshakes turned away since start because a limit
    /// was reached.
    pub refused_busy: u64,
    /// Penalties imposed since start, by strikes and by `condemn` alike.
    pub penalties: u64,
    /// Of those, the ones `condemn` imposed.
    pub condemned: u64,
    /// QUIC connection attempts answered with a Retry since start.
    pub retried: u64,
}

/// The unit a source is judged as.
///
/// An IPv4 address is one source, and an IPv6 address is judged as its /64:
/// that is what one subscriber is given, and every address in it is free to
/// whoever holds it.  In this host's own /64s each address is a source of
/// its own, kept as the low 64 bits alone since the prefix is the host's.
/// Kept as bytes rather than an `IpAddr` so an entry in the table stays
/// small.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Key {
    V4([u8; 4]),
    V6([u8; 8]),
    /// An address in one of `Config::host_networks`, by its interface
    /// identifier.  Two host /64s at once -- the old prefix and the new while
    /// an ISP renumbers -- would share a key for the same identifier, which
    /// is the same device under a stable identifier and harmless otherwise.
    Host([u8; 8]),
}

impl Key {
    /// The source `ip` is judged as under `cfg`.
    fn of(cfg: &Config, ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(a) => Self::V4(a.octets()),
            IpAddr::V6(a) => {
                let bits = a.to_bits();
                let [prefix, iid] = [bits >> 64, bits & u128::from(u64::MAX)]
                    .map(|half| u64::try_from(half).expect("a half fits").to_be_bytes());
                let host = cfg
                    .host_networks
                    .iter()
                    .any(|&(net, len)| crate::clients::in_subnet(IpAddr::V6(a), net, len));

                if host {
                    Self::Host(iid)
                } else {
                    Self::V6(prefix)
                }
            }
        }
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::V4(o) => fmt::Display::fmt(&Ipv4Addr::from(o), f),
            Self::V6(p) => {
                let a = Ipv6Addr::from_bits(u128::from(u64::from_be_bytes(p)) << 64);

                write!(f, "{a}/64")
            }
            Self::Host(i) => {
                let a = Ipv6Addr::from_bits(u128::from(u64::from_be_bytes(i)));

                write!(f, "{a} in this host's /64")
            }
        }
    }
}

/// The source an address is judged as, from [`Guard::source`]: what other
/// defences key their own per-source state by, so they draw the line
/// between one source and the next exactly where the guard does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Source(Key);

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// What is known about one source.
///
/// The times are whole seconds on the guard's own clock rather than
/// `Instant`s, which keeps an entry at a fifth of the size: the table can
/// hold tens of thousands of them, and nothing here needs finer than a
/// second.
#[derive(Clone, Copy, Debug)]
struct Mark {
    /// Connections that asked nothing since `first`.
    strikes: u32,
    /// Penalties earned since the source was last forgiven.
    offences: u32,
    /// When the current window started.
    first: u32,
    /// When the most recent penalty ends or ended, or zero if it never had
    /// one.
    until: u32,
    /// When anything was last held against it, which is what eviction goes
    /// by.
    seen: u32,
}

impl Mark {
    fn new(now: u32) -> Self {
        Self {
            strikes: 0,
            offences: 0,
            first: now,
            until: 0,
            seen: now,
        }
    }

    /// Reports whether the source is being refused.
    fn banned(&self, now: u32) -> bool {
        now < self.until
    }

    /// Reports whether anything is still held against the source.
    fn worth_keeping(&self, now: u32, t: &Terms) -> bool {
        self.banned(now)
            || (self.strikes > 0 && now.saturating_sub(self.first) < t.window)
            || (self.offences > 0 && now < self.until.saturating_add(t.forgive))
    }

    /// The order sources are given up in when the table is full: one with
    /// only strikes first, then one with a record, then one being refused.
    fn rank(&self, now: u32) -> u8 {
        if self.banned(now) {
            2
        } else if self.offences > 0 {
            1
        } else {
            0
        }
    }
}

/// The configuration's numbers, in the guard's own seconds.
#[derive(Clone, Copy, Debug)]
struct Terms {
    strikes: u32,
    window: u32,
    penalty: u32,
    max_penalty: u32,
    forgive: u32,
}

impl Terms {
    fn of(cfg: &Config) -> Self {
        Self {
            strikes: cfg.strikes,
            window: secs(cfg.window),
            penalty: secs(cfg.penalty),
            max_penalty: secs(cfg.max_penalty),
            forgive: secs(cfg.forgive),
        }
    }

    /// How long the `n`-th offence is refused for.
    fn penalty_for(&self, n: u32) -> u32 {
        let doubling = 1u32.checked_shl(n.saturating_sub(1)).unwrap_or(u32::MAX);

        self.penalty
            .saturating_mul(doubling)
            .min(self.max_penalty.max(self.penalty))
    }
}

/// A duration in whole seconds, rounded up so that a penalty is never
/// shorter than asked for.
fn secs(d: Duration) -> u32 {
    let s = d.as_secs().saturating_add(u64::from(d.subsec_nanos() > 0));

    u32::try_from(s).unwrap_or(u32::MAX)
}

/// How many sources may accumulate before a sweep is forced.
const SWEEP_AT: usize = 16_384;

/// The most sources the table holds, whatever is scanning.
///
/// At 32 bytes an entry this is a few megabytes at worst -- a small price
/// for a table a distributed scan cannot grow without bound.
const MAX_TRACKED: usize = 65_536;

/// What the table is cut back to once it reaches `MAX_TRACKED`, so the cost
/// of cutting it is paid once per many sources rather than once per source.
const EVICT_TO: usize = MAX_TRACKED - MAX_TRACKED / 4;

/// How often the table is swept even when it is not growing, in seconds.
const SWEEP_EVERY: u32 = 600;

/// The smallest capacity worth shrinking the table back to.
const SHRINK_FLOOR: usize = 1024;

/// How often a refusal at a limit may be logged, in seconds.
const WARN_EVERY: u32 = 60;

/// The guard's mutable state, behind one lock so the accept path takes it
/// once.
struct State {
    /// Everything held against each source.
    marks: AHashMap<Key, Mark>,
    /// Connections open per source, holding only sources that have one: an
    /// entry is removed when its last connection closes.
    live: AHashMap<Key, u32>,
    /// Connections open across every source in `live`.
    open: usize,
    /// The table size at which `marks` is next swept.
    sweep_at: usize,
    /// When `marks` was last swept.
    swept: u32,
}

impl State {
    /// Forgets what is no longer held against anyone, and gives up sources
    /// if the table is still too large.
    fn sweep(&mut self, now: u32, t: &Terms) {
        self.marks.retain(|_, m| m.worth_keeping(now, t));
        if self.marks.len() >= MAX_TRACKED {
            self.evict(EVICT_TO, now);
        }

        let len = self.marks.len();
        if self.marks.capacity() > 4 * len.max(SHRINK_FLOOR) {
            self.marks.shrink_to(2 * len);
        }

        self.sweep_at = (2 * len).clamp(SWEEP_AT, MAX_TRACKED);
        self.swept = now;
    }

    /// Gives up sources until `keep` are left, in `Mark::rank` order and the
    /// least recently seen first within a rank.
    fn evict(&mut self, keep: usize, now: u32) {
        let excess = self.marks.len().saturating_sub(keep);
        if excess == 0 {
            return;
        }

        let mut order: Vec<(u8, u32, Key)> = self
            .marks
            .iter()
            .map(|(k, m)| (m.rank(now), m.seen, *k))
            .collect();
        order.select_nth_unstable(excess - 1);
        for (_, _, k) in &order[..excess] {
            self.marks.remove(k);
        }
    }
}

/// Refuses connections from a source that has proved it never asks anything,
/// and bounds what the internet may hold open at once.
///
/// The configuration sits behind its own lock because `/control/dns_config`
/// can change the allowlist on a running server.
pub struct Guard {
    cfg: RwLock<Config>,
    state: Mutex<State>,
    /// Handshakes in progress.  Global rather than per source, so it lives
    /// outside the lock and a slot is taken with one atomic operation.
    handshakes: AtomicUsize,
    /// What the guard's clock counts from.
    epoch: Instant,
    /// When a refusal at a limit was last logged, plus one so that zero can
    /// mean never.
    warned: AtomicU32,
    /// Refusals at a limit since the last one logged.
    unwarned: AtomicU64,
    refused_banned: AtomicU64,
    refused_busy: AtomicU64,
    penalties: AtomicU64,
    condemned: AtomicU64,
    retried: AtomicU64,
    /// Seconds added to the clock, so the tests do not have to wait.
    #[cfg(test)]
    skew: AtomicU32,
}

impl Guard {
    /// Builds a guard.
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg: RwLock::new(cfg),
            state: Mutex::new(State {
                marks: AHashMap::new(),
                live: AHashMap::new(),
                open: 0,
                sweep_at: SWEEP_AT,
                swept: 0,
            }),
            handshakes: AtomicUsize::new(0),
            epoch: Instant::now(),
            warned: AtomicU32::new(0),
            unwarned: AtomicU64::new(0),
            refused_banned: AtomicU64::new(0),
            refused_busy: AtomicU64::new(0),
            penalties: AtomicU64::new(0),
            condemned: AtomicU64::new(0),
            retried: AtomicU64::new(0),
            #[cfg(test)]
            skew: AtomicU32::new(0),
        }
    }

    /// Replaces the configuration on a running guard.
    ///
    /// The marks are kept, unlike the rate limiter's buckets: a reconfigure
    /// happens whenever an operator saves the DNS settings, and dropping them
    /// would hand every scanner a fresh start each time.  An address added to
    /// the allowlist is exempt at once regardless, because `admits` consults
    /// the list before the marks.
    ///
    /// Lowering a limit leaves what is already open alone: every `Ticket`
    /// and `HandshakeSlot` gives back exactly what it took, so the counts
    /// simply stay above the new limit, refusing newcomers, until enough of
    /// them close.
    pub fn set_config(&self, cfg: Config) {
        *self.cfg.write() = cfg;
    }

    /// Reports whether a connection from `ip` should be accepted.
    ///
    /// Called before the TLS handshake, which is the whole point: the
    /// handshake is the cost being avoided.  This consults the penalties
    /// alone and charges nothing; `open` is the same question with the limits
    /// on what may be open at once as well.
    ///
    /// A penalty only turns away connections that have not been made yet.  A
    /// caller that holds connections open across many requests, and strikes
    /// or condemns per request, asks this per request too.
    pub fn admits(&self, ip: IpAddr) -> bool {
        let Some(key) = self.judged(ip) else {
            return true;
        };

        let now = self.now();
        let banned = self
            .state
            .lock()
            .marks
            .get(&key)
            .is_some_and(|m| m.banned(now));
        if banned {
            self.refused_banned.fetch_add(1, Ordering::Relaxed);
        }

        !banned
    }

    /// Reports whether `ip` is serving a penalty, without counting anything.
    ///
    /// `admits` is the question asked of a connection or a request about to
    /// be turned away, and counts each refusal; this is the same question
    /// asked for a report, such as whether a closing connection may still
    /// clear its source -- a source refused while it had a connection open
    /// may not.
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        let Some(key) = self.judged(ip) else {
            return false;
        };

        let now = self.now();

        self.state
            .lock()
            .marks
            .get(&key)
            .is_some_and(|m| m.banned(now))
    }

    /// Admits a connection from `ip` and counts it as open until the ticket
    /// is dropped.
    ///
    /// Called with an address the transport has proved: as soon as a TCP
    /// connection is accepted, and before its TLS handshake; for QUIC,
    /// `crate::quic` calls it once the address is validated.  It refuses a
    /// source serving a penalty, one that already has `max_per_source`
    /// connections open, and anyone at all once `max_connections` are open.
    /// A refusal is only ever the connection being closed: being turned away
    /// because the server is busy is not held against a source.
    ///
    /// An exempt source is given a ticket that counts nothing, without
    /// touching the table.
    ///
    /// A TCP listener's accept loop, with the handshake bounded as the
    /// existing listeners already bound it:
    ///
    /// ```text
    /// let Ok(ticket) = guard.open(peer.ip()) else { continue };
    /// let Some(slot) = guard.handshake(peer.ip()) else { continue };
    /// spawn(async move {
    ///     let tls = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await;
    ///     drop(slot);
    ///     let Ok(Ok(tls)) = tls else { guard.wasted(peer.ip()); return };
    ///     let served = serve(tls).await;
    ///     guard.record(peer.ip(), served);
    ///     drop(ticket);
    /// });
    /// ```
    ///
    /// Plain DNS over TCP has no handshake, so it takes a ticket and no slot.
    pub fn open(self: &Arc<Self>, ip: IpAddr) -> Result<Ticket, Refused> {
        let (key, total, per_source) = {
            let cfg = self.cfg.read();
            if exempt(&cfg, ip) {
                return Ok(Ticket(None));
            }

            (Key::of(&cfg, ip), cfg.max_connections, cfg.max_per_source)
        };

        let now = self.now();
        let mut st = self.state.lock();
        if st.marks.get(&key).is_some_and(|m| m.banned(now)) {
            drop(st);
            self.refused_banned.fetch_add(1, Ordering::Relaxed);

            return Err(Refused::Banned);
        }

        let held = st.live.get(&key).copied().unwrap_or(0);
        let over = if total != 0 && st.open >= total {
            Some(("connections", total))
        } else if per_source != 0 && held as usize >= per_source {
            Some(("per source", per_source))
        } else {
            None
        };
        if let Some((limit, max)) = over {
            drop(st);
            self.refuse_busy(ip, limit, max, now);

            return Err(Refused::Busy);
        }

        st.live.insert(key, held + 1);
        st.open += 1;
        drop(st);

        Ok(Ticket(Some(Held {
            guard: self.clone(),
            key,
        })))
    }

    /// Takes one of the `max_handshakes` slots for a handshake from `ip`,
    /// held until the slot is dropped.
    ///
    /// For an address the transport has proved.  It does not consult the
    /// penalties -- `open` has already done that -- and a caller refused a
    /// slot closes the connection and records nothing, since being busy is
    /// not the source's fault.  Drop the slot the moment the handshake
    /// finishes or fails, not when the connection closes.  An exempt source
    /// is given a slot that counts nothing.
    pub fn handshake(self: &Arc<Self>, ip: IpAddr) -> Option<HandshakeSlot> {
        let max = {
            let cfg = self.cfg.read();
            if exempt(&cfg, ip) {
                return Some(HandshakeSlot(None));
            }

            cfg.max_handshakes
        };

        let slot = self.take_handshake(max);
        if slot.is_none() {
            self.refuse_busy(ip, "handshakes", max, self.now());
        }

        slot
    }

    /// Records how one finished connection from `ip` behaved.
    ///
    /// `served` is the number of queries it was answered, so the two cases a
    /// caller has are one call.  A connection with neither to report is not
    /// reported at all: one whose every question was turned away because the
    /// server was busy, and one that closed the moment it opened without
    /// sending a byte, before anything was spent on it.
    pub fn record(&self, ip: IpAddr, served: u32) {
        if served == 0 {
            self.wasted(ip);
        } else {
            self.served(ip);
        }
    }

    /// Records that a connection from `ip` answered at least one query.
    ///
    /// That clears everything held against the source -- its strikes and its
    /// offences -- and for IPv6 it clears the whole /64, outside this host's
    /// own: a source that asks something is a client.  Everything except a
    /// penalty being served,
    /// which only runs out.  A penalty refuses new connections, not the ones
    /// a source already has, so a scanner that kept a DNS connection open
    /// while it earned a penalty elsewhere could otherwise ask one real
    /// question on it and have the penalty, and the offence behind it,
    /// forgotten.
    ///
    /// Decided under the same lock as the clearing, so a penalty imposed
    /// while this report is on its way is not lifted by it either.
    pub fn served(&self, ip: IpAddr) {
        let Some(key) = self.judged(ip) else {
            return;
        };

        let now = self.now();
        let mut st = self.state.lock();
        if st.marks.get(&key).is_some_and(|m| m.banned(now)) {
            return;
        }

        st.marks.remove(&key);
    }

    /// Records that a connection from `ip` closed without asking anything.
    ///
    /// The caller must only report an address the transport has proved --
    /// anything accepted over TCP, or a QUIC connection whose handshake
    /// completed.
    pub fn wasted(&self, ip: IpAddr) {
        self.charge(ip, None);
    }

    /// Holds one strike against `ip` for something short of a query.
    ///
    /// Worth exactly one wasted connection, but callable per request: for a
    /// connection that is kept open and used for things no client needs --
    /// a wrong password, a request that does not parse, a path that is not
    /// there.  A real client does these by mistake now and then, so it is
    /// allowed a few within the window before it is refused.  An act that no
    /// client commits even by mistake is `condemn`'s instead.
    ///
    /// A request that earned a strike is not a request the connection was
    /// served: count it out of what is later passed to `record`, or the
    /// report at close clears the strike it just earned.
    pub fn strike(&self, ip: IpAddr) {
        self.charge(ip, None);
    }

    /// Refuses `ip` at once, for something only a hostile client does.
    ///
    /// For a request that settles the question on its own -- the web
    /// interface asked for `/.env` or `/wp-login.php`, paths that exist on
    /// no server like this one and are asked for only by something looking
    /// for a way in.  It is an offence like running out of strikes, so it
    /// escalates the same way, and `reason` says in the log which act it was.
    /// Nothing counts while a source is already refused, so a burst of such
    /// requests on one connection is one offence, not one each.  An exempt
    /// source is never condemned.
    ///
    /// Two things for the caller.  The penalty turns away new connections,
    /// not the one that earned it: close it, or check `admits` per request.
    /// And that connection must not then be reported as served, whatever
    /// else it asked -- a scanner fetches `/` before `/.env`.  `served`
    /// leaves a penalty in progress alone, but a kept-alive connection can
    /// outlast one, and its report would then forgive the offence it earned.
    pub fn condemn(&self, ip: IpAddr, reason: &'static str) {
        self.charge(ip, Some(reason));
    }

    /// Holds a strike, or with a reason a condemnation, against `ip`.
    fn charge(&self, ip: IpAddr, reason: Option<&'static str>) {
        let (key, t) = {
            let cfg = self.cfg.read();
            if exempt(&cfg, ip) {
                return;
            }

            (Key::of(&cfg, ip), Terms::of(&cfg))
        };

        let now = self.now();
        let mut st = self.state.lock();
        if (st.marks.len() >= st.sweep_at && !st.marks.contains_key(&key))
            || now.saturating_sub(st.swept) >= SWEEP_EVERY
        {
            st.sweep(now, &t);
        }

        let m = st.marks.entry(key).or_insert_with(|| Mark::new(now));

        // Already shut out: nothing it does while refused counts again.
        if m.banned(now) {
            return;
        }

        m.seen = now;
        if now.saturating_sub(m.first) >= t.window {
            m.strikes = 0;
            m.first = now;
        }
        if m.offences > 0 && now >= m.until.saturating_add(t.forgive) {
            m.offences = 0;
        }

        let connections = if reason.is_none() {
            m.strikes += 1;
            if m.strikes < t.strikes {
                return;
            }

            m.strikes
        } else {
            0
        };

        // The strikes are spent on the penalty rather than held over it, so
        // a source that has served its time starts again from nothing.
        m.strikes = 0;
        m.offences = m.offences.saturating_add(1);
        let offence = m.offences;
        let seconds = t.penalty_for(offence);
        m.until = now.saturating_add(seconds);
        drop(st);

        self.penalties.fetch_add(1, Ordering::Relaxed);

        // The one line worth logging, and the one rustls could not give: its
        // warning names the address the client *dialled*, never the client.
        // Bounded by the penalty, so it cannot itself flood.
        match reason {
            None => tracing::info!(
                client = %ip,
                source = %key,
                connections,
                offence,
                seconds,
                "refusing a source that keeps connecting without asking anything"
            ),
            Some(reason) => {
                self.condemned.fetch_add(1, Ordering::Relaxed);
                tracing::info!(
                    client = %ip,
                    source = %key,
                    reason,
                    offence,
                    seconds,
                    "refusing a source for a request only an attacker makes"
                );
            }
        }
    }

    /// The source `ip` is judged as, or `None` when it is outside the guard's
    /// remit altogether.
    fn judged(&self, ip: IpAddr) -> Option<Key> {
        let cfg = self.cfg.read();

        (!exempt(&cfg, ip)).then(|| Key::of(&cfg, ip))
    }

    /// Reports whether `ip` is one the guard leaves alone: on this network,
    /// or listed in `ratelimit_whitelist`.
    ///
    /// For the other defences that should spare the same sources the guard
    /// does, so that "local" means one thing throughout: the bound on queries
    /// in flight asks this, and so does the login throttle.  Unlike the
    /// guard's own check it does not spare everyone while the guard is
    /// switched off, because those defences are not.
    ///
    /// This host's own IPv6 /64s are not among them.  On a rented server the
    /// /64 an address comes from is often shared with other customers --
    /// Linode, DigitalOcean and others hand theirs out that way -- and
    /// exempting it would exempt them; an address there is judged on its
    /// own instead, see [`Guard::source`].
    pub fn exempts(&self, ip: IpAddr) -> bool {
        spared(&self.cfg.read(), ip)
    }

    /// The source `ip` is judged as, for another defence to key its own
    /// per-source state by: an IPv4 address; an IPv6 /64; or, inside one of
    /// this host's own /64s, the address itself.
    ///
    /// The bound on queries in flight keys by this, so that a household
    /// reaching the server by its global IPv6 address is a budget per device
    /// there as it is here, rather than one between all of them.  It says
    /// nothing about exemption, which is [`Guard::exempts`].
    pub fn source(&self, ip: IpAddr) -> Source {
        Source(Key::of(&self.cfg.read(), ip))
    }

    /// Counts a refusal at a limit, and logs it if none has been logged for
    /// a minute.
    fn refuse_busy(&self, ip: IpAddr, limit: &'static str, max: usize, now: u32) {
        self.refused_busy.fetch_add(1, Ordering::Relaxed);
        self.unwarned.fetch_add(1, Ordering::Relaxed);

        if let Some(refused) = self.due_warning(now) {
            tracing::warn!(
                client = %ip,
                limit,
                max,
                refused,
                "turning connections away: the limit on what the internet may hold open was reached"
            );
        }
    }

    /// Claims the right to log a refusal at a limit, returning how many there
    /// have been since the last one logged.
    ///
    /// One caller a minute wins, whichever listener it is on, so a flood of
    /// refusals is one line a minute however fast it arrives.
    fn due_warning(&self, now: u32) -> Option<u64> {
        let last = self.warned.load(Ordering::Relaxed);
        let stamp = now.saturating_add(1);
        if last != 0 && stamp < last.saturating_add(WARN_EVERY) {
            return None;
        }

        self.warned
            .compare_exchange(last, stamp, Ordering::Relaxed, Ordering::Relaxed)
            .ok()?;

        Some(self.unwarned.swap(0, Ordering::Relaxed))
    }

    /// Takes a handshake slot against `max`, counting it whoever it is for.
    fn take_handshake(self: &Arc<Self>, max: usize) -> Option<HandshakeSlot> {
        self.handshakes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (max == 0 || n < max).then_some(n + 1)
            })
            .ok()?;

        Some(HandshakeSlot(Some(self.clone())))
    }

    /// Takes a handshake slot for an address nobody has proved yet.
    ///
    /// The slot is counted even when the address claims to be exempt: an
    /// exemption is a property of an address, and an unvalidated QUIC packet
    /// has not shown that it comes from the one it names.  Nothing is logged
    /// on failure, because the caller asks for a Retry rather than refusing.
    pub(crate) fn unproven_handshake(self: &Arc<Self>) -> Option<HandshakeSlot> {
        let max = self.cfg.read().max_handshakes;

        self.take_handshake(max)
    }

    /// Reports whether half the handshake slots are taken.
    ///
    /// Past that point an address nobody has proved is asked to prove itself
    /// before it gets one: a spoofer can hold the first half until its
    /// handshakes time out, and never the second.
    pub(crate) fn handshakes_scarce(&self) -> bool {
        let max = self.cfg.read().max_handshakes;

        max != 0 && self.handshakes.load(Ordering::Relaxed).saturating_mul(2) >= max
    }

    /// Reports how a connection from `ip` would fare in `open`, without
    /// charging it anything.
    pub(crate) fn standing(&self, ip: IpAddr) -> Result<(), Refused> {
        let (key, total, per_source) = {
            let cfg = self.cfg.read();
            if exempt(&cfg, ip) {
                return Ok(());
            }

            (Key::of(&cfg, ip), cfg.max_connections, cfg.max_per_source)
        };

        let now = self.now();
        let st = self.state.lock();
        if st.marks.get(&key).is_some_and(|m| m.banned(now)) {
            drop(st);
            self.refused_banned.fetch_add(1, Ordering::Relaxed);

            return Err(Refused::Banned);
        }

        let held = st.live.get(&key).copied().unwrap_or(0) as usize;
        if (total != 0 && st.open >= total) || (per_source != 0 && held >= per_source) {
            return Err(Refused::Busy);
        }

        Ok(())
    }

    /// Counts a QUIC Retry sent.
    pub(crate) fn retried(&self) {
        self.retried.fetch_add(1, Ordering::Relaxed);
    }

    /// Gives back one connection held by `key`.
    fn release(&self, key: Key) {
        let mut st = self.state.lock();
        if let Some(n) = st.live.get_mut(&key) {
            *n -= 1;
            if *n == 0 {
                st.live.remove(&key);
            }
        }
        st.open -= 1;
    }

    /// The guard's clock, in whole seconds since it was built.
    fn now(&self) -> u32 {
        let now = u32::try_from(self.epoch.elapsed().as_secs()).unwrap_or(u32::MAX);
        #[cfg(test)]
        let now = now.saturating_add(self.skew.load(Ordering::Relaxed));

        now
    }

    /// The number of tracked sources.
    pub fn tracked(&self) -> usize {
        self.state.lock().marks.len()
    }

    /// What the guard has seen.
    ///
    /// Walks the table to count the sources being refused, so it is for
    /// diagnostics rather than anything on a hot path.
    pub fn stats(&self) -> Stats {
        let now = self.now();
        let (tracked, banned, open, sources) = {
            let st = self.state.lock();

            (
                st.marks.len(),
                st.marks.values().filter(|m| m.banned(now)).count(),
                st.open,
                st.live.len(),
            )
        };

        Stats {
            tracked,
            banned,
            open,
            sources,
            handshakes: self.handshakes.load(Ordering::Relaxed),
            refused_banned: self.refused_banned.load(Ordering::Relaxed),
            refused_busy: self.refused_busy.load(Ordering::Relaxed),
            penalties: self.penalties.load(Ordering::Relaxed),
            condemned: self.condemned.load(Ordering::Relaxed),
            retried: self.retried.load(Ordering::Relaxed),
        }
    }

    /// Forgets every source.
    ///
    /// Only what is held against them: the connections open now stay
    /// counted, because their tickets will still give them back.
    pub fn clear(&self) {
        let mut st = self.state.lock();
        st.marks.clear();
        st.sweep_at = SWEEP_AT;
    }

    /// Moves the clock on, so the tests do not have to wait.
    #[cfg(test)]
    pub(crate) fn advance(&self, by: Duration) {
        self.skew.fetch_add(secs(by), Ordering::Relaxed);
    }
}

impl Default for Guard {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

/// Reports whether `ip` is outside the guard's remit under `cfg`.
///
/// Judged on the full address, never on its /64: an operator who exempts
/// one address has not exempted its neighbours.  The allowlist is compared
/// in canonical form, so an IPv4 client reaching a dual-stack socket as
/// `::ffff:a.b.c.d` is still the address the operator wrote down.
fn exempt(cfg: &Config, ip: IpAddr) -> bool {
    cfg.strikes == 0 || spared(cfg, ip)
}

/// Reports whether `cfg` spares `ip` for what it is, rather than because the
/// guard is off: an address on this network, or one the operator listed.
fn spared(cfg: &Config, ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    let local = || {
        is_local(ip)
            || cfg
                .local_networks
                .iter()
                .any(|&(net, bits)| crate::clients::in_subnet(ip, net, bits))
    };

    (cfg.exempt_local && local()) || cfg.allowlist.iter().any(|a| a.to_canonical() == ip)
}

/// This host's own IPv6 /64s, for `Config::host_networks`: the /64 of each
/// global IPv6 address among `addrs`, once each, in the order first seen.
///
/// A home server takes its global address from the LAN's /64, and so does
/// every device in the house.  When the router advertises the server by that
/// address, those devices reach it from the same /64, and the guard judges
/// each of them on its own there rather than all of them as one source.
///
/// Judged, not exempted, and never anything wider than the /64, because this
/// runs on rented servers too, where the /64 may be shared between customers
/// and an interface's on-link prefix may be a /48 that certainly is.  Nothing
/// for IPv4, whose on-link subnets are other people's machines too, and
/// whose addresses are judged one at a time anyway.  Unique-local and
/// link-local addresses are local already, and a Teredo address's /64 is
/// shared by every client of its relay, so neither is included.
pub fn host_networks(addrs: impl IntoIterator<Item = IpAddr>) -> Vec<(IpAddr, u8)> {
    let mut out: Vec<(IpAddr, u8)> = Vec::new();
    for ip in addrs {
        let IpAddr::V6(a) = ip else {
            continue;
        };
        let teredo = a.segments()[..2] == [0x2001, 0];
        if a.is_multicast() || a.to_ipv4_mapped().is_some() || is_local(ip) || teredo {
            continue;
        }

        let prefix = Ipv6Addr::from_bits(a.to_bits() & !(u128::MAX >> 64));
        let net = (IpAddr::V6(prefix), 64);
        if !out.contains(&net) {
            out.push(net);
        }
    }

    out
}

/// One open connection, counted against the limits until it is dropped.
///
/// Returned by `Guard::open`.  Hold it for as long as the connection is
/// open, and let it drop when the connection closes; it gives back exactly
/// what it took, whatever the configuration has become in the meantime.
#[must_use = "the connection is counted only while the ticket is held"]
pub struct Ticket(Option<Held>);

/// What a counted ticket holds.
struct Held {
    guard: Arc<Guard>,
    key: Key,
}

impl Ticket {
    /// Reports whether the connection is counted against the limits, which
    /// it is unless its source is exempt.
    pub fn is_counted(&self) -> bool {
        self.0.is_some()
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if let Some(h) = self.0.take() {
            h.guard.release(h.key);
        }
    }
}

impl fmt::Debug for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ticket")
            .field("counted", &self.is_counted())
            .finish()
    }
}

/// One handshake in progress, counted against `max_handshakes` until it is
/// dropped.
///
/// Returned by `Guard::handshake`.  Drop it the moment the handshake
/// finishes or fails.
#[must_use = "the handshake is counted only while the slot is held"]
pub struct HandshakeSlot(Option<Arc<Guard>>);

impl HandshakeSlot {
    /// Reports whether the handshake is counted against the limit, which it
    /// is unless its source is exempt.
    pub fn is_counted(&self) -> bool {
        self.0.is_some()
    }
}

impl Drop for HandshakeSlot {
    fn drop(&mut self) {
        if let Some(g) = self.0.take() {
            g.handshakes.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl fmt::Debug for HandshakeSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeSlot")
            .field("counted", &self.is_counted())
            .finish()
    }
}

/// Reports whether an address belongs to this network rather than the
/// internet.
///
/// These are local on every host, whatever it is configured with;
/// `Config::local_networks` adds the rest.  `Ipv6Addr::is_unique_local` and
/// `is_unicast_link_local` are still unstable, so `fc00::/7` and `fe80::/10`
/// are spelled out.
fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            a.is_loopback() || a.is_private() || a.is_link_local() || a.is_unspecified()
        }
        IpAddr::V6(a) => {
            let o = a.octets();

            a.is_loopback()
                || a.is_unspecified()
                || o[0] & 0xfe == 0xfc
                || (o[0] == 0xfe && o[1] & 0xc0 == 0x80)
                // An address mapped from IPv4 is judged as that address.
                || a.to_ipv4_mapped().is_some_and(|v4| {
                    v4.is_loopback() || v4.is_private() || v4.is_link_local()
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A public address, so nothing is exempt by locality.
    fn scanner() -> IpAddr {
        "198.51.100.7".parse().unwrap()
    }

    fn guard(strikes: u32) -> Guard {
        Guard::new(Config {
            strikes,
            ..Default::default()
        })
    }

    fn shared(cfg: Config) -> Arc<Guard> {
        Arc::new(Guard::new(cfg))
    }

    /// Runs `ip` out of strikes.
    fn strike_out(g: &Guard, ip: IpAddr) {
        let strikes = g.cfg.read().strikes;
        for _ in 0..strikes {
            g.wasted(ip);
        }
    }

    /// How long `ip`'s current penalty has left, in seconds.
    fn remaining(g: &Guard, ip: IpAddr) -> u32 {
        let now = g.now();
        let key = g.source(ip).0;
        let st = g.state.lock();

        st.marks
            .get(&key)
            .map_or(0, |m| m.until.saturating_sub(now))
    }

    #[test]
    fn a_source_that_never_asks_anything_is_refused() {
        let g = guard(3);
        let ip = scanner();

        for i in 0..2 {
            assert!(g.admits(ip), "strike {i} is not yet the last one");
            g.wasted(ip);
        }

        assert!(g.admits(ip), "two of three strikes is still a welcome");
        g.wasted(ip);
        assert!(!g.admits(ip), "the third strike shuts it out");
    }

    #[test]
    fn a_source_that_asks_something_is_never_refused() {
        // The whole point: a busy client -- or a NAT full of them -- opens
        // connections at any rate it likes.  Only silence counts, and one
        // answered query clears the record, so the alternation below can run
        // forever without the guard ever noticing it.
        let g = guard(3);
        let ip = scanner();

        for _ in 0..100 {
            assert!(g.admits(ip));
            g.wasted(ip);
            g.wasted(ip);
            g.served(ip);
        }

        assert!(g.admits(ip));
        assert_eq!(g.tracked(), 0, "an answered query leaves nothing behind");
    }

    #[test]
    fn connections_spread_out_do_not_accumulate() {
        // A liveness monitor connects to see whether the port answers and
        // closes without asking anything.  At one a minute it must never be
        // shut out, however long it runs -- which is why the strikes are
        // counted over a window rather than for ever.
        let g = guard(3);
        let ip = scanner();

        for _ in 0..50 {
            g.wasted(ip);
            g.advance(Duration::from_secs(61));
            assert!(g.admits(ip), "one connection a minute is not a scan");
        }
    }

    #[test]
    fn the_penalty_runs_out() {
        let g = guard(2);
        let ip = scanner();

        g.wasted(ip);
        g.wasted(ip);
        assert!(!g.admits(ip));

        g.advance(Duration::from_secs(601));
        assert!(g.admits(ip), "the penalty is served");

        // This used to assert that the address was forgotten outright.  It
        // no longer is, because a scanner comes back and its second offence
        // has to cost more than its first.  What must still hold is that the
        // strikes are not held against it: it starts again from none, and a
        // client that was misconfigured and fixed never runs out of them.
        assert_eq!(g.tracked(), 1, "the offence is remembered");
        g.wasted(ip);
        assert!(g.admits(ip), "and the strikes are not: one is not two");
    }

    #[test]
    fn a_local_address_is_never_refused() {
        let g = guard(1);

        for ip in [
            "127.0.0.1",
            "192.168.1.10",
            "10.4.4.4",
            "172.16.0.1",
            "169.254.1.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:192.168.1.10",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            for _ in 0..10 {
                g.wasted(ip);
            }
            g.condemn(ip, "a test");

            assert!(g.admits(ip), "{ip} is on this network, not the internet");
        }

        assert_eq!(g.tracked(), 0);
    }

    #[test]
    fn zero_strikes_switches_the_guard_off() {
        let g = shared(Config {
            strikes: 0,
            max_connections: 1,
            max_per_source: 1,
            max_handshakes: 1,
            ..Default::default()
        });
        let ip = scanner();

        for _ in 0..1000 {
            g.wasted(ip);
        }
        g.condemn(ip, "a test");

        assert!(g.admits(ip));
        assert_eq!(g.tracked(), 0);

        // The limits are part of the guard, so they go off with it.
        let held: Vec<_> = (0..10).map(|_| g.open(ip).unwrap()).collect();
        let slots: Vec<_> = (0..10).map(|_| g.handshake(ip).unwrap()).collect();
        assert!(held.iter().all(|t| !t.is_counted()));
        assert!(slots.iter().all(|s| !s.is_counted()));
    }

    #[test]
    fn an_allowlisted_address_is_exempt_at_once() {
        let g = guard(1);
        let ip = scanner();

        g.wasted(ip);
        assert!(!g.admits(ip));

        // `ratelimit_whitelist` is the operator's escape hatch, and saving it
        // has to take effect on the running server rather than at the next
        // restart.
        g.set_config(Config {
            strikes: 1,
            allowlist: vec![ip],
            ..Default::default()
        });
        assert!(g.admits(ip), "the allowlist is consulted before the marks");
    }

    #[test]
    fn an_allowlisted_address_is_recognised_when_it_arrives_mapped() {
        // A dual-stack socket reports an IPv4 client as `::ffff:a.b.c.d`, and
        // the operator wrote down `a.b.c.d`.
        let g = Guard::new(Config {
            strikes: 1,
            allowlist: vec![scanner()],
            ..Default::default()
        });
        let mapped: IpAddr = "::ffff:198.51.100.7".parse().unwrap();

        g.wasted(mapped);
        assert!(g.admits(mapped));
        assert_eq!(g.tracked(), 0);
    }

    #[test]
    fn a_public_address_is_not_local() {
        for ip in ["198.51.100.7", "8.8.8.8", "2001:db8::1", "::ffff:8.8.8.8"] {
            assert!(!is_local(ip.parse().unwrap()), "{ip} is on the internet");
        }
    }

    /// This host's global address, and two other devices in its /64.
    const HOST: &str = "2001:db8:aa:bb::53";
    const HOST_DEVICE: &str = "2001:db8:aa:bb:1c2d:3e4f:5a6b:7c8d";
    const HOST_NEIGHBOUR: &str = "2001:db8:aa:bb:9e8d:7c6b:5a4f:3e2d";

    /// A shared guard with `strikes`, on a host whose address is `HOST`.
    fn guard_on_host(strikes: u32) -> Arc<Guard> {
        shared(Config {
            strikes,
            host_networks: host_networks([HOST.parse().unwrap()]),
            ..Default::default()
        })
    }

    /// A guard with one strike to give, local networks as `local`.
    fn guard_with_local(local: Vec<(IpAddr, u8)>) -> Guard {
        Guard::new(Config {
            strikes: 1,
            local_networks: local,
            ..Default::default()
        })
    }

    /// Reports whether `g` leaves `ip` alone, asked both ways it is asked.
    fn spares(g: &Guard, ip: &str) -> bool {
        let ip: IpAddr = ip.parse().unwrap();
        g.condemn(ip, "a test");
        let admitted = g.admits(ip);
        assert_eq!(admitted, g.exempts(ip), "{ip}: one notion of local");

        admitted
    }

    #[test]
    fn an_address_in_a_configured_private_network_is_local() {
        // `dns.private_networks` is the operator saying what their network
        // is, and the resolver already believes them.
        let g = guard_with_local(vec![("203.0.113.0".parse().unwrap(), 24)]);

        assert!(spares(&g, "203.0.113.77"));
        assert!(spares(&g, "::ffff:203.0.113.78"), "mapped, it is the same");
        assert!(!spares(&g, "203.0.114.1"), "the next /24 is the internet");
        assert!(
            spares(&g, "192.168.1.10"),
            "the networks every host has stay local whatever is configured"
        );
    }

    #[test]
    fn shared_address_space_is_local_by_default() {
        // 100.64.0.0/10: carrier-grade NAT, and every Tailscale address.  The
        // client registry already called it local; the guard did not.
        let g = guard(1);

        assert!(spares(&g, "100.64.0.1"));
        assert!(spares(&g, "100.101.102.103"));
        assert!(!spares(&g, "100.128.0.1"), "past the /10");
    }

    #[test]
    fn an_address_in_the_hosts_own_slash_64_is_not_exempt() {
        // On a rented server the /64 may be shared with other customers, so
        // an address in it is judged, only on its own.
        let g = guard_on_host(1);

        assert!(!spares(&g, HOST_DEVICE));
        let neighbour: IpAddr = HOST_NEIGHBOUR.parse().unwrap();
        assert!(!g.exempts(neighbour));
        assert!(g.open(neighbour).unwrap().is_counted(), "it is counted");
    }

    #[test]
    fn two_addresses_in_the_hosts_own_slash_64_are_separate_sources() {
        // A household reaching the server by its global address: one device
        // tripping the guard is not a ban for the rest.
        let g = guard_on_host(2);
        let (a, b): (IpAddr, IpAddr) = (
            HOST_DEVICE.parse().unwrap(),
            HOST_NEIGHBOUR.parse().unwrap(),
        );

        strike_out(&g, a);
        assert!(!g.admits(a));
        assert!(g.admits(b), "the next device is somebody else");
        g.wasted(b);
        assert!(g.admits(b), "with strikes of its own");
        assert_eq!(g.tracked(), 2);
        assert_ne!(g.source(a), g.source(b));
    }

    #[test]
    fn each_address_in_the_hosts_own_slash_64_has_its_own_allowance() {
        let g = Arc::new(Guard::new(Config {
            max_per_source: 2,
            host_networks: host_networks([HOST.parse().unwrap()]),
            ..Default::default()
        }));
        let (a, b): (IpAddr, IpAddr) = (
            HOST_DEVICE.parse().unwrap(),
            HOST_NEIGHBOUR.parse().unwrap(),
        );

        let _held: Vec<_> = (0..2).map(|_| g.open(a).unwrap()).collect();
        assert_eq!(g.open(a).unwrap_err(), Refused::Busy);
        let _theirs: Vec<_> = (0..2).map(|_| g.open(b).unwrap()).collect();
        assert_eq!(g.stats().sources, 2);
    }

    #[test]
    fn an_address_outside_the_hosts_own_slash_64_is_still_its_slash_64() {
        let g = guard_on_host(1);
        let noisy: IpAddr = "2001:db8:aa:bc::1".parse().unwrap();
        let fresh: IpAddr = "2001:db8:aa:bc::2".parse().unwrap();

        g.wasted(noisy);
        assert!(
            !g.admits(fresh),
            "a fresh address next door is no fresh start"
        );
        assert_eq!(g.source(noisy), g.source(fresh));
        assert!(g.admits(HOST_DEVICE.parse().unwrap()));
    }

    #[test]
    fn a_ticket_gives_back_what_it_took_when_the_hosts_networks_change() {
        // An ISP renumbers under a connection that is open.
        let g = Arc::new(Guard::new(Config {
            host_networks: host_networks([HOST.parse().unwrap()]),
            ..Default::default()
        }));
        let t = g.open(HOST_DEVICE.parse().unwrap()).unwrap();

        g.set_config(Config::default());
        assert_eq!(g.stats().sources, 1);
        drop(t);
        assert_eq!((g.stats().open, g.stats().sources), (0, 0));
    }

    #[test]
    fn switching_locality_off_switches_off_the_configured_networks_too() {
        let g = Guard::new(Config {
            strikes: 1,
            exempt_local: false,
            local_networks: vec![("203.0.113.0".parse().unwrap(), 24)],
            ..Default::default()
        });

        assert!(!spares(&g, "203.0.113.77"));
        assert!(!spares(&g, "100.64.0.1"));
    }

    #[test]
    fn the_hosts_networks_are_the_slash_64s_of_its_global_ipv6_addresses() {
        let ips = |v: &[&str]| -> Vec<IpAddr> { v.iter().map(|s| s.parse().unwrap()).collect() };
        let found = host_networks(ips(&[
            // A SLAAC address, a temporary one and a DHCPv6 one: one /64.
            "2a02:1:2:3:aaaa:bbbb:cccc:dddd",
            "2a02:1:2:3:1111:2222:3333:4444",
            "2a02:1:2:3::1234",
            // A second prefix, as a renumbering ISP leaves for a while.
            "2a02:1:2:4::1",
            // Nothing for any of these.
            "203.0.113.5",
            "192.168.1.2",
            "::1",
            "::",
            "fe80::1",
            "fd12:3456::1",
            "::ffff:203.0.113.5",
            "ff02::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        ]));

        assert_eq!(
            found,
            vec![
                ("2a02:1:2:3::".parse().unwrap(), 64),
                ("2a02:1:2:4::".parse().unwrap(), 64),
            ]
        );
    }

    #[test]
    fn an_ipv6_scanner_cannot_escape_by_changing_address_within_its_slash_64() {
        // Every address in a /64 belongs to whoever was given it, so a fresh
        // one per connection is free -- and must not be a fresh start.
        let g = guard(3);

        for i in 1..=3u16 {
            let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, i, i, i, i));
            assert!(g.admits(ip), "strike {i} is not yet the last one");
            g.wasted(ip);
        }

        let another: IpAddr = "2001:db8:1:2:dead:beef::1".parse().unwrap();
        assert!(!g.admits(another), "the whole /64 is refused");
        assert_eq!(g.tracked(), 1, "and it is one source, not three");

        let neighbour: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert!(g.admits(neighbour), "the next /64 is somebody else");
    }

    #[test]
    fn a_query_from_anywhere_in_the_slash_64_clears_it() {
        // A household with one real client in it is a household with a
        // client, whichever of its addresses the scanner used.
        let g = guard(3);
        let noisy: IpAddr = "2001:db8:1:2::bad".parse().unwrap();
        let client: IpAddr = "2001:db8:1:2::600d".parse().unwrap();

        strike_out(&g, noisy);
        assert!(!g.admits(noisy));
        g.advance(Duration::from_secs(600));

        g.served(client);
        assert!(g.admits(noisy));
        assert_eq!(g.tracked(), 0, "the offence is forgiven with the strikes");
    }

    #[test]
    fn a_query_answered_while_refused_does_not_lift_the_penalty() {
        // A scanner holds a DNS connection open, earns a penalty on the web
        // port, then asks one real question on the connection it kept.  The
        // report of that answer used to wipe the penalty and the offence.
        let g = guard(2);
        let ip = scanner();

        g.condemn(ip, "asked for /.env");
        g.advance(Duration::from_secs(60));
        g.served(ip);
        assert!(!g.admits(ip), "still refused");
        assert_eq!(remaining(&g, ip), 540, "for exactly as long as before");

        // Served in full, the offence is still on record: the next one
        // costs double, as a repeat offender's should.
        g.advance(Duration::from_secs(540));
        g.condemn(ip, "asked for /.git/config");
        assert_eq!(remaining(&g, ip), 1200);
    }

    #[test]
    fn outside_a_penalty_a_query_still_clears_strikes_and_offences() {
        let g = guard(2);
        let ip = scanner();

        g.wasted(ip);
        g.served(ip);
        g.wasted(ip);
        assert!(g.admits(ip), "the first strike was forgiven");

        strike_out(&g, ip);
        g.advance(Duration::from_secs(600));
        g.served(ip);
        assert_eq!(g.tracked(), 0);
        strike_out(&g, ip);
        assert_eq!(remaining(&g, ip), 600, "and so was the offence");
    }

    #[test]
    fn a_mapped_ipv4_address_is_judged_as_the_ipv4_address_it_is() {
        let g = guard(2);
        let mapped: IpAddr = "::ffff:198.51.100.7".parse().unwrap();

        g.wasted(mapped);
        g.wasted(scanner());
        assert!(!g.admits(scanner()));
        assert!(!g.admits(mapped));
        assert_eq!(g.tracked(), 1);
    }

    #[test]
    fn a_source_is_logged_as_what_it_is_judged_as() {
        let g = guard_on_host(6);
        let judged = |ip: &str| g.source(ip.parse().unwrap()).to_string();

        assert_eq!(judged("198.51.100.7"), "198.51.100.7");
        assert_eq!(judged("::ffff:198.51.100.7"), "198.51.100.7");
        assert_eq!(judged("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64");
        assert_eq!(
            judged("2001:db8:aa:bb:1c2d:3e4f:5a6b:7c8d"),
            "::1c2d:3e4f:5a6b:7c8d in this host's /64"
        );
    }

    #[test]
    fn a_repeat_offender_is_refused_for_twice_as_long_each_time() {
        let g = guard(2);
        let ip = scanner();

        for expected in [600, 1200, 2400, 4800] {
            strike_out(&g, ip);
            assert!(!g.admits(ip));
            assert_eq!(remaining(&g, ip), expected);

            g.advance(Duration::from_secs(expected.into()));
            assert!(g.admits(ip), "a penalty of {expected} seconds is served");
        }
    }

    #[test]
    fn the_penalty_never_grows_past_its_ceiling() {
        let g = guard(1);
        let ip = scanner();
        let ceiling = 24 * 3600;

        for _ in 0..40 {
            g.wasted(ip);
            let left = remaining(&g, ip);
            assert!(left <= ceiling, "{left} seconds is past the ceiling");
            g.advance(Duration::from_secs(left.into()));
        }

        g.wasted(ip);
        assert_eq!(remaining(&g, ip), ceiling);
    }

    #[test]
    fn a_ceiling_below_the_first_penalty_does_not_shorten_it() {
        let g = Guard::new(Config {
            strikes: 1,
            max_penalty: Duration::from_secs(1),
            ..Default::default()
        });

        g.wasted(scanner());
        assert_eq!(remaining(&g, scanner()), 600);
    }

    #[test]
    fn offences_are_forgotten_after_a_quiet_day() {
        let g = guard(1);
        let ip = scanner();

        g.wasted(ip);
        g.advance(Duration::from_secs(600));
        g.wasted(ip);
        assert_eq!(remaining(&g, ip), 1200, "the second offence costs double");

        // A day after the second penalty ended, with nothing in between.
        g.advance(Duration::from_secs(1200 + 24 * 3600));
        g.wasted(ip);
        assert_eq!(remaining(&g, ip), 600, "and a day later it is a first");
    }

    #[test]
    fn a_quiet_offender_is_swept_away_after_its_day() {
        let g = guard(1);

        g.wasted(scanner());
        g.advance(Duration::from_secs(600 + 24 * 3600));

        // Anything that makes the guard look at its table.
        g.wasted("203.0.113.1".parse().unwrap());
        assert_eq!(g.tracked(), 1, "only the newcomer is left");
    }

    #[test]
    fn an_answered_query_forgives_every_offence() {
        let g = guard(1);
        let ip = scanner();

        for _ in 0..5 {
            g.wasted(ip);
            g.advance(Duration::from_secs(remaining(&g, ip).into()));
        }

        g.served(ip);
        assert_eq!(g.tracked(), 0);
        g.wasted(ip);
        assert_eq!(remaining(&g, ip), 600, "a fixed client starts from nothing");
    }

    #[test]
    fn a_condemned_source_is_refused_at_once() {
        let g = guard(6);
        let ip = scanner();

        g.condemn(ip, "asked for /.env");
        assert!(!g.admits(ip), "one such request settles it");
        assert_eq!(remaining(&g, ip), 600);

        let s = g.stats();
        assert_eq!((s.penalties, s.condemned, s.banned), (1, 1, 1));
    }

    #[test]
    fn condemnation_escalates_like_running_out_of_strikes() {
        let g = guard(2);
        let ip = scanner();

        strike_out(&g, ip);
        g.advance(Duration::from_secs(600));
        g.condemn(ip, "asked for /wp-login.php");
        assert_eq!(remaining(&g, ip), 1200, "it is the second offence");
    }

    #[test]
    fn nothing_counts_against_a_source_while_it_is_refused() {
        // A scanner that fires fifty probes down one kept-alive connection
        // has committed one offence, not fifty: it would otherwise reach the
        // day-long ceiling in one burst.
        let g = guard(2);
        let ip = scanner();

        g.condemn(ip, "asked for /.env");
        for _ in 0..50 {
            g.condemn(ip, "asked for /.git/config");
            g.wasted(ip);
        }

        assert_eq!(remaining(&g, ip), 600);
        assert_eq!(g.stats().penalties, 1);
    }

    #[test]
    fn a_strike_counts_like_a_wasted_connection() {
        let g = guard(3);
        let ip = scanner();

        g.strike(ip);
        g.wasted(ip);
        assert!(g.admits(ip));
        g.strike(ip);
        assert!(!g.admits(ip));
    }

    #[test]
    fn one_source_cannot_take_every_connection() {
        let g = shared(Config {
            max_per_source: 3,
            ..Default::default()
        });
        let ip = scanner();

        let held: Vec<_> = (0..3).map(|_| g.open(ip).unwrap()).collect();
        assert!(held.iter().all(Ticket::is_counted));
        assert_eq!(g.open(ip).unwrap_err(), Refused::Busy);

        let other: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(g.open(other).is_ok(), "somebody else is not affected");
    }

    #[test]
    fn a_slash_64_shares_one_allowance() {
        let g = shared(Config {
            max_per_source: 2,
            ..Default::default()
        });

        let _a = g.open("2001:db8::1".parse().unwrap()).unwrap();
        let _b = g.open("2001:db8::2".parse().unwrap()).unwrap();
        assert_eq!(
            g.open("2001:db8::3".parse().unwrap()).unwrap_err(),
            Refused::Busy
        );
    }

    #[test]
    fn the_whole_guard_has_a_ceiling() {
        let g = shared(Config {
            max_connections: 3,
            ..Default::default()
        });

        let held: Vec<_> = (1..=3u8)
            .map(|i| g.open(IpAddr::V4(Ipv4Addr::new(203, 0, 113, i))).unwrap())
            .collect();
        assert_eq!(
            g.open("203.0.113.4".parse().unwrap()).unwrap_err(),
            Refused::Busy
        );

        drop(held);
        assert!(g.open("203.0.113.4".parse().unwrap()).is_ok());
    }

    #[test]
    fn a_ticket_gives_its_connection_back_when_dropped() {
        let g = shared(Config {
            max_per_source: 1,
            ..Default::default()
        });
        let ip = scanner();

        let t = g.open(ip).unwrap();
        assert_eq!((g.stats().open, g.stats().sources), (1, 1));
        assert!(g.open(ip).is_err());

        drop(t);
        let s = g.stats();
        assert_eq!(
            (s.open, s.sources),
            (0, 0),
            "a source with nothing open is not kept"
        );
        assert!(g.open(ip).is_ok());
    }

    #[test]
    fn being_busy_is_not_an_offence() {
        // A NAT with one phone too many is busy, not hostile, and turning its
        // connections away must not become a penalty for the rest of it.
        let g = shared(Config {
            max_per_source: 1,
            max_handshakes: 1,
            ..Default::default()
        });
        let ip = scanner();

        let _t = g.open(ip).unwrap();
        let _s = g.handshake(ip).unwrap();
        for _ in 0..1000 {
            assert!(g.open(ip).is_err());
            assert!(g.handshake(ip).is_none());
        }

        assert_eq!(g.tracked(), 0, "no strike, no offence");
        assert!(g.admits(ip));
        assert_eq!(g.stats().refused_busy, 2000);
    }

    #[test]
    fn a_source_serving_a_penalty_is_refused_a_ticket() {
        let g = shared(Config::default());
        let ip = scanner();

        g.condemn(ip, "a test");
        assert_eq!(g.open(ip).unwrap_err(), Refused::Banned);
        assert_eq!(g.stats().refused_banned, 1);
        assert_eq!(g.stats().refused_busy, 0);
    }

    #[test]
    fn an_exempt_source_is_never_counted_or_capped() {
        let g = shared(Config {
            max_connections: 1,
            max_per_source: 1,
            max_handshakes: 1,
            ..Default::default()
        });
        let lan: IpAddr = "192.168.1.10".parse().unwrap();

        let held: Vec<_> = (0..100).map(|_| g.open(lan).unwrap()).collect();
        let slots: Vec<_> = (0..100).map(|_| g.handshake(lan).unwrap()).collect();
        assert!(held.iter().all(|t| !t.is_counted()));
        assert!(slots.iter().all(|s| !s.is_counted()));

        let s = g.stats();
        assert_eq!((s.open, s.sources, s.handshakes), (0, 0, 0));
        assert!(g.open(scanner()).is_ok(), "and it used none of the budget");
    }

    #[test]
    fn handshakes_have_their_own_ceiling() {
        let g = shared(Config {
            max_handshakes: 2,
            ..Default::default()
        });

        let a = g.handshake(scanner()).unwrap();
        let _b = g.handshake("203.0.113.1".parse().unwrap()).unwrap();
        assert!(g.handshake("203.0.113.2".parse().unwrap()).is_none());
        assert_eq!(g.stats().handshakes, 2);

        drop(a);
        assert!(g.handshake("203.0.113.2".parse().unwrap()).is_some());
    }

    #[test]
    fn lowering_a_limit_leaves_what_is_open_alone() {
        let g = shared(Config::default());
        let ip = scanner();

        let held: Vec<_> = (0..10).map(|_| g.open(ip).unwrap()).collect();
        let slots: Vec<_> = (0..10).map(|_| g.handshake(ip).unwrap()).collect();

        g.set_config(Config {
            max_connections: 2,
            max_per_source: 2,
            max_handshakes: 2,
            ..Default::default()
        });
        assert!(g.open(ip).is_err(), "newcomers wait for the count to fall");
        assert!(g.handshake(ip).is_none());

        drop(held);
        drop(slots);
        let s = g.stats();
        assert_eq!(
            (s.open, s.sources, s.handshakes),
            (0, 0, 0),
            "every ticket gave back exactly what it took"
        );
        assert!(g.open(ip).is_ok());
    }

    #[test]
    fn clearing_the_table_leaves_open_connections_counted() {
        let g = shared(Config::default());
        let t = g.open(scanner()).unwrap();

        g.clear();
        assert_eq!(g.stats().open, 1);
        drop(t);
        assert_eq!(g.stats().open, 0);
    }

    #[test]
    fn a_distributed_scan_cannot_grow_the_table_without_bound() {
        let g = guard(6);

        for i in 0..200_000u32 {
            g.wasted(IpAddr::V4(Ipv4Addr::from(0x0b00_0000 + i)));
            assert!(g.tracked() <= MAX_TRACKED);
        }

        // The table's allocation is bounded as well as its length.
        assert!(g.state.lock().marks.capacity() <= 2 * MAX_TRACKED);
    }

    #[test]
    fn the_table_gives_up_strikes_before_penalties() {
        let g = guard(2);
        let banned: Vec<IpAddr> = (0..1000u32)
            .map(|i| IpAddr::V4(Ipv4Addr::from(0xc633_6400 + i)))
            .collect();
        for &ip in &banned {
            strike_out(&g, ip);
        }

        // A scan from far more addresses than the table holds, each one
        // connecting once.
        for i in 0..(2 * MAX_TRACKED as u32) {
            g.wasted(IpAddr::V4(Ipv4Addr::from(0x0b00_0000 + i)));
        }

        assert!(g.tracked() <= MAX_TRACKED);
        assert!(
            banned.iter().all(|&ip| !g.admits(ip)),
            "a source serving a penalty outlasts one with a single strike"
        );
    }

    #[test]
    fn a_refusal_at_a_limit_is_logged_once_a_minute() {
        let g = guard(6);

        g.unwarned.fetch_add(1, Ordering::Relaxed);
        assert_eq!(g.due_warning(g.now()), Some(1), "the first is logged");

        for _ in 0..500 {
            g.unwarned.fetch_add(1, Ordering::Relaxed);
            assert_eq!(g.due_warning(g.now()), None, "the flood is not");
        }

        g.advance(Duration::from_secs(60));
        assert_eq!(
            g.due_warning(g.now()),
            Some(500),
            "and a minute later one line says how many there were"
        );
    }

    #[test]
    fn a_table_entry_stays_small() {
        // The table can hold `MAX_TRACKED` of these, so what one costs is
        // what a distributed scan costs.
        assert!(std::mem::size_of::<(Key, Mark)>() <= 32);
    }
}
