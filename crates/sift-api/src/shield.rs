//! What the encrypted listeners do about who is on the other end.
//!
//! The HTTPS listener (`https`) and the HTTP/3 one (`http3`) both put the web
//! interface, the control API and DNS-over-HTTPS on a port the internet can
//! reach, and both hand every request to the router the plain-HTTP listener
//! uses too.  What they add on top of it is written here once, so the two
//! cannot drift apart, and kept out of the router, which also serves the plain
//! listener on the LAN:
//!
//! - **What counts as asking something.**  The connection guard in
//!   `sift_dns::probe` forgives a source whose connection asked something, so
//!   what counts is a defence in itself.  A request counts when it was
//!   answered with a status below 400 and the answer does not carry
//!   [`doh::Unanswered`]: a path scanner is answered 401s and 404s, and a
//!   stranger the access list refuses is answered a DNS refusal inside a 200,
//!   and neither has asked anything a client of this server asks.  It is
//!   counted when the answer is ready, not when the request arrives, because
//!   only the answer says which it was.  An answer carrying
//!   [`doh::Overloaded`] is neither: the server was too busy to answer it,
//!   and being busy is never held against a source -- nor is it something a
//!   source can be forgiven for.
//! - **A run of refusals.**  Answers that ask nothing, one after another,
//!   end the connection once there are `MAX_RUN` of them.  Only an answer
//!   with something in it -- a 2xx, or a 304 -- starts the run again.  A
//!   redirect counts as asking, but does not: `/` redirects a signed-out
//!   visitor to the login page whoever it is.
//! - **A tripwire.**  Some paths are asked for by nothing but something
//!   looking for a way in -- `/.env`, `/wp-login.php`, `/cgi-bin/` -- and
//!   [`tripwire`] names them.  Asking for one condemns the source on the spot,
//!   is answered a plain 404, and ends the connection.
//! - **Deadlines.**  A connection that has asked nothing ten seconds after its
//!   handshake is dropped, and one with nothing in flight for a minute is
//!   closed; a request body has a minute to arrive and a handler five minutes
//!   to answer.  [`Limits`] says why each is what it is.
//!
//! A connection that ends badly -- condemned, refused mid-way because its
//! source was banned by another one, or closed for a long run of requests
//! that asked nothing -- is reported to the guard as having asked nothing at
//! all, whatever it asked before.  A scanner fetches `/` before `/.env`, and
//! the report at close would otherwise lift the penalty it had just earned.

use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use bytes::Bytes;
use http::{HeaderValue, Method, Response, StatusCode, Version, header};
use hyper::body::{Frame, SizeHint};
use parking_lot::Mutex;
use sift_dns::probe::Guard;
use tokio::sync::Notify;
use tokio::time::{Instant, Sleep};

use crate::doh;

/// The deadlines one connection is held to.
///
/// `Limits::default()` is what the listeners use; the tests shorten them so
/// they do not have to wait ten seconds to see a connection dropped.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    /// How long a TLS connection has, from being accepted, to finish its
    /// handshake -- and so also how long it may take to send its first byte.
    ///
    /// Only the HTTPS listener's: QUIC's handshake is `sift_dns::quic`'s.
    pub handshake: Duration,
    /// How long after its handshake a connection has to send its first
    /// request.
    ///
    /// A browser, a DoH client and a script all send one at once; ten
    /// seconds is the handshake's own allowance again.  Without it, a
    /// connection that completed its handshake and then sent nothing lived
    /// for ever -- hyper waits for the first bytes with no deadline at all --
    /// and, since the guard only hears about a connection when it closes,
    /// it was never counted against its source either.
    pub first_request: Duration,
    /// How long HTTP/1.1 may take to deliver a request's head.
    ///
    /// hyper starts this clock whenever it starts waiting for a head, which
    /// includes waiting between requests on a kept-alive connection, so it
    /// is also how long such a connection may sit idle.  Ten seconds cuts a
    /// slow-header attack short and is a common keep-alive limit; a client
    /// whose connection was closed opens another.
    pub header_read: Duration,
    /// How long a connection may go with no request in flight before it is
    /// asked to close.
    ///
    /// Upstream's server closes an idle connection after the same minute.
    /// Nothing here holds a connection open between requests the way a
    /// WebSocket would, so a minute with nothing asked is a connection nobody
    /// is using -- or one kept alive by answering pings, which is how an
    /// HTTP/2 connection is otherwise held for ever.
    pub idle: Duration,
    /// How long a connection asked to close because it was idle has to
    /// finish what it is sending.
    ///
    /// The last answer may still be on its way to a slow client: this is
    /// room for a few megabytes over a poor mobile link, after the minute of
    /// idleness it has already had.
    pub grace: Duration,
    /// How long a connection closed for misbehaving has to finish -- enough
    /// to send the answer that ended it, and no more.
    pub cut: Duration,
    /// How long a request's body has to arrive, from when its head did.
    ///
    /// Upstream reads a whole request under a one-minute deadline.  The
    /// largest body anything here accepts is a few megabytes of filtering
    /// rules, which a minute is plenty for.  One that runs out is answered
    /// 408.
    pub upload: Duration,
    /// How long a handler has to produce its answer.
    ///
    /// Five minutes is upstream's write deadline, and deliberately not the
    /// minute the body gets: refreshing every filter list or downloading an
    /// update can take longer than that on a slow link, and cutting either
    /// short would cancel it half-done.  Nothing a stranger can reach takes
    /// anywhere near this long -- the login form, the assets and DNS each
    /// have limits of their own -- so this is a backstop, answered 503.
    pub handler: Duration,
    /// How long HTTP/3 may take to deliver a request's headers once the
    /// stream carrying them is open.
    pub resolve: Duration,
    /// How long one piece of an HTTP/3 answer may wait for the client to
    /// make room for it.
    ///
    /// Each piece is small, so a client that is reading at all makes room
    /// long before this; one that has stopped reading is holding the answer
    /// in memory, and is let go.
    pub stall: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(10),
            first_request: Duration::from_secs(10),
            header_read: Duration::from_secs(10),
            idle: Duration::from_secs(60),
            grace: Duration::from_secs(30),
            cut: Duration::from_secs(5),
            upload: Duration::from_secs(60),
            handler: Duration::from_secs(300),
            resolve: Duration::from_secs(10),
            stall: Duration::from_secs(30),
        }
    }
}

/// Consecutive answers that asked nothing after which a connection is
/// closed.
///
/// It bounds a path scanner that keeps one connection alive and walks a
/// wordlist down it.  A browser whose session has expired is answered a
/// handful of 401s -- every request the dashboard has in flight -- and then
/// loads the login page, which counts; an iPhone asks for two or three icons
/// that are not there.  Thirty-two in a row is none of those.  Nothing is
/// held against a source per 401 or 404: a strike per refusal would lock
/// that browser out mid-way through finding its way to the login page.
///
/// "In a row" is broken only by an answer that serves something -- see
/// [`starts_over`] -- and not by a redirect: a signed-out visitor is sent
/// from `/` to the login page whoever it is, so a scanner that asked for `/`
/// every thirty-one guesses walked a wordlist of any length down one
/// connection.
const MAX_RUN: u32 = 32;

/// Why a connection was ended by what it did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// It asked for something only an attacker asks for.
    Condemned,
    /// Its source was refused while it was open.
    Refused,
    /// It was answered `MAX_RUN` times in a row without asking anything.
    Aimless,
}

/// One connection, as the guard sees it.
///
/// Shared by the connection's driver, which enforces the deadlines, and by
/// each request on it, which reports what it asked.
pub(crate) struct Visit {
    guard: Arc<Guard>,
    ip: IpAddr,
    limits: Limits,
    /// When the handshake completed.
    opened: Instant,
    tally: Mutex<Tally>,
    /// Wakes the driver when there is something new to decide.
    wake: Notify,
}

/// What a connection has done so far.
struct Tally {
    /// Requests answered in a way that counts.
    asked: u32,
    /// Answers that asked nothing since the last one that started the run
    /// over.
    run: u32,
    /// Requests the server was too busy to answer, which are neither.
    overloaded: u32,
    /// Requests dispatched, answered or not.
    dispatched: u32,
    /// Requests dispatched and not yet answered.
    in_flight: u32,
    /// When `in_flight` last fell to zero.
    quiet_since: Instant,
    /// Why the connection is to be ended, once it is.
    end: Option<End>,
}

/// What to do with a request, decided before it reaches the router.
pub(crate) enum Admission {
    /// Serve it, and report the answer through the flight.
    Serve(Flight),
    /// It tripped the wire: answer a plain 404 and let the connection close.
    Trip,
    /// Its source is refused: close without answering.
    Refuse,
}

/// What the driver should do with the connection now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Nothing yet; decide again at this moment, or when woken.
    Wait(Option<Instant>),
    /// Ask the connection to close, and drop it if it has not after this
    /// long.
    Close(Duration),
    /// Drop it now.  Nothing is in flight to finish.
    Drop,
}

impl Visit {
    /// Starts watching a connection from `ip` whose handshake has completed.
    pub(crate) fn new(guard: Arc<Guard>, ip: IpAddr, limits: Limits) -> Arc<Self> {
        let now = Instant::now();

        Arc::new(Self {
            guard,
            ip,
            limits,
            opened: now,
            tally: Mutex::new(Tally {
                asked: 0,
                run: 0,
                overloaded: 0,
                dispatched: 0,
                in_flight: 0,
                quiet_since: now,
                end: None,
            }),
            wake: Notify::new(),
        })
    }

    /// The deadlines this connection is held to.
    pub(crate) fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Decides whether a request is served.
    ///
    /// The ban is checked per request because a penalty only turns away new
    /// connections: a source condemned on one connection would otherwise go
    /// on being served on another it already had open.
    pub(crate) fn admit(self: &Arc<Self>, method: &Method, path: &str) -> Admission {
        if !self.guard.admits(self.ip) {
            self.end(End::Refused);

            return Admission::Refuse;
        }

        if let Some(reason) = tripwire(method, path) {
            self.guard.condemn(self.ip, reason);
            self.end(End::Condemned);

            return Admission::Trip;
        }

        let mut t = self.tally.lock();
        t.dispatched = t.dispatched.saturating_add(1);
        t.in_flight += 1;
        drop(t);

        Admission::Serve(Flight {
            visit: self.clone(),
        })
    }

    /// Decides what should become of the connection at `now`.
    pub(crate) fn verdict(&self, now: Instant) -> Verdict {
        let t = self.tally.lock();
        if t.end.is_some() {
            return Verdict::Close(self.limits.cut);
        }

        if t.dispatched == 0 {
            let due = self.opened + self.limits.first_request;

            return if now >= due {
                Verdict::Drop
            } else {
                Verdict::Wait(Some(due))
            };
        }

        if t.in_flight > 0 {
            // Every request in flight is bounded by its own deadlines, and
            // the driver is woken when the last of them is answered.
            return Verdict::Wait(None);
        }

        let due = t.quiet_since + self.limits.idle;
        if now >= due {
            Verdict::Close(self.limits.grace)
        } else {
            Verdict::Wait(Some(due))
        }
    }

    /// Resolves when something has happened that may change the verdict.
    pub(crate) async fn changed(&self) {
        self.wake.notified().await;
    }

    /// Tells the guard how the connection behaved, once it has closed.
    ///
    /// A connection that ended badly asked nothing, whatever it asked on the
    /// way.  Nor is one reported as having asked something while its source
    /// is refused: that report would lift a penalty some other connection
    /// from the same source earned -- a scanner fetching `/` on one
    /// connection and `/.env` on another would otherwise clear itself by
    /// closing the first.
    ///
    /// A connection whose every question the server was too busy to answer
    /// is not reported at all.  It asked nothing that was answered, so it
    /// cannot be forgiven for asking; and it cannot be struck for asking
    /// nothing either, or an overload -- ten sources holding every worker
    /// with slow lookups -- would get each DoH client that asked during it
    /// banned, while the sources causing it, whose lookups end in an
    /// upstream's SERVFAIL, were never struck at all.
    pub(crate) fn report(&self) {
        let (asked, overloaded, end) = {
            let t = self.tally.lock();

            (t.asked, t.overloaded, t.end)
        };

        if end.is_none() && asked == 0 && overloaded > 0 {
            return;
        }

        let asked = if end.is_some() || (asked > 0 && self.guard.is_banned(self.ip)) {
            0
        } else {
            asked
        };

        self.guard.record(self.ip, asked);
    }

    /// Marks the connection to be ended, and wakes its driver.
    fn end(&self, why: End) {
        let mut t = self.tally.lock();
        if t.end.is_some() {
            return;
        }
        t.end = Some(why);
        drop(t);

        if why == End::Aimless {
            tracing::debug!(
                client = %self.ip,
                answers = MAX_RUN,
                "closing a connection that keeps asking for what it is refused"
            );
        }

        self.wake.notify_one();
    }
}

/// One request on its way through the router.
///
/// Counted as in flight until it is dropped, which the HTTPS listener does
/// once the answer's head is ready and the HTTP/3 one once the answer has
/// been sent.
pub(crate) struct Flight {
    visit: Arc<Visit>,
}

impl Flight {
    /// Records the answer the request was given.
    ///
    /// Three outcomes, not two: an answer that asked something, one that
    /// asked nothing, and one the server was too busy to give, which is
    /// neither -- it does not count, and it does not bring the connection
    /// any closer to being closed for a run of refusals.
    pub(crate) fn answered<B>(&self, response: &Response<B>) {
        let extensions = response.extensions();
        let mut t = self.visit.tally.lock();

        if extensions.get::<doh::Overloaded>().is_some() {
            t.overloaded = t.overloaded.saturating_add(1);

            return;
        }

        let status = response.status();
        if status.as_u16() < 400 && extensions.get::<doh::Unanswered>().is_none() {
            t.asked = t.asked.saturating_add(1);
            if starts_over(status) {
                t.run = 0;
            }

            return;
        }

        t.run = t.run.saturating_add(1);
        let aimless = t.run >= MAX_RUN;
        drop(t);

        if aimless {
            self.visit.end(End::Aimless);
        }
    }
}

impl Drop for Flight {
    fn drop(&mut self) {
        let mut t = self.visit.tally.lock();
        t.in_flight -= 1;
        let quiet = t.in_flight == 0;
        if quiet {
            t.quiet_since = Instant::now();
        }
        drop(t);

        // The driver sleeps without a deadline while anything is in flight,
        // so it has to hear when the idle clock starts.
        if quiet {
            self.visit.wake.notify_one();
        }
    }
}

/// Reports whether an answer that counted starts a run of refusals over.
///
/// A 2xx served something, and so does a 304: it is the answer to a browser
/// revalidating a page or a script it already holds, and treating it unlike
/// the 200 it stands for would judge a browser with a warm cache differently
/// from one with a cold cache.  It gives a scanner nothing, either -- the
/// server answers 304 only where it would otherwise have answered 200, to
/// the same request.
///
/// Every other 3xx still counts as asking something, but does not start the
/// run over.  The redirects here are the same for everyone: `/` sends a
/// signed-out visitor to the login page whether it is a browser or a scanner
/// between two guesses, so it says nothing about which one is asking.
fn starts_over(status: StatusCode) -> bool {
    status.is_success() || status == StatusCode::NOT_MODIFIED
}

/// Sleeps until `at`, or for ever when there is nothing to wait for.
pub(crate) async fn until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// A request body that must have arrived within a deadline.
///
/// Measured from when the request's head arrived, so a body that trickles
/// in a byte at a time runs out of time just as one that never starts does.
/// Past the deadline it fails, which the handler reading it turns into a
/// rejection, and the listener then answers 408 in its place.
pub(crate) struct Upload<B> {
    inner: B,
    deadline: Pin<Box<Sleep>>,
    late: Arc<AtomicBool>,
}

/// Whether an [`Upload`] ran out of time.
#[derive(Clone)]
pub(crate) struct Late(Arc<AtomicBool>);

impl Late {
    /// Reports whether the body ran out of time.
    pub(crate) fn is_set(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

impl<B> Upload<B> {
    /// Wraps `inner`, which must have arrived within `within` from now.
    pub(crate) fn new(inner: B, within: Duration) -> (Self, Late) {
        let late = Arc::new(AtomicBool::new(false));

        (
            Self {
                inner,
                deadline: Box::pin(tokio::time::sleep(within)),
                late: late.clone(),
            },
            Late(late),
        )
    }
}

impl<B> hyper::body::Body for Upload<B>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: Into<axum::BoxError>,
{
    type Data = Bytes;
    type Error = axum::BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = &mut *self;

        // The deadline first: past it, even a body with bytes waiting has
        // taken too long.
        if this.deadline.as_mut().poll(cx).is_ready() {
            this.late.store(true, Ordering::Relaxed);

            return Poll::Ready(Some(Err("the request body took too long to arrive".into())));
        }

        Pin::new(&mut this.inner)
            .poll_frame(cx)
            .map(|f| f.map(|r| r.map_err(Into::into)))
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// A short plain-text answer, for the ones the listeners give themselves.
///
/// `close` asks an HTTP/1 client to close the connection after it; HTTP/2 and
/// HTTP/3 forbid the header, and are closed another way.
pub(crate) fn plain(status: StatusCode, close: bool) -> Response<Body> {
    let mut r = Response::new(Body::from(status.canonical_reason().unwrap_or("")));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    if close {
        r.headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }

    r
}

/// Reports whether a request arrived over HTTP/1, where `Connection: close`
/// is how a server says it is done.
pub(crate) fn is_http1(v: Version) -> bool {
    matches!(v, Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11)
}

/// Names the probe a request is, if it is one nothing but an attacker makes.
///
/// A false positive locks the operator out of their own server, so this
/// errs hard towards letting things through.  Every rule is one no browser,
/// DoH client, monitoring check or this web interface would ever trip:
///
/// - `CONNECT`, which asks the server to act as a proxy.  A browser sends it
///   only to a proxy it was configured to use.
/// - A `..` segment, however it is encoded -- `%2e%2e`, doubly encoded, with
///   a backslash, or with `;` parameters as some servers allow.  Browsers
///   and HTTP libraries resolve dot segments before sending, so a request
///   still carrying one was written to walk out of the web root.
/// - Encodings that exist only to slip past a check like this one, and that
///   no browser or library writes: a NUL byte (`%00`, which cut a path short
///   in the C that parsed it -- `/index.php%00.txt`); an overlong UTF-8
///   sequence (`%c0%ae` is a dot spelled in two bytes where it takes one,
///   which RFC 3629 forbids and some decoders accepted anyway); and IIS's
///   `%u002e` escapes, which are not percent-encoding at all.
/// - A script this server does not run: a segment ending in `.php` or one of
///   the other extensions PHP is served under (`.php3` to `.php7`, `.phtml`,
///   `.phar`, `.phps`), `.asp`, `.aspx`, `.jsp` or `.cgi`, and `/cgi-bin/`.
///   `xmlrpc.php` and `wp-login.php` are among these.
/// - Files that hold secrets or a server's history: `.env` (and
///   `.env.local` and the like), `.git`, `.svn`, `.hg`, `.aws`, `.ssh`,
///   `.DS_Store`, `.htaccess` and `.htpasswd`, at any depth.  Only a
///   named list: `.well-known` is asked for by browsers, password managers
///   and certificate authorities, and is never matched.
/// - WordPress's own directories, phpMyAdmin and PHPUnit, at any depth,
///   since a scanner tries them under every prefix it can think of.
/// - A handful of first segments that name another product's admin or login
///   page: Spring's `/actuator`, the routers' `/boaform` and `/HNAP1`,
///   `/solr`, Exchange's `/owa` and `/ecp`, the VPN logins `/+CSCOE+` and
///   `/remote/login`, and Apache's `/server-status`.  Only as the first
///   segment, because these are ordinary words deeper down.
/// - `/etc/passwd` anywhere in the path.
///
/// Matching is on the percent-decoded path, ignoring case, and only on the
/// path: HTTP/2 requests arrive in absolute form, which says nothing about
/// the client.  The query string is not looked at.  Every rule is judged on
/// the path decoded once and decoded twice, because some servers decode
/// twice and scanners write `%252eenv` for them; nothing this server serves
/// has a `%` in its name, so the second decoding changes nothing a client
/// asks for.
///
/// Nothing under `/dns-query` is judged except for traversal and the
/// encodings above: the segment after it is a ClientID, which the operator
/// chooses, and `owa` or `cgi-bin` are as good names for a phone as any --
/// but a ClientID is a DNS label, which none of those encodings can spell.
pub(crate) fn tripwire(method: &Method, path: &str) -> Option<&'static str> {
    if method == Method::CONNECT {
        return Some("a CONNECT request, which only a proxy is sent");
    }

    let once = percent_decode(path.as_bytes());
    let twice = percent_decode(&once);

    if iis_escape(path.as_bytes()) || iis_escape(&once) {
        return Some("an IIS %u escape, which only a filter evasion writes");
    }
    for p in [&once, &twice] {
        if segments(p).any(|s| without_params(s) == b"..") {
            return Some("a path that climbs out of the web root");
        }
        if p.contains(&0) {
            return Some("a NUL byte in the path, which cuts it short for C");
        }
        if overlong(p) {
            return Some("an overlong UTF-8 sequence, which only a filter evasion writes");
        }
    }

    if path == "/dns-query" || path.starts_with("/dns-query/") {
        return None;
    }

    if let Some(reason) = by_name(&once) {
        return Some(reason);
    }
    if twice != once {
        return by_name(&twice);
    }

    None
}

/// The rules on what a decoded path names, rather than how it is written.
fn by_name(decoded: &[u8]) -> Option<&'static str> {
    let lower = String::from_utf8_lossy(decoded).to_ascii_lowercase();
    if lower.contains("/etc/passwd") {
        return Some("/etc/passwd");
    }

    let mut first = None;
    let mut second = None;
    for (i, seg) in lower
        .split(['/', '\\'])
        .filter(|s| !s.is_empty())
        .enumerate()
    {
        let seg = seg.split(';').next().unwrap_or(seg);
        match i {
            0 => first = Some(seg),
            1 => second = Some(seg),
            _ => {}
        }

        if let Some(reason) = anywhere(seg) {
            return Some(reason);
        }
    }

    match (first?, second.unwrap_or("")) {
        ("actuator", _) => Some("Spring's actuator"),
        ("boaform" | "hnap1", _) => Some("a router's administration page"),
        ("solr", _) => Some("Solr's admin page"),
        ("owa" | "ecp", _) => Some("Exchange's web access"),
        ("+cscoe+", _) => Some("a VPN's login page"),
        ("remote", s) if s.starts_with("login") || s == "fgt_lang" => Some("a VPN's login page"),
        ("server-status", _) => Some("Apache's status page"),
        _ => None,
    }
}

/// The rules that apply to a segment wherever it is in the path.
fn anywhere(seg: &str) -> Option<&'static str> {
    const SCRIPTS: &[&str] = &[
        ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar", ".phps", ".asp", ".aspx",
        ".jsp", ".cgi",
    ];
    const HIDDEN: &[&str] = &[
        ".git",
        ".svn",
        ".hg",
        ".aws",
        ".ssh",
        ".ds_store",
        ".htaccess",
        ".htpasswd",
    ];
    const WORDPRESS: &[&str] = &[
        "wp-admin",
        "wp-content",
        "wp-includes",
        "wp-login",
        "wp-json",
        "wp-config",
    ];

    if SCRIPTS.iter().any(|x| seg.ends_with(x)) || seg == "cgi-bin" {
        return Some("a script this server does not run");
    }
    if seg == ".env" || seg.starts_with(".env.") || HIDDEN.contains(&seg) {
        return Some("a file that holds secrets");
    }
    if WORDPRESS.iter().any(|w| seg.starts_with(w)) {
        return Some("WordPress");
    }
    if seg.starts_with("phpmyadmin") {
        return Some("phpMyAdmin");
    }
    if seg == "phpunit" {
        return Some("PHPUnit");
    }

    None
}

/// The segments of a path, split on either slash.
fn segments(p: &[u8]) -> impl Iterator<Item = &[u8]> {
    p.split(|&b| b == b'/' || b == b'\\')
}

/// A segment without the `;`-parameters some servers strip before resolving
/// it, which is what makes `..;` a way past a check for `..`.
fn without_params(seg: &[u8]) -> &[u8] {
    seg.split(|&b| b == b';').next().unwrap_or(seg)
}

/// Reports whether `p` holds an IIS `%uXXXX` escape.
///
/// A `%` must be followed by two hex digits, and `u` is not one, so no
/// well-formed URL carries this; IIS decoded it anyway, which is why
/// scanners still send `%u002e%u002e/` in the hope of meeting one.
fn iis_escape(p: &[u8]) -> bool {
    p.windows(6).any(|w| {
        w[0] == b'%' && w[1].eq_ignore_ascii_case(&b'u') && w[2..].iter().all(u8::is_ascii_hexdigit)
    })
}

/// Reports whether `p` holds an overlong UTF-8 sequence: a character written
/// in more bytes than it takes.
///
/// Only the lead byte and the one after it are needed to tell: `C0` and `C1`
/// can only begin a two-byte form of an ASCII character, and `E0`, `F0` --
/// and the obsolete five- and six-byte leads `F8` and `FC` -- are overlong
/// when the next byte is below the least a shortest form would need.  A
/// continuation byte is required after each, so a lone `%C0` -- `À` in
/// Latin-1, which an old client might still send -- is not taken for one.
fn overlong(p: &[u8]) -> bool {
    p.windows(2).any(|w| {
        matches!(
            (w[0], w[1]),
            (0xC0 | 0xC1, 0x80..=0xBF)
                | (0xE0, 0x80..=0x9F)
                | (0xF0, 0x80..=0x8F)
                | (0xF8, 0x80..=0x87)
                | (0xFC, 0x80..=0x83)
        )
    })
}

/// Decodes `%XX` escapes, leaving anything that is not one as it is.
fn percent_decode(s: &[u8]) -> Vec<u8> {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%'
            && let Some(&[h, l]) = s.get(i + 1..i + 3)
            && let (Some(h), Some(l)) = (hex(h), hex(l))
        {
            out.push(h << 4 | l);
            i += 3;

            continue;
        }

        out.push(s[i]);
        i += 1;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trips(path: &str) -> bool {
        tripwire(&Method::GET, path).is_some()
    }

    #[test]
    fn what_only_a_scanner_asks_for_trips_the_wire() {
        for path in [
            "/.env",
            "/.env.production",
            "/api/.env",
            "/.git/config",
            "/.git/HEAD",
            "/app/.git/config",
            "/.aws/credentials",
            "/.ssh/id_rsa",
            "/.DS_Store",
            "/.htaccess",
            "/.svn/entries",
            "/wp-login.php",
            "/wp-admin/",
            "/blog/wp-admin/setup-config.php",
            "/wp-content/plugins/x/readme.txt",
            "/wp-includes/wlwmanifest.xml",
            "/xmlrpc.php",
            "/index.php",
            "/index.php/foo",
            "/admin/config.php",
            "/default.asp",
            "/owa/auth/logon.aspx",
            "/login.jsp;jsessionid=1",
            "/cgi-bin/luci",
            "/test.cgi",
            "/phpmyadmin/",
            "/phpMyAdmin5.2/index.php",
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/actuator/env",
            "/actuator",
            "/boaform/admin/formLogin",
            "/HNAP1/",
            "/solr/admin/info/system",
            "/ecp/",
            "/+CSCOE+/logon.html",
            "/remote/login",
            "/remote/logincheck",
            "/remote/fgt_lang",
            "/server-status",
            "/../../etc/passwd",
            "/static/../../etc/shadow",
            "/%2e%2e/%2e%2e/etc/shadow",
            "/%252e%252e/secret",
            "/.%2e/x",
            "/assets/..%5c..%5cwindows/win.ini",
            "/..;/manager/html",
            "/cgi-bin/.%2e/.%2e/bin/sh",
            "/foo/etc/passwd",
            "/%2Eenv",
            "/%2egit/config",
            // Every name rule, decoded twice as well as once.
            "/%252eenv",
            "/%252Egit/config",
            "/wp%252dlogin",
            "/%2573erver-status",
            "/x%252ephp",
            // The other extensions PHP is served under.
            "/shell.phtml",
            "/info.php3",
            "/info.php4",
            "/index.php5",
            "/index.php7",
            "/tools.phar",
            "/source.phps",
            "/uploads/x.PHTML",
            // A NUL, however many times it is encoded.
            "/index.php%00.txt",
            "/login.html%00",
            "/x%2500y",
            // Overlong dots and slashes, in each length.
            "/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/hosts",
            "/%C0%AE%C0%AE%C0%AFwindows",
            "/..%c0%afwinnt",
            "/%c1%9c",
            "/%e0%80%ae%e0%80%ae/",
            "/%f0%80%80%ae",
            "/%25c0%25ae",
            // IIS's escapes, as sent and encoded again.
            "/%u002e%u002e/%u002e%u002e/windows/win.ini",
            "/%U002E%U002E/",
            "/scripts/%u2215",
            "/%25u002e%25u002e/",
        ] {
            assert!(trips(path), "{path} should trip the wire");
        }

        assert!(tripwire(&Method::CONNECT, "").is_some());
        assert!(tripwire(&Method::CONNECT, "/").is_some());
    }

    #[test]
    fn what_a_client_asks_for_does_not() {
        for path in [
            "/",
            "/index.html",
            "/login.html",
            "/install.html",
            "/forgot_password.html",
            "/static/main.PQI5dCPj.js",
            "/static/login.BcvxCeuY.js",
            "/assets/favicon.png",
            "/assets/apple-touch-icon-180x180.png",
            "/favicon.ico",
            "/robots.txt",
            "/sitemap.xml",
            "/manifest.json",
            "/apple-touch-icon.png",
            "/apple-touch-icon-precomposed.png",
            "/apple-touch-icon-120x120-precomposed.png",
            "/.well-known/change-password",
            "/.well-known/traffic-advice",
            "/.well-known/acme-challenge/abc",
            "/.well-known/security.txt",
            "/control/status",
            "/control/login",
            "/control/apple/doh.mobileconfig",
            "/control/querylog",
            "/dns-query",
            "/settings",
            "/remote",
            "/remote/something",
            "/api/owa",
            "/x/actuator",
            "/environment",
            "/.envelope-is-not-env/..x",
            "/a..b",
            "/...",
            "*",
            "",
            // Words that only look like the new rules.
            "/assets/php-logo.svg",
            "/docs/pharmacy.html",
            "/phone5",
            "/static/app.phpx",
            "/unicode",
            "/%75nicode",
            "/100%25",
            "/100%25done",
            "/discount%",
            "/%zz",
            // Characters a browser writes: valid UTF-8, in every length,
            // including the leads that are overlong only before a low byte.
            "/caf%C3%A9",
            "/%E2%82%AC",
            "/%E0%A4%85",
            "/%F0%9F%98%80",
            "/%C0",
            "/%C0b",
            "/search%20term",
        ] {
            assert!(!trips(path), "{path} must not trip the wire");
        }

        for m in [Method::GET, Method::POST, Method::HEAD, Method::OPTIONS] {
            assert!(tripwire(&m, "/dns-query").is_none());
        }
    }

    #[test]
    fn a_client_id_is_the_operators_choice_and_is_not_judged() {
        // A ClientID is whatever the operator named the device, and any of
        // these is a plausible name.  Only traversal is judged there.
        for id in [
            "owa",
            "cgi-bin",
            "actuator",
            "wp-admin",
            "phpmyadmin",
            "solr",
            "remote",
            "server-status",
            "phone5",
            "php5",
            "x.phar",
            "unicode",
            "u002e",
        ] {
            assert!(!trips(&format!("/dns-query/{id}")), "{id}");
        }

        assert!(trips("/dns-query/../.env"));
        assert!(trips("/dns-query/%2e%2e/x"));

        // A ClientID is a DNS label, which none of these can spell.
        assert!(trips("/dns-query/phone%00"));
        assert!(trips("/dns-query/%c0%ae%c0%ae/x"));
        assert!(trips("/dns-query/%u002e%u002e/x"));
    }

    #[test]
    fn nothing_the_web_interface_or_the_router_serves_trips_the_wire() {
        // Every file in the build the binary embeds, by the path a browser
        // asks for it at.
        let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../web/build"));
        let mut files = Vec::new();
        let mut dirs = vec![root.to_path_buf()];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).expect("reading the web build") {
                let p = entry.unwrap().path();
                if p.is_dir() {
                    dirs.push(p);
                    continue;
                }

                let rel = p
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                let served = rel.strip_suffix(".br").unwrap_or(&rel).to_string();
                files.push(format!("/{served}"));
            }
        }
        assert!(
            files.iter().any(|f| f == "/index.html"),
            "the web build was not found: {files:?}"
        );
        for f in &files {
            assert!(!trips(f), "{f} is part of the web interface");
        }

        // Every route the router registers, under the prefix it is nested
        // at.  Read from the source so a route added later is covered too.
        let src = include_str!("routes.rs");
        let mut routes = Vec::new();
        let mut rest = src;
        while let Some(at) = rest.find(".route(") {
            rest = &rest[at + ".route(".len()..];
            let trimmed = rest.trim_start();
            if let Some(lit) = trimmed.strip_prefix('"')
                && let Some(end) = lit.find('"')
            {
                routes.push(lit[..end].to_string());
            }
        }
        assert!(
            routes.len() > 60,
            "the route table was not read: {routes:?}"
        );
        for r in &routes {
            let r = r.replace("{client_id}", "my-phone");
            for path in [r.clone(), format!("/control{r}")] {
                for m in [Method::GET, Method::POST, Method::PUT] {
                    assert!(tripwire(&m, &path).is_none(), "{m} {path} is a route");
                }
            }
        }
    }

    #[test]
    fn percent_decoding_leaves_what_is_not_an_escape() {
        assert_eq!(percent_decode(b"/a%2Fb%zz%4"), b"/a/b%zz%4");
        assert_eq!(percent_decode(b"%2e%2E"), b"..");
        assert_eq!(percent_decode(b"%"), b"%");
    }

    /// A guard that judges loopback, as the internet is judged.
    fn guard() -> Arc<Guard> {
        Arc::new(Guard::new(sift_dns::probe::Config {
            exempt_local: false,
            ..Default::default()
        }))
    }

    fn here() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    fn answer(status: u16) -> Response<()> {
        let mut r = Response::new(());
        *r.status_mut() = StatusCode::from_u16(status).unwrap();

        r
    }

    fn serve(v: &Arc<Visit>, path: &str, status: u16) {
        let Admission::Serve(f) = v.admit(&Method::GET, path) else {
            panic!("{path} should be served");
        };
        f.answered(&answer(status));
    }

    #[test]
    fn a_browser_finding_its_way_back_to_the_login_page_asks_something() {
        let g = guard();
        let v = Visit::new(g.clone(), here(), Limits::default());

        // A dashboard whose session expired: its polls are refused, then it
        // loads the login page.  And an iPhone after icons that are not there.
        for (path, status) in [
            ("/", 302),
            ("/login.html", 200),
            ("/static/login.BcvxCeuY.js", 304),
            ("/control/status", 401),
            ("/control/stats", 401),
            ("/control/querylog", 401),
            ("/apple-touch-icon.png", 401),
            ("/apple-touch-icon-precomposed.png", 404),
            ("/login.html", 200),
        ] {
            serve(&v, path, status);
        }
        assert!(
            matches!(v.verdict(Instant::now()), Verdict::Wait(Some(_))),
            "nothing about that ends the connection"
        );

        g.wasted(here());
        v.report();
        assert_eq!(
            g.tracked(),
            0,
            "it asked something, which clears the source"
        );
    }

    #[test]
    fn an_answer_marked_unanswered_does_not_count() {
        let g = guard();
        let v = Visit::new(g.clone(), here(), Limits::default());

        let mut refused = answer(200);
        refused.extensions_mut().insert(doh::Unanswered);
        let Admission::Serve(f) = v.admit(&Method::POST, "/dns-query") else {
            panic!();
        };
        f.answered(&refused);
        drop(f);

        v.report();
        assert_eq!(g.tracked(), 1, "a refused DNS query is a strike");
    }

    #[test]
    fn a_long_run_of_refusals_ends_the_connection_and_what_it_asked_before() {
        let g = guard();
        let v = Visit::new(g.clone(), here(), Limits::default());

        serve(&v, "/", 302);
        for i in 0..MAX_RUN {
            assert!(
                matches!(v.verdict(Instant::now()), Verdict::Wait(_)),
                "closed after only {i}"
            );
            serve(&v, &format!("/guess{i}"), 404);
        }
        assert_eq!(v.verdict(Instant::now()), Verdict::Close(v.limits.cut));

        v.report();
        assert_eq!(g.tracked(), 1, "reported as asking nothing");
    }

    #[test]
    fn a_redirect_between_guesses_does_not_start_the_run_over() {
        // `/` answers a signed-out visitor 302 whoever it is, so asking for
        // it between guesses used to let one connection walk any wordlist.
        let g = guard();
        let v = Visit::new(g.clone(), here(), Limits::default());

        for i in 0..MAX_RUN {
            assert!(
                matches!(v.verdict(Instant::now()), Verdict::Wait(_)),
                "closed after only {i}"
            );
            serve(&v, "/", 302);
            serve(&v, &format!("/guess{i}"), 404);
        }
        assert_eq!(v.verdict(Instant::now()), Verdict::Close(v.limits.cut));

        v.report();
        assert_eq!(g.tracked(), 1, "and what it asked on the way is forgotten");
    }

    #[test]
    fn an_answer_that_serves_something_starts_the_run_over() {
        for status in [200, 204, 206, 304] {
            let g = guard();
            let v = Visit::new(g.clone(), here(), Limits::default());

            for round in 0..3 {
                for i in 0..MAX_RUN - 1 {
                    serve(&v, &format!("/missing-{round}-{i}"), 404);
                }
                serve(&v, "/login.html", status);
            }
            assert!(
                matches!(v.verdict(Instant::now()), Verdict::Wait(_)),
                "{status} started the run over each time"
            );

            v.report();
            assert_eq!(g.tracked(), 0, "{status} is asking something");
        }
    }

    /// Answers a request the way DNS-over-HTTPS does when the server was too
    /// busy to: a SERVFAIL inside a 200, marked overloaded.
    fn busy(v: &Arc<Visit>) {
        let Admission::Serve(f) = v.admit(&Method::POST, "/dns-query") else {
            panic!("a DoH query should be served");
        };
        let mut r = answer(200);
        r.extensions_mut().insert(doh::Overloaded);
        f.answered(&r);
    }

    #[test]
    fn an_answer_the_server_was_too_busy_to_give_is_not_a_refusal() {
        let g = guard();
        let v = Visit::new(g.clone(), here(), Limits::default());

        // Twice as many as a run of refusals may have: a DoH client asking
        // through an overload collects them within seconds.
        for _ in 0..MAX_RUN * 2 {
            busy(&v);
        }
        assert!(
            matches!(v.verdict(Instant::now()), Verdict::Wait(Some(_))),
            "not closed as aimless"
        );

        v.report();
        assert_eq!(g.tracked(), 0, "and not struck when it closes");
    }

    #[test]
    fn a_connection_that_was_only_ever_too_busy_is_not_reported_at_all() {
        // Two strikes to a penalty, one already spent: a strike for the busy
        // connection would ban the source, and forgiving it would clear it.
        let g = Arc::new(Guard::new(sift_dns::probe::Config {
            exempt_local: false,
            strikes: 2,
            ..Default::default()
        }));
        g.wasted(here());

        let v = Visit::new(g.clone(), here(), Limits::default());
        for _ in 0..3 {
            busy(&v);
        }
        v.report();

        assert_eq!(g.stats().banned, 0, "not struck");
        assert_eq!(g.tracked(), 1, "nor forgiven what it had before");
    }

    #[test]
    fn being_busy_does_not_hide_what_else_a_connection_did() {
        // Busy answers beside refusals: the refusals still run out, and the
        // connection is then reported as asking nothing.
        let g = guard();
        let v = Visit::new(g.clone(), here(), Limits::default());
        for i in 0..MAX_RUN {
            busy(&v);
            serve(&v, &format!("/guess{i}"), 404);
        }
        assert_eq!(v.verdict(Instant::now()), Verdict::Close(v.limits.cut));
        v.report();
        assert_eq!(g.tracked(), 1);

        // And busy answers beside one that counted: the one that counted is
        // what the connection is reported for.
        let g = guard();
        g.wasted(here());
        let v = Visit::new(g.clone(), here(), Limits::default());
        busy(&v);
        serve(&v, "/login.html", 200);
        busy(&v);
        v.report();
        assert_eq!(g.tracked(), 0, "it asked something");
    }

    #[test]
    fn a_tripwire_condemns_and_the_page_fetched_first_does_not_lift_it() {
        let g = guard();
        let v = Visit::new(g.clone(), here(), Limits::default());

        serve(&v, "/", 200);
        assert!(matches!(v.admit(&Method::GET, "/.env"), Admission::Trip));
        assert_eq!(g.stats().condemned, 1);
        assert_eq!(v.verdict(Instant::now()), Verdict::Close(v.limits.cut));

        v.report();
        assert_eq!(g.stats().banned, 1, "the ban stands");
    }

    #[test]
    fn a_source_banned_elsewhere_is_refused_mid_connection_and_not_cleared() {
        let g = guard();
        let a = Visit::new(g.clone(), here(), Limits::default());
        let b = Visit::new(g.clone(), here(), Limits::default());

        serve(&a, "/", 200);
        assert!(matches!(
            b.admit(&Method::GET, "/wp-login.php"),
            Admission::Trip
        ));

        // The first connection closing after the ban must not lift it.
        a.report();
        assert_eq!(g.stats().banned, 1);

        // And one still open is refused its next request.
        let c = Visit::new(g.clone(), here(), Limits::default());
        assert!(matches!(c.admit(&Method::GET, "/"), Admission::Refuse));
        assert_eq!(c.verdict(Instant::now()), Verdict::Close(c.limits.cut));
    }

    #[test]
    fn deadlines_follow_what_is_in_flight() {
        let g = guard();
        let v = Visit::new(g, here(), Limits::default());
        let t0 = v.opened;

        assert_eq!(
            v.verdict(t0),
            Verdict::Wait(Some(t0 + v.limits.first_request))
        );
        assert_eq!(v.verdict(t0 + v.limits.first_request), Verdict::Drop);

        let Admission::Serve(f) = v.admit(&Method::GET, "/") else {
            panic!();
        };
        assert_eq!(
            v.verdict(t0 + v.limits.first_request * 100),
            Verdict::Wait(None),
            "nothing is closed with a request in flight"
        );

        drop(f);
        let quiet = v.tally.lock().quiet_since;
        assert_eq!(v.verdict(quiet), Verdict::Wait(Some(quiet + v.limits.idle)));
        assert_eq!(
            v.verdict(quiet + v.limits.idle),
            Verdict::Close(v.limits.grace)
        );
    }
}
