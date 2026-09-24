//! Serving the router over TLS.
//!
//! axum's own `serve` takes a plain listener, so the TLS handshake is done
//! here and each accepted connection is handed to hyper directly.  That makes
//! this file answerable for everything axum's server would have done about
//! the network, and for more, because this port is on the internet and
//! carries the web interface, the control API and DNS-over-HTTPS together:
//!
//! - **Admission.**  Every connection takes a ticket from the connection
//!   guard before anything is spent on it, holding it until it closes, and a
//!   handshake slot only while its TLS handshake runs.  A source serving a
//!   penalty, or one over its allowance, is closed before the handshake,
//!   which is the cost being avoided.  A connection that closes without
//!   sending a byte is not held against its source -- see [`connection`].
//! - **A failed accept never ends the listener, and never spins.**  Running
//!   out of file descriptors fails every accept until something closes;
//!   retrying at once, as this used to, spun a core for as long as that
//!   lasted.  It pauses for a second instead, as axum's own server does, and
//!   says so at most once a minute.
//! - **Deadlines**, set out in [`shield::Limits`], and enforced by the loop in
//!   [`serve_connection`].  They are judged on *requests* rather than on bytes
//!   moving: an HTTP/2 connection exchanges keep-alive pings on its own, so a
//!   peer that answers them but never asks anything -- or never reads what it
//!   asked for -- looks busy to anything counting bytes.  What bounds a
//!   client that stops reading is that its connection has nothing in flight
//!   once the answer is handed over, so it is closed a minute later with half
//!   a minute to finish; and HTTP/2 counts a stream as open until its answer
//!   has actually been written, so `MAX_STREAMS` bounds what it can make this
//!   side hold meanwhile.
//! - **What counts as asking something, and the tripwire**, both in
//!   [`crate::shield`], and both applied here rather than in the router, which
//!   also serves the plain listener on the LAN.
//!
//! Nothing served here upgrades a connection -- there are no WebSockets -- so
//! connections are served without upgrade support.  An upgraded connection
//! would leave hyper, and with it every deadline here, while still holding its
//! ticket.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use sift_dns::probe::{Guard, HandshakeSlot, Ticket};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tower::ServiceExt as _;

use crate::doh::TlsServerName;
use crate::shield::{self, Admission, Limits, Upload, Verdict, Visit};

/// How long a connection may stay open before closing without a byte and
/// still cost its source nothing.
///
/// A port monitor closes the moment the connection is up, so a second is
/// ample.  The DNS listeners allow the same.
const SILENT_GRACE: Duration = Duration::from_secs(1);

/// How often an HTTP/2 connection is pinged, and how long the answer may
/// take.
///
/// A peer that has gone away without closing -- a phone that lost its
/// signal, a NAT that forgot the mapping -- otherwise holds its connection
/// until TCP gives up on it, which takes a quarter of an hour.
const PING_INTERVAL: Duration = Duration::from_secs(30);
const PING_TIMEOUT: Duration = Duration::from_secs(10);

/// HTTP/2 streams one connection may have open at once.
///
/// A browser opens a few dozen at most; hyper's default is 200.  A hundred is
/// the least RFC 9113 asks a server to allow, and halves what one connection
/// can have in flight -- or have waiting to be written to a client that has
/// stopped reading.
const MAX_STREAMS: u32 = 100;

/// The largest HTTP/1 request head, and so the most one connection's read
/// buffer grows to while a head arrives.
///
/// hyper's default is about 400 KiB, which is what every slow-header
/// connection could make this process hold.  A browser's head is a few
/// kilobytes, and HTTP/2 allows 16 KiB; a larger one is answered 431.
const MAX_HEAD: usize = 64 * 1024;

/// Binds `addr` and serves `app` over TLS until `shutdown` changes.
///
/// Returns the task driving the listener, so the caller can await it on
/// shutdown.
pub async fn serve(
    addr: SocketAddr,
    tls: Arc<rustls::ServerConfig>,
    app: Router,
    probes: Arc<Guard>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> io::Result<tokio::task::JoinHandle<()>> {
    let listener = TcpListener::bind(addr).await?;

    Ok(tokio::spawn(accept(
        listener,
        tls,
        app,
        probes,
        shutdown,
        Limits::default(),
    )))
}

/// What every connection on one listener shares.
struct Site {
    acceptor: TlsAcceptor,
    app: Router,
    probes: Arc<Guard>,
    http: Builder<TokioExecutor>,
    limits: Limits,
}

/// Accepts connections until `shutdown` changes.
async fn accept(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    app: Router,
    probes: Arc<Guard>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    limits: Limits,
) {
    let site = Arc::new(Site {
        acceptor: TlsAcceptor::from(tls),
        app,
        probes,
        http: http(&limits),
        limits,
    });
    // The DNS listeners' record of accept failures: one that belongs to a
    // single connection is passed over at once, and anything else --
    // running out of descriptors above all -- is waited out a second at a
    // time and logged once a minute.
    let failures = sift_dns::server::AcceptErrors::new("https");

    loop {
        let (stream, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => {
                    if let Some(pause) = failures.pause_after(&e) {
                        tokio::select! {
                            () = tokio::time::sleep(pause) => {}
                            _ = shutdown.changed() => return,
                        }
                    }

                    continue;
                }
            },
            _ = shutdown.changed() => return,
        };

        // Turned away before the handshake, which is what it would cost: a
        // source serving a penalty, one over its allowance, or anyone once
        // the process holds all it will.  Dropping the stream closes it.
        let ip = peer.ip();
        let Ok(ticket) = site.probes.open(ip) else {
            continue;
        };
        let Some(slot) = site.probes.handshake(ip) else {
            continue;
        };

        tokio::spawn(connection(site.clone(), stream, peer, ticket, slot));
    }
}

/// The HTTP settings every connection is served with.
fn http(limits: &Limits) -> Builder<TokioExecutor> {
    let mut b = Builder::new(TokioExecutor::new());

    // Without a timer hyper's header deadline is silently off: its default
    // of thirty seconds only applies when one has been supplied.
    b.http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read)
        .max_buf_size(MAX_HEAD);
    b.http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(PING_INTERVAL)
        .keep_alive_timeout(PING_TIMEOUT)
        .max_concurrent_streams(MAX_STREAMS);

    b
}

/// Handshakes and serves one connection, then reports it to the guard.
///
/// A connection that closes before sending a single byte is not reported at
/// all.  It cost nothing but the accept -- no handshake was started, no
/// buffer filled -- and it is exactly what a port monitor does: Uptime Kuma
/// checking 443 every twenty seconds opens a connection and closes it, and
/// striking each one had the monitor banned within a minute, doubling to a
/// day, with nothing it could do to be served again.  The allowance is
/// `SILENT_GRACE` from the connect, as on the DNS listeners: one that stays
/// open and silent longer held a descriptor and a handshake slot all that
/// time, and connecting and closing just before each deadline would hold
/// both for ever at no charge, so it is struck as it always was.
async fn connection(
    site: Arc<Site>,
    stream: TcpStream,
    peer: SocketAddr,
    ticket: Ticket,
    slot: HandshakeSlot,
) {
    stream.set_nodelay(true).ok();

    let opened = Instant::now();
    let deadline = opened + site.limits.handshake;
    let mut first = [0u8; 1];
    match tokio::time::timeout_at(deadline, stream.peek(&mut first)).await {
        Ok(Ok(0) | Err(_)) => {
            if opened.elapsed() >= SILENT_GRACE {
                site.probes.wasted(peer.ip());
            }

            return;
        }
        Ok(Ok(_)) => {}
        Err(_) => {
            site.probes.wasted(peer.ip());

            return;
        }
    }

    let accepted = tokio::time::timeout_at(deadline, site.acceptor.accept(stream)).await;
    drop(slot);
    let Ok(Ok(tls)) = accepted else {
        // A handshake that was started and never finished asked nothing, and
        // TCP has already proved the address.
        site.probes.wasted(peer.ip());

        return;
    };

    let visit = Visit::new(site.probes.clone(), peer.ip(), site.limits);
    serve_connection(&site, tls, peer, &visit).await;
    visit.report();

    drop(ticket);
}

/// Serves HTTP on one TLS connection until it closes or is closed.
///
/// hyper drives the protocol; this loop only decides when the connection has
/// had long enough, from what [`Visit::verdict`] says.  Asked to close, hyper
/// finishes what is in flight -- on HTTP/2 it sends GOAWAY first -- and the
/// connection is dropped outright if that has not happened in time.
async fn serve_connection(
    site: &Site,
    tls: TlsStream<TcpStream>,
    peer: SocketAddr,
    visit: &Arc<Visit>,
) {
    // What the client asked for in its handshake, for DNS-over-HTTPS to read
    // a ClientID from, as DoT reads one from the same place.
    let name = TlsServerName(tls.get_ref().1.server_name().map(Arc::from));

    let svc = {
        let app = site.app.clone();
        let visit = visit.clone();

        hyper::service::service_fn(move |req| {
            handle(req, app.clone(), peer, name.clone(), visit.clone())
        })
    };

    let conn = site.http.serve_connection(TokioIo::new(tls), svc);
    tokio::pin!(conn);

    // When the connection is dropped however far it has got, once it has
    // been asked to close.
    let mut hard: Option<Instant> = None;
    loop {
        let wake = match hard {
            Some(at) => Some(at),
            None => match visit.verdict(Instant::now()) {
                Verdict::Wait(at) => at,
                Verdict::Drop => return,
                Verdict::Close(within) => {
                    conn.as_mut().graceful_shutdown();
                    let at = Instant::now() + within;
                    hard = Some(at);

                    Some(at)
                }
            },
        };

        tokio::select! {
            _ = conn.as_mut() => return,
            () = shield::until(wake) => {
                if hard.is_some_and(|at| Instant::now() >= at) {
                    return;
                }
            }
            () = visit.changed(), if hard.is_none() => {}
        }
    }
}

/// Serves one request, if it is to be served.
async fn handle(
    req: Request<Incoming>,
    app: Router,
    peer: SocketAddr,
    name: TlsServerName,
    visit: Arc<Visit>,
) -> Result<Response<Body>, Turned> {
    let h1 = shield::is_http1(req.version());

    let flight = match visit.admit(req.method(), req.uri().path()) {
        Admission::Serve(f) => f,
        // The same answer as any path that is not there, and nothing more.
        Admission::Trip => return Ok(shield::plain(StatusCode::NOT_FOUND, h1)),
        Admission::Refuse => return Err(Turned),
    };

    let limits = *visit.limits();
    let (parts, body) = req.into_parts();
    let (body, late) = Upload::new(body, limits.upload);
    let mut req = Request::from_parts(parts, Body::new(body));
    // The handlers read the client's address from here, as they do behind
    // axum's own server, and DNS-over-HTTPS the name it connected with.
    req.extensions_mut().insert(ConnectInfo(peer));
    req.extensions_mut().insert(name);

    let response = match tokio::time::timeout(limits.handler, app.oneshot(req)).await {
        Ok(Ok(r)) => r,
        Ok(Err(never)) => match never {},
        Err(_) => shield::plain(StatusCode::SERVICE_UNAVAILABLE, h1),
    };

    // A body that ran out of time fails whichever extractor was reading it,
    // with a rejection that blames the request's content; the client is
    // better told what actually happened.
    let response = if late.is_set() {
        shield::plain(StatusCode::REQUEST_TIMEOUT, h1)
    } else {
        response
    };

    flight.answered(&response);

    Ok(response)
}

/// What a request from a refused source is failed with.
///
/// hyper closes an HTTP/1 connection on a service error without answering,
/// and resets the stream on HTTP/2; either way nothing is served.
#[derive(Debug)]
struct Turned;

impl fmt::Display for Turned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the source is refused")
    }
}

impl std::error::Error for Turned {}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use axum::routing::{get, post};
    use bytes::Bytes;
    use http_body_util::{BodyExt as _, Empty};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    /// Deadlines short enough to watch, and long enough that a loaded
    /// machine still completes a handshake inside them.
    fn quick() -> Limits {
        Limits {
            handshake: Duration::from_secs(1),
            first_request: Duration::from_millis(600),
            header_read: Duration::from_millis(600),
            idle: Duration::from_millis(600),
            grace: Duration::from_millis(400),
            cut: Duration::from_millis(400),
            upload: Duration::from_millis(400),
            handler: Duration::from_millis(600),
            ..Limits::default()
        }
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

    /// A router that answers the way the real one does to a browser.
    fn app() -> Router {
        Router::new()
            .route(
                "/",
                get(|| async { (StatusCode::FOUND, [("location", "login.html")]) }),
            )
            .route("/login.html", get(|| async { "<html>" }))
            .route(
                "/sni",
                get(
                    |axum::Extension(TlsServerName(n)): axum::Extension<TlsServerName>| async move {
                        n.as_deref().unwrap_or("(none)").to_string()
                    },
                ),
            )
            .route(
                "/static/login.js",
                get(|| async { StatusCode::NOT_MODIFIED }),
            )
            .route(
                "/control/status",
                get(|| async { StatusCode::UNAUTHORIZED }),
            )
            .route(
                "/dns-query",
                post(|| async {
                    let mut r = axum::response::IntoResponse::into_response("refused");
                    r.extensions_mut().insert(crate::doh::Unanswered);
                    r
                }),
            )
            .route(
                "/busy",
                get(|| async {
                    let mut r = axum::response::IntoResponse::into_response("servfail");
                    r.extensions_mut().insert(crate::doh::Overloaded);
                    r
                }),
            )
            .route(
                "/upload",
                post(|body: Bytes| async move { format!("{}", body.len()) }),
            )
            .route(
                "/slow",
                get(|| async {
                    std::future::pending::<()>().await;
                    "never"
                }),
            )
            .fallback(|| async { StatusCode::NOT_FOUND })
    }

    struct Server {
        addr: SocketAddr,
        pem: String,
        _stop: tokio::sync::watch::Sender<bool>,
    }

    async fn start(g: Arc<Guard>) -> Server {
        start_with(g, quick()).await
    }

    /// Starts a listener with its own deadlines.
    async fn start_with(g: Arc<Guard>, limits: Limits) -> Server {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let c = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let pem = c.cert.pem();
        let tls = sift_dns::tls::load(&sift_dns::tls::Source {
            certificate_chain: pem.clone(),
            private_key: c.signing_key.serialize_pem(),
            certificate_path: String::new(),
            private_key_path: String::new(),
        })
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(accept(listener, tls.https, app(), g, rx, limits));

        Server {
            addr,
            pem,
            _stop: stop,
        }
    }

    /// Opens a TLS connection offering `alpn`.
    async fn tls(
        s: &Server,
        alpn: &[u8],
    ) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut s.pem.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![alpn.to_vec()];

        let tcp = TcpStream::connect(s.addr).await?;
        tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect("localhost".try_into().unwrap(), tcp)
            .await
    }

    type Sender1 = hyper::client::conn::http1::SendRequest<Empty<Bytes>>;

    /// An HTTP/1.1 client, and the task that ends when the server closes.
    async fn h1(s: &Server) -> (Sender1, tokio::task::JoinHandle<()>) {
        let io = TokioIo::new(tls(s, b"http/1.1").await.unwrap());
        let (tx, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();

        (
            tx,
            tokio::spawn(async move {
                let _ = conn.await;
            }),
        )
    }

    async fn get1(tx: &mut Sender1, path: &str) -> hyper::Result<StatusCode> {
        tx.ready().await?;
        let req = Request::get(path)
            .header("host", "localhost")
            .body(Empty::new())
            .unwrap();
        let resp = tx.send_request(req).await?;
        let status = resp.status();
        let _ = resp.into_body().collect().await;

        Ok(status)
    }

    /// Waits for `check` to hold, for up to five seconds.
    async fn settle(mut check: impl FnMut() -> bool) -> bool {
        for _ in 0..500 {
            if check() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        check()
    }

    /// Reads until the server closes, or until `within` runs out.
    async fn closed_within<S: tokio::io::AsyncRead + Unpin>(s: &mut S, within: Duration) -> bool {
        let mut buf = [0u8; 4096];
        tokio::time::timeout(within, async {
            loop {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
        })
        .await
        .is_ok()
    }

    #[tokio::test]
    async fn a_connection_that_sends_nothing_after_its_handshake_is_dropped_and_counted() {
        let g = guard();
        let s = start(g.clone()).await;

        let started = Instant::now();
        let mut c = tls(&s, b"http/1.1").await.unwrap();
        assert!(
            closed_within(&mut c, Duration::from_secs(5)).await,
            "the server should give up on a silent connection"
        );
        assert!(started.elapsed() >= quick().first_request);

        assert!(
            settle(|| g.tracked() == 1).await,
            "a connection that asked nothing is a strike"
        );
    }

    #[tokio::test]
    async fn a_slow_first_request_is_cut_off_at_the_first_request_deadline() {
        // The HTTP/2 preface, a byte at a time: hyper waits for all of it
        // before it knows which protocol it is speaking, with no deadline of
        // its own.
        let g = guard();
        let s = start(g.clone()).await;

        let mut c = tls(&s, b"h2").await.unwrap();
        let (mut r, mut w) = tokio::io::split(&mut c);
        let trickle = async {
            for b in b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
                if w.write_all(&[*b]).await.is_err() || w.flush().await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            std::future::pending::<()>().await;
        };

        let closed = tokio::select! {
            closed = closed_within(&mut r, Duration::from_secs(5)) => closed,
            () = trickle => false,
        };
        assert!(closed, "the trickle outlived the deadline");
        assert!(settle(|| g.tracked() == 1).await);
    }

    #[tokio::test]
    async fn a_slow_header_is_cut_off() {
        let g = guard();
        let s = start(g.clone()).await;
        let mut c = tls(&s, b"http/1.1").await.unwrap();

        // One real request, so the first-request deadline is out of the way
        // and only hyper's header deadline is left to act.
        c.write_all(b"GET /login.html HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut got = Vec::new();
        while !got.ends_with(b"<html>") {
            let mut buf = [0u8; 1024];
            let n = c.read(&mut buf).await.unwrap();
            assert_ne!(n, 0, "closed before answering");
            got.extend_from_slice(&buf[..n]);
        }

        let started = Instant::now();
        let (mut r, mut w) = tokio::io::split(&mut c);
        let trickle = async {
            w.write_all(b"GET /login.html HTTP/1.1\r\nhost: localhost\r\nx-slow: ")
                .await
                .unwrap();
            loop {
                if w.write_all(b"a").await.is_err() || w.flush().await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };

        let closed = tokio::select! {
            closed = closed_within(&mut r, Duration::from_secs(5)) => closed,
            () = trickle => true,
        };
        assert!(
            closed,
            "a header a byte at a time must not hold the connection"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "cut off by the header deadline, took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_tripwire_condemns_the_source_and_its_next_connection_is_refused_before_the_handshake()
     {
        let g = guard();
        let s = start(g.clone()).await;

        let (mut tx, done) = h1(&s).await;
        assert_eq!(get1(&mut tx, "/.env").await.unwrap(), StatusCode::NOT_FOUND);
        assert!(
            tokio::time::timeout(Duration::from_secs(5), done)
                .await
                .is_ok(),
            "the connection is closed after the answer"
        );
        assert_eq!(g.stats().condemned, 1);

        let before = g.stats().refused_banned;
        assert!(tls(&s, b"http/1.1").await.is_err(), "no handshake is had");
        assert!(g.stats().refused_banned > before);
        assert_eq!(g.stats().handshakes, 0);
    }

    #[tokio::test]
    async fn a_page_fetched_before_a_tripwire_does_not_lift_the_ban() {
        let g = guard();
        let s = start(g.clone()).await;

        let (mut tx, done) = h1(&s).await;
        assert_eq!(get1(&mut tx, "/").await.unwrap(), StatusCode::FOUND);
        assert_eq!(
            get1(&mut tx, "/wp-login.php").await.unwrap(),
            StatusCode::NOT_FOUND
        );
        let _ = tokio::time::timeout(Duration::from_secs(5), done).await;

        // The close report has been made once the ticket is given back.
        assert!(settle(|| g.stats().open == 0).await);
        assert_eq!(g.stats().banned, 1, "the ban still stands");
    }

    #[tokio::test]
    async fn a_browser_like_visit_is_never_struck_or_banned() {
        let g = guard();
        // Something already held against the source, which asking clears.
        g.wasted(here());
        let s = start(g.clone()).await;

        // Over HTTP/2, as a browser speaks it, several requests at once.
        let io = TokioIo::new(tls(&s, b"h2").await.unwrap());
        let (tx, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .unwrap();
        let done = tokio::spawn(async move {
            let _ = conn.await;
        });

        let mut statuses = Vec::new();
        for path in [
            "/",
            "/login.html",
            "/static/login.js",
            "/control/status",
            "/control/status",
            "/control/status",
            "/apple-touch-icon.png",
            "/apple-touch-icon-precomposed.png",
            "/login.html",
        ] {
            let mut tx = tx.clone();
            tx.ready().await.unwrap();
            let req = Request::get(format!("https://localhost{path}"))
                .body(Empty::<Bytes>::new())
                .unwrap();
            let resp = tx.send_request(req).await.unwrap();
            statuses.push(resp.status().as_u16());
            let _ = resp.into_body().collect().await;
        }
        assert_eq!(statuses, [302, 200, 304, 401, 401, 401, 404, 404, 200]);
        drop(tx);
        let _ = tokio::time::timeout(Duration::from_secs(5), done).await;

        assert!(settle(|| g.stats().open == 0).await);
        assert_eq!(
            g.tracked(),
            0,
            "it asked something, which clears the source"
        );
        assert_eq!(g.stats().penalties, 0);
    }

    #[tokio::test]
    async fn a_doh_answer_marked_unanswered_does_not_count() {
        let g = guard();
        let s = start(g.clone()).await;

        let io = TokioIo::new(tls(&s, b"http/1.1").await.unwrap());
        let (mut tx, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        let done = tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::post("/dns-query")
            .header("host", "localhost")
            .body(http_body_util::Full::new(Bytes::from_static(b"q")))
            .unwrap();
        let resp = tx.send_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = resp.into_body().collect().await;
        drop(tx);
        let _ = tokio::time::timeout(Duration::from_secs(5), done).await;

        assert!(
            settle(|| g.tracked() == 1).await,
            "a 200 the DNS side did not count is not asking"
        );
    }

    /// A guard two strikes from a penalty with one already spent, so that a
    /// connection's report shows as a ban if it strikes, as a clean record if
    /// it forgives, and as neither if it was not made at all.
    fn one_strike_left() -> Arc<Guard> {
        let g = Arc::new(Guard::new(sift_dns::probe::Config {
            exempt_local: false,
            strikes: 2,
            ..Default::default()
        }));
        g.wasted(here());

        g
    }

    /// Asserts that the connections from `here()` have all been reported,
    /// and that the reports neither struck nor forgave the source.
    async fn neither_struck_nor_forgiven(g: &Guard) {
        assert!(settle(|| g.stats().open == 0).await, "the connection ended");
        assert_eq!(g.stats().banned, 0, "not struck");
        assert_eq!(g.tracked(), 1, "nor forgiven the strike it had before");
    }

    #[tokio::test]
    async fn a_doh_client_asking_through_an_overload_over_http1_is_neither_closed_nor_struck() {
        let g = one_strike_left();
        let s = start(g.clone()).await;

        let (mut tx, done) = h1(&s).await;
        for i in 0..2 * 32 {
            assert_eq!(
                get1(&mut tx, "/busy").await.expect("still open"),
                StatusCode::OK,
                "answer {i}"
            );
        }
        drop(tx);
        let _ = tokio::time::timeout(Duration::from_secs(5), done).await;

        neither_struck_nor_forgiven(&g).await;
    }

    #[tokio::test]
    async fn a_doh_client_asking_through_an_overload_over_http2_is_neither_closed_nor_struck() {
        let g = one_strike_left();
        let s = start(g.clone()).await;

        let io = TokioIo::new(tls(&s, b"h2").await.unwrap());
        let (tx, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .unwrap();
        let done = tokio::spawn(async move {
            let _ = conn.await;
        });

        for i in 0..2 * 32 {
            let mut tx = tx.clone();
            tx.ready().await.expect("still open");
            let req = Request::get("https://localhost/busy")
                .body(Empty::<Bytes>::new())
                .unwrap();
            let resp = tx.send_request(req).await.expect("still open");
            assert_eq!(resp.status(), StatusCode::OK, "answer {i}");
            let _ = resp.into_body().collect().await;
        }
        drop(tx);
        let _ = tokio::time::timeout(Duration::from_secs(5), done).await;

        neither_struck_nor_forgiven(&g).await;
    }

    #[tokio::test]
    async fn a_connection_closed_before_its_first_byte_costs_nothing() {
        // A port monitor: connect, and close.  More of them than the guard's
        // strikes, one after another, as a monitor makes them.
        let g = guard();
        let s = start(g.clone()).await;

        for i in 0..10 {
            let c = TcpStream::connect(s.addr).await.unwrap();
            assert!(
                settle(|| g.stats().open == 1).await,
                "connection {i} was accepted"
            );
            drop(c);
            assert!(settle(|| g.stats().open == 0).await, "and let go");
        }

        assert_eq!(g.tracked(), 0, "none of them is held against the source");
        assert_eq!(g.stats().handshakes, 0);
        assert!(g.admits(here()));
    }

    #[tokio::test]
    async fn a_connection_that_lingers_in_silence_before_leaving_is_struck() {
        // Closing without a byte is free only for a moment: one that waits
        // until just before each deadline would otherwise hold a descriptor
        // and a handshake slot for ever at no charge.
        let g = guard();
        let s = start_with(
            g.clone(),
            Limits {
                handshake: Duration::from_secs(5),
                ..quick()
            },
        )
        .await;

        let c = TcpStream::connect(s.addr).await.unwrap();
        assert!(settle(|| g.stats().open == 1).await);
        tokio::time::sleep(SILENT_GRACE + Duration::from_millis(300)).await;
        drop(c);

        assert!(
            settle(|| g.tracked() == 1).await,
            "lingering before leaving is a strike"
        );
        assert_eq!(g.stats().handshakes, 0, "and the slot was given back");
    }

    #[tokio::test]
    async fn a_connection_that_sends_nothing_by_the_handshake_deadline_is_struck() {
        let g = guard();
        let s = start(g.clone()).await;

        let started = Instant::now();
        let mut c = TcpStream::connect(s.addr).await.unwrap();
        assert!(
            closed_within(&mut c, Duration::from_secs(5)).await,
            "the server should give up on a connection that never starts"
        );
        assert!(started.elapsed() >= quick().handshake);

        assert!(
            settle(|| g.tracked() == 1).await,
            "holding a handshake slot for nothing is a strike"
        );
        assert_eq!(g.stats().handshakes, 0, "and the slot was given back");
    }

    #[tokio::test]
    async fn a_connection_that_sends_something_other_than_tls_is_struck() {
        // Only a connection that sent nothing at all is free: plain HTTP on
        // the HTTPS port is a failed handshake, as it always was.
        let g = guard();
        let s = start(g.clone()).await;

        let mut c = TcpStream::connect(s.addr).await.unwrap();
        c.write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .unwrap();
        assert!(closed_within(&mut c, Duration::from_secs(5)).await);

        assert!(settle(|| g.tracked() == 1).await);
    }

    #[tokio::test]
    async fn a_run_of_not_found_closes_the_connection_and_counts_as_nothing() {
        let g = guard();
        let s = start(g.clone()).await;

        let (mut tx, done) = h1(&s).await;
        assert_eq!(get1(&mut tx, "/").await.unwrap(), StatusCode::FOUND);

        let mut answered = 0;
        for i in 0..40 {
            match get1(&mut tx, &format!("/guess-{i}")).await {
                Ok(status) => {
                    assert_eq!(status, StatusCode::NOT_FOUND);
                    answered += 1;
                }
                Err(_) => break,
            }
        }
        assert_eq!(answered, 32, "closed after the run");
        assert!(
            tokio::time::timeout(Duration::from_secs(5), done)
                .await
                .is_ok()
        );

        assert!(
            settle(|| g.tracked() == 1).await,
            "the page it fetched first does not clear it"
        );
    }

    #[tokio::test]
    async fn asking_for_the_front_page_between_guesses_does_not_keep_a_connection_open() {
        let g = guard();
        let s = start(g.clone()).await;

        let (mut tx, done) = h1(&s).await;
        let mut guesses = 0;
        for i in 0..40 {
            let Ok(status) = get1(&mut tx, "/").await else {
                break;
            };
            assert_eq!(status, StatusCode::FOUND);
            match get1(&mut tx, &format!("/guess-{i}")).await {
                Ok(status) => {
                    assert_eq!(status, StatusCode::NOT_FOUND);
                    guesses += 1;
                }
                Err(_) => break,
            }
        }
        assert_eq!(guesses, 32, "the redirects did not start the run over");
        assert!(
            tokio::time::timeout(Duration::from_secs(5), done)
                .await
                .is_ok()
        );

        assert!(settle(|| g.tracked() == 1).await);
    }

    #[tokio::test]
    async fn a_source_banned_while_connected_is_closed_rather_than_served() {
        let g = guard();
        let s = start(g.clone()).await;

        let (mut tx, done) = h1(&s).await;
        assert_eq!(get1(&mut tx, "/login.html").await.unwrap(), StatusCode::OK);

        // Banned by something another connection did.
        g.condemn(here(), "a test");
        assert!(
            get1(&mut tx, "/login.html").await.is_err(),
            "nothing served"
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(5), done)
                .await
                .is_ok()
        );

        assert!(settle(|| g.stats().open == 0).await);
        assert_eq!(g.stats().banned, 1, "and its close does not lift the ban");
    }

    #[tokio::test]
    async fn an_idle_http2_connection_is_closed_while_the_client_holds_it_open() {
        let g = guard();
        let s = start(g.clone()).await;

        let io = TokioIo::new(tls(&s, b"h2").await.unwrap());
        let (mut tx, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .unwrap();
        // The client keeps its half running, and its sender alive, for as
        // long as the server lets it: it never closes by itself.
        let done = tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = Request::get("https://localhost/login.html")
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert_eq!(tx.send_request(req).await.unwrap().status(), StatusCode::OK);
        let quiet = Instant::now();

        let l = quick();
        assert!(
            tokio::time::timeout(l.idle + l.grace + Duration::from_secs(3), done)
                .await
                .is_ok(),
            "an idle connection is let go"
        );
        assert!(quiet.elapsed() >= l.idle, "but not before it is idle");
        assert!(settle(|| g.stats().open == 0).await);
        assert_eq!(g.tracked(), 0, "it asked something before going quiet");
    }

    #[tokio::test]
    async fn a_body_that_does_not_arrive_in_time_is_answered_408() {
        let g = guard();
        let s = start(g.clone()).await;
        let mut c = tls(&s, b"http/1.1").await.unwrap();

        c.write_all(b"POST /upload HTTP/1.1\r\nhost: localhost\r\ncontent-length: 100\r\n\r\nabc")
            .await
            .unwrap();

        let mut got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut got)).await;
        let text = String::from_utf8_lossy(&got);
        assert!(text.starts_with("HTTP/1.1 408"), "got {text:?}");
    }

    #[tokio::test]
    async fn a_handler_that_never_answers_is_answered_503() {
        let g = guard();
        let s = start(g.clone()).await;

        let (mut tx, _done) = h1(&s).await;
        assert_eq!(
            get1(&mut tx, "/slow").await.unwrap(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn every_request_carries_the_server_name_the_client_connected_with() {
        // What DNS-over-HTTPS reads a ClientID from when the path has none.
        let s = start(guard()).await;

        for alpn in [&b"http/1.1"[..], b"h2"] {
            let io = TokioIo::new(tls(&s, alpn).await.unwrap());
            let body = if alpn == b"h2" {
                let (mut tx, conn) =
                    hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
                        .await
                        .unwrap();
                tokio::spawn(conn);
                let req = Request::get("https://localhost/sni")
                    .body(Empty::<Bytes>::new())
                    .unwrap();
                let resp = tx.send_request(req).await.unwrap();
                resp.into_body().collect().await.unwrap().to_bytes()
            } else {
                let (mut tx, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
                tokio::spawn(conn);
                let req = Request::get("/sni")
                    .header("host", "localhost")
                    .body(Empty::<Bytes>::new())
                    .unwrap();
                let resp = tx.send_request(req).await.unwrap();
                resp.into_body().collect().await.unwrap().to_bytes()
            };

            assert_eq!(&body[..], b"localhost", "{}", String::from_utf8_lossy(alpn));
        }
    }
}
