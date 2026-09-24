//! Serving the web interface and DNS-over-HTTPS over HTTP/3.
//!
//! This is the `serve_http3` setting.  HTTP/3 runs over QUIC rather than TCP,
//! so it needs its own listener on the HTTPS port; requests are then handed to
//! the same router the HTTP/1.1 and HTTP/2 listener uses, which is what keeps
//! DNS-over-HTTPS behaving identically whichever version a client speaks.
//!
//! It is held to what the HTTPS listener is held to -- the connection guard's
//! admission, the deadlines, what counts as asking something and the
//! tripwire, all in [`crate::shield`] -- and to four things of its own:
//!
//! - **Admission is QUIC's**, through `sift_dns::quic`: an address nobody has
//!   proved may be asked to retry before a handshake is spent on it, and one
//!   serving a penalty is sent nothing at all, since it may be forged.
//! - **Stream limits sized for HTTP/3.**  A client needs one request stream
//!   per request in flight, and three unidirectional streams: its control
//!   stream and the two QPACK streams.  quinn's defaults of 100 of each let a
//!   peer park a hundred streams of each kind for nothing.
//! - **A bound on header sections**, advertised to the client, where h3's
//!   default is to accept any size at all.
//! - **A bound on the frames h3 buffers.**  h3 reads a HEADERS frame -- or a
//!   frame of a type it does not know, which it then discards -- into memory
//!   whole before it looks at it, whatever length the peer declared, and only
//!   then checks the header section's size.  QUIC's flow control does not
//!   stop that, because h3 keeps reading, and every byte it reads is credit
//!   handed back to the peer.  On a request stream that went on until the
//!   request's deadline; on the control stream, which lives as long as the
//!   connection, it went on for ever.  [`Metered`] follows the frame headers
//!   as they arrive and refuses any frame but DATA declared larger than
//!   `MAX_FRAME`, before h3 has buffered any of it.  DATA is never buffered
//!   whole -- h3 hands it on as it comes -- so a request body is left to the
//!   router's own limits.
//!
//! What h3 does with the rest was checked rather than assumed: a
//! unidirectional stream of a type it does not know is stopped at once, and
//! the QPACK streams are never read past their type -- this h3 uses no
//! dynamic table -- so what a peer can put on one is its stream window.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use bytes::{Buf as _, Bytes};
use h3::error::Code;
use h3::quic::{ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf};
use h3::server::{RequestResolver, RequestStream};
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt as _;
use hyper::body::Frame;
use quinn::{Endpoint, VarInt};
use sift_dns::probe::Guard;
use sift_dns::quic;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tower::ServiceExt as _;

use crate::doh::TlsServerName;
use crate::shield::{self, Admission, Limits, Upload, Verdict, Visit};

/// Request streams one connection may have open at once.
///
/// A page load asks for a few dozen things at once, and a DoH client one per
/// query in flight.  Each open stream is a task here, holding what the
/// request has read and the answer until it is sent, so this is also how
/// many tasks one connection can have running.
const MAX_BIDI: u32 = 64;

/// Unidirectional streams one connection may have open at once.
///
/// A client opens three -- its control stream and the QPACK encoder and
/// decoder streams -- and may open a reserved "grease" one now and then, which
/// h3 stops as soon as it has read its type.
const MAX_UNI: u32 = 8;

/// The largest header section a request may carry, advertised to the client
/// as `SETTINGS_MAX_FIELD_SECTION_SIZE`.
///
/// What HTTP/2 allows here too.  A larger one is answered 431.
const MAX_FIELD_SECTION: u64 = 16 * 1024;

/// The largest frame other than DATA a peer may send, on any stream.
///
/// A header section of `MAX_FIELD_SECTION` encodes to less than this, and
/// nothing else a client sends -- SETTINGS, GOAWAY, priority updates -- is
/// more than a few dozen bytes.
const MAX_FRAME: u64 = 64 * 1024;

/// The pieces an answer is sent in, each of which the client has
/// `Limits::stall` to make room for.
const PIECE: usize = 16 * 1024;

/// `H3_NO_ERROR`, for closing a connection that has done nothing wrong.
const H3_NO_ERROR: VarInt = VarInt::from_u32(0x100);

/// Why the listener could not start.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The rustls configuration cannot be used for QUIC, which needs TLS 1.3.
    #[error("quic tls: {0}")]
    Tls(String),

    /// The socket could not be bound.
    #[error("binding {addr}: {source}")]
    Bind {
        /// The address that could not be bound.
        addr: SocketAddr,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
}

/// Builds a QUIC endpoint that offers HTTP/3.
pub fn endpoint(addr: SocketAddr, tls: Arc<rustls::ServerConfig>) -> Result<Endpoint, Error> {
    Endpoint::server(server_config(tls)?, addr).map_err(|source| Error::Bind { addr, source })
}

/// The QUIC configuration: what both QUIC listeners share, with HTTP/3's own
/// stream limits.
fn server_config(tls: Arc<rustls::ServerConfig>) -> Result<quinn::ServerConfig, Error> {
    let mut cfg = quic::server_config(tls).map_err(|e| Error::Tls(e.to_string()))?;

    let transport =
        Arc::get_mut(&mut cfg.transport).expect("the transport config is not yet shared");
    transport
        .max_concurrent_bidi_streams(MAX_BIDI.into())
        .max_concurrent_uni_streams(MAX_UNI.into());

    Ok(cfg)
}

/// Serves HTTP/3 until `shutdown` resolves.
pub async fn serve(
    endpoint: Endpoint,
    router: Router,
    probes: Arc<Guard>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) {
    run(endpoint, router, probes, shutdown, Limits::default()).await;
}

/// Accepts connections until `shutdown` resolves.
async fn run(
    endpoint: Endpoint,
    router: Router,
    probes: Arc<Guard>,
    shutdown: impl std::future::Future<Output = ()> + Send,
    limits: Limits,
) {
    tokio::pin!(shutdown);

    loop {
        let incoming = tokio::select! {
            i = endpoint.accept() => match i {
                Some(i) => i,
                // The endpoint was closed.
                None => return,
            },
            () = &mut shutdown => {
                endpoint.close(0u32.into(), b"shutting down");

                return;
            }
        };

        // Ignored, retried or refused here, without waiting, as
        // `sift_dns::quic` decides; only a connection worth a handshake is
        // spawned.
        let Some(pending) = quic::admit(&probes, incoming) else {
            continue;
        };

        let router = router.clone();
        let probes = probes.clone();
        tokio::spawn(async move {
            // A handshake that fails is counted there, and only against an
            // address that was proved beforehand: an initial packet can carry
            // a forged source.
            let Some((conn, ticket)) = pending.establish(quic::H3_EXCESSIVE_LOAD).await else {
                return;
            };
            let peer = conn.remote_address();

            let visit = Visit::new(probes, peer.ip(), limits);
            serve_connection(conn, router, peer, &visit).await;
            visit.report();

            drop(ticket);
        });
    }
}

/// Handles every request on one connection, until it closes or is closed.
///
/// The deadlines are [`Visit::verdict`]'s, as on the HTTPS listener.  Asked
/// to close, the connection is sent GOAWAY, so requests already accepted may
/// finish, and is closed outright once they have had their time.
async fn serve_connection(
    conn: quinn::Connection,
    router: Router,
    peer: SocketAddr,
    visit: &Arc<Visit>,
) {
    let quic = conn.clone();
    let limits = *visit.limits();

    // What the client asked for in its handshake, for DNS-over-HTTPS to read
    // a ClientID from, as DoQ reads one from the same place.
    let name = TlsServerName(
        conn.handshake_data()
            .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|d| d.server_name)
            .map(Arc::from),
    );

    // Setting up HTTP/3 opens streams towards the peer, which a peer that
    // grants none could hold up for ever.
    let built = tokio::time::timeout(
        limits.first_request,
        h3::server::builder()
            .max_field_section_size(MAX_FIELD_SECTION)
            .build::<_, Bytes>(Metered(h3_quinn::Connection::new(conn))),
    )
    .await;
    let Ok(Ok(mut h3)) = built else {
        quic.close(H3_NO_ERROR, b"");

        return;
    };

    // QUIC's stream limit already bounds the requests in flight, since each
    // task holds its stream until it is done; this makes the bound this
    // side's to keep rather than an accident of when quinn frees a stream.
    let permits = Arc::new(Semaphore::new(MAX_BIDI as usize));

    let mut hard: Option<Instant> = None;
    loop {
        let wake = match hard {
            Some(at) => Some(at),
            None => match visit.verdict(Instant::now()) {
                Verdict::Wait(at) => at,
                Verdict::Drop => break,
                Verdict::Close(within) => {
                    let at = Instant::now() + within;
                    hard = Some(at);
                    if tokio::time::timeout_at(at, h3.shutdown(0)).await.is_err() {
                        break;
                    }

                    Some(at)
                }
            },
        };

        tokio::select! {
            next = async {
                let permit = permits.clone().acquire_owned().await;

                (permit, h3.accept().await)
            } => match next {
                (Ok(permit), Ok(Some(resolver))) => {
                    let router = router.clone();
                    let visit = visit.clone();
                    let name = name.clone();
                    tokio::spawn(serve_request(resolver, router, peer, name, visit, permit));
                }
                // The client is going away, or the connection broke.
                _ => break,
            },
            () = shield::until(wake) => {
                if hard.is_some_and(|at| Instant::now() >= at) {
                    break;
                }
            }
            () = visit.changed(), if hard.is_none() => {}
        }
    }

    quic.close(H3_NO_ERROR, b"");
}

/// Handles one request.
async fn serve_request(
    resolver: RequestResolver<Metered, Bytes>,
    router: Router,
    peer: SocketAddr,
    name: TlsServerName,
    visit: Arc<Visit>,
    _permit: OwnedSemaphorePermit,
) {
    let limits = *visit.limits();

    // A stream that never finishes its headers is dropped with them.
    let Ok(Ok((req, mut stream))) =
        tokio::time::timeout(limits.resolve, resolver.resolve_request()).await
    else {
        return;
    };

    let flight = match visit.admit(req.method(), req.uri().path()) {
        Admission::Serve(f) => f,
        Admission::Trip => {
            let answer = shield::plain(StatusCode::NOT_FOUND, false);
            if deliver(&mut stream, answer, limits.stall).await.is_err() {
                stream.stop_stream(Code::H3_REQUEST_CANCELLED);
            }

            return;
        }
        Admission::Refuse => {
            stream.stop_sending(Code::H3_REQUEST_REJECTED);
            stream.stop_stream(Code::H3_REQUEST_REJECTED);

            return;
        }
    };

    // The body goes to the router as it arrives, so the route's own limit on
    // its size applies, as it does over HTTP/1 and HTTP/2.
    let (mut send, recv) = stream.split();
    let (body, late) = Upload::new(Received(recv), limits.upload);
    let (parts, ()) = req.into_parts();
    let mut request = Request::from_parts(parts, Body::new(body));
    // The router's handlers read the client address from here; with the
    // HTTP/1 listener axum inserts it, and nothing does so for HTTP/3.
    // DNS-over-HTTPS reads the name the client connected with, too.
    request.extensions_mut().insert(ConnectInfo(peer));
    request.extensions_mut().insert(name);

    let response = match tokio::time::timeout(limits.handler, router.oneshot(request)).await {
        Ok(Ok(r)) => r,
        Ok(Err(never)) => match never {},
        Err(_) => shield::plain(StatusCode::SERVICE_UNAVAILABLE, false),
    };
    let response = if late.is_set() {
        shield::plain(StatusCode::REQUEST_TIMEOUT, false)
    } else {
        response
    };

    flight.answered(&response);
    if deliver(&mut send, response, limits.stall).await.is_err() {
        send.stop_stream(Code::H3_REQUEST_CANCELLED);
    }

    // In flight until the answer is sent: unlike hyper, this side is the one
    // sending it.
    drop(flight);
}

/// Sends an answer, giving the client `stall` to make room for each piece.
async fn deliver<S>(
    stream: &mut RequestStream<S, Bytes>,
    response: Response<Body>,
    stall: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: h3::quic::SendStream<Bytes>,
{
    let (parts, body) = response.into_parts();
    tokio::time::timeout(stall, stream.send_response(Response::from_parts(parts, ()))).await??;

    // Every answer the router gives is already in memory.
    let mut data = tokio::time::timeout(stall, body.collect())
        .await??
        .to_bytes();
    while !data.is_empty() {
        let piece = data.split_to(data.len().min(PIECE));
        tokio::time::timeout(stall, stream.send_data(piece)).await??;
    }

    tokio::time::timeout(stall, stream.finish()).await??;

    Ok(())
}

/// A request's body, read from its stream as the router asks for it.
struct Received(RequestStream<Watched<h3_quinn::RecvStream>, Bytes>);

impl hyper::body::Body for Received {
    type Data = Bytes;
    type Error = h3::error::StreamError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        match ready!(self.0.poll_recv_data(cx)) {
            Ok(Some(mut data)) => {
                Poll::Ready(Some(Ok(Frame::data(data.copy_to_bytes(data.remaining())))))
            }
            Ok(None) => Poll::Ready(None),
            Err(e) => Poll::Ready(Some(Err(e))),
        }
    }
}

/// The QUIC connection h3 is given: quinn's, with every stream the peer
/// opens watched by [`Frames`].
struct Metered(h3_quinn::Connection);

impl h3::quic::Connection<Bytes> for Metered {
    type RecvStream = Watched<h3_quinn::RecvStream>;
    type OpenStreams = Opener;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        h3::quic::Connection::<Bytes>::poll_accept_recv(&mut self.0, cx)
            .map_ok(|s| Watched::new(s, Frames::unidirectional()))
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        h3::quic::Connection::<Bytes>::poll_accept_bidi(&mut self.0, cx)
            .map_ok(|s| Watched::new(s, Frames::request()))
    }

    fn opener(&self) -> Self::OpenStreams {
        Opener(h3::quic::Connection::<Bytes>::opener(&self.0))
    }
}

impl h3::quic::OpenStreams<Bytes> for Metered {
    type BidiStream = Watched<h3_quinn::BidiStream<Bytes>>;
    type SendStream = h3_quinn::SendStream<Bytes>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        h3::quic::OpenStreams::<Bytes>::poll_open_bidi(&mut self.0, cx)
            .map_ok(|s| Watched::new(s, Frames::request()))
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        h3::quic::OpenStreams::<Bytes>::poll_open_send(&mut self.0, cx)
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        h3::quic::OpenStreams::<Bytes>::close(&mut self.0, code, reason);
    }
}

/// What h3 opens streams with, handing back watched ones.
struct Opener(h3_quinn::OpenStreams);

impl h3::quic::OpenStreams<Bytes> for Opener {
    type BidiStream = Watched<h3_quinn::BidiStream<Bytes>>;
    type SendStream = h3_quinn::SendStream<Bytes>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        h3::quic::OpenStreams::<Bytes>::poll_open_bidi(&mut self.0, cx)
            .map_ok(|s| Watched::new(s, Frames::request()))
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        h3::quic::OpenStreams::<Bytes>::poll_open_send(&mut self.0, cx)
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        h3::quic::OpenStreams::<Bytes>::close(&mut self.0, code, reason);
    }
}

/// A stream whose incoming bytes are checked against [`Frames`] before h3
/// sees them.
struct Watched<S> {
    inner: S,
    frames: Frames,
}

impl<S> Watched<S> {
    fn new(inner: S, frames: Frames) -> Self {
        Self { inner, frames }
    }
}

/// What a watched stream fails with once a frame is refused.
#[derive(Debug, thiserror::Error)]
#[error("a frame larger than {MAX_FRAME} bytes that is not DATA")]
struct Oversized;

impl<S> h3::quic::RecvStream for Watched<S>
where
    S: h3::quic::RecvStream<Buf = Bytes>,
{
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        if self.frames.refused() {
            return Poll::Ready(Err(StreamErrorIncoming::Unknown(Box::new(Oversized))));
        }

        let r = ready!(self.inner.poll_data(cx));
        if let Ok(Some(chunk)) = &r
            && let Err(taken) = self.frames.feed(chunk)
        {
            // Tell the peer to stop, rather than go on reading what it sends
            // only to throw it away.
            self.inner.stop_sending(Code::H3_EXCESSIVE_LOAD.value());

            // h3 is still handed what came before the refusal, so that it
            // knows what the stream is: a control stream's type and its
            // SETTINGS can arrive in the same packet as the frame refused.
            // It hears of the refusal on its next read, and turns it into a
            // reset of a request stream, or into closing the connection when
            // it is the control stream.
            return Poll::Ready(if taken == 0 {
                Err(StreamErrorIncoming::Unknown(Box::new(Oversized)))
            } else {
                Ok(Some(chunk.slice(..taken)))
            });
        }

        Poll::Ready(r)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.inner.stop_sending(error_code);
    }

    fn recv_id(&self) -> StreamId {
        self.inner.recv_id()
    }
}

impl h3::quic::SendStream<Bytes> for Watched<h3_quinn::BidiStream<Bytes>> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.inner.poll_ready(cx)
    }

    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        self.inner.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.inner.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.inner.reset(reset_code);
    }

    fn send_id(&self) -> StreamId {
        self.inner.send_id()
    }
}

impl h3::quic::BidiStream<Bytes> for Watched<h3_quinn::BidiStream<Bytes>> {
    type SendStream = h3_quinn::SendStream<Bytes>;
    type RecvStream = Watched<h3_quinn::RecvStream>;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        let (send, recv) = self.inner.split();

        (send, Watched::new(recv, self.frames))
    }
}

/// HTTP/3's frame type for DATA.
const DATA: u64 = 0x0;

/// The unidirectional stream type that carries frames: the control stream.
const CONTROL: u64 = 0x0;

/// Where a stream is in the HTTP/3 framing, followed a byte at a time.
///
/// Only the frame headers are read -- a type and a length, each a QUIC
/// variable-length integer -- and a payload is skipped over by its length, so
/// following a stream costs next to nothing, however it is split into
/// packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Frames {
    /// A unidirectional stream whose type has not arrived yet.
    StreamType(Varint),
    /// A frame's type is arriving.
    Type(Varint),
    /// A frame's length is arriving.
    Length { data: bool, len: Varint },
    /// Inside a payload, with this many bytes of it still to come.
    Payload(u64),
    /// Not frames: a QPACK stream, or one h3 stops unread.
    Opaque,
    /// A frame was refused.
    Refused,
}

impl Frames {
    /// Following a request stream, which is frames from its first byte.
    fn request() -> Self {
        Self::Type(Varint::default())
    }

    /// Following a unidirectional stream, which starts with its type.
    fn unidirectional() -> Self {
        Self::StreamType(Varint::default())
    }

    fn refused(&self) -> bool {
        *self == Self::Refused
    }

    /// Follows `bytes`, and fails once a frame other than DATA is declared
    /// longer than `MAX_FRAME`, with how many of them were taken: everything
    /// up to the end of the header that declared it.
    fn feed(&mut self, bytes: &[u8]) -> Result<(), usize> {
        let mut at = 0;
        while let Some(&b) = bytes.get(at) {
            match self {
                Self::Opaque => return Ok(()),
                Self::Refused => return Err(at),
                Self::Payload(left) => {
                    let rest = bytes.len() - at;
                    let n = usize::try_from(*left).map_or(rest, |l| l.min(rest));
                    at += n;
                    *left -= n as u64;
                    if *left == 0 {
                        *self = Self::request();
                    }

                    continue;
                }
                Self::StreamType(v) => {
                    if let Some(t) = v.push(b) {
                        *self = if t == CONTROL {
                            Self::request()
                        } else {
                            Self::Opaque
                        };
                    }
                }
                Self::Type(v) => {
                    if let Some(t) = v.push(b) {
                        *self = Self::Length {
                            data: t == DATA,
                            len: Varint::default(),
                        };
                    }
                }
                Self::Length { data, len } => {
                    if let Some(n) = len.push(b) {
                        if !*data && n > MAX_FRAME {
                            *self = Self::Refused;

                            return Err(at + 1);
                        }

                        *self = if n == 0 {
                            Self::request()
                        } else {
                            Self::Payload(n)
                        };
                    }
                }
            }

            at += 1;
        }

        Ok(())
    }
}

/// A QUIC variable-length integer, arriving a byte at a time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Varint {
    value: u64,
    have: u8,
    need: u8,
}

impl Varint {
    /// Takes the next byte, returning the value once it is complete.
    ///
    /// The first byte's top two bits give the length: one, two, four or
    /// eight bytes.
    fn push(&mut self, b: u8) -> Option<u64> {
        if self.have == 0 {
            self.need = 1 << (b >> 6);
            self.value = u64::from(b & 0x3f);
        } else {
            self.value = self.value << 8 | u64::from(b);
        }
        self.have += 1;

        (self.have == self.need).then_some(self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed certificate, for binding tests.
    fn test_tls() -> sift_dns::tls::Loaded {
        let c = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generating a certificate");

        sift_dns::tls::load(&sift_dns::tls::Source {
            certificate_chain: c.cert.pem(),
            private_key: c.signing_key.serialize_pem(),
            certificate_path: String::new(),
            private_key_path: String::new(),
        })
        .expect("the pair should load")
    }

    #[tokio::test]
    async fn an_endpoint_binds_and_offers_http3() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let tls = test_tls();
        assert_eq!(tls.h3.alpn_protocols, vec![b"h3".to_vec()]);

        let ep = endpoint("127.0.0.1:0".parse().unwrap(), tls.h3)
            .expect("binding an ephemeral port should work");
        assert_ne!(ep.local_addr().unwrap().port(), 0);
    }

    /// A running listener, and what a client needs to reach it.
    struct Server {
        addr: SocketAddr,
        pem: String,
        _stop: tokio::sync::oneshot::Sender<()>,
    }

    fn router() -> Router {
        use axum::routing::{get, post};

        Router::new()
            .route(
                "/echo",
                post(|body: Bytes| async move { format!("got {}", body.len()) }),
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
    }

    fn start(g: Arc<Guard>, limits: Limits) -> Server {
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

        let ep = endpoint("127.0.0.1:0".parse().unwrap(), tls.h3).unwrap();
        let addr = ep.local_addr().unwrap();
        let (stop, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(run(
            ep,
            router(),
            g,
            async {
                let _ = rx.await;
            },
            limits,
        ));

        Server {
            addr,
            pem,
            _stop: stop,
        }
    }

    /// A guard that judges loopback, as the internet is judged.
    fn guard() -> Arc<Guard> {
        Arc::new(Guard::new(sift_dns::probe::Config {
            exempt_local: false,
            ..Default::default()
        }))
    }

    /// A QUIC client that trusts the server's certificate, offers HTTP/3,
    /// and gives up on a silent server after a second.
    fn client(pem: &str) -> quinn::Endpoint {
        let mut roots = rustls::RootCertStore::empty();
        for der in rustls_pemfile::certs(&mut pem.as_bytes()) {
            roots.add(der.unwrap()).unwrap();
        }

        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"h3".to_vec()];

        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(cfg)).unwrap();
        let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(1).try_into().unwrap()));
        cfg.transport_config(Arc::new(transport));

        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(cfg);

        client
    }

    type Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

    /// An HTTP/3 session, and the task that ends when the server closes it.
    async fn session(s: &Server) -> (Sender, tokio::task::JoinHandle<()>) {
        let conn = client(&s.pem)
            .connect(s.addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (mut driver, sender) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let drive = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        (sender, drive)
    }

    /// Sends one request and reads the whole answer.
    async fn fetch(
        sender: &mut Sender,
        req: http::Request<()>,
        body: &[u8],
    ) -> Result<(StatusCode, Vec<u8>), h3::error::StreamError> {
        let mut stream = sender.send_request(req).await?;
        if !body.is_empty() {
            stream.send_data(Bytes::from(body.to_vec())).await?;
        }
        stream.finish().await?;

        let resp = stream.recv_response().await?;
        let mut out = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await? {
            out.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
        }

        Ok((resp.status(), out))
    }

    fn get(path: &str) -> http::Request<()> {
        http::Request::get(format!("https://localhost{path}"))
            .body(())
            .unwrap()
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

    #[tokio::test]
    async fn a_request_round_trips_over_http3() {
        let s = start(Arc::new(Guard::default()), Limits::default());
        let (mut sender, drive) = session(&s).await;

        let req = http::Request::post("https://localhost/echo")
            .body(())
            .unwrap();
        let (status, body) = fetch(&mut sender, req, b"0123456789").await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"got 10");

        drive.abort();
    }

    #[tokio::test]
    async fn every_http3_request_carries_the_server_name_the_client_connected_with() {
        // What DNS-over-HTTPS reads a ClientID from when the path has none,
        // taken from quinn's record of the handshake.
        let s = start(Arc::new(Guard::default()), Limits::default());
        let (mut sender, drive) = session(&s).await;

        let (status, body) = fetch(&mut sender, get("/sni"), b"").await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"localhost");

        drive.abort();
    }

    #[tokio::test]
    async fn the_http3_stream_limits_are_applied() {
        let s = start(Arc::new(Guard::default()), Limits::default());
        let conn = client(&s.pem)
            .connect(s.addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        // Opening a stream only waits when the server's limit says so.
        let mut bidi = Vec::new();
        for i in 0..MAX_BIDI {
            let s = tokio::time::timeout(Duration::from_millis(500), conn.open_bi())
                .await
                .unwrap_or_else(|_| panic!("request stream {i} is within the limit"))
                .unwrap();
            bidi.push(s);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(200), conn.open_bi())
                .await
                .is_err(),
            "one request stream more than the limit must wait"
        );

        let mut uni = Vec::new();
        for i in 0..MAX_UNI {
            let s = tokio::time::timeout(Duration::from_millis(500), conn.open_uni())
                .await
                .unwrap_or_else(|_| panic!("stream {i} is within the limit"))
                .unwrap();
            uni.push(s);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(200), conn.open_uni())
                .await
                .is_err(),
            "one unidirectional stream more than the limit must wait"
        );
    }

    #[tokio::test]
    async fn a_header_section_over_the_limit_is_not_accepted() {
        let s = start(Arc::new(Guard::default()), Limits::default());
        let (mut sender, drive) = session(&s).await;

        // One request first, so the client has the server's settings.
        let (status, _) = fetch(&mut sender, get("/login.html"), b"").await.unwrap();
        assert_eq!(status, StatusCode::OK);

        let mut req = get("/login.html");
        req.headers_mut()
            .insert("x-big", "a".repeat(20 * 1024).parse().unwrap());
        match fetch(&mut sender, req, b"").await {
            Err(h3::error::StreamError::HeaderTooBig { max_size, .. }) => {
                assert_eq!(max_size, MAX_FIELD_SECTION, "the limit advertised");
            }
            Ok((status, _)) => assert_eq!(status, StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE),
            Err(e) => panic!("got {e:?}"),
        }

        drive.abort();
    }

    /// Writes a frame header whose length says `len`, with a four-byte
    /// length whatever its value.
    fn frame_header(ty: u8, len: u32) -> Vec<u8> {
        let mut h = vec![ty];
        h.extend_from_slice(&(len | 0x8000_0000).to_be_bytes());

        h
    }

    #[tokio::test]
    async fn a_header_frame_larger_than_allowed_is_refused_before_it_is_buffered() {
        let s = start(Arc::new(Guard::default()), Limits::default());
        let conn = client(&s.pem)
            .connect(s.addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        // HEADERS, declaring a megabyte, then as much of it as flow control
        // lets through.
        let (mut send, _recv) = conn.open_bi().await.unwrap();
        send.write_all(&frame_header(0x1, 1 << 20)).await.unwrap();
        let junk = vec![0u8; 512 * 1024];
        let r = tokio::time::timeout(Duration::from_secs(5), send.write_all(&junk)).await;

        match r {
            Ok(Err(quinn::WriteError::Stopped(code))) => {
                assert_eq!(code, VarInt::from_u32(0x107), "H3_EXCESSIVE_LOAD");
            }
            other => panic!("the server should have stopped the stream, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_oversized_frame_on_the_control_stream_closes_the_connection() {
        let s = start(Arc::new(Guard::default()), Limits::default());
        let conn = client(&s.pem)
            .connect(s.addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        // The control stream, its SETTINGS, and then a reserved frame type
        // declaring a megabyte: h3 would have read it all to skip it.
        let mut control = conn.open_uni().await.unwrap();
        control.write_all(&[0x00, 0x04, 0x00]).await.unwrap();
        control
            .write_all(&frame_header(0x21, 1 << 20))
            .await
            .unwrap();
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            control.write_all(&vec![0u8; 64 * 1024]),
        )
        .await;

        let closed = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
        match closed {
            Ok(quinn::ConnectionError::ApplicationClosed(c)) => {
                assert_eq!(
                    c.error_code,
                    VarInt::from_u32(0x104),
                    "H3_CLOSED_CRITICAL_STREAM"
                );
            }
            other => panic!("the connection should have been closed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_http3_tripwire_condemns_the_source_and_its_next_connection_hears_nothing() {
        let g = guard();
        let limits = Limits {
            cut: Duration::from_millis(300),
            ..Limits::default()
        };
        let s = start(g.clone(), limits);
        let (mut sender, drive) = session(&s).await;

        let (status, _) = fetch(&mut sender, get("/login.html"), b"").await.unwrap();
        assert_eq!(status, StatusCode::OK);
        let (status, _) = fetch(&mut sender, get("/.git/config"), b"").await.unwrap();
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(g.stats().condemned, 1);

        let _ = tokio::time::timeout(Duration::from_secs(10), drive).await;
        assert!(settle(|| g.stats().open == 0).await);
        assert_eq!(
            g.stats().banned,
            1,
            "the page fetched first did not lift it"
        );

        let again = client(&s.pem).connect(s.addr, "localhost").unwrap().await;
        assert!(
            matches!(again, Err(quinn::ConnectionError::TimedOut)),
            "a source serving a penalty is sent nothing: got {again:?}"
        );
    }

    #[tokio::test]
    async fn an_http3_answer_marked_unanswered_does_not_count() {
        let g = guard();
        let s = start(g.clone(), Limits::default());
        let (mut sender, drive) = session(&s).await;

        let req = http::Request::post("https://localhost/dns-query")
            .body(())
            .unwrap();
        let (status, _) = fetch(&mut sender, req, b"q").await.unwrap();
        assert_eq!(status, StatusCode::OK);

        drop(sender);
        drive.abort();
        assert!(
            settle(|| g.tracked() == 1).await,
            "a 200 the DNS side did not count is not asking"
        );
    }

    #[tokio::test]
    async fn a_doh_client_asking_through_an_overload_over_http3_is_neither_closed_nor_struck() {
        // Two strikes to a penalty with one already spent: a strike for this
        // connection would show as a ban, and forgiving it as a clean record.
        let g = Arc::new(Guard::new(sift_dns::probe::Config {
            exempt_local: false,
            strikes: 2,
            ..Default::default()
        }));
        let here: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        g.wasted(here);

        let s = start(g.clone(), Limits::default());
        let (mut sender, drive) = session(&s).await;
        for i in 0..2 * 32 {
            let (status, _) = fetch(&mut sender, get("/busy"), b"")
                .await
                .unwrap_or_else(|e| panic!("answer {i}: {e:?}"));
            assert_eq!(status, StatusCode::OK, "answer {i}");
        }

        drop(sender);
        drive.abort();
        assert!(settle(|| g.stats().open == 0).await, "the connection ended");
        assert_eq!(g.stats().banned, 0, "not struck");
        assert_eq!(g.tracked(), 1, "nor forgiven the strike it had before");
    }

    #[tokio::test]
    async fn a_silent_http3_connection_is_closed_and_counted() {
        let g = guard();
        // Well inside the client's own idle timeout, so it is the server
        // that closes.
        let limits = Limits {
            first_request: Duration::from_millis(300),
            ..Limits::default()
        };
        let s = start(g.clone(), limits);

        let conn = client(&s.pem)
            .connect(s.addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let closed = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
        assert!(
            matches!(closed, Ok(quinn::ConnectionError::ApplicationClosed(_))),
            "got {closed:?}"
        );
        assert!(settle(|| g.tracked() == 1).await, "it asked nothing");
    }

    #[test]
    fn frames_are_followed_however_the_bytes_are_split() {
        // HEADERS of 3 bytes, DATA of 70,000 (more than MAX_FRAME, which DATA
        // may be), then an unknown frame of 2 bytes -- fed a byte at a time
        // and all at once.
        let mut wire = vec![0x01, 0x03, 1, 2, 3];
        wire.extend_from_slice(&[0x00, 0x80, 0x01, 0x11, 0x70]);
        wire.extend(std::iter::repeat_n(0u8, 70_000));
        wire.extend_from_slice(&[0x21, 0x02, 9, 9]);

        let mut whole = Frames::request();
        assert!(whole.feed(&wire).is_ok());
        assert_eq!(whole, Frames::request());

        let mut bytewise = Frames::request();
        for b in &wire {
            assert!(bytewise.feed(std::slice::from_ref(b)).is_ok());
        }
        assert_eq!(bytewise, Frames::request());

        // A HEADERS frame one byte over the limit is refused on its header,
        // before any of it has arrived.
        let mut big = Frames::request();
        assert_eq!(big.feed(&frame_header(0x1, MAX_FRAME as u32 + 1)), Err(5));
        assert!(big.refused());
        assert_eq!(big.feed(b"more"), Err(0), "and stays refused");

        let mut edge = Frames::request();
        assert!(edge.feed(&frame_header(0x1, MAX_FRAME as u32)).is_ok());
    }

    #[test]
    fn only_the_control_stream_is_followed_among_unidirectional_ones() {
        // A control stream whose type, SETTINGS and an oversized frame come
        // in one chunk: everything before the payload is taken, so h3 still
        // learns it is the control stream.
        let mut control = Frames::unidirectional();
        let mut wire = vec![0x00, 0x04, 0x00];
        wire.extend(frame_header(0x21, 1 << 20));
        wire.extend([0u8; 100]);
        assert_eq!(control.feed(&wire), Err(8));

        // A QPACK encoder stream carries instructions, not frames.
        let mut qpack = Frames::unidirectional();
        assert!(qpack.feed(&[0x02]).is_ok());
        assert!(qpack.feed(&frame_header(0x21, 1 << 20)).is_ok());
        assert_eq!(qpack, Frames::Opaque);

        // A two-byte stream type, split across chunks.
        let mut grease = Frames::unidirectional();
        assert!(grease.feed(&[0x40]).is_ok());
        assert!(grease.feed(&[0x21]).is_ok());
        assert_eq!(grease, Frames::Opaque);
    }

    #[tokio::test]
    async fn binding_a_privileged_port_is_reported_not_panicked() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let r = endpoint("127.0.0.1:443".parse().unwrap(), test_tls().h3);
        // Running as root would succeed; either way it must not panic.
        if let Err(e) = r {
            assert!(matches!(e, Error::Bind { .. }));
        }
    }
}
