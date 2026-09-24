//! The DNS-over-QUIC listener, as specified by RFC 9250.
//!
//! Each query arrives on its own bidirectional stream, carrying the same
//! two-byte-length framing that TCP and DNS-over-TLS use, so the message
//! handling is shared with them. What differs is the transport: a client may
//! have many queries in flight on one connection without head-of-line
//! blocking, and it closes its send side once the query is written.
//!
//! Connections are admitted by `crate::quic`, which is where the connection
//! guard's rules for an address a QUIC packet merely claims are written
//! down, and the limits on what one connection may make this process hold
//! are set here: how many streams at once, how much of a stream may arrive
//! before it is read, and how long a stream may take to arrive and to be
//! answered.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::Endpoint;

use crate::quic;
use crate::resolver::Proto;
use crate::server::{Answer, Conduct, Server, ServerNameError, Tally};

/// The largest query this will read from a stream.
const MAX_MSG: usize = 64 * 1024;

/// The most streams a single connection may have open at once.
///
/// Each open stream is a query being read or answered, so this is what one
/// connection may have in hand.  quic-go, which upstream uses, allows 100; a
/// stub resolver has a handful outstanding.  At 64, with the stream window
/// below, one connection is bounded well under the connection's own receive
/// window, and the per-source bound on queries in flight still applies on
/// top of it.
const MAX_CONCURRENT_STREAMS: u32 = 64;

/// What a peer may send on one stream before it has to wait for it to be
/// read: one whole query, length prefix included, and no more.
///
/// A stream carries exactly one message of at most 65,535 bytes plus its
/// two-byte length, so a real client never waits on this, while a stream
/// that sends something bigger is refused by `read_to_end` anyway.
const STREAM_RECEIVE_WINDOW: u32 = 66_000;

/// How long a stream may take to deliver its query once opened.
///
/// A query is sent in one flight; dnsproxy gives a stream ten seconds for
/// the read and ten for the write.  Without it, 64 streams that each send a
/// byte and stop hold their buffers for as long as the connection is kept
/// alive.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// How long an answer may take to be written to a stream.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Why the listener could not start.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The rustls configuration cannot be used for QUIC.
    ///
    /// QUIC requires TLS 1.3; a certificate usable over TCP may still be
    /// refused here.
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

/// Builds the QUIC server configuration for DNS-over-QUIC.
///
/// `quic::server_config` carries what both QUIC listeners share -- the idle
/// timeout, the connection's windows, no datagrams, the backlog of attempts
/// -- and the stream limits, which are DoQ's own, are set here.
fn server_config(tls: Arc<rustls::ServerConfig>) -> Result<quinn::ServerConfig, Error> {
    let mut cfg = quic::server_config(tls).map_err(|e| Error::Tls(e.to_string()))?;

    let transport =
        Arc::get_mut(&mut cfg.transport).expect("the transport config is not yet shared");
    transport
        .max_concurrent_bidi_streams(MAX_CONCURRENT_STREAMS.into())
        // Unidirectional streams carry nothing in DoQ.
        .max_concurrent_uni_streams(0u32.into())
        .stream_receive_window(STREAM_RECEIVE_WINDOW.into());

    Ok(cfg)
}

/// Builds a QUIC endpoint from a rustls configuration.
pub fn endpoint(addr: SocketAddr, tls: Arc<rustls::ServerConfig>) -> Result<Endpoint, Error> {
    Endpoint::server(server_config(tls)?, addr).map_err(|source| Error::Bind { addr, source })
}

/// Serves DNS-over-QUIC until `shutdown` resolves.
///
/// Each connection is admitted by [`quic::admit`]: a source serving a penalty
/// is sent nothing at all, an address nobody has proved is asked to retry
/// once the server is under pressure, and a proved one is held to the same
/// limits as a TCP connection.  A client that connects with
/// `<id>.<tls.server_name>` is asking to be treated as the client named
/// `<id>`, the same as over DoT.
pub async fn serve(
    endpoint: Endpoint,
    server: Arc<Server>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) {
    tokio::pin!(shutdown);

    loop {
        let incoming = tokio::select! {
            i = endpoint.accept() => match i {
                Some(i) => i,
                None => {
                    tracing::warn!(addr = ?endpoint.local_addr().ok(), "dns over quic stopped: the endpoint closed");

                    return;
                }
            },
            () = &mut shutdown => {
                endpoint.close(0u32.into(), b"shutting down");
                tracing::debug!(addr = ?endpoint.local_addr().ok(), "dns over quic stopped: shutting down");

                return;
            }
        };

        let Some(pending) = quic::admit(&server.probes, incoming) else {
            continue;
        };

        let server = server.clone();
        tokio::spawn(async move {
            let Some((conn, ticket)) = pending.establish(quic::DOQ_EXCESSIVE_LOAD).await else {
                return;
            };
            let peer = conn.remote_address();

            let sni = conn
                .handshake_data()
                .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .and_then(|d| d.server_name.clone());
            let named = Arc::new(server.client_id_for(sni.as_deref()));
            if let Err(e) = named.as_ref() {
                tracing::debug!(client = %peer.ip(), error = %e, "resolving client id");
            }

            // Once the connection is over -- and the handshake has proved
            // the address -- what it did or did not ask counts, unless all it
            // was told is that the server was busy.  A connection that opened
            // no stream at all paid for a handshake and asked nothing.
            serve_connection(&conn, &server, peer, named)
                .await
                .report(&server.probes, peer.ip());
            drop(ticket);
        });
    }
}

/// Serves every query stream of one connection until it closes, and says
/// how the connection behaved.
///
/// Each stream is one query, served concurrently with the rest, which is
/// the point of using QUIC.  They are served as tasks of this one, and the
/// verdict waits for those still being answered when the connection ends:
/// they are the connection's questions too, and a query still waiting for a
/// worker when an impatient client hung up is one the server was too busy
/// for, not one that was never asked.
async fn serve_connection(
    conn: &quinn::Connection,
    server: &Arc<Server>,
    peer: SocketAddr,
    named: Arc<Result<Option<String>, ServerNameError>>,
) -> Conduct {
    let mut streams = tokio::task::JoinSet::new();
    let mut tally = Tally::default();

    loop {
        tokio::select! {
            accepted = conn.accept_bi() => {
                let Ok((send, recv)) = accepted else {
                    break;
                };
                let server = server.clone();
                let named = named.clone();
                streams.spawn(async move { serve_stream(send, recv, &server, peer, &named).await });
            }
            // Collected as they finish, so a connection kept open for hours
            // holds only the streams in progress.
            Some(done) = streams.join_next() => {
                if let Ok(c) = done {
                    tally.add(c);
                }
            }
        }
    }

    while let Some(done) = streams.join_next().await {
        if let Ok(c) = done {
            tally.add(c);
        }
    }

    tally.conduct()
}

/// Handles one query stream, reporting what it came to: served, when an
/// answer went back to something a client of this server asks; busy, when
/// it was turned away because the server was; and otherwise wasted.
async fn serve_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    server: &Server,
    peer: SocketAddr,
    named: &Result<Option<String>, ServerNameError>,
) -> Conduct {
    // The client closes its send side after the query, so reading to the end
    // yields exactly one framed message.  A stream that does not finish in
    // time is dropped, which stops it.
    let Ok(Ok(buf)) = tokio::time::timeout(READ_TIMEOUT, recv.read_to_end(MAX_MSG + 2)).await
    else {
        return Conduct::Wasted;
    };

    if buf.len() < 2 {
        return Conduct::Wasted;
    }

    let len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
    if len == 0 || buf.len() < 2 + len {
        return Conduct::Wasted;
    }
    let wire = &buf[2..2 + len];

    let answer = match named {
        Ok(id) => server.answer(wire, peer, Proto::Quic, id.clone()).await,
        Err(_) => Answer::servfail(wire),
    };

    // What it came to if it is not served, whether or not the answer then
    // reaches the client.
    let unserved = if answer.busy {
        Conduct::Busy
    } else {
        Conduct::Wasted
    };

    let Some(resp) = answer.bytes else {
        // Refused or dropped; closing without an answer is the DoQ equivalent
        // of not replying.
        let _ = send.finish();

        return unserved;
    };

    let Ok(len) = u16::try_from(resp.len()) else {
        let _ = send.finish();

        return unserved;
    };

    let mut framed = Vec::with_capacity(resp.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&resp);

    if !matches!(
        tokio::time::timeout(WRITE_TIMEOUT, send.write_all(&framed)).await,
        Ok(Ok(()))
    ) {
        return unserved;
    }
    let _ = send.finish();

    if answer.counts {
        Conduct::Served(1)
    } else {
        unserved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed certificate for `dns.example.com`.
    fn test_tls() -> crate::tls::Loaded {
        let c = rcgen::generate_simple_self_signed(vec!["dns.example.com".to_string()])
            .expect("generating a certificate");

        crate::tls::load(&crate::tls::Source {
            certificate_chain: c.cert.pem(),
            private_key: c.signing_key.serialize_pem(),
            ..Default::default()
        })
        .expect("the test pair must load")
    }

    #[tokio::test]
    async fn an_endpoint_binds_and_reports_its_address() {
        let tls = test_tls();
        let ep = endpoint("127.0.0.1:0".parse().unwrap(), tls.doq)
            .expect("a TLS 1.3 capable certificate must build an endpoint");

        let addr = ep.local_addr().expect("the endpoint has an address");
        assert_ne!(
            addr.port(),
            0,
            "an ephemeral port should have been assigned"
        );
        ep.close(0u32.into(), b"done");
    }

    #[tokio::test]
    async fn binding_a_privileged_port_is_reported_not_panicked() {
        let tls = test_tls();
        // Port 1 needs privileges this test does not have.
        let r = endpoint("127.0.0.1:1".parse().unwrap(), tls.doq);
        assert!(matches!(r, Err(Error::Bind { .. })), "got {r:?}");
    }

    /// Builds a QUIC client that trusts only the given certificate.
    fn client_endpoint(cert_pem: &str) -> quinn::Endpoint {
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut cert_pem.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }

        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"doq".to_vec()];

        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(cfg)
            .expect("the client config must suit QUIC");
        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())
            .expect("binding the client endpoint");
        ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));

        ep
    }

    /// Frames a query the way DoQ carries it.
    fn framed(name: &str) -> Vec<u8> {
        use hickory_proto::op::{Message, Query};
        use hickory_proto::rr::{Name, RecordType};
        use hickory_proto::serialize::binary::BinEncodable as _;

        let mut m = Message::query();
        // RFC 9250 asks for a zero ID, since QUIC streams already correlate.
        m.metadata.id = 0;
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_utf8(name).unwrap(), RecordType::A));

        let wire = m.to_bytes().unwrap();
        let mut out = Vec::with_capacity(wire.len() + 2);
        out.extend_from_slice(&(wire.len() as u16).to_be_bytes());
        out.extend_from_slice(&wire);

        out
    }

    /// Starts a listener blocking `ads.example.com`, returning its address.
    async fn start(tls: &crate::tls::Loaded) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
        let (addr, stop, _) = start_with(tls, test_server()).await;

        (addr, stop)
    }

    /// A server blocking `ads.example.com`, whose guard leaves loopback
    /// alone as it does the rest of the local network.
    fn test_server() -> Arc<Server> {
        use crate::cache::{Cache, Config as CacheConfig};
        use crate::pool::{Mode, Pool, SharedPool};
        use crate::ratelimit::{Config as RlConfig, Limiter};
        use crate::resolver::{Resolver, Settings};
        use crate::rewrite::Table;
        use crate::server::NoopObserver;
        use sift_filter::engine::Engine;

        let resolver = Resolver::new(
            Engine::build(
                [(1i64, "||ads.example.com^")],
                sift_filter::engine::NO_LISTS,
            ),
            Table::default(),
            Cache::new(CacheConfig::default()),
            SharedPool::new(Pool::new(
                vec![],
                vec![],
                vec![],
                Mode::LoadBalance,
                Duration::from_millis(50),
                Duration::from_millis(50),
            )),
            Settings::default(),
        );

        Arc::new(Server::new(
            Arc::new(resolver),
            Arc::new(Limiter::new(RlConfig {
                per_second: 0,
                ..Default::default()
            })),
            Arc::new(NoopObserver),
        ))
    }

    /// Serves `server` over DoQ on loopback.
    async fn start_with(
        tls: &crate::tls::Loaded,
        server: Arc<Server>,
    ) -> (SocketAddr, tokio::sync::oneshot::Sender<()>, Arc<Server>) {
        let ep = endpoint("127.0.0.1:0".parse().unwrap(), tls.doq.clone()).unwrap();
        let addr = ep.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let serving = server.clone();
        tokio::spawn(async move {
            serve(ep, serving, async {
                let _ = rx.await;
            })
            .await;
        });

        (addr, tx, server)
    }

    /// Sends one query on its own stream and returns the framed reply.
    async fn ask(conn: &quinn::Connection, name: &str) -> Vec<u8> {
        let (mut send, mut recv) = conn.open_bi().await.expect("opening a stream");
        send.write_all(&framed(name))
            .await
            .expect("writing the query");
        // Closing the send side is what tells the server the query is whole.
        send.finish().expect("finishing the stream");

        recv.read_to_end(MAX_MSG).await.expect("reading the reply")
    }

    #[tokio::test]
    async fn a_query_round_trips_over_quic() {
        use hickory_proto::op::Message;
        use hickory_proto::serialize::binary::BinDecodable as _;

        let c = rcgen::generate_simple_self_signed(vec!["dns.example.com".to_string()]).unwrap();
        let cert_pem = c.cert.pem();
        let tls = crate::tls::load(&crate::tls::Source {
            certificate_chain: cert_pem.clone(),
            private_key: c.signing_key.serialize_pem(),
            ..Default::default()
        })
        .unwrap();

        let (addr, stop) = start(&tls).await;
        let client = client_endpoint(&cert_pem);
        let conn = client
            .connect(addr, "dns.example.com")
            .expect("connecting")
            .await
            .expect("handshake");

        let reply = ask(&conn, "ads.example.com.").await;
        assert!(reply.len() > 2, "the reply should be framed");
        let len = usize::from(u16::from_be_bytes([reply[0], reply[1]]));
        assert_eq!(
            reply.len(),
            len + 2,
            "the frame length should match the body"
        );

        let m = Message::from_bytes(&reply[2..]).expect("a DNS message");
        assert_eq!(m.answers.len(), 1, "the blocked name should be answered");

        let _ = stop.send(());
    }

    #[tokio::test]
    async fn many_queries_share_one_connection() {
        use hickory_proto::op::Message;
        use hickory_proto::serialize::binary::BinDecodable as _;

        // Carrying several queries at once without head-of-line blocking is
        // the reason to use QUIC at all.
        let c = rcgen::generate_simple_self_signed(vec!["dns.example.com".to_string()]).unwrap();
        let cert_pem = c.cert.pem();
        let tls = crate::tls::load(&crate::tls::Source {
            certificate_chain: cert_pem.clone(),
            private_key: c.signing_key.serialize_pem(),
            ..Default::default()
        })
        .unwrap();

        let (addr, stop) = start(&tls).await;
        let client = client_endpoint(&cert_pem);
        let conn = client
            .connect(addr, "dns.example.com")
            .expect("connecting")
            .await
            .expect("handshake");

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let conn = conn.clone();
            set.spawn(async move { ask(&conn, "ads.example.com.").await });
        }

        let mut answered = 0;
        while let Some(r) = set.join_next().await {
            let reply = r.expect("the task should not panic");
            let m = Message::from_bytes(&reply[2..]).expect("a DNS message");
            assert_eq!(m.answers.len(), 1);
            answered += 1;
        }
        assert_eq!(answered, 16);

        let _ = stop.send(());
    }

    #[test]
    fn the_doq_config_advertises_the_rfc_9250_protocol() {
        // A client that offers only `doq` must be able to negotiate.
        assert_eq!(test_tls().doq.alpn_protocols, vec![b"doq".to_vec()]);
    }

    #[test]
    fn a_doq_connection_is_bounded_to_what_one_query_per_stream_needs() {
        let cfg = server_config(test_tls().doq).unwrap();
        let t = format!("{:?}", cfg.transport);

        for want in [
            "max_concurrent_bidi_streams: 64,",
            "max_concurrent_uni_streams: 0,",
            "stream_receive_window: 66000,",
            // From `quic::server_config`, which both QUIC listeners share.
            "receive_window: 1048576,",
            "datagram_receive_buffer_size: None,",
        ] {
            assert!(t.contains(want), "{want} not in {t}");
        }
    }

    /// Where the tests' clients come from, judged like the internet.
    fn watch_loopback(server: &Server) {
        server.set_probe_config(crate::probe::Config {
            exempt_local: false,
            ..Default::default()
        });
    }

    /// Waits for `check` to hold, for up to three seconds.
    async fn settle(mut check: impl FnMut() -> bool) -> bool {
        for _ in 0..300 {
            if check() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        check()
    }

    #[tokio::test]
    async fn a_connection_may_hold_only_sixty_four_streams_and_a_stalled_one_is_stopped() {
        use hickory_proto::op::Message;
        use hickory_proto::serialize::binary::BinDecodable as _;

        let c = rcgen::generate_simple_self_signed(vec!["dns.example.com".to_string()]).unwrap();
        let cert_pem = c.cert.pem();
        let tls = crate::tls::load(&crate::tls::Source {
            certificate_chain: cert_pem.clone(),
            private_key: c.signing_key.serialize_pem(),
            ..Default::default()
        })
        .unwrap();
        let (addr, _stop) = start(&tls).await;
        let conn = client_endpoint(&cert_pem)
            .connect(addr, "dns.example.com")
            .unwrap()
            .await
            .unwrap();

        // Sixty-four streams that each send a byte of a query and stop.
        let mut stalled = Vec::new();
        for _ in 0..MAX_CONCURRENT_STREAMS {
            let (mut send, recv) = conn.open_bi().await.unwrap();
            send.write_all(&[0x00]).await.unwrap();
            stalled.push((send, recv));
        }

        assert!(
            tokio::time::timeout(Duration::from_millis(300), conn.open_bi())
                .await
                .is_err(),
            "the sixty-fifth waits for one of them to close"
        );

        // Each is stopped once its query has not arrived in time: the server
        // drops what it was holding for it and tells the client so.
        let started = std::time::Instant::now();
        for (send, _) in &stalled {
            let stopped =
                tokio::time::timeout(READ_TIMEOUT + Duration::from_secs(3), send.stopped())
                    .await
                    .expect("a stalled stream is stopped within the deadline");
            assert!(matches!(stopped, Ok(Some(_))), "got {stopped:?}");
        }
        assert!(started.elapsed() >= READ_TIMEOUT - Duration::from_millis(500));

        // The client resets what was stopped, the streams are handed back,
        // and the connection answers as before.
        drop(stalled);
        let (mut send, mut recv) = tokio::time::timeout(Duration::from_secs(3), conn.open_bi())
            .await
            .expect("the streams are handed back")
            .unwrap();
        send.write_all(&framed("ads.example.com.")).await.unwrap();
        send.finish().unwrap();
        let reply = recv.read_to_end(MAX_MSG).await.unwrap();
        let m = Message::from_bytes(&reply[2..]).unwrap();
        assert_eq!(m.answers.len(), 1);
    }

    #[tokio::test]
    async fn only_what_a_client_asks_clears_its_record_over_quic() {
        let c = rcgen::generate_simple_self_signed(vec!["dns.example.com".to_string()]).unwrap();
        let cert_pem = c.cert.pem();
        let tls = crate::tls::load(&crate::tls::Source {
            certificate_chain: cert_pem.clone(),
            private_key: c.signing_key.serialize_pem(),
            ..Default::default()
        })
        .unwrap();
        let server = test_server();
        watch_loopback(&server);
        let (addr, _stop, server) = start_with(&tls, server).await;
        let client = client_endpoint(&cert_pem);

        // `version.bind` is answered REFUSED, which is not being served.
        let conn = client
            .connect(addr, "dns.example.com")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let mut q = hickory_proto::op::Message::query();
        q.add_query(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_utf8("version.bind.").unwrap(),
            hickory_proto::rr::RecordType::TXT,
        ));
        let wire = hickory_proto::serialize::binary::BinEncodable::to_bytes(&q).unwrap();
        let mut framed_q = (wire.len() as u16).to_be_bytes().to_vec();
        framed_q.extend_from_slice(&wire);
        send.write_all(&framed_q).await.unwrap();
        send.finish().unwrap();
        assert!(
            recv.read_to_end(MAX_MSG).await.unwrap().len() > 2,
            "answered"
        );
        conn.close(0u32.into(), b"done");
        assert!(
            settle(|| server.probes.tracked() == 1).await,
            "a connection that asked only that asked nothing"
        );

        let conn = client
            .connect(addr, "dns.example.com")
            .unwrap()
            .await
            .unwrap();
        ask(&conn, "ads.example.com.").await;
        conn.close(0u32.into(), b"done");
        assert!(
            settle(|| server.probes.tracked() == 0).await,
            "a real question clears the record"
        );
        assert!(
            settle(|| server.probes.stats().open == 0).await,
            "and every connection's ticket went back"
        );
    }

    #[tokio::test]
    async fn a_doq_connection_answered_only_busy_leaves_no_strike() {
        use hickory_proto::op::{Message, ResponseCode};
        use hickory_proto::serialize::binary::BinDecodable as _;

        let c = rcgen::generate_simple_self_signed(vec!["dns.example.com".to_string()]).unwrap();
        let cert_pem = c.cert.pem();
        let tls = crate::tls::load(&crate::tls::Source {
            certificate_chain: cert_pem.clone(),
            private_key: c.signing_key.serialize_pem(),
            ..Default::default()
        })
        .unwrap();
        let server = test_server();
        server.set_probe_config(crate::probe::Config {
            strikes: 1,
            exempt_local: false,
            ..Default::default()
        });
        // Every query this source may have in flight is taken, as a flood
        // of slow lookups takes them.
        let held = server.fill_share("127.0.0.1".parse().unwrap()).await;
        let (addr, _stop, server) = start_with(&tls, server).await;

        let conn = client_endpoint(&cert_pem)
            .connect(addr, "dns.example.com")
            .unwrap()
            .await
            .unwrap();
        let reply = ask(&conn, "ads.example.com.").await;
        assert_eq!(
            Message::from_bytes(&reply[2..])
                .unwrap()
                .metadata
                .response_code,
            ResponseCode::ServFail
        );
        conn.close(0u32.into(), b"done");

        assert!(settle(|| server.probes.stats().open == 0).await);
        assert_eq!(server.probes.tracked(), 0, "no strike");
        assert!(server.probes.admits("127.0.0.1".parse().unwrap()));
        drop(held);
    }

    #[tokio::test]
    async fn a_doq_connection_that_opens_no_stream_is_a_strike() {
        // A handshake, and nothing asked: what a scanner does over QUIC.
        let c = rcgen::generate_simple_self_signed(vec!["dns.example.com".to_string()]).unwrap();
        let cert_pem = c.cert.pem();
        let tls = crate::tls::load(&crate::tls::Source {
            certificate_chain: cert_pem.clone(),
            private_key: c.signing_key.serialize_pem(),
            ..Default::default()
        })
        .unwrap();
        let server = test_server();
        watch_loopback(&server);
        let (addr, _stop, server) = start_with(&tls, server).await;

        let conn = client_endpoint(&cert_pem)
            .connect(addr, "dns.example.com")
            .unwrap()
            .await
            .unwrap();
        conn.close(0u32.into(), b"done");
        assert!(settle(|| server.probes.tracked() == 1).await);
    }

    #[tokio::test]
    async fn a_source_serving_a_penalty_hears_nothing_from_doq() {
        // Admission goes through `quic::admit`: a source serving a penalty is
        // sent nothing at all, since the address may be forged.
        let c = rcgen::generate_simple_self_signed(vec!["dns.example.com".to_string()]).unwrap();
        let cert_pem = c.cert.pem();
        let tls = crate::tls::load(&crate::tls::Source {
            certificate_chain: cert_pem.clone(),
            private_key: c.signing_key.serialize_pem(),
            ..Default::default()
        })
        .unwrap();
        let server = test_server();
        watch_loopback(&server);
        server
            .probes
            .condemn("127.0.0.1".parse().unwrap(), "a test");
        let (addr, _stop, server) = start_with(&tls, server).await;

        let mut client = client_endpoint(&cert_pem);
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut cert_pem.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"doq".to_vec()];
        let mut impatient = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(cfg).unwrap(),
        ));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(1).try_into().unwrap()));
        impatient.transport_config(Arc::new(transport));
        client.set_default_client_config(impatient);

        let err = client
            .connect(addr, "dns.example.com")
            .unwrap()
            .await
            .expect_err("not answered");
        assert!(
            matches!(err, quinn::ConnectionError::TimedOut),
            "got {err:?}"
        );
        assert!(server.probes.stats().refused_banned >= 1);
    }

    #[tokio::test]
    async fn a_doq_client_named_by_the_certificate_but_not_the_server_is_answered_servfail() {
        use hickory_proto::op::{Message, ResponseCode};
        use hickory_proto::serialize::binary::BinDecodable as _;

        let c = rcgen::generate_simple_self_signed(vec![
            "dns.example.com".to_string(),
            "other.example.net".to_string(),
        ])
        .unwrap();
        let cert_pem = c.cert.pem();
        let tls = crate::tls::load(&crate::tls::Source {
            certificate_chain: cert_pem.clone(),
            private_key: c.signing_key.serialize_pem(),
            ..Default::default()
        })
        .unwrap();
        let server = test_server();
        server.set_server_name("dns.example.com", true);
        let (addr, _stop, _) = start_with(&tls, server).await;
        let client = client_endpoint(&cert_pem);

        let ours = client
            .connect(addr, "dns.example.com")
            .unwrap()
            .await
            .unwrap();
        let reply = ask(&ours, "ads.example.com.").await;
        assert_eq!(Message::from_bytes(&reply[2..]).unwrap().answers.len(), 1);

        let other = client
            .connect(addr, "other.example.net")
            .unwrap()
            .await
            .unwrap();
        let reply = ask(&other, "ads.example.com.").await;
        assert_eq!(
            Message::from_bytes(&reply[2..])
                .unwrap()
                .metadata
                .response_code,
            ResponseCode::ServFail
        );
    }
}
