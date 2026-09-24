//! Admitting QUIC connections, the same way for both QUIC listeners.
//!
//! DNS-over-QUIC here and HTTP/3 in `sift-api` take connections from the
//! internet over UDP, where the source address on the first packet is
//! whatever the sender chose to write there.  Every decision the connection
//! guard makes about one of them has to be made knowing whether that address
//! has been *proved*, so the policy is written here once rather than in each
//! listener, where the two copies would drift.
//!
//! QUIC's own tool for proving an address is the Retry: a stateless packet
//! carrying a token sealed to the address it was sent to, which the client
//! has to send back.  A client that does has shown it receives at that
//! address, and a spoofer never sees the token.  It costs a real client one
//! round trip and the server almost nothing -- no connection state, no
//! handshake -- so it is the answer whenever the guard would otherwise spend
//! a handshake on an address it cannot yet trust.
//!
//! What `admit` does with each `quinn::Incoming`, in order:
//!
//! 1. A source serving a penalty is **ignored**: nothing at all is sent back,
//!    because the address may be forged, and a reply goes to whoever it
//!    names.
//! 2. A proved address is judged exactly as a TCP one is -- a ticket from
//!    `Guard::open`, then a handshake slot -- and if either is refused, so is
//!    the connection.  Sending a refusal to a proved address reflects
//!    nothing onto anybody.
//! 3. An address nobody has proved is asked to **retry** once half the
//!    handshake slots are taken, or whenever `open` would turn it away.
//!    Otherwise it is accepted and takes a handshake slot, and is charged
//!    nothing else until its handshake completes and so proves it.
//!
//! What that guarantees about a forged address: it is never struck or
//! penalised, because a handshake that fails before the address is proved
//! records nothing; it is never charged a connection, so a spoofer cannot use
//! up the allowance of the address it forges; and it holds at most half the
//! handshake slots, only until its handshakes time out.  A proved address
//! whose handshake then fails *is* charged, exactly as one over TCP is.
//!
//! quinn can also hand a client NEW_TOKEN tokens that let it skip the Retry
//! on its next visit, but only with its `bloom` feature, which this build
//! does not enable; without it every such token is ignored and none is sent.
//! So while the server is under pressure every new client pays the Retry's
//! round trip, and while it is not, none does.
//!
//! A listener's accept loop, in full:
//!
//! ```text
//! let Some(pending) = quic::admit(&guard, incoming) else { continue };
//! spawn(async move {
//!     let Some((conn, ticket)) = pending.establish(quic::DOQ_EXCESSIVE_LOAD).await else {
//!         return;
//!     };
//!     let peer = conn.remote_address();
//!     let served = serve(conn).await;
//!     guard.record(peer.ip(), served);
//!     drop(ticket);
//! });
//! ```

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use quinn::VarInt;
use quinn::crypto::rustls::{NoInitialCipherSuite, QuicServerConfig};

use crate::probe::{Guard, HandshakeSlot, Refused, Ticket};

/// How long a QUIC handshake may take before it is abandoned.
///
/// The TLS listeners allow the same.  A handshake that means it finishes in
/// a few round trips; one that has not after this long is holding a slot.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// `DOQ_EXCESSIVE_LOAD` from RFC 9250, for closing a DoQ connection that was
/// turned away at a limit once its handshake had completed.
pub const DOQ_EXCESSIVE_LOAD: VarInt = VarInt::from_u32(0x4);

/// `H3_EXCESSIVE_LOAD` from RFC 9114, the same for HTTP/3.
pub const H3_EXCESSIVE_LOAD: VarInt = VarInt::from_u32(0x0107);

/// How long a connection may sit idle before it is closed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// What a peer may send on one stream before it has to wait for it to be
/// read.
///
/// Both listeners read at most 64 KiB from a stream -- a DNS message, or a
/// request body -- so this is one of those and room to spare.  quinn's
/// default is sized for bulk transfer, over a megabyte a stream.
const STREAM_RECEIVE_WINDOW: u32 = 128 * 1024;

/// What a peer may send across a whole connection before it has to wait.
///
/// quinn's default is unlimited, which leaves only the per-stream window
/// times the stream limit -- 512 streams of 1.25 MB for DoQ -- between one
/// connection and the memory it can make this process buffer.
const RECEIVE_WINDOW: u32 = 1024 * 1024;

/// What this side buffers for a peer before a write has to wait for it to
/// acknowledge.
///
/// A peer that stops acknowledging holds this much memory for as long as the
/// connection lives, so it is sized for a web page's assets rather than
/// quinn's bulk-transfer default of 10 MB.
const SEND_WINDOW: u64 = 512 * 1024;

/// Connection attempts quinn may hold before the listener has looked at them.
///
/// The accept loop decides on each at once, so a backlog this deep means
/// the process is not keeping up and more would only be more memory.
const MAX_INCOMING: usize = 4096;

/// Bytes quinn may buffer for one attempt before the listener decides on it,
/// and for all of them together.
const INCOMING_BUFFER: u64 = 64 * 1024;
const INCOMING_BUFFER_TOTAL: u64 = 16 * 1024 * 1024;

/// Builds the QUIC server configuration both listeners start from.
///
/// It carries the limits that are about what a stranger can make this
/// process hold -- idle time, flow-control windows, the backlog of attempts
/// not yet looked at -- and leaves the stream limits, which are each
/// protocol's own, to the listener.  The transport is not yet shared, so a
/// listener adjusts it through `Arc::get_mut`:
///
/// ```text
/// let mut cfg = quic::server_config(tls).map_err(|e| Error::Tls(e.to_string()))?;
/// let transport = Arc::get_mut(&mut cfg.transport).expect("not yet shared");
/// transport.max_concurrent_bidi_streams(64u32.into());
/// ```
///
/// Datagrams are switched off, since neither DoQ nor this HTTP/3 carries
/// any, and connection migration is left on, so a phone that moves from
/// Wi-Fi to mobile data keeps its connection.  Fails when the TLS
/// configuration cannot be used for QUIC, which requires TLS 1.3.
pub fn server_config(
    tls: Arc<rustls::ServerConfig>,
) -> Result<quinn::ServerConfig, NoInitialCipherSuite> {
    let crypto = QuicServerConfig::try_from(tls)?;

    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(
            IDLE_TIMEOUT.try_into().expect("the idle timeout fits"),
        ))
        .stream_receive_window(STREAM_RECEIVE_WINDOW.into())
        .receive_window(RECEIVE_WINDOW.into())
        .send_window(SEND_WINDOW)
        .datagram_receive_buffer_size(None);

    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    cfg.transport_config(Arc::new(transport))
        .max_incoming(MAX_INCOMING)
        .incoming_buffer_size(INCOMING_BUFFER)
        .incoming_buffer_size_total(INCOMING_BUFFER_TOTAL);

    Ok(cfg)
}

/// Applies the guard's policy to one incoming connection.
///
/// Returns the handshake to drive when the connection was accepted, and
/// `None` when it has already been answered -- ignored, retried or refused
/// -- and there is nothing more to do.  It never waits, so it belongs in the
/// accept loop itself; `Pending::establish` is the part to spawn.
pub fn admit(guard: &Arc<Guard>, incoming: quinn::Incoming) -> Option<Pending> {
    let ip = incoming.remote_address().ip();
    let validated = incoming.remote_address_validated();

    match judge(guard, ip, validated) {
        Verdict::Ignore => {
            incoming.ignore();

            None
        }
        Verdict::Refuse => {
            incoming.refuse();

            None
        }
        Verdict::Retry => {
            // An unvalidated attempt may always be retried, so the error is
            // not expected; if it happens anyway, sending nothing is the
            // answer that cannot be abused.
            match incoming.retry() {
                Ok(()) => guard.retried(),
                Err(e) => e.into_incoming().ignore(),
            }

            None
        }
        Verdict::Accept { slot, ticket } => match incoming.accept() {
            Ok(connecting) => Some(Pending {
                guard: guard.clone(),
                connecting,
                slot,
                ticket,
                ip,
                validated,
            }),
            // The handshake failed on its first packet.
            Err(_) => {
                drop(slot);
                if validated {
                    guard.wasted(ip);
                }

                None
            }
        },
    }
}

/// An accepted connection whose handshake is under way.
///
/// It holds a handshake slot until `establish` returns, and, for an address
/// that was already proved, the connection's ticket.  Dropping it abandons
/// the handshake and gives both back.
#[must_use = "the handshake is only driven by `establish`"]
pub struct Pending {
    guard: Arc<Guard>,
    connecting: quinn::Connecting,
    slot: HandshakeSlot,
    ticket: Option<Ticket>,
    ip: IpAddr,
    validated: bool,
}

impl Pending {
    /// The address the connection came from.
    pub fn remote_address(&self) -> SocketAddr {
        self.connecting.remote_address()
    }

    /// Completes the handshake, returning the connection and the ticket to
    /// hold for as long as it is open.
    ///
    /// The handshake slot is given back as soon as the handshake finishes or
    /// fails.  A connection whose address was not proved before is charged
    /// its ticket now that the handshake has proved it, and if a limit turns
    /// it away at that point it is closed with `busy` -- `DOQ_EXCESSIVE_LOAD`
    /// or `H3_EXCESSIVE_LOAD` -- rather than served.
    ///
    /// Returns `None` when there is nothing to serve.  A handshake that fails
    /// or takes longer than `HANDSHAKE_TIMEOUT` counts as a wasted connection
    /// only if the address had been proved beforehand; the caller records
    /// nothing either way.
    pub async fn establish(self, busy: VarInt) -> Option<(quinn::Connection, Ticket)> {
        let Self {
            guard,
            connecting,
            slot,
            ticket,
            ip,
            validated,
        } = self;

        let done = tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting).await;
        drop(slot);

        let Ok(Ok(conn)) = done else {
            if validated {
                guard.wasted(ip);
            }

            return None;
        };

        let ticket = match ticket {
            Some(t) => t,
            None => match guard.open(ip) {
                Ok(t) => t,
                Err(_) => {
                    conn.close(busy, b"busy");

                    return None;
                }
            },
        };

        Some((conn, ticket))
    }
}

impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending")
            .field("remote", &self.remote_address())
            .field("validated", &self.validated)
            .finish_non_exhaustive()
    }
}

/// What to do with one incoming connection.
#[derive(Debug)]
enum Verdict {
    /// Send nothing.
    Ignore,
    /// Ask the client to prove its address first.
    Retry,
    /// Tell a proved address it is turned away.
    Refuse,
    /// Go ahead with the handshake.  The ticket is already charged when the
    /// address was proved; otherwise it is charged once the handshake is.
    Accept {
        slot: HandshakeSlot,
        ticket: Option<Ticket>,
    },
}

/// Decides what to do with a connection from `ip`, taking what it is granted.
///
/// Kept apart from `admit` so the policy can be tested without a network.
fn judge(guard: &Arc<Guard>, ip: IpAddr, validated: bool) -> Verdict {
    if validated {
        let ticket = match guard.open(ip) {
            Ok(t) => t,
            Err(Refused::Banned) => return Verdict::Ignore,
            Err(Refused::Busy) => return Verdict::Refuse,
        };

        return match guard.handshake(ip) {
            Some(slot) => Verdict::Accept {
                slot,
                ticket: Some(ticket),
            },
            None => Verdict::Refuse,
        };
    }

    match guard.standing(ip) {
        Ok(()) => {}
        Err(Refused::Banned) => return Verdict::Ignore,
        // It would be turned away once proved, so have it prove itself
        // before anything is spent on it.  Retrying is harmless if the
        // address is forged, where refusing would answer the victim.
        Err(Refused::Busy) => return Verdict::Retry,
    }

    if guard.handshakes_scarce() {
        return Verdict::Retry;
    }

    match guard.unproven_handshake() {
        Some(slot) => Verdict::Accept { slot, ticket: None },
        None => Verdict::Retry,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::probe::Config;

    /// Where the tests' clients come from: loopback, judged like the internet.
    fn here() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    /// A public address, standing in for everyone else.
    fn stranger() -> IpAddr {
        "203.0.113.50".parse().unwrap()
    }

    /// A guard that judges loopback, with the given limits.
    fn guard(max_handshakes: usize, max_per_source: usize) -> Arc<Guard> {
        Arc::new(Guard::new(Config {
            exempt_local: false,
            max_handshakes,
            max_per_source,
            ..Default::default()
        }))
    }

    #[test]
    fn a_source_serving_a_penalty_is_ignored_whether_or_not_its_address_is_proven() {
        let g = guard(256, 64);
        g.condemn(here(), "a test");

        for validated in [false, true] {
            assert!(
                matches!(judge(&g, here(), validated), Verdict::Ignore),
                "validated: {validated}"
            );
        }
        assert_eq!(g.stats().open, 0);
        assert_eq!(g.stats().handshakes, 0);
    }

    #[test]
    fn an_unproven_address_takes_a_handshake_and_nothing_else() {
        let g = guard(256, 64);

        let v = judge(&g, here(), false);
        let Verdict::Accept { slot, ticket } = &v else {
            panic!("got {v:?}");
        };
        assert!(slot.is_counted());
        assert!(
            ticket.is_none(),
            "no connection is charged before it is proved"
        );

        let s = g.stats();
        assert_eq!((s.open, s.sources, s.handshakes), (0, 0, 1));
    }

    #[test]
    fn a_proven_address_is_charged_its_connection_before_the_handshake() {
        let g = guard(256, 64);

        let v = judge(&g, here(), true);
        let Verdict::Accept { ticket, .. } = &v else {
            panic!("got {v:?}");
        };
        assert!(ticket.as_ref().is_some_and(Ticket::is_counted));
        assert_eq!(g.stats().open, 1);

        drop(v);
        assert_eq!((g.stats().open, g.stats().handshakes), (0, 0));
    }

    #[test]
    fn an_unproven_address_is_asked_to_retry_once_half_the_handshakes_are_taken() {
        let g = guard(4, 64);

        let first = judge(&g, here(), false);
        assert!(matches!(first, Verdict::Accept { .. }), "got {first:?}");
        let _held = g.handshake(stranger()).unwrap();

        assert!(
            matches!(judge(&g, here(), false), Verdict::Retry),
            "two of four is half"
        );
        assert!(
            matches!(judge(&g, here(), true), Verdict::Accept { .. }),
            "a proved address may still use the other half"
        );
    }

    #[test]
    fn a_proven_address_is_refused_when_no_handshake_is_free() {
        let g = guard(1, 64);
        let _held = g.handshake(stranger()).unwrap();

        assert!(matches!(judge(&g, here(), false), Verdict::Retry));
        assert!(matches!(judge(&g, here(), true), Verdict::Refuse));
        assert_eq!(g.stats().open, 0, "the ticket taken first was given back");
        assert_eq!(g.tracked(), 0, "and being busy is not an offence");
    }

    #[test]
    fn a_proven_address_over_its_allowance_is_refused_before_the_handshake() {
        let g = guard(256, 1);
        let _held = g.open(here()).unwrap();

        assert!(matches!(judge(&g, here(), true), Verdict::Refuse));
        assert_eq!(g.stats().handshakes, 0, "nothing was spent on it");
    }

    #[test]
    fn a_forged_address_cannot_use_up_its_victims_allowance() {
        // A spoofer can put the victim's address on as many initial packets
        // as it likes.  None of them may count against what the victim
        // itself is allowed to open, nor as anything the victim did.
        let g = guard(256, 2);
        let victim = stranger();

        let forged: Vec<_> = (0..100).map(|_| judge(&g, victim, false)).collect();
        assert!(forged.iter().all(|v| matches!(v, Verdict::Accept { .. })));
        drop(forged);

        let a = g.open(victim).expect("the victim's allowance is untouched");
        let _b = g.open(victim).expect("all of it");

        // Once the victim is at its allowance, a forged attempt is retried,
        // not refused: a refusal would be sent to the victim.
        assert!(matches!(judge(&g, victim, false), Verdict::Retry));

        drop(a);
        assert!(g.open(victim).is_ok());
        assert_eq!(g.tracked(), 0, "and nothing is held against it");
    }

    #[test]
    fn an_unproven_claim_to_be_local_still_takes_a_counted_handshake() {
        // An exemption belongs to an address, and an unvalidated packet has
        // not shown it comes from the one it names -- so a spoofer writing a
        // LAN address on its packets does not get handshakes for free.
        let g = Arc::new(Guard::new(Config {
            max_handshakes: 2,
            ..Default::default()
        }));
        let lan: IpAddr = "192.168.1.10".parse().unwrap();

        let v = judge(&g, lan, false);
        let Verdict::Accept { slot, ticket } = &v else {
            panic!("got {v:?}");
        };
        assert!(slot.is_counted());
        assert!(ticket.is_none());

        // Proved, it is exempt as ever.
        let v = judge(&g, lan, true);
        let Verdict::Accept { slot, ticket } = &v else {
            panic!("got {v:?}");
        };
        assert!(!slot.is_counted());
        assert!(ticket.as_ref().is_some_and(|t| !t.is_counted()));
    }

    #[test]
    fn a_listener_can_still_set_its_own_stream_limits() {
        let mut cfg = server_config(test_tls().0.doq).expect("a TLS 1.3 certificate suits QUIC");

        let transport = Arc::get_mut(&mut cfg.transport);
        assert!(transport.is_some(), "the transport must not be shared yet");
    }

    /// A self-signed certificate for `dns.example.com`, and its PEM.
    fn test_tls() -> (crate::tls::Loaded, String) {
        let c = rcgen::generate_simple_self_signed(vec!["dns.example.com".to_string()])
            .expect("generating a certificate");
        let pem = c.cert.pem();
        let loaded = crate::tls::load(&crate::tls::Source {
            certificate_chain: pem.clone(),
            private_key: c.signing_key.serialize_pem(),
            ..Default::default()
        })
        .expect("the test pair must load");

        (loaded, pem)
    }

    /// Starts a listener that admits through `guard` and holds each
    /// connection open until the client closes it.
    fn listen(guard: Arc<Guard>, tls: &crate::tls::Loaded) -> (SocketAddr, quinn::Endpoint) {
        let cfg = server_config(tls.doq.clone()).unwrap();
        let ep = quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = ep.local_addr().unwrap();

        let server = ep.clone();
        tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                let Some(pending) = admit(&guard, incoming) else {
                    continue;
                };
                tokio::spawn(async move {
                    if let Some((conn, _ticket)) = pending.establish(DOQ_EXCESSIVE_LOAD).await {
                        conn.closed().await;
                    }
                });
            }
        });

        (addr, ep)
    }

    /// A client that trusts only `cert_pem`, offers `alpn`, and gives up on
    /// a silent server after a second.
    fn client(cert_pem: &str, alpn: &[u8]) -> quinn::Endpoint {
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut cert_pem.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }

        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![alpn.to_vec()];

        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
        let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(1).try_into().unwrap()));
        cfg.transport_config(Arc::new(transport));

        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        ep.set_default_client_config(cfg);

        ep
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
    async fn an_unproven_client_under_pressure_is_retried_and_then_served() {
        let (tls, pem) = test_tls();
        let g = guard(2, 64);
        let _held = g.handshake(stranger()).unwrap();
        let (addr, server) = listen(g.clone(), &tls);

        let conn = client(&pem, b"doq")
            .connect(addr, "dns.example.com")
            .unwrap()
            .await
            .expect("the retried client completes its handshake");

        assert_eq!(g.stats().retried, 1, "it was asked to prove its address");
        assert!(
            settle(|| g.stats().open == 1).await,
            "and is counted once it has"
        );

        conn.close(0u32.into(), b"done");
        assert!(
            settle(|| g.stats().open == 0).await,
            "closing gives the connection back"
        );
        assert_eq!(g.stats().sources, 0);
        assert_eq!(g.tracked(), 0);

        server.close(0u32.into(), b"done");
    }

    #[tokio::test]
    async fn an_unproven_client_is_counted_once_its_handshake_completes() {
        let (tls, pem) = test_tls();
        let g = guard(256, 64);
        let (addr, server) = listen(g.clone(), &tls);

        let conn = client(&pem, b"doq")
            .connect(addr, "dns.example.com")
            .unwrap()
            .await
            .expect("an unpressed server answers at once");

        assert_eq!(g.stats().retried, 0, "no Retry without pressure");
        assert!(settle(|| g.stats().open == 1).await);
        assert!(
            settle(|| g.stats().handshakes == 0).await,
            "the slot is given back"
        );

        conn.close(0u32.into(), b"done");
        assert!(settle(|| g.stats().open == 0).await);

        server.close(0u32.into(), b"done");
    }

    #[tokio::test]
    async fn a_proven_client_with_no_handshake_free_is_refused_not_left_hanging() {
        let (tls, pem) = test_tls();
        let g = guard(1, 64);
        let _held = g.handshake(stranger()).unwrap();
        let (addr, server) = listen(g.clone(), &tls);

        let err = client(&pem, b"doq")
            .connect(addr, "dns.example.com")
            .unwrap()
            .await
            .expect_err("there is no handshake to be had");

        // A refusal arrives as a close; silence would have been a timeout.
        assert!(
            matches!(err, quinn::ConnectionError::ConnectionClosed(_)),
            "got {err:?}"
        );
        let s = g.stats();
        assert_eq!((s.retried, s.open, s.refused_busy), (1, 0, 1));
        assert_eq!(g.tracked(), 0, "being busy is not held against it");

        server.close(0u32.into(), b"done");
    }

    #[tokio::test]
    async fn a_source_serving_a_penalty_is_sent_nothing_at_all() {
        let (tls, pem) = test_tls();
        let g = guard(256, 64);
        g.condemn(here(), "a test");
        let (addr, server) = listen(g.clone(), &tls);

        let err = client(&pem, b"doq")
            .connect(addr, "dns.example.com")
            .unwrap()
            .await
            .expect_err("a refused source is not answered");

        assert!(
            matches!(err, quinn::ConnectionError::TimedOut),
            "the client heard nothing, not even a refusal: got {err:?}"
        );
        assert!(g.stats().refused_banned >= 1);
        assert_eq!(g.stats().retried, 0);

        server.close(0u32.into(), b"done");
    }

    #[tokio::test]
    async fn a_failed_handshake_counts_only_once_the_address_is_proven() {
        // A client offering a protocol the listener does not speak fails its
        // handshake -- which is what a scanner looks like to the guard.
        let (tls, pem) = test_tls();
        let g = guard(256, 64);
        let (addr, server) = listen(g.clone(), &tls);
        let wrong = client(&pem, b"h3");

        let unproven = wrong.connect(addr, "dns.example.com").unwrap().await;
        assert!(unproven.is_err());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(g.tracked(), 0, "an address nobody proved is never struck");

        // Under pressure the same client is retried first, so its address is
        // proved by the time the handshake fails.
        g.set_config(Config {
            exempt_local: false,
            max_handshakes: 2,
            ..Default::default()
        });
        let _held = g.handshake(stranger()).unwrap();

        let proven = wrong.connect(addr, "dns.example.com").unwrap().await;
        assert!(proven.is_err());
        assert!(
            settle(|| g.tracked() == 1).await,
            "a proved address that asked nothing has earned a strike"
        );

        server.close(0u32.into(), b"done");
    }
}
