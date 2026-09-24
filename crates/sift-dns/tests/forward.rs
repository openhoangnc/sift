//! What reaches the upstream, and what comes back.
//!
//! These drive the resolver against a tiny local server, so the settings that
//! only show up in the forwarded request — the client subnet, the DNSSEC OK
//! bit, request coalescing — can be observed rather than inferred.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use sift_dns::cache::{Cache, Config as CacheConfig};
use sift_dns::client::{Client, tls_config};
use sift_dns::pool::{Mode, Pool, SharedPool};
use sift_dns::resolver::{Action, ClientInfo, Proto, Resolver, Settings};
use sift_dns::rewrite::Table;
use sift_filter::engine::Engine;
use tokio::net::UdpSocket;

/// What the fake upstream saw and how often.
#[derive(Default)]
struct Seen {
    /// How many requests arrived.
    count: AtomicUsize,
    /// The client subnet of the last request, if it carried one.
    subnet: parking_lot::Mutex<Option<String>>,
    /// Whether the last request asked for DNSSEC records.
    dnssec: parking_lot::Mutex<bool>,
}

/// Starts a local server that answers every query with `answer`.
///
/// `delay` holds each answer back, which is what makes a second identical
/// request arrive while the first is still in flight.
async fn upstream(answer: IpAddr, delay: Duration) -> (SocketAddr, Arc<Seen>) {
    serve(answer, delay, Answering::default()).await
}

/// The same, answering the way a real upstream answers a signed name: the
/// address, its `RRSIG`, a signed denial in the authority section, the `AD`
/// bit, and an OPT record of its own advertising a size this server never
/// asked for.
async fn signing_upstream(answer: IpAddr) -> (SocketAddr, Arc<Seen>) {
    serve(
        answer,
        Duration::ZERO,
        Answering {
            signed: true,
            ..Default::default()
        },
    )
    .await
}

/// The same, answering with enough records that the reply cannot fit in the
/// 512 bytes a client that sent no OPT record is entitled to.
async fn wordy_upstream(answer: IpAddr, extra: usize) -> (SocketAddr, Arc<Seen>) {
    serve(
        answer,
        Duration::ZERO,
        Answering {
            extra,
            ..Default::default()
        },
    )
    .await
}

/// How the fake upstream answers.
#[derive(Clone, Copy, Default)]
struct Answering {
    /// Answer the way a DNSSEC-signed name is answered.
    signed: bool,
    /// How many address records to add beyond the first.
    extra: usize,
}

async fn serve(answer: IpAddr, delay: Duration, how: Answering) -> (SocketAddr, Arc<Seen>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("binding");
    let addr = sock.local_addr().expect("local addr");
    let seen = Arc::new(Seen::default());

    let s = seen.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let Ok(req) = Message::from_bytes(&buf[..n]) else {
                continue;
            };

            s.count.fetch_add(1, Ordering::SeqCst);
            *s.subnet.lock() = sift_dns::edns::subnet_of(&req).map(|x| x.to_cidr());
            *s.dnssec.lock() = sift_dns::edns::dnssec_ok(&req);

            let mut resp = Message::query();
            resp.metadata.id = req.metadata.id;
            resp.metadata.message_type = hickory_proto::op::MessageType::Response;
            resp.queries = req.queries.clone();
            if let Some(q) = req.queries.first() {
                let data = match answer {
                    IpAddr::V4(a) => RData::A(A(a)),
                    IpAddr::V6(a) => RData::AAAA(hickory_proto::rr::rdata::AAAA(a)),
                };
                resp.answers = vec![Record::from_rdata(q.name().clone(), 300, data); 1 + how.extra];

                if how.signed {
                    resp.metadata.authentic_data = true;
                    resp.answers.push(signature(q.name(), RecordType::RRSIG));
                    resp.authorities = vec![
                        signature(q.name(), RecordType::NSEC),
                        signature(q.name(), RecordType::RRSIG),
                    ];

                    let mut e = hickory_proto::op::Edns::new();
                    e.set_max_payload(1232);
                    e.set_dnssec_ok(true);
                    resp.edns = Some(e);
                }
            }

            let wire = resp.to_bytes().expect("encoding");
            tokio::time::sleep(delay).await;
            let _ = sock.send_to(&wire, peer).await;
        }
    });

    (addr, seen)
}

/// A DNSSEC record with opaque rdata, which is how one arrives: hickory is
/// built without its `dnssec` feature, so an `RRSIG` parses as `Unknown` while
/// still reporting `RecordType::RRSIG`.
fn signature(name: &Name, rtype: RecordType) -> Record {
    Record::from_rdata(
        name.clone(),
        300,
        RData::Unknown {
            code: rtype,
            rdata: hickory_proto::rr::rdata::NULL::with(vec![0x01, 0x02, 0x03]),
        },
    )
}

/// Builds a resolver pointed at one upstream.
async fn resolver(server: SocketAddr, settings: Settings) -> Resolver {
    let up = sift_dns::addr::parse(&server.to_string())
        .expect("parsing")
        .upstream
        .expect("an upstream");
    let client = Client::connect(up, &[], Duration::from_secs(2), false, tls_config())
        .await
        .expect("connecting");

    Resolver::new(
        Engine::build([(1i64, "")], sift_filter::engine::NO_LISTS),
        Table::default(),
        Cache::new(CacheConfig {
            size_bytes: 0,
            ..CacheConfig::default()
        }),
        SharedPool::new(Pool::new(
            vec![Arc::new(client)],
            vec![],
            vec![],
            Mode::LoadBalance,
            Duration::from_secs(2),
            Duration::from_secs(2),
        )),
        settings,
    )
}

/// An `A` query for `name`.
fn request(name: &str) -> Message {
    let mut m = Message::query();
    m.metadata.id = 0x4242;
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(
        Name::from_utf8(name).expect("a name"),
        RecordType::A,
    ));

    m
}

/// A client on an ordinary network, rather than loopback.
fn lan_client() -> ClientInfo {
    ClientInfo {
        addr: Some("203.0.113.77".parse().expect("an address")),
        ..Default::default()
    }
}

#[tokio::test]
async fn the_client_subnet_is_forwarded_when_it_is_enabled() {
    let (server, seen) = upstream("192.0.2.1".parse().unwrap(), Duration::ZERO).await;
    let r = resolver(
        server,
        Settings {
            ecs_enabled: true,
            ..Default::default()
        },
    )
    .await;

    let out = r
        .resolve(&request("example.com."), Proto::Udp, &lan_client())
        .await;
    assert!(matches!(out.action, Action::Respond(_)));

    assert_eq!(
        seen.subnet.lock().clone().as_deref(),
        Some("203.0.113.0/24"),
        "the address is masked to /24 before it is sent"
    );
    assert_eq!(out.req_ecs, "203.0.113.0/24", "and recorded in the log");
}

#[tokio::test]
async fn no_subnet_is_forwarded_when_the_feature_is_off() {
    let (server, seen) = upstream("192.0.2.1".parse().unwrap(), Duration::ZERO).await;
    let r = resolver(server, Settings::default()).await;

    let out = r
        .resolve(&request("example.com."), Proto::Udp, &lan_client())
        .await;

    assert_eq!(seen.subnet.lock().clone(), None);
    assert!(out.req_ecs.is_empty());
}

#[tokio::test]
async fn a_loopback_client_is_never_described_to_the_upstream() {
    // Its subnet says nothing useful and would only leak that the query came
    // from the server itself.
    let (server, seen) = upstream("192.0.2.1".parse().unwrap(), Duration::ZERO).await;
    let r = resolver(
        server,
        Settings {
            ecs_enabled: true,
            ..Default::default()
        },
    )
    .await;

    let _ = r
        .resolve(
            &request("example.com."),
            Proto::Udp,
            &ClientInfo {
                addr: Some("127.0.0.1".parse().unwrap()),
                ..Default::default()
            },
        )
        .await;

    assert_eq!(seen.subnet.lock().clone(), None);
}

#[tokio::test]
async fn a_custom_subnet_replaces_the_clients() {
    let (server, seen) = upstream("192.0.2.1".parse().unwrap(), Duration::ZERO).await;
    let r = resolver(
        server,
        Settings {
            ecs_enabled: true,
            ecs_custom: Some("198.51.100.9".parse().unwrap()),
            ..Default::default()
        },
    )
    .await;

    let _ = r
        .resolve(&request("example.com."), Proto::Udp, &lan_client())
        .await;

    assert_eq!(
        seen.subnet.lock().clone().as_deref(),
        Some("198.51.100.0/24")
    );
}

#[tokio::test]
async fn the_dnssec_bit_is_set_only_when_it_is_asked_for() {
    let (server, seen) = upstream("192.0.2.1".parse().unwrap(), Duration::ZERO).await;

    let plain = resolver(server, Settings::default()).await;
    let _ = plain
        .resolve(&request("example.com."), Proto::Udp, &lan_client())
        .await;
    assert!(!*seen.dnssec.lock());

    let signed = resolver(
        server,
        Settings {
            dnssec_enabled: true,
            ..Default::default()
        },
    )
    .await;
    let _ = signed
        .resolve(&request("example.com."), Proto::Udp, &lan_client())
        .await;
    assert!(*seen.dnssec.lock());
}

/// The settings a server has when `enable_dnssec` is on, which is the default
/// a fresh AdGuardHome.yaml carries.
fn dnssec_on() -> Settings {
    Settings {
        dnssec_enabled: true,
        ..Default::default()
    }
}

fn record_types(m: &Message) -> (Vec<RecordType>, Vec<RecordType>) {
    (
        m.answers.iter().map(Record::record_type).collect(),
        m.authorities.iter().map(Record::record_type).collect(),
    )
}

fn answer_to(out: &sift_dns::resolver::Outcome) -> &Message {
    match &out.action {
        Action::Respond(m) => m,
        Action::Drop => panic!("the query should have been answered"),
    }
}

#[tokio::test]
async fn a_plain_query_is_never_answered_with_signatures() {
    // The bit is set upstream for every query while `enable_dnssec` is on, so
    // the signatures arrive whether the client asked or not.  Passing them on
    // is what macOS's `mDNSResponder` throws the whole answer away over.
    let (server, _) = signing_upstream("192.0.2.1".parse().unwrap()).await;
    let r = resolver(server, dnssec_on()).await;

    let out = r
        .resolve(&request("example.com."), Proto::Udp, &lan_client())
        .await;
    let resp = answer_to(&out);

    assert_eq!(
        record_types(resp),
        (vec![RecordType::A], vec![]),
        "the address, and nothing the client did not ask for"
    );
    assert!(!resp.metadata.authentic_data, "nor a validation verdict");
    assert!(
        resp.edns.is_none(),
        "nor an OPT record, the request having carried none"
    );
}

#[tokio::test]
async fn a_validating_client_still_gets_its_signatures() {
    let (server, seen) = signing_upstream("192.0.2.1".parse().unwrap()).await;
    let r = resolver(server, dnssec_on()).await;

    let mut req = request("example.com.");
    sift_dns::edns::set_dnssec_ok(&mut req, true);

    let out = r.resolve(&req, Proto::Udp, &lan_client()).await;
    let resp = answer_to(&out);

    assert!(*seen.dnssec.lock());
    assert_eq!(
        record_types(resp),
        (
            vec![RecordType::A, RecordType::RRSIG],
            vec![RecordType::NSEC, RecordType::RRSIG]
        ),
    );
    assert!(resp.metadata.authentic_data);
    assert!(resp.edns.as_ref().expect("an OPT record").flags().dnssec_ok);
}

#[tokio::test]
async fn the_answers_opt_record_is_the_clients_own() {
    // The upstream advertises 1232 and sets `DO` because that is what it was
    // asked; the client asked for neither.
    let (server, _) = signing_upstream("192.0.2.1".parse().unwrap()).await;
    let r = resolver(server, dnssec_on()).await;

    let mut req = request("example.com.");
    let mut e = hickory_proto::op::Edns::new();
    e.set_max_payload(1400);
    req.edns = Some(e);

    let out = r.resolve(&req, Proto::Udp, &lan_client()).await;
    let resp = answer_to(&out);
    let edns = resp
        .edns
        .as_ref()
        .expect("the client sent one, so it gets one");

    assert!(!edns.flags().dnssec_ok);
    assert_eq!(edns.max_payload(), 1400);
    assert_eq!(record_types(resp).0, vec![RecordType::A]);
}

#[tokio::test]
async fn a_cached_answer_is_shaped_for_whoever_asks_for_it() {
    // The cache holds what the upstream said; two clients asking the same
    // question differently are owed different answers out of it.
    let (server, seen) = signing_upstream("192.0.2.1".parse().unwrap()).await;
    let r = Resolver::new(
        Engine::build([(1i64, "")], sift_filter::engine::NO_LISTS),
        Table::default(),
        Cache::new(CacheConfig::default()),
        {
            let up = sift_dns::addr::parse(&server.to_string())
                .expect("parsing")
                .upstream
                .expect("an upstream");
            let client = Client::connect(up, &[], Duration::from_secs(2), false, tls_config())
                .await
                .expect("connecting");

            SharedPool::new(Pool::new(
                vec![Arc::new(client)],
                vec![],
                vec![],
                Mode::LoadBalance,
                Duration::from_secs(2),
                Duration::from_secs(2),
            ))
        },
        dnssec_on(),
    );

    let mut signed = request("example.com.");
    sift_dns::edns::set_dnssec_ok(&mut signed, true);
    let first = r.resolve(&signed, Proto::Udp, &lan_client()).await;
    assert_eq!(record_types(answer_to(&first)).0.len(), 2);

    // Same question, no DO: a different cache entry, so the upstream is asked
    // again -- and the answer is stripped on the way to this client.
    let out = r
        .resolve(&request("example.com."), Proto::Udp, &lan_client())
        .await;
    assert_eq!(record_types(answer_to(&out)).0, vec![RecordType::A]);

    // And the signed entry is still whole: shaping the answer must not have
    // reached into what was stored.
    let again = r.resolve(&signed, Proto::Udp, &lan_client()).await;
    assert!(again.cached, "the second signed query is a cache hit");
    assert_eq!(
        record_types(answer_to(&again)).0,
        vec![RecordType::A, RecordType::RRSIG]
    );
    assert_eq!(
        seen.count.load(Ordering::SeqCst),
        2,
        "one exchange per shape"
    );
}

#[tokio::test]
async fn a_datagram_answer_is_cut_to_what_the_client_can_receive() {
    // A client that sent no OPT record is entitled to 512 bytes and nothing
    // more; anything larger is a datagram the network may simply drop, and the
    // client never learns there was an answer at all.
    let (server, _) = wordy_upstream("192.0.2.1".parse().unwrap(), 120).await;
    let r = resolver(server, Settings::default()).await;

    let out = r
        .resolve(&request("example.com."), Proto::Udp, &lan_client())
        .await;
    let resp = answer_to(&out);
    let wire = resp.to_bytes().expect("encoding");

    assert!(wire.len() <= 512, "{} bytes went out", wire.len());
    assert!(resp.metadata.truncation, "so the client retries over TCP");
    assert!(
        !resp.answers.is_empty() && resp.answers.len() < 121,
        "what fits is kept, rather than the answer being thrown away"
    );
}

#[tokio::test]
async fn a_client_that_asked_for_room_gets_it() {
    let (server, _) = wordy_upstream("192.0.2.1".parse().unwrap(), 120).await;
    let r = resolver(server, Settings::default()).await;

    let mut req = request("example.com.");
    let mut e = hickory_proto::op::Edns::new();
    e.set_max_payload(4096);
    req.edns = Some(e);

    let out = r.resolve(&req, Proto::Udp, &lan_client()).await;
    let resp = answer_to(&out);

    assert_eq!(resp.answers.len(), 121, "all of it fits in 4096");
    assert!(!resp.metadata.truncation);
}

#[tokio::test]
async fn a_stream_transport_is_never_truncated() {
    // TCP, DoT, DoH and DoQ all carry a length of their own, so the 512-byte
    // datagram limit has nothing to do with them.  Upstream answers them with
    // `dns.MaxMsgSize`.
    let (server, _) = wordy_upstream("192.0.2.1".parse().unwrap(), 120).await;
    let r = resolver(server, Settings::default()).await;

    for proto in [Proto::Tcp, Proto::Tls, Proto::Https, Proto::Quic] {
        let out = r
            .resolve(&request("example.com."), proto, &lan_client())
            .await;
        let resp = answer_to(&out);

        assert_eq!(resp.answers.len(), 121, "{proto:?} carries its own length");
        assert!(!resp.metadata.truncation, "{proto:?}");
    }
}

#[tokio::test]
async fn identical_requests_in_flight_are_coalesced() {
    // A burst of the same question from several devices should cost one
    // upstream exchange, not one each.
    let (server, seen) = upstream("192.0.2.1".parse().unwrap(), Duration::from_millis(150)).await;
    let r = Arc::new(
        resolver(
            server,
            Settings {
                pending_enabled: true,
                ..Default::default()
            },
        )
        .await,
    );

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..5 {
        let r = r.clone();
        set.spawn(async move {
            r.resolve(&request("example.com."), Proto::Udp, &lan_client())
                .await
        });
    }

    let mut answered = 0;
    while let Some(out) = set.join_next().await {
        let out = out.expect("the task should not panic");
        if let Action::Respond(m) = &out.action
            && m.metadata.response_code == ResponseCode::NoError
            && !m.answers.is_empty()
        {
            answered += 1;
        }
    }

    assert_eq!(answered, 5, "every caller should get the answer");
    assert_eq!(
        seen.count.load(Ordering::SeqCst),
        1,
        "only one request should have reached the upstream"
    );
}

#[tokio::test]
async fn a_coalesced_answer_is_addressed_to_each_asker() {
    // The waiters used to be handed the leader's answer with only the ID
    // changed: its question, spelled the way the leader spelled it, which a
    // client randomising the case of its names (DNS 0x20) rejects.
    let (server, seen) = upstream("192.0.2.1".parse().unwrap(), Duration::from_millis(150)).await;
    let r = Arc::new(
        resolver(
            server,
            Settings {
                pending_enabled: true,
                ..Default::default()
            },
        )
        .await,
    );

    let spellings = [
        "example.com.",
        "EXAMPLE.com.",
        "eXaMpLe.CoM.",
        "Example.Com.",
    ];
    let mut set = tokio::task::JoinSet::new();
    for (i, spelled) in spellings.into_iter().enumerate() {
        let r = r.clone();
        let mut req = request("example.com.");
        req.metadata.id = 0x1000 + i as u16;
        req.queries[0] = Query::query(Name::from_ascii(spelled).expect("a name"), RecordType::A);
        set.spawn(async move {
            let out = r.resolve(&req, Proto::Udp, &lan_client()).await;
            (req, out)
        });
    }

    while let Some(done) = set.join_next().await {
        let (req, out) = done.expect("the task should not panic");
        let Action::Respond(m) = &out.action else {
            panic!("no answer for {:?}", req.queries[0].name());
        };
        assert_eq!(m.metadata.id, req.metadata.id);
        assert_eq!(
            m.queries[0].name().to_ascii(),
            req.queries[0].name().to_ascii(),
            "each asker gets its own question back"
        );
    }
    assert_eq!(
        seen.count.load(Ordering::SeqCst),
        1,
        "and they shared one exchange"
    );
}

#[tokio::test]
async fn without_coalescing_every_request_goes_upstream() {
    let (server, seen) = upstream("192.0.2.1".parse().unwrap(), Duration::from_millis(150)).await;
    let r = Arc::new(resolver(server, Settings::default()).await);

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..3 {
        let r = r.clone();
        set.spawn(async move {
            r.resolve(&request("example.com."), Proto::Udp, &lan_client())
                .await
        });
    }
    while set.join_next().await.is_some() {}

    assert_eq!(seen.count.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn a_bogus_address_becomes_nxdomain() {
    // Some resolvers answer a name that does not exist with a search-page
    // address; that answer is worse than none.
    let (server, _) = upstream("192.0.2.77".parse().unwrap(), Duration::ZERO).await;
    let r = resolver(
        server,
        Settings {
            bogus_nxdomain: vec![("192.0.2.0".parse().unwrap(), 24)],
            ..Default::default()
        },
    )
    .await;

    let out = r
        .resolve(&request("example.com."), Proto::Udp, &lan_client())
        .await;
    let resp = out.response().expect("an answer");

    assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    assert!(resp.answers.is_empty());
}

#[tokio::test]
async fn an_address_outside_the_bogus_range_is_passed_through() {
    let (server, _) = upstream("198.51.100.5".parse().unwrap(), Duration::ZERO).await;
    let r = resolver(
        server,
        Settings {
            bogus_nxdomain: vec![("192.0.2.0".parse().unwrap(), 24)],
            ..Default::default()
        },
    )
    .await;

    let out = r
        .resolve(&request("example.com."), Proto::Udp, &lan_client())
        .await;
    let resp = out.response().expect("an answer");

    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert_eq!(resp.answers.len(), 1);
}

#[tokio::test]
async fn an_aaaa_query_is_synthesised_from_the_a_answer() {
    // The fake upstream answers every question with an address, so an AAAA
    // query comes back empty only because DNS64 rewrites what it receives;
    // here it answers A, which is what DNS64 asks for second.
    let (server, _) = upstream("192.0.2.33".parse().unwrap(), Duration::ZERO).await;
    let r = resolver(
        server,
        Settings {
            dns64: sift_dns::dns64::Prefixes::new(true, []),
            ..Default::default()
        },
    )
    .await;

    let mut req = Message::query();
    req.metadata.id = 1;
    req.add_query(Query::query(
        Name::from_utf8("example.com.").unwrap(),
        RecordType::AAAA,
    ));

    let out = r.resolve(&req, Proto::Udp, &lan_client()).await;
    let resp = out.response().expect("an answer");

    let addrs = sift_dns::resolver::answer_addrs(resp);
    assert_eq!(
        addrs,
        vec!["64:ff9b::c000:221".parse::<IpAddr>().unwrap()],
        "the IPv4 answer should be mapped into the well-known prefix"
    );
}
