//! The DNS-over-HTTPS listener.
//!
//! Served from the same router as the web interface, because upstream serves
//! both on the HTTPS port. Queries go through [`sift_dns::server::Server`]
//! rather than straight to the resolver, so DoH is subject to the same rate
//! limits, access control, query log and statistics as plain DNS.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::state::Shared;

/// The media type a DNS message is carried in.
const DNS_MESSAGE: &str = "application/dns-message";

/// The largest query this will accept.
///
/// A POSTed body is cut off at this many bytes while it is read, not buffered
/// and measured afterwards, and a GET's parameter is measured before it is
/// decoded.  It is also upstream's limit on every request body, DNS-over-HTTPS
/// included, which [`crate::routes::DEFAULT_BODY_LIMIT`] restates for the
/// rest of the router.
const MAX_QUERY: usize = 64 * 1024;

/// Marks whether the connection a request arrived on was encrypted.
///
/// Injected per listener: the TLS listener sets it, the plain one does not.
#[derive(Clone, Copy, Debug)]
pub struct Secure(pub bool);

/// Marks a response that answered a request without it having asked
/// anything a client of this server asks.
///
/// Set as a response extension, which never reaches the wire, and read by the
/// encrypted listeners when they tell the connection guard whether a
/// connection asked something: a DoH query refused by the access list is
/// answered with a 200 like any other, so the status alone cannot say.
#[derive(Clone, Copy, Debug)]
pub struct Unanswered;

/// Marks a response to a query the DNS server was too busy to answer: the
/// source's share of queries in flight was taken, or no worker came free in
/// time.
///
/// A response extension like [`Unanswered`], and never on the wire either.
/// It means something different: an overload is the server's doing, not the
/// client's, so the encrypted listeners count such an answer neither as
/// asking something nor as asking nothing -- see `crate::shield`.  Without
/// it, a DoH client asking during an overload collected SERVFAILs that did
/// not count, was closed for a run of refusals, and was struck for it, over
/// and over, until it was banned; while the sources causing the overload,
/// whose own lookups ended in an upstream's SERVFAIL, counted and were
/// never struck at all.
#[derive(Clone, Copy, Debug)]
pub struct Overloaded;

/// The server name the client sent in the TLS handshake of the connection a
/// request arrived on, or `None` when it sent none.
///
/// Inserted into every request by the encrypted listeners -- `https` from
/// rustls, `http3` from quinn's handshake data -- and absent on the plain
/// listener, which has no handshake.  A DoH query without a ClientID in its
/// path may carry one here, as `<id>.<tls.server_name>`.
#[derive(Clone, Debug)]
pub struct TlsServerName(pub Option<Arc<str>>);

/// The name a DoH request was addressed to, as upstream's
/// `clientServerNameFromHTTP` reads it.
///
/// Over TLS it is the server name from the handshake, and `None` when the
/// client sent none; the `Host` header is not consulted, since it says
/// nothing about the connection and a client may write anything there.
/// Without TLS -- the plain listener, with `http.doh.insecure_enabled` -- it
/// is the host the request names, from the URI's authority when it has one,
/// as HTTP/2 and absolute-form requests do, and from `Host` otherwise, with
/// the port taken off; `None` when there is none.
pub struct Addressed(Option<String>);

impl<S: Send + Sync> FromRequestParts<S> for Addressed {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        if parts.extensions.get::<Secure>().is_some_and(|s| s.0) {
            let sent = parts
                .extensions
                .get::<TlsServerName>()
                .and_then(|n| n.0.as_deref())
                .map(str::to_string);

            return Ok(Self(sent));
        }

        let host = match parts.uri.authority() {
            Some(a) => Some(a.as_str().rsplit_once('@').map_or(a.as_str(), |(_, h)| h)),
            None => parts
                .headers
                .get(header::HOST)
                .and_then(|v| v.to_str().ok()),
        };

        Ok(Self(
            host.map(|h| split_host(h).unwrap_or(h).to_string())
                .filter(|h| !h.is_empty()),
        ))
    }
}

/// The host of `host:port`, or all of it when it carries no port, as Go's
/// `netutil.SplitHost` has it: `[::1]:443` is `::1`, but `[::1]` is left
/// alone.
///
/// `None` for what Go's `net.SplitHostPort` refuses for a reason other than
/// a missing port -- `::1` with its brackets left off, a stray `]`.  The
/// caller then judges the value whole, which is never a DNS name, so it is
/// refused only under `strict_sni_check`; upstream refuses it whenever a
/// server name is set, a difference that needs a malformed `Host` header on
/// the plain listener to show.
fn split_host(hostport: &str) -> Option<&str> {
    // Without a colon there is no port to take off.
    let Some(i) = hostport.rfind(':') else {
        return Some(hostport);
    };

    let (host, j, k) = if hostport.starts_with('[') {
        let end = hostport.find(']')?;
        if end + 1 == hostport.len() {
            return Some(hostport);
        }
        if end + 1 != i {
            // A colon straight after the bracket that is not the last one is
            // too many colons; anything else there is a missing port.
            return (hostport.as_bytes()[end + 1] != b':').then_some(hostport);
        }

        (&hostport[1..end], 1, end + 1)
    } else {
        let host = &hostport[..i];
        if host.contains(':') {
            return None;
        }

        (host, 0, 0)
    };

    if hostport[j..].contains('[') || hostport[k..].contains(']') {
        return None;
    }

    Some(host)
}

/// The `?dns=` parameter of a GET query.
#[derive(Deserialize)]
pub struct DnsParam {
    /// The query, base64url-encoded without padding.
    #[serde(default)]
    pub dns: Option<String>,
}

/// `GET /dns-query`
pub async fn get(
    state: State<Shared>,
    secure: axum::Extension<Secure>,
    conn: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    addressed: Addressed,
    Query(p): Query<DnsParam>,
) -> Response {
    match query_param(p) {
        Ok(wire) => answer(state, secure, conn, headers, addressed, None, wire).await,
        Err(why) => bad_request(why),
    }
}

/// `GET /dns-query/{client_id}`
pub async fn get_with_client(
    state: State<Shared>,
    secure: axum::Extension<Secure>,
    conn: ConnectInfo<SocketAddr>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
    addressed: Addressed,
    Query(p): Query<DnsParam>,
) -> Response {
    match query_param(p) {
        Ok(wire) => {
            answer(
                state,
                secure,
                conn,
                headers,
                addressed,
                Some(client_id),
                wire,
            )
            .await
        }
        Err(why) => bad_request(why),
    }
}

/// `POST /dns-query`
pub async fn post(
    state: State<Shared>,
    secure: axum::Extension<Secure>,
    conn: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    addressed: Addressed,
    body: Body,
) -> Response {
    // Neither refusal needs the body, so neither waits for it.
    let refused = check_content_type(&headers).or_else(|| not_served(&state, secure.0.0));
    if let Some(r) = refused {
        return r;
    }

    match read_body(body).await {
        Ok(wire) => answer(state, secure, conn, headers, addressed, None, wire).await,
        Err(why) => bad_request(why),
    }
}

/// `POST /dns-query/{client_id}`
pub async fn post_with_client(
    state: State<Shared>,
    secure: axum::Extension<Secure>,
    conn: ConnectInfo<SocketAddr>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
    addressed: Addressed,
    body: Body,
) -> Response {
    // Neither refusal needs the body, so neither waits for it.
    let refused = check_content_type(&headers).or_else(|| not_served(&state, secure.0.0));
    if let Some(r) = refused {
        return r;
    }

    match read_body(body).await {
        Ok(wire) => {
            answer(
                state,
                secure,
                conn,
                headers,
                addressed,
                Some(client_id),
                wire,
            )
            .await
        }
        Err(why) => bad_request(why),
    }
}

/// The query a GET carries, or why it carries none.
fn query_param(p: DnsParam) -> Result<Bytes, &'static str> {
    let Some(encoded) = p.dns else {
        return Err("missing the dns parameter");
    };
    let Some(wire) = decode_query(&encoded) else {
        return Err("the dns parameter is not valid base64url");
    };

    Ok(Bytes::from(wire))
}

/// Reads a POSTed query, giving up as soon as it runs past [`MAX_QUERY`].
///
/// Read here rather than by the `Bytes` extractor so that a query too large
/// is answered as it always was, and as upstream's DoH handler answers one: a
/// 400, where the extractor would say 413.  The router's own limit is the
/// same size, so nothing larger reaches this either way.
async fn read_body(body: Body) -> Result<Bytes, &'static str> {
    axum::body::to_bytes(body, MAX_QUERY).await.map_err(|e| {
        if e.into_inner().is::<http_body_util::LengthLimitError>() {
            "the query is too large"
        } else {
            "the query could not be read"
        }
    })
}

/// Rejects a POST that does not carry a DNS message.
fn check_content_type(headers: &HeaderMap) -> Option<Response> {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());

    match ct {
        Some(v) if v.starts_with(DNS_MESSAGE) => None,
        _ => Some(unanswered(
            (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                format!("the body must be {DNS_MESSAGE}"),
            )
                .into_response(),
        )),
    }
}

/// Refuses DNS-over-HTTPS on a plain listener unless the operator allowed it.
///
/// Serving DNS over plain HTTP exposes queries to the network, so it is off
/// unless `http.doh.insecure_enabled` asks for it.
fn not_served(s: &Shared, encrypted: bool) -> Option<Response> {
    if encrypted || s.config.read().http.doh.insecure_enabled {
        return None;
    }

    Some(unanswered(
        (
            StatusCode::NOT_FOUND,
            "DNS-over-HTTPS is not served over plain HTTP; set http.doh.insecure_enabled to allow it",
        )
            .into_response(),
    ))
}

/// Marks a response as not having answered anything a client asks.
///
/// Every refusal carries it, not only the ones the listeners would otherwise
/// miscount: a status of 400 or more already says as much, but the marker
/// saying it too means the rule does not rest on the status alone.
fn unanswered(mut r: Response) -> Response {
    r.extensions_mut().insert(Unanswered);

    r
}

/// Decodes the base64url form a GET query carries.
///
/// RFC 8484 specifies base64url without padding, but some clients send it
/// padded, so both are accepted.
pub fn decode_query(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};

    if s.len() > MAX_QUERY {
        return None;
    }

    URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| URL_SAFE.decode(s))
        .ok()
}

/// Answers a query whose addressed name was refused: SERVFAIL, carried in a
/// 200 like any DNS answer, and marked as not asking anything.
///
/// When the bytes are not a DNS message there is no SERVFAIL to shape, and
/// the query is refused with the 400 an unanswered one always gets.
fn servfail(wire: &[u8]) -> Response {
    match sift_dns::server::Answer::servfail(wire).bytes {
        Some(bytes) => unanswered(([(header::CONTENT_TYPE, DNS_MESSAGE)], bytes).into_response()),
        None => bad_request("the query was not answered"),
    }
}

/// Builds a 400 with a plain-text reason.
fn bad_request(why: &str) -> Response {
    unanswered((StatusCode::BAD_REQUEST, why.to_string()).into_response())
}

/// The client address to attribute a request to.
///
/// When the connection comes from a trusted proxy, the left-most address in
/// `X-Forwarded-For` is the real client; from anywhere else the header is
/// attacker-controlled and is ignored, which is the whole point of the
/// `trusted_proxies` list.
pub fn real_client(
    peer: SocketAddr,
    headers: &HeaderMap,
    trusted: &[sift_config::types::Prefix],
) -> SocketAddr {
    if !trusted.iter().any(|p| p.contains(peer.ip())) {
        return peer;
    }

    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .and_then(|v| v.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok());

    match forwarded {
        Some(ip) => SocketAddr::new(ip, peer.port()),
        None => peer,
    }
}

/// Resolves a query and renders the reply.
///
/// The reply is marked [`Unanswered`] whenever the DNS server says the query
/// was not something a client asks -- refused by the access list, malformed,
/// unsupported -- so a scanner cannot clear its record with the connection
/// guard by sending one: the refusal is a 200 carrying a DNS message like any
/// other, and the marker is the only thing that tells them apart.  One the
/// server was too busy to answer is marked [`Overloaded`] instead; see
/// [`render`].
async fn answer(
    State(s): State<Shared>,
    axum::Extension(Secure(encrypted)): axum::Extension<Secure>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Addressed(sent): Addressed,
    client_id: Option<String>,
    wire: Bytes,
) -> Response {
    if let Some(r) = not_served(&s, encrypted) {
        return r;
    }

    if wire.len() > MAX_QUERY {
        return bad_request("the query is too large");
    }

    let client = real_client(peer, &headers, &s.config.read().dns.trusted_proxies);

    // A ClientID in the path wins, and is taken as it always was.  Without
    // one, upstream's `clientIDFromDNSContext` reads the name the request was
    // addressed to, as it does for DoT and DoQ: one label below
    // `tls.server_name` is a ClientID, and a name it refuses is answered
    // SERVFAIL before access control, the query log or the statistics see
    // the query.
    let client_id = match client_id.filter(|c| !c.is_empty()) {
        Some(id) => Some(id),
        None => match s.dns_server.client_id_for(sent.as_deref()) {
            Ok(id) => id,
            Err(e) => {
                tracing::debug!(client = %client.ip(), error = %e, "resolving client id");

                return servfail(&wire);
            }
        },
    };

    let reply = s
        .dns_server
        .answer(&wire, client, sift_dns::resolver::Proto::Https, client_id)
        .await;

    render(reply)
}

/// Renders what the DNS server made of a query, marked with what the
/// encrypted listeners need to know about it.
///
/// Exactly one of three: [`Overloaded`] when the server was too busy to
/// answer, [`Unanswered`] when the query was not something a client asks,
/// and nothing when it was.  An overloaded answer is not also marked
/// unanswered, because it is not: nothing is known about the query except
/// that it went unanswered for want of a worker.
fn render(reply: sift_dns::server::Answer) -> Response {
    let mut r = match reply.bytes {
        Some(resp) => ([(header::CONTENT_TYPE, DNS_MESSAGE)], resp).into_response(),
        // The query was refused or dropped: rate limited, blocked by access
        // control, or malformed.
        None => (StatusCode::BAD_REQUEST, "the query was not answered").into_response(),
    };

    if reply.busy {
        r.extensions_mut().insert(Overloaded);
    } else if !reply.counts {
        r.extensions_mut().insert(Unanswered);
    }

    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_both_padded_and_unpadded_base64url() {
        // "hello" in both forms.
        assert_eq!(decode_query("aGVsbG8").as_deref(), Some(&b"hello"[..]));
        assert_eq!(decode_query("aGVsbG8=").as_deref(), Some(&b"hello"[..]));
    }

    #[test]
    fn decodes_the_url_safe_alphabet() {
        // Bytes that encode to `-` and `_` rather than `+` and `/`.
        let raw = [0xFBu8, 0xFF, 0xBF];
        use base64::Engine as _;
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        assert!(enc.contains('-') || enc.contains('_'), "got {enc}");
        assert_eq!(decode_query(&enc).as_deref(), Some(&raw[..]));
    }

    #[test]
    fn rejects_nonsense_and_oversized_input() {
        assert!(decode_query("!!!not base64!!!").is_none());
        assert!(decode_query(&"A".repeat(MAX_QUERY + 1)).is_none());
    }

    #[test]
    fn each_answer_carries_exactly_the_marker_it_earned() {
        use sift_dns::server::Answer;

        let bytes = || Some(vec![0u8; 12]);
        let marks = |r: &Response| {
            (
                r.extensions().get::<Overloaded>().is_some(),
                r.extensions().get::<Unanswered>().is_some(),
            )
        };

        // Too busy to answer: a DNS answer like any other on the wire, and
        // marked as neither asking something nor asking nothing.
        let r = render(Answer {
            bytes: bytes(),
            counts: false,
            busy: true,
        });
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()[header::CONTENT_TYPE], DNS_MESSAGE);
        assert_eq!(marks(&r), (true, false));

        // Answered, but not a question a client asks.
        let r = render(Answer {
            bytes: bytes(),
            counts: false,
            busy: false,
        });
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(marks(&r), (false, true));

        // A question asked and answered.
        let r = render(Answer {
            bytes: bytes(),
            counts: true,
            busy: false,
        });
        assert_eq!(marks(&r), (false, false));

        // Nothing to send.
        let r = render(Answer {
            bytes: None,
            counts: false,
            busy: false,
        });
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(marks(&r), (false, true));
    }

    #[test]
    fn an_untrusted_forwarded_header_is_ignored() {
        // Anyone can send X-Forwarded-For; honouring it from an arbitrary
        // peer would let a client claim any address, and with it any other
        // client's per-client settings.
        let peer: SocketAddr = "192.0.2.9:5000".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "198.51.100.7".parse().unwrap());

        assert_eq!(real_client(peer, &h, &[]), peer);
    }

    #[test]
    fn a_trusted_proxy_supplies_the_real_client() {
        let peer: SocketAddr = "192.0.2.9:5000".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            "198.51.100.7, 203.0.113.1".parse().unwrap(),
        );

        let trusted = vec![sift_config::types::Prefix {
            addr: "192.0.2.0".parse().unwrap(),
            bits: 24,
        }];
        assert_eq!(
            real_client(peer, &h, &trusted).ip(),
            "198.51.100.7".parse::<std::net::IpAddr>().unwrap(),
            "the left-most address is the client"
        );
    }

    #[test]
    fn a_trusted_proxy_without_the_header_keeps_the_peer() {
        let peer: SocketAddr = "192.0.2.9:5000".parse().unwrap();
        let trusted = vec![sift_config::types::Prefix {
            addr: "192.0.2.0".parse().unwrap(),
            bits: 24,
        }];

        assert_eq!(real_client(peer, &HeaderMap::new(), &trusted), peer);
    }

    mod through_the_router {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use axum::body::Body;
        use axum::http::{Method, Request, StatusCode};
        use hickory_proto::op::{Message, Query, ResponseCode};
        use hickory_proto::rr::{Name, RecordType};
        use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

        use super::super::{DNS_MESSAGE, MAX_QUERY, TlsServerName, Unanswered};
        use crate::routes::testing::{self, CHUNK, Endless};
        use crate::state::Shared;

        fn query(name: &str) -> Vec<u8> {
            let mut m = Message::query();
            m.metadata.id = 0x4321;
            m.metadata.recursion_desired = true;
            m.add_query(Query::query(Name::from_utf8(name).unwrap(), RecordType::A));

            m.to_bytes().unwrap()
        }

        fn state() -> Shared {
            testing::state(vec![testing::user("admin", "pw", 4)], |l| l)
        }

        async fn post(s: &Shared, body: Body) -> axum::response::Response {
            let req = Request::builder()
                .method(Method::POST)
                .uri("/dns-query")
                .header("content-type", DNS_MESSAGE);

            testing::send(s, true, "192.0.2.1:5000", req, body).await
        }

        fn marked(r: &axum::response::Response) -> bool {
            r.extensions().get::<Unanswered>().is_some()
        }

        #[tokio::test]
        async fn a_query_refused_by_the_access_list_is_marked_unanswered() {
            // The refusal is a 200 carrying a DNS message like any other, so
            // without the marker a scanner refused by the access list would
            // clear its record with the connection guard by asking.
            let s = state();
            *s.dns_server.access.write() =
                sift_dns::server::Access::new(&[], &["192.0.2.1".to_string()]);

            let r = post(&s, Body::from(query("ads.example.com."))).await;
            assert_eq!(r.status(), StatusCode::OK, "answered as it always was");
            assert!(marked(&r), "but not as a client's question");

            let body = axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap();
            let m = Message::from_bytes(&body).unwrap();
            assert_eq!(m.metadata.response_code, ResponseCode::Refused);
        }

        #[tokio::test]
        async fn a_query_a_client_asks_is_not_marked() {
            let s = state();

            let r = post(&s, Body::from(query("ads.example.com."))).await;
            assert_eq!(r.status(), StatusCode::OK);
            assert!(!marked(&r), "a blocked name is still a question asked");

            let body = axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap();
            let m = Message::from_bytes(&body).unwrap();
            assert_eq!(m.metadata.id, 0x4321);
            assert_eq!(m.answers.len(), 1);
        }

        #[tokio::test]
        async fn every_refusal_is_marked_too() {
            let s = state();

            // Not a DNS message at all: the server sends nothing back.
            let r = post(&s, Body::from(&b"not dns"[..])).await;
            assert_eq!(r.status(), StatusCode::BAD_REQUEST);
            assert!(marked(&r));

            // The wrong media type.
            let req = Request::builder()
                .method(Method::POST)
                .uri("/dns-query")
                .header("content-type", "application/json");
            let r = testing::send(&s, true, "192.0.2.1:5000", req, Body::from("{}")).await;
            assert_eq!(r.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
            assert!(marked(&r));

            // Plain HTTP, which this server does not serve DNS over.
            let r = testing::send(
                &s,
                false,
                "192.0.2.1:5000",
                Request::builder()
                    .method(Method::POST)
                    .uri("/dns-query")
                    .header("content-type", DNS_MESSAGE),
                Body::from(query("ads.example.com.")),
            )
            .await;
            assert_eq!(r.status(), StatusCode::NOT_FOUND);
            assert!(marked(&r));
        }

        #[tokio::test]
        async fn a_post_over_64_kib_is_refused_while_it_is_read() {
            // axum's default let a DoH client make this buffer 2 MB before the
            // size was looked at.  Now the body is cut off at the limit, and
            // answered with the 400 it always got -- and upstream gives.
            let s = state();
            let taken = Arc::new(AtomicUsize::new(0));

            let r = post(
                &s,
                Body::new(Endless {
                    taken: taken.clone(),
                }),
            )
            .await;

            assert_eq!(r.status(), StatusCode::BAD_REQUEST);
            assert!(marked(&r));
            let body = axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(&body[..], b"the query is too large");

            let taken = taken.load(Ordering::Relaxed);
            assert!(
                taken <= MAX_QUERY + CHUNK,
                "read {taken} bytes of an endless body"
            );

            // A body of exactly the limit is still read, and judged as DNS.
            let r = post(&s, Body::from(vec![0u8; MAX_QUERY])).await;
            let body = axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_ne!(&body[..], b"the query is too large");
        }

        #[tokio::test]
        async fn a_get_that_carries_no_query_is_marked() {
            let s = state();

            for uri in [
                "/dns-query",
                "/dns-query?dns=!!!",
                "/dns-query/phone?dns=%00",
            ] {
                let r = testing::send(
                    &s,
                    true,
                    "192.0.2.1:5000",
                    Request::builder().uri(uri),
                    Body::empty(),
                )
                .await;

                assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{uri}");
                assert!(marked(&r), "{uri}");
            }
        }

        #[test]
        fn no_request_can_carry_a_get_parameter_past_the_limit() {
            // `http` refuses a URI longer than this before any router sees
            // it, so `decode_query`'s own check is the second line, not the
            // first: the parameter is bounded before it is even parsed.
            let long = format!("/dns-query?dns={}", "A".repeat(MAX_QUERY));
            assert!(long.parse::<axum::http::Uri>().is_err());
        }

        /// A server whose name is `dns.example.com`, and which refuses the
        /// client named `phone` -- so a test can tell which ClientID a query
        /// was taken as by whether it is refused.
        fn named(strict: bool) -> Shared {
            let s = state();
            s.dns_server.set_server_name("dns.example.com", strict);
            *s.dns_server.access.write() =
                sift_dns::server::Access::new(&[], &["phone".to_string()]);

            s
        }

        /// Posts a query over an encrypted listener to `path`, from a client
        /// that sent `sni` in its handshake.
        async fn post_to(s: &Shared, path: &str, sni: Option<&str>) -> axum::response::Response {
            let req = Request::builder()
                .method(Method::POST)
                .uri(path)
                .header("content-type", DNS_MESSAGE)
                .extension(TlsServerName(sni.map(Arc::from)));

            testing::send(
                s,
                true,
                "192.0.2.1:5000",
                req,
                Body::from(query("ads.example.com.")),
            )
            .await
        }

        /// The response code of a DoH answer, and whether it was marked as
        /// not asking anything.
        async fn rcode(r: axum::response::Response) -> (ResponseCode, bool) {
            assert_eq!(r.status(), StatusCode::OK);
            assert_eq!(r.headers()["content-type"], DNS_MESSAGE);
            let unanswered = marked(&r);

            let body = axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap();
            let m = Message::from_bytes(&body).unwrap();
            assert_eq!(m.metadata.id, 0x4321, "an answer to the query sent");

            (m.metadata.response_code, unanswered)
        }

        #[tokio::test]
        async fn a_client_id_below_the_server_name_is_read_from_the_tls_server_name() {
            let s = named(false);

            // `phone` is refused by name, so a refusal is the proof it was
            // read.
            let r = post_to(&s, "/dns-query", Some("phone.dns.example.com")).await;
            assert_eq!(rcode(r).await, (ResponseCode::Refused, true));

            // The server's own name carries none.
            let r = post_to(&s, "/dns-query", Some("dns.example.com")).await;
            assert_eq!(rcode(r).await, (ResponseCode::NoError, false));

            // And a GET is read the same way.
            use base64::Engine as _;
            let q =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(query("ads.example.com."));
            let req = Request::builder()
                .uri(format!("/dns-query?dns={q}"))
                .extension(TlsServerName(Some(Arc::from("phone.dns.example.com"))));
            let r = testing::send(&s, true, "192.0.2.1:5000", req, Body::empty()).await;
            assert_eq!(rcode(r).await, (ResponseCode::Refused, true));
        }

        #[tokio::test]
        async fn a_label_that_is_not_a_client_id_is_answered_servfail_strict_or_not() {
            for strict in [false, true] {
                let s = named(strict);

                let r = post_to(&s, "/dns-query", Some("phone_1.dns.example.com")).await;
                assert_eq!(
                    rcode(r).await,
                    (ResponseCode::ServFail, true),
                    "strict: {strict}"
                );
            }
        }

        #[tokio::test]
        async fn a_name_that_is_neither_is_answered_servfail_only_when_strict() {
            for sni in [Some("other.example.org"), Some("a.b.dns.example.com"), None] {
                let r = post_to(&named(false), "/dns-query", sni).await;
                assert_eq!(
                    rcode(r).await,
                    (ResponseCode::NoError, false),
                    "not strict: {sni:?}"
                );

                let r = post_to(&named(true), "/dns-query", sni).await;
                assert_eq!(
                    rcode(r).await,
                    (ResponseCode::ServFail, true),
                    "strict: {sni:?}"
                );
            }
        }

        #[tokio::test]
        async fn a_client_id_in_the_path_wins_over_the_server_name() {
            let s = named(true);

            // A name strict checking refuses does not matter once the path
            // names the client: `phone` is refused as `phone`, not SERVFAIL.
            let r = post_to(&s, "/dns-query/phone", Some("other.example.org")).await;
            assert_eq!(rcode(r).await, (ResponseCode::Refused, true));

            // And the path's ClientID is the one taken, not the name's.
            let r = post_to(&s, "/dns-query/laptop", Some("phone.dns.example.com")).await;
            assert_eq!(rcode(r).await, (ResponseCode::NoError, false));
        }

        #[tokio::test]
        async fn with_no_server_name_the_name_sent_changes_nothing() {
            let s = state();
            *s.dns_server.access.write() =
                sift_dns::server::Access::new(&[], &["phone".to_string()]);

            for sni in [
                Some("phone.dns.example.com"),
                Some("phone_1.dns.example.com"),
                Some("other.example.org"),
                None,
            ] {
                let r = post_to(&s, "/dns-query", sni).await;
                assert_eq!(rcode(r).await, (ResponseCode::NoError, false), "{sni:?}");
            }
        }

        #[tokio::test]
        async fn the_plain_listener_reads_the_host_and_the_encrypted_one_does_not() {
            let s = named(false);
            s.config.write().http.doh.insecure_enabled = true;

            // Without TLS there is no server name, so the host the request
            // names stands in for it, port and all taken off.
            for (uri, host) in [
                ("/dns-query", Some("phone.dns.example.com:80")),
                ("/dns-query", Some("phone.dns.example.com")),
                ("http://phone.dns.example.com:8080/dns-query", None),
            ] {
                let mut req = Request::builder()
                    .method(Method::POST)
                    .uri(uri)
                    .header("content-type", DNS_MESSAGE);
                if let Some(h) = host {
                    req = req.header("host", h);
                }
                let r = testing::send(
                    &s,
                    false,
                    "192.0.2.1:5000",
                    req,
                    Body::from(query("ads.example.com.")),
                )
                .await;
                assert_eq!(
                    rcode(r).await,
                    (ResponseCode::Refused, true),
                    "{uri} {host:?}"
                );
            }

            // Over TLS, a Host header naming a client is not the name the
            // client connected with.
            let req = Request::builder()
                .method(Method::POST)
                .uri("/dns-query")
                .header("content-type", DNS_MESSAGE)
                .header("host", "phone.dns.example.com")
                .extension(TlsServerName(Some(Arc::from("dns.example.com"))));
            let r = testing::send(
                &s,
                true,
                "192.0.2.1:5000",
                req,
                Body::from(query("ads.example.com.")),
            )
            .await;
            assert_eq!(rcode(r).await, (ResponseCode::NoError, false));
        }

        #[tokio::test]
        async fn bytes_that_are_not_a_query_to_a_refused_name_still_get_a_400() {
            // There is no SERVFAIL to shape for something that is not a DNS
            // message, so it is answered as the DNS server's silence always
            // was.
            let s = named(true);
            let req = Request::builder()
                .method(Method::POST)
                .uri("/dns-query")
                .header("content-type", DNS_MESSAGE)
                .extension(TlsServerName(Some(Arc::from("other.example.org"))));
            let r = testing::send(&s, true, "192.0.2.1:5000", req, Body::from("not dns")).await;

            assert_eq!(r.status(), StatusCode::BAD_REQUEST);
            assert!(marked(&r));
        }
    }

    #[test]
    fn the_port_is_taken_off_a_host_as_go_takes_it() {
        for (given, host) in [
            ("dns.example.com", Some("dns.example.com")),
            ("dns.example.com:443", Some("dns.example.com")),
            ("dns.example.com:", Some("dns.example.com")),
            ("[::1]:443", Some("::1")),
            // No port: Go leaves the brackets on.
            ("[::1]", Some("[::1]")),
            ("[::1]x", Some("[::1]x")),
            // What `net.SplitHostPort` refuses outright.
            ("::1", None),
            ("[::1]:1:2", None),
            ("[::1", None),
            ("a]b:1", None),
            ("[a[b]:1", None),
        ] {
            assert_eq!(split_host(given), host, "{given}");
        }
    }

    #[test]
    fn a_post_must_carry_a_dns_message() {
        let mut h = HeaderMap::new();
        assert!(
            check_content_type(&h).is_some(),
            "a missing type is refused"
        );

        h.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        assert!(
            check_content_type(&h).is_some(),
            "the wrong type is refused"
        );

        h.insert(header::CONTENT_TYPE, DNS_MESSAGE.parse().unwrap());
        assert!(check_content_type(&h).is_none());

        // A charset parameter is tolerated.
        h.insert(
            header::CONTENT_TYPE,
            format!("{DNS_MESSAGE}; charset=utf-8").parse().unwrap(),
        );
        assert!(check_content_type(&h).is_none());
    }
}
