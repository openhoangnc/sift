//! UDP and TCP listeners, and what every transport shares on the way to the
//! resolver.
//!
//! Four defences live here, and none of them is a rate -- `probe.rs` says
//! why rate is the wrong measure for a connection:
//!
//! - **A listener never stops.**  An accept that fails -- the process out of
//!   descriptors, or a connection that died in the queue -- is waited out and
//!   retried, and said in the log at most once a minute.  Returning from the
//!   loop instead closed the port for good while the rest of the process
//!   carried on as though nothing had happened.
//! - **A connection may be idle, but not slow.**  Between messages a client
//!   may take its time; once a message has begun, the rest of it has to
//!   follow within `MESSAGE_TIMEOUT`, and an answer has to be taken within
//!   `WRITE_TIMEOUT`.  A connection that stalls either way is closed and has
//!   asked nothing, whatever it asked before.
//! - **One source cannot take every worker.**  On the stream transports a
//!   source -- what the connection guard judges as one: an IPv4 address, an
//!   IPv6 /64, or an address in this host's own /64 -- may have
//!   `IN_FLIGHT_PER_SOURCE` queries being answered at once.  That bounds
//!   concurrency and not rate: a busy NAT whose queries are answered in
//!   milliseconds never comes near it, while one connection holding hundreds
//!   of lookups that wait out the upstream timeout does.
//! - **A flood of datagrams cannot become a flood of waiting tasks.**  While
//!   every worker is taken, at most `UDP_WAITING` datagrams wait for one, and
//!   the rest are dropped at once, as a full socket buffer drops them.
//!
//! The listeners also tell the connection guard how each connection behaved,
//! through `Conduct`, and two answers there are deliberately "nothing":
//! a connection whose questions were turned away only because the server was
//! busy, and one that closed at once without sending a byte -- before a TLS
//! handshake, on DoT, where after one it is a strike.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ahash::AHashMap;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::msg;
use crate::probe::{Guard, Source};
use crate::ratelimit::Limiter;
use crate::resolver::{Action, ClientInfo, Outcome, Proto, Resolver};

/// The largest datagram the server will read.
const UDP_BUF: usize = 4096;

/// How long a TCP client may stay idle between queries.
const TCP_IDLE: Duration = Duration::from_secs(30);

/// How long the rest of a message may take once its first byte has arrived.
///
/// A query is at most 64 KiB and a real one a few hundred bytes, sent in one
/// write: it arrives in one round trip.  Without a bound, a client that sends
/// a length and then nothing held its connection and descriptor for good.
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long an answer may take to be written and flushed.
///
/// A client that never reads what it is sent fills its window and then
/// blocks the write for as long as it likes; dnsproxy gives the same ten
/// seconds to a whole request.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a TLS handshake may take before the connection is dropped.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How soon after it is accepted a connection may close without sending a
/// byte and be charged nothing for it.
///
/// A port monitor -- Uptime Kuma's TCP check, `nc -z`, a load balancer's
/// health check -- closes the moment the connection is up, so a second is
/// ample.  One that stays connected longer before leaving without a word
/// held a descriptor, and on DoT a handshake slot, for all that time, which
/// is exactly the cost the guard exists to charge for: without the bound,
/// connecting and closing just before each deadline would hold both for
/// ever at no charge.
const SILENT_GRACE: Duration = Duration::from_secs(1);

/// Queries one source may have being answered at once on the stream
/// transports.
///
/// More than a household or an office asks at once: queries are answered in
/// milliseconds from the cache and in tens of them from an upstream, so even
/// a browser opening a page of forty names over one DoH connection has fewer
/// than this outstanding for longer than a round trip, and the few over it
/// wait for a slot rather than failing.  It takes ten sources rather than one
/// to fill the default `max_goroutines` of 300 with lookups that wait out a
/// ten-second upstream timeout.
const IN_FLIGHT_PER_SOURCE: usize = 32;

/// How long a query over its source's share waits for a slot before it is
/// answered `SERVFAIL`.
///
/// Long enough for one upstream round trip to free a slot, so a burst waits
/// rather than fails; short enough that a client whose source is holding all
/// of them hears so rather than timing out.
const IN_FLIGHT_WAIT: Duration = Duration::from_secs(1);

/// How long a query waits for one of the `max_goroutines` workers before it
/// is answered `SERVFAIL`, or on UDP dropped.
///
/// dnsproxy waits for ever, and does it in its accept loops, so a full
/// semaphore stops the listeners taking anything new until a slot frees.  A
/// stream client here is told instead, well inside its own timeout, and a
/// datagram is dropped, which is what a full socket buffer does to it there.
const WORKER_WAIT: Duration = Duration::from_secs(2);

/// Datagrams that may wait for a worker at once; past this, one that finds
/// every worker taken is dropped without waiting.
///
/// Each datagram is a task, and a task that waits holds its bytes and its
/// parsed message for up to `WORKER_WAIT`.  The rate limit does not bound how
/// many there are, because it counts per source and a datagram's source
/// costs nothing to forge, so a flood while the workers were all taken was a
/// flood of waiting tasks.  dnsproxy stops reading the socket instead, and
/// the kernel drops what does not fit in its buffer; this drops what does
/// not fit here.  A thousand is more than three times the default
/// `max_goroutines` queued behind the workers, a few megabytes at most --
/// and when every worker is held for longer than the wait, more than will be
/// answered in it anyway.  The stream transports are bounded by what may be
/// open and what one source may have in flight, so they are not counted.
const UDP_WAITING: usize = 1024;

/// How long an accept loop waits after an error that is not about one
/// connection, before it tries again -- what hyper did and axum does.
const ACCEPT_BACKOFF: Duration = Duration::from_secs(1);

/// How often a warning that can recur on every request may be logged.
const WARN_EVERY: u64 = 60;

/// Notified about every handled query, for the query log and statistics.
pub trait Observer: Send + Sync + 'static {
    /// Called once per handled request.
    fn observe(&self, ev: &Event<'_>);
}

/// A no-op observer, useful in tests and when logging is disabled.
pub struct NoopObserver;

impl Observer for NoopObserver {
    fn observe(&self, _ev: &Event<'_>) {}
}

/// Everything known about one handled request.
pub struct Event<'a> {
    /// The request as received.
    pub request: &'a Message,
    /// How the request was handled.
    pub outcome: &'a Outcome,
    /// The client's address.
    pub client: SocketAddr,
    /// The transport the request arrived on.
    pub proto: Proto,
}

/// One entry of an access list.
///
/// The field takes three forms, and the web interface says so: an address, a
/// CIDR network, or a ClientID -- the name a DoH path segment, a DoT server
/// name or a DoQ connection carries.  Upstream's `processAccessClients` sorts
/// each string into one of them and refuses anything else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccessEntry {
    /// One exact address.
    Ip(IpAddr),
    /// A network, as an address and a prefix length.
    Net(IpAddr, u8),
    /// A ClientID.
    Id(String),
}

/// Classifies one access-list entry, or `None` when it is none of the three.
///
/// The order is upstream's: an address, then a network, then a ClientID,
/// which is why `10.0.0.1` is an address and not a one-label name.
pub fn parse_access_entry(s: &str) -> Option<AccessEntry> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(AccessEntry::Ip(ip));
    }

    if let Some((addr, bits)) = s.split_once('/')
        && let Ok(ip) = addr.parse::<IpAddr>()
        && let Ok(bits) = bits.parse::<u8>()
    {
        let width = if ip.is_ipv4() { 32 } else { 128 };

        return (bits <= width).then_some(AccessEntry::Net(ip, bits));
    }

    is_valid_client_id(s).then(|| AccessEntry::Id(s.to_string()))
}

/// Reports whether a string is a usable ClientID.
///
/// Upstream's `client.ValidateClientID` is `netutil.ValidateHostnameLabel`: a
/// single DNS label, because that is what has to survive being a DoH path
/// segment and a DoT server name.
pub fn is_valid_client_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// One side of the access lists, sorted into the forms it accepts.
#[derive(Clone, Debug, Default)]
pub struct AccessList {
    /// Exact addresses.
    ips: Vec<IpAddr>,
    /// Networks.
    nets: Vec<(IpAddr, u8)>,
    /// ClientIDs.
    ids: Vec<String>,
}

impl AccessList {
    /// Sorts configured entries into the three forms.
    ///
    /// An entry that is none of them is dropped with a warning rather than
    /// refused: `/control/access/set` rejects one before it can be stored, so
    /// reaching here means a file edited by hand, and refusing to start over
    /// a typo would be worse than ignoring it loudly.
    pub fn parse(entries: &[String]) -> Self {
        let mut out = Self::default();
        for e in entries {
            match parse_access_entry(e) {
                Some(AccessEntry::Ip(ip)) => out.ips.push(ip),
                Some(AccessEntry::Net(ip, bits)) => out.nets.push((ip, bits)),
                Some(AccessEntry::Id(id)) => out.ids.push(id),
                None => {
                    tracing::warn!(entry = %e, "ignoring an access list entry that is not an ip address, a cidr or a clientid");
                }
            }
        }

        out
    }

    /// Reports whether nothing at all is listed.
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() && self.nets.is_empty() && self.ids.is_empty()
    }

    /// Reports whether an address is listed, by itself or by a network.
    fn has_ip(&self, ip: IpAddr) -> bool {
        self.ips.contains(&ip) || self.nets.iter().any(|&(net, bits)| in_net(ip, net, bits))
    }

    /// Reports whether a ClientID is listed.
    ///
    /// A request that carries none matches nothing, which is what keeps an
    /// allowlist of addresses working over plain UDP.
    fn has_id(&self, id: Option<&str>) -> bool {
        id.is_some_and(|id| self.ids.iter().any(|x| x == id))
    }
}

/// Reports whether `ip` falls inside the network `net/bits`.
///
/// Host bits in `net` are ignored rather than rejected, as Go's
/// `netip.Prefix.Contains` ignores them: `192.168.99.3/31` is the pair
/// `.2`-`.3`, not an error.
fn in_net(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            mask_bits(u32::from(a).into(), bits, 32) == mask_bits(u32::from(n).into(), bits, 32)
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            mask_bits(u128::from(a), bits, 128) == mask_bits(u128::from(n), bits, 128)
        }
        _ => false,
    }
}

/// Zeroes every bit of `v` below the top `bits` of a `width`-bit address.
///
/// A v4 address arrives widened into the low 32 bits, so the mask reaching
/// above `width` costs nothing: those bits are already zero on both sides.
fn mask_bits(v: u128, bits: u8, width: u32) -> u128 {
    if u32::from(bits) >= width {
        return v;
    }

    v & (u128::MAX << (width - u32::from(bits)))
}

/// Which clients may query this server.
///
/// Upstream's `accessManager`.  Holding only bare addresses -- which this
/// once did -- silently dropped every CIDR and every ClientID, so an
/// allowlist written in those forms parsed to nothing, and an empty allowlist
/// admits everybody.
#[derive(Clone, Debug, Default)]
pub struct Access {
    /// If anything is listed, only these clients may query.
    pub allowed: AccessList,
    /// These clients may not query.
    pub disallowed: AccessList,
}

impl Access {
    /// Builds the access control from the two configured lists.
    pub fn new(allowed: &[String], disallowed: &[String]) -> Self {
        Self {
            allowed: AccessList::parse(allowed),
            disallowed: AccessList::parse(disallowed),
        }
    }

    /// Reports whether a client may query.
    ///
    /// Upstream's `IsBlockedClient` combines the two checks differently in
    /// each mode, and the asymmetry is the point: in allowlist mode a client
    /// is refused only when *both* refuse it, so a listed ClientID gets in
    /// from an unlisted address and a listed address gets in with no ClientID
    /// at all.  In blocklist mode either one refusing is enough.
    pub fn permits(&self, ip: IpAddr, client_id: Option<&str>) -> bool {
        if !self.allowed.is_empty() {
            return self.allowed.has_ip(ip) || self.allowed.has_id(client_id);
        }

        !self.disallowed.has_ip(ip) && !self.disallowed.has_id(client_id)
    }
}

/// The name this server answers encrypted queries under, and whether a
/// client has to use it.
#[derive(Clone, Debug, Default)]
struct ServerName {
    /// `tls.server_name`, or empty when encryption is off.
    name: String,
    /// `tls.strict_sni_check`.
    strict: bool,
}

/// Why the server name a client connected with is refused, which answers
/// every query it asks `SERVFAIL`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ServerNameError {
    /// Strict checking is on, and the name is neither the server's own nor
    /// one label below it.
    #[error("client server name {sent:?} doesn't match host server name {host:?}")]
    Mismatch {
        /// What the client sent, empty when it sent nothing.
        sent: String,
        /// The configured server name.
        host: String,
    },
    /// The label below the server's name is not a usable ClientID.
    #[error("invalid clientid {0:?}")]
    InvalidClientId(String),
}

/// The shared state every listener needs.
pub struct Server {
    /// The resolver that answers queries.
    pub resolver: Arc<Resolver>,
    /// The rate limiter.
    pub limiter: Arc<Limiter>,
    /// Client access control.
    pub access: Arc<parking_lot::RwLock<Access>>,
    /// The query observer.
    pub observer: Arc<dyn Observer>,
    /// The guard over connections that never ask anything.
    ///
    /// The per-source bound on queries in flight asks it which sources are
    /// exempt, so the two never disagree about what is local.
    pub probes: Arc<Guard>,
    /// The bound on requests being handled at once, or `None` for no bound.
    ///
    /// This is `max_goroutines`: without it a flood of slow upstream lookups
    /// can pile up until the process runs out of memory.
    concurrency: parking_lot::RwLock<Option<Arc<tokio::sync::Semaphore>>>,
    /// Each source's share of the queries being answered on the stream
    /// transports.
    in_flight: Arc<InFlight>,
    /// The server name a ClientID is read from.
    server_name: parking_lot::RwLock<ServerName>,
    /// Queries answered `SERVFAIL` because a bound was reached, for the log.
    overloaded: Throttle,
    /// Datagrams waiting for a worker right now; see `UDP_WAITING`.
    udp_waiting: AtomicUsize,
}

impl Server {
    /// Builds a server around a resolver.
    pub fn new(
        resolver: Arc<Resolver>,
        limiter: Arc<Limiter>,
        observer: Arc<dyn Observer>,
    ) -> Self {
        let probes = Arc::new(Guard::default());

        Self {
            resolver,
            limiter,
            access: Arc::new(parking_lot::RwLock::new(Access::default())),
            observer,
            in_flight: Arc::new(InFlight::new(probes.clone())),
            probes,
            concurrency: parking_lot::RwLock::new(None),
            server_name: parking_lot::RwLock::new(ServerName::default()),
            overloaded: Throttle::new(),
            udp_waiting: AtomicUsize::new(0),
        }
    }

    /// Sets how many requests may be handled at once; zero means no bound.
    pub fn set_max_concurrent(&self, n: u32) {
        *self.concurrency.write() = (n > 0).then(|| {
            Arc::new(tokio::sync::Semaphore::new(
                usize::try_from(n).unwrap_or(usize::MAX),
            ))
        });
    }

    /// Configures the connection guard.
    ///
    /// The bound on queries in flight asks the guard whom it exempts --
    /// `ratelimit_whitelist`, and this network as `Guard::exempts` defines
    /// it -- so this configures that too, and the two cannot disagree.
    pub fn set_probe_config(&self, cfg: crate::probe::Config) {
        self.probes.set_config(cfg);
    }

    /// Sets the name encrypted clients connect to, and whether they must.
    ///
    /// `name` is `tls.server_name` and `strict` is `tls.strict_sni_check`,
    /// both only while encryption is on -- upstream hands its DNS server an
    /// empty TLS configuration otherwise.  Takes effect on the next
    /// connection.
    pub fn set_server_name(&self, name: &str, strict: bool) {
        *self.server_name.write() = ServerName {
            name: name.to_string(),
            strict,
        };
    }

    /// Reads a ClientID from the server name an encrypted client connected
    /// with, or refuses the name.
    ///
    /// Upstream's `clientIDFromClientServerName`, which runs on every query
    /// over DNS-over-TLS and DNS-over-QUIC, and over DNS-over-HTTPS when the
    /// path carries no ClientID.  `sent` is the TLS server name, or for
    /// DNS-over-HTTPS without TLS the `Host` header's host; `None` when the
    /// client sent none.  With no server name configured nothing is read and
    /// nothing is refused.  Otherwise:
    ///
    /// - the server's own name carries no ClientID;
    /// - one label below it is the ClientID, lowercased -- and a label that
    ///   is not a valid ClientID is refused whether or not the check is
    ///   strict, as upstream refuses it;
    /// - anything else carries none, or with `strict_sni_check` on is
    ///   refused.
    ///
    /// A refusal is answered `SERVFAIL`, query by query: see
    /// [`Answer::servfail`].  The names are compared without regard to case,
    /// where upstream compares them as sent: rustls lowercases the server
    /// name before anything here sees it.
    pub fn client_id_for(&self, sent: Option<&str>) -> Result<Option<String>, ServerNameError> {
        let ServerName { name, strict } = self.server_name.read().clone();

        client_id_from_server_name(&name, sent, strict)
    }

    /// Handles one request and returns the bytes to send back, if any.
    pub async fn handle(&self, wire: &[u8], client: SocketAddr, proto: Proto) -> Option<Vec<u8>> {
        self.handle_as(wire, client, proto, None).await
    }

    /// Handles one request on behalf of a named client.
    ///
    /// The ClientID comes from a DoH path segment or a DoT server name, and
    /// selects a persistent client's own settings.
    pub async fn handle_as(
        &self,
        wire: &[u8],
        client: SocketAddr,
        proto: Proto,
        client_id: Option<String>,
    ) -> Option<Vec<u8>> {
        self.answer(wire, client, proto, client_id).await.bytes
    }

    /// Handles one request, and says whether it was something a client asks.
    ///
    /// The connection guard in [`crate::probe`] forgives a source that asks
    /// something, so what counts as asking is a defence in itself: a stranger
    /// refused by the access list, or a scanner asking `version.bind`, is
    /// answered, but has not asked anything a client of this server would.
    pub async fn answer(
        &self,
        wire: &[u8],
        client: SocketAddr,
        proto: Proto,
        client_id: Option<String>,
    ) -> Answer {
        // Access control and rate limiting come before parsing, so a flood of
        // malformed datagrams costs as little as possible.
        if !self
            .access
            .read()
            .permits(client.ip(), client_id.as_deref())
        {
            // Silence only on a datagram transport, where a spoofed source
            // would turn the answer into amplification.  A connected client
            // has already paid for the handshake and upstream tells it
            // plainly, so closing the connection instead — which is what this
            // did — reads as a broken server rather than a refusal.
            if proto.is_datagram() {
                return Answer::NOTHING;
            }

            let bytes = Message::from_bytes(wire)
                .ok()
                .and_then(|req| msg::refused(&req).to_bytes().ok());

            return Answer {
                bytes,
                counts: false,
                busy: false,
            };
        }

        // The limit is a datagram defence, and upstream gates it on the
        // transport for exactly that reason:
        //
        //     // ratelimit based on IP only, protects CPU cycles and outbound
        //     // connections
        //     if d.Proto == ProtoUDP && p.isRatelimited(ip) {
        //
        // A stream client has completed a handshake, so the address it claims
        // is its own and no answer sent to it can be aimed at a victim.
        // Limiting one anyway cut off every client behind a single busy
        // address -- a NAT, an office, a phone hotspot -- and did it silently:
        // 60 queries at `ratelimit: 20` left 57 connections closed with no
        // answer, and on a kept-alive connection the next question could not
        // even be written.
        if proto.is_datagram() && !self.limiter.allow(client.ip()) {
            return Answer::NOTHING;
        }

        let Ok(req) = Message::from_bytes(wire) else {
            return Answer::NOTHING;
        };

        // A source's share first, so a query waiting for one holds no worker
        // while it waits.  Datagrams are left alone: the rate limit is their
        // defence, and a spoofed source would spend a victim's share.
        let _seat = if proto.is_datagram() {
            None
        } else {
            match self.in_flight.enter(client.ip()).await {
                Some(seat) => Some(seat),
                None => {
                    self.overload(client.ip(), "queries in flight from one source");

                    return Answer::overloaded(&req);
                }
            }
        };

        let sem = self.concurrency.read().clone();
        let _permit = match sem {
            Some(s) => match s.clone().try_acquire_owned() {
                Ok(p) => Some(p),
                Err(TryAcquireError::Closed) => return Answer::NOTHING,
                Err(TryAcquireError::NoPermits) => {
                    // Every worker is taken, so this waits -- and a datagram
                    // waits only while there is room for it to.
                    let _waiting = if proto.is_datagram() {
                        let Some(w) = Waiting::enter(&self.udp_waiting, UDP_WAITING) else {
                            self.overload(client.ip(), "max_goroutines");

                            return Answer::DROPPED_BUSY;
                        };

                        Some(w)
                    } else {
                        None
                    };

                    match tokio::time::timeout(WORKER_WAIT, s.acquire_owned()).await {
                        Ok(Ok(p)) => Some(p),
                        Ok(Err(_)) => return Answer::NOTHING,
                        Err(_) => {
                            self.overload(client.ip(), "max_goroutines");

                            // A datagram gets what a full socket buffer gives
                            // it upstream, and its client asks again; a
                            // connection must hear something.
                            return if proto.is_datagram() {
                                Answer::DROPPED_BUSY
                            } else {
                                Answer::overloaded(&req)
                            };
                        }
                    }
                }
            },
            None => None,
        };

        let info = ClientInfo {
            addr: Some(client.ip()),
            id: client_id,
            name: None,
            tags: Vec::new(),
        };
        let outcome = self.resolver.resolve(&req, proto, &info).await;

        self.observer.observe(&Event {
            request: &req,
            outcome: &outcome,
            client,
            proto,
        });

        match &outcome.action {
            Action::Drop => Answer::NOTHING,
            Action::Respond(resp) => {
                let bytes = resp.to_bytes().ok();

                Answer {
                    // A malformed or unsupported question is answered, but it
                    // is not what a client asks -- and neither is one of the
                    // names `dns.blocked_hosts` refuses, which by default are
                    // exactly what a scanner fingerprinting the server asks.
                    counts: bytes.is_some()
                        && !outcome.blocked_host
                        && !matches!(
                            resp.metadata.response_code,
                            ResponseCode::FormErr | ResponseCode::NotImp
                        ),
                    bytes,
                    busy: false,
                }
            }
        }
    }

    /// Notes a query answered `SERVFAIL` because a bound was reached, and
    /// says so at most once a minute.
    fn overload(&self, client: IpAddr, limit: &'static str) {
        if let Some(refused) = self.overloaded.due() {
            tracing::warn!(
                %client,
                limit,
                refused,
                "answering SERVFAIL: too many queries are being answered at once"
            );
        }
    }
}

/// What handling one request produced.
#[derive(Debug)]
pub struct Answer {
    /// The bytes to send back, if anything is to be sent.
    pub bytes: Option<Vec<u8>>,
    /// Whether the request was something a client of this server asks, which
    /// is what clears a source's record with the connection guard.
    ///
    /// Never true without `bytes`.
    pub counts: bool,
    /// Whether the request went unanswered because the server was busy --
    /// the source's share of queries in flight was taken, or no worker came
    /// free in time.
    ///
    /// Being busy is never held against a source, so a caller must treat
    /// such an answer as neither asking something nor asking nothing: a
    /// connection that saw one and nothing that counts is recorded with the
    /// guard not at all.  Never true together with `counts`.
    pub busy: bool,
}

impl Answer {
    /// Nothing to send, and nothing asked.
    const NOTHING: Self = Self {
        bytes: None,
        counts: false,
        busy: false,
    };

    /// `SERVFAIL` to a request that was not answered, which does not count
    /// as having been served.
    ///
    /// For a connection whose server name was refused -- see
    /// [`Server::client_id_for`] -- which upstream answers this way before
    /// the request reaches access control, the query log or the statistics.
    /// Nothing is sent when the bytes are not a DNS message, and a stream
    /// listener closes the connection then, as dnsproxy does.
    pub fn servfail(wire: &[u8]) -> Self {
        match Message::from_bytes(wire) {
            Ok(req) => Self::failure(&req),
            Err(_) => Self::NOTHING,
        }
    }

    /// `SERVFAIL` to a parsed request, shaped to it.
    fn failure(req: &Message) -> Self {
        let mut resp = msg::servfail(req);
        msg::shape_to_request(req, &mut resp);

        Self {
            bytes: resp.to_bytes().ok(),
            counts: false,
            busy: false,
        }
    }

    /// `SERVFAIL` to a request the server was too busy to answer.
    fn overloaded(req: &Message) -> Self {
        Self {
            busy: true,
            ..Self::failure(req)
        }
    }

    /// Nothing to send, because the server was too busy to answer.
    const DROPPED_BUSY: Self = Self {
        bytes: None,
        counts: false,
        busy: true,
    };
}

/// A warning that may be due on every request, said at most once a minute.
///
/// Shared by every task that can hit it, so it is atomics rather than a lock:
/// one caller a minute wins the right to log, and says how many there were.
struct Throttle {
    /// What the clock counts from.
    epoch: Instant,
    /// When the warning was last said, in seconds plus one, so zero is never.
    said: AtomicU64,
    /// Occurrences since.
    pending: AtomicU64,
}

impl Throttle {
    fn new() -> Self {
        Self {
            epoch: Instant::now(),
            said: AtomicU64::new(0),
            pending: AtomicU64::new(0),
        }
    }

    /// Counts one occurrence, returning how many there have been since the
    /// warning was last said when it is time to say it again.
    fn due(&self) -> Option<u64> {
        self.due_at(self.epoch.elapsed().as_secs())
    }

    /// `due`, at `secs` on the throttle's own clock.
    fn due_at(&self, secs: u64) -> Option<u64> {
        self.pending.fetch_add(1, Ordering::Relaxed);

        let now = secs.saturating_add(1);
        let said = self.said.load(Ordering::Relaxed);
        if said != 0 && now < said.saturating_add(WARN_EVERY) {
            return None;
        }

        self.said
            .compare_exchange(said, now, Ordering::Relaxed, Ordering::Relaxed)
            .ok()?;

        Some(self.pending.swap(0, Ordering::Relaxed))
    }
}

/// One datagram waiting for a worker, counted against `UDP_WAITING` until it
/// is dropped.
struct Waiting<'a>(&'a AtomicUsize);

impl<'a> Waiting<'a> {
    /// Counts one more waiting in `count`, or `None` when `max` already are.
    fn enter(count: &'a AtomicUsize, max: usize) -> Option<Self> {
        count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < max).then_some(n + 1)
            })
            .ok()?;

        Some(Self(count))
    }
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// How one connection behaved, as the connection guard is to be told it.
///
/// Four outcomes rather than the count the guard takes, because two of them
/// are not reported to it at all, and whether the last one is depends on
/// the transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Conduct {
    /// It was answered this many queries a client asks, at least one.
    Served(u32),
    /// It asked nothing a client asks.
    Wasted,
    /// Nothing it asked counted, and some of it was turned away because the
    /// server was busy.  Being busy is never held against a source, and a
    /// connection that asked only while the server was overloaded -- which
    /// is every connection, during a flood of slow lookups -- would
    /// otherwise earn its source a strike for each, and a ban.
    Busy,
    /// It closed without sending a byte, within `SILENT_GRACE` of opening.
    /// Whether that cost anything depends on the transport: nothing on plain
    /// TCP, a handshake after TLS.
    Silent,
}

impl Conduct {
    /// Tells `guard` how a connection from `ip` behaved.
    pub(crate) fn report(self, guard: &Guard, ip: IpAddr) {
        match self {
            Self::Served(n) => guard.record(ip, n),
            Self::Wasted => guard.record(ip, 0),
            Self::Busy | Self::Silent => {}
        }
    }
}

/// What the questions on one connection have come to so far.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Tally {
    /// Queries answered that a client asks.
    counted: u32,
    /// Whether any was turned away because the server was busy.
    busy: bool,
}

impl Tally {
    /// Adds what one question came to.
    pub(crate) fn add(&mut self, c: Conduct) {
        match c {
            Conduct::Served(n) => self.counted = self.counted.saturating_add(n),
            Conduct::Busy => self.busy = true,
            Conduct::Wasted | Conduct::Silent => {}
        }
    }

    /// What the connection came to: served if anything counted, busy if
    /// nothing did but the server was, and otherwise nothing asked.
    pub(crate) fn conduct(self) -> Conduct {
        if self.counted > 0 {
            Conduct::Served(self.counted)
        } else if self.busy {
            Conduct::Busy
        } else {
            Conduct::Wasted
        }
    }
}

/// Each source's share of the queries being answered at once.
///
/// A semaphore per source, held only while something from it is being
/// answered or waiting to be: the table holds the sources with a query in
/// hand, not every source ever seen, so a scan from a million addresses
/// costs nothing once it has been answered.
///
/// A source is what the connection guard judges as one -- an IPv4 address,
/// an IPv6 /64, or inside this host's own /64s a single address -- so the
/// two draw the line in the same place: a household reaching the server by
/// its global IPv6 address is a share per device, not one between them all.
struct InFlight {
    sources: parking_lot::Mutex<AHashMap<Source, Arc<Semaphore>>>,
    /// Who is exempt, and what counts as one source, are the connection
    /// guard's to say, so that they mean here exactly what they mean to it.
    guard: Arc<Guard>,
}

impl InFlight {
    fn new(guard: Arc<Guard>) -> Self {
        Self {
            sources: parking_lot::Mutex::default(),
            guard,
        }
    }

    /// Takes one of `ip`'s slots, waiting up to `IN_FLIGHT_WAIT` for one to
    /// free, or `None` when none did.  An exempt source is given one that
    /// counts nothing.
    async fn enter(self: &Arc<Self>, ip: IpAddr) -> Option<Seat> {
        if self.guard.exempts(ip) {
            return Some(Seat {
                held: None,
                permit: None,
            });
        }

        let source = self.guard.source(ip);
        let sem = self
            .sources
            .lock()
            .entry(source)
            .or_insert_with(|| Arc::new(Semaphore::new(IN_FLIGHT_PER_SOURCE)))
            .clone();

        // Made before the wait, so that a caller who gives up -- a DoH
        // request cancelled while it waits -- still gives the entry back.
        let mut seat = Seat {
            held: Some((self.clone(), source, sem.clone())),
            permit: None,
        };

        let acquired = tokio::time::timeout(IN_FLIGHT_WAIT, sem.acquire_owned()).await;
        seat.permit = Some(acquired.ok()?.ok()?);

        Some(seat)
    }

    /// The sources with something in hand, for the tests.
    #[cfg(test)]
    fn sources(&self) -> usize {
        self.sources.lock().len()
    }
}

#[cfg(test)]
impl Server {
    /// Takes every one of `ip`'s slots among the queries in flight, until
    /// what is returned is dropped: what a source holding its whole share
    /// with slow lookups looks like to its other queries.
    pub(crate) async fn fill_share(&self, ip: IpAddr) -> Vec<Seat> {
        let mut seats = Vec::new();
        for _ in 0..IN_FLIGHT_PER_SOURCE {
            seats.push(self.in_flight.enter(ip).await.expect("a free slot"));
        }

        seats
    }
}

/// One query's slot in its source's share, given back when dropped.
pub(crate) struct Seat {
    /// The table, the source and its semaphore; `None` for an exempt source.
    held: Option<(Arc<InFlight>, Source, Arc<Semaphore>)>,
    /// The slot itself, once taken.
    permit: Option<OwnedSemaphorePermit>,
}

impl Drop for Seat {
    fn drop(&mut self) {
        drop(self.permit.take());

        let Some((table, source, sem)) = self.held.take() else {
            return;
        };
        drop(sem);

        // Every other holder of the semaphore -- a slot, a waiter, a seat
        // being made -- took its reference under this lock, so a count of
        // one under it means the table's is the last.
        let mut sources = table.sources.lock();
        if sources
            .get(&source)
            .is_some_and(|s| Arc::strong_count(s) == 1)
        {
            sources.remove(&source);
        }
    }
}

/// Something connections are accepted from: a TCP listener, or in the tests
/// one that fails on demand.
trait Accept: Send + Sync + 'static {
    /// One accepted connection.
    type Conn: Send + 'static;

    /// Waits for the next connection.
    fn accept(&self) -> impl Future<Output = io::Result<(Self::Conn, SocketAddr)>> + Send;
}

impl Accept for TcpListener {
    type Conn = TcpStream;

    fn accept(&self) -> impl Future<Output = io::Result<(TcpStream, SocketAddr)>> + Send {
        TcpListener::accept(self)
    }
}

/// How a listener rides out what its socket reports.
///
/// Two kinds of error come out of `accept`.  One is about a single
/// connection -- it was reset or aborted while it waited in the queue -- and
/// the next accept is unaffected, so the loop simply carries on, as axum's
/// does.  The other is about the process: out of descriptors, out of memory.
/// That clears only when something else closes, and asking again at once
/// would spin a core against it, so the loop waits `ACCEPT_BACKOFF` first.
/// Neither ends the loop.  dnsproxy returns from its accept loop on any
/// error, and it gets away with it more often only because Go raises the
/// descriptor limit at start.
pub struct AcceptErrors {
    /// Which listener, for the log.
    what: &'static str,
    /// The warning, at most once a minute.
    throttle: Throttle,
}

impl AcceptErrors {
    /// A listener's record of its errors; `what` names it in the log.
    pub fn new(what: &'static str) -> Self {
        Self {
            what,
            throttle: Throttle::new(),
        }
    }

    /// Decides what to do after `e`: carry on at once (`None`), or wait for
    /// the returned time first.  Errors of the second kind are logged, at most
    /// once a minute, with how many there were.
    pub fn pause_after(&self, e: &io::Error) -> Option<Duration> {
        if is_connection_error(e) {
            return None;
        }

        if let Some(errors) = self.throttle.due() {
            tracing::error!(
                listener = self.what,
                error = %e,
                errors,
                "accepting failed; trying again every second"
            );
        }

        Some(ACCEPT_BACKOFF)
    }
}

/// Reports whether an error from `accept` or `recv_from` is about one peer
/// rather than the socket.
///
/// Linux's `accept` hands a pending connection's network error back as its
/// own; Windows reports an ICMP unreachable for an earlier datagram on the
/// next `recv_from`.  Neither says anything about the next call.
fn is_connection_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
            | io::ErrorKind::TimedOut
            | io::ErrorKind::NetworkDown
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
    )
}

/// Waits for the next connection, riding out whatever the listener reports
/// in between, or `None` once `shutdown` resolves.
async fn next_conn<L: Accept, F: Future<Output = ()>>(
    listener: &L,
    errors: &AcceptErrors,
    shutdown: &mut Pin<&mut F>,
) -> Option<(L::Conn, SocketAddr)> {
    loop {
        let accepted = tokio::select! {
            r = listener.accept() => r,
            () = shutdown.as_mut() => return None,
        };

        match accepted {
            Ok(c) => return Some(c),
            Err(e) => {
                if let Some(pause) = errors.pause_after(&e) {
                    tokio::select! {
                        () = tokio::time::sleep(pause) => {}
                        () = shutdown.as_mut() => return None,
                    }
                }
            }
        }
    }
}

/// Serves plain DNS over UDP until `shutdown` resolves.
///
/// An error reading the socket is ridden out as an accept error is, rather
/// than closing port 53 for good.
pub async fn serve_udp(
    sock: UdpSocket,
    server: Arc<Server>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) {
    let sock = Arc::new(sock);
    let errors = AcceptErrors::new("dns over udp");
    tokio::pin!(shutdown);

    let mut buf = vec![0u8; UDP_BUF];
    loop {
        let received = tokio::select! {
            r = sock.recv_from(&mut buf) => r,
            () = shutdown.as_mut() => break,
        };

        let (n, peer) = match received {
            Ok(r) => r,
            Err(e) => {
                if let Some(pause) = errors.pause_after(&e) {
                    tokio::select! {
                        () = tokio::time::sleep(pause) => {}
                        () = shutdown.as_mut() => break,
                    }
                }

                continue;
            }
        };

        let wire = buf[..n].to_vec();
        let server = server.clone();
        let sock = sock.clone();
        tokio::spawn(async move {
            if let Some(resp) = server.handle(&wire, peer, Proto::Udp).await {
                // Already cut to what this client said it could receive, by
                // `msg::truncate` in the resolver -- see the comment there for
                // why it does not happen at this end.
                let _ = sock.send_to(&resp, peer).await;
            }
        });
    }

    tracing::debug!(addr = ?sock.local_addr().ok(), "dns over udp stopped: shutting down");
}

/// Serves plain DNS over TCP until `shutdown` resolves.
///
/// Returns only then: an error accepting is ridden out, see
/// [`AcceptErrors`].
pub async fn serve_tcp(
    listener: TcpListener,
    server: Arc<Server>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) {
    let addr = listener.local_addr().ok();
    tcp_loop(listener, server, shutdown).await;
    tracing::debug!(?addr, "dns over tcp stopped: shutting down");
}

/// The accept loop behind [`serve_tcp`].
async fn tcp_loop<L: Accept<Conn = TcpStream>>(
    listener: L,
    server: Arc<Server>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) {
    let errors = AcceptErrors::new("dns over tcp");
    tokio::pin!(shutdown);

    while let Some((stream, peer)) = next_conn(&listener, &errors, &mut shutdown).await {
        // A source serving a penalty, or one at a limit on what may be open
        // at once, is closed here before anything is read from it.
        let Ok(ticket) = server.probes.open(peer.ip()) else {
            continue;
        };

        let server = server.clone();
        tokio::spawn(async move {
            stream.set_nodelay(true).ok();

            // Plain DNS has no handshake, so a connection that closes at
            // once before its first byte cost an accept and nothing else, and
            // is charged nothing: `Conduct::Silent` is reported as it is.
            serve_stream(stream, &server, peer, Proto::Tcp, Ok(None))
                .await
                .report(&server.probes, peer.ip());
            drop(ticket);
        });
    }
}

/// Serves DNS-over-TLS until `shutdown` resolves.
///
/// A handshake failure closes that one connection and leaves the listener
/// running: an unreachable server is a worse outcome than a rejected client.
/// Like [`serve_tcp`] it returns only at shutdown.
///
/// A client that connects with `<id>.<tls.server_name>` is asking to be
/// treated as the client named `<id>`, which is how a ClientID reaches a DoT
/// listener; see [`Server::client_id_for`] for which names are refused.
pub async fn serve_dot(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    server: Arc<Server>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) {
    let addr = listener.local_addr().ok();
    dot_loop(listener, tls, server, TLS_HANDSHAKE_TIMEOUT, shutdown).await;
    tracing::debug!(?addr, "dns over tls stopped: shutting down");
}

/// The accept loop behind [`serve_dot`], allowing each connection `handshake`
/// to send its first byte and finish its handshake.
async fn dot_loop<L: Accept<Conn = TcpStream>>(
    listener: L,
    tls: Arc<rustls::ServerConfig>,
    server: Arc<Server>,
    handshake: Duration,
    shutdown: impl std::future::Future<Output = ()> + Send,
) {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let errors = AcceptErrors::new("dns over tls");
    tokio::pin!(shutdown);

    while let Some((stream, peer)) = next_conn(&listener, &errors, &mut shutdown).await {
        let ip = peer.ip();

        // The handshake is the cost a scanner imposes, so a source serving a
        // penalty is closed before it, without a byte of TLS being read --
        // and so is anyone once too many connections, or too many
        // handshakes, are open, which is being busy rather than an offence.
        let Ok(ticket) = server.probes.open(ip) else {
            continue;
        };
        let Some(slot) = server.probes.handshake(ip) else {
            continue;
        };

        let server = server.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            stream.set_nodelay(true).ok();

            // Bound the handshake so a client that connects and says nothing
            // cannot hold a task open.  The deadline covers the wait for the
            // first byte as well as the handshake after it.
            let opened = tokio::time::Instant::now();
            let deadline = opened + handshake;

            // Nothing has been spent on a connection until its first byte
            // arrives, so one that closes at once without sending any is
            // charged nothing: an uptime monitor checking that the port is
            // open does exactly that, every few seconds, and was banned for
            // it with no way to find out why.  One that sends nothing for
            // longer held a descriptor and a handshake slot all that time:
            // it goes on to the handshake like anything else, which fails at
            // once, and is charged as a handshake that never finished.
            let mut first = [0u8; 1];
            let closed_at_once =
                match tokio::time::timeout_at(deadline, stream.peek(&mut first)).await {
                    Ok(Ok(0) | Err(_)) => opened.elapsed() < SILENT_GRACE,
                    Ok(Ok(_)) | Err(_) => false,
                };
            if closed_at_once {
                return;
            }

            let accepted = tokio::time::timeout_at(deadline, acceptor.accept(stream)).await;
            drop(slot);
            let Ok(Ok(tls_stream)) = accepted else {
                // A handshake that never finished asked nothing by
                // definition, and TCP has already proved the address.  A
                // name `strict_sni_check` refused ends up here too.
                server.probes.wasted(ip);

                return;
            };

            let named = server.client_id_for(tls_stream.get_ref().1.server_name());
            if let Err(e) = &named {
                tracing::debug!(client = %ip, error = %e, "resolving client id");
            }

            // After a handshake, closing without a word is exactly what a
            // scanner does: the handshake was the cost, and it was paid.
            let conduct = match serve_stream(tls_stream, &server, peer, Proto::Tls, named).await {
                Conduct::Silent => Conduct::Wasted,
                c => c,
            };
            conduct.report(&server.probes, ip);
            drop(ticket);
        });
    }
}

/// Extracts a ClientID from the name a client asked for.
///
/// Only the label directly below the server's own name counts, and the name
/// itself carries no identifier.  A client that asks for something unrelated
/// gets no identifier rather than having part of that name taken as one.
///
/// The listeners use [`Server::client_id_for`], which also refuses what
/// upstream refuses; this is the lenient reading of the same rule.
pub fn client_id_from_sni(sni: &str, server_name: &str) -> Option<String> {
    client_id_from_server_name(server_name, Some(sni), false)
        .ok()
        .flatten()
}

/// Upstream's `clientIDFromClientServerName`: see [`Server::client_id_for`].
fn client_id_from_server_name(
    host: &str,
    sent: Option<&str>,
    strict: bool,
) -> Result<Option<String>, ServerNameError> {
    if host.is_empty() {
        return Ok(None);
    }

    let raw = sent.unwrap_or_default();
    let sent = raw.trim_end_matches('.').to_ascii_lowercase();
    let host_lc = host.trim_end_matches('.').to_ascii_lowercase();
    if sent == host_lc {
        return Ok(None);
    }

    // netutil.IsImmediateSubdomain: longer by a dot and a label, and ending
    // in the host's name.
    let id = sent
        .strip_suffix(host_lc.as_str())
        .and_then(|rest| rest.strip_suffix('.'))
        .filter(|id| !id.is_empty() && !id.contains('.'));
    let Some(id) = id else {
        if !strict {
            return Ok(None);
        }

        return Err(ServerNameError::Mismatch {
            sent: raw.to_string(),
            host: host.to_string(),
        });
    };

    if !is_valid_client_id(id) {
        return Err(ServerNameError::InvalidClientId(id.to_string()));
    }

    Ok(Some(id.to_string()))
}

/// Why a stream stopped being served.
enum Stop {
    /// It closed, went idle, or sent something that ends it: what it asked
    /// before counts.
    Closed,
    /// It stalled mid-message, or would not take an answer: it asked
    /// nothing, whatever it asked before.
    Stalled,
}

/// Handles queries on one stream until it closes, goes idle or stalls, and
/// says how it behaved.
///
/// Plain DNS over TCP and DNS-over-TLS share this: both carry the same
/// two-byte-length framing, and only the transport underneath differs.
/// `named` is what [`Server::client_id_for`] made of the server name the
/// connection was opened with; a refused one is answered `SERVFAIL`, query by
/// query, which is served to nobody.
///
/// A stream that closes within `SILENT_GRACE` without sending a byte is
/// `Conduct::Silent`, which the caller judges: it has paid for a handshake
/// or it has not.  One that stays longer before leaving without a word, or
/// goes idle, held its descriptor all that time and asked nothing.
async fn serve_stream<S>(
    mut stream: S,
    server: &Server,
    peer: SocketAddr,
    proto: Proto,
    named: Result<Option<String>, ServerNameError>,
) -> Conduct
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let opened = tokio::time::Instant::now();
    let mut tally = Tally::default();
    let mut spoke = false;

    let stop = loop {
        // Between messages a client may take its time: that is what keeping
        // a connection open is for.
        let first = match tokio::time::timeout(TCP_IDLE, stream.read_u8()).await {
            Ok(Ok(b)) => b,
            // Closed, or reset, at once and before a byte of anything.
            Ok(Err(_)) if !spoke && opened.elapsed() < SILENT_GRACE => return Conduct::Silent,
            // Idle timeout or a clean close.
            _ => break Stop::Closed,
        };
        spoke = true;

        // Once a message has begun, the rest of it has to follow.
        let wire =
            match tokio::time::timeout(MESSAGE_TIMEOUT, read_message(&mut stream, first)).await {
                Ok(Ok(w)) => w,
                _ => break Stop::Stalled,
            };
        if wire.is_empty() {
            break Stop::Closed;
        }

        let answer = match &named {
            Ok(id) => server.answer(&wire, peer, proto, id.clone()).await,
            Err(_) => Answer::servfail(&wire),
        };

        // Held neither for nor against it, whether or not the client stays
        // to read that it was turned away.
        if answer.busy {
            tally.add(Conduct::Busy);
        }

        // Nothing to send: close rather than leave the client waiting.  Bytes
        // that do not parse as a query buy a scanner nothing.
        let Some(resp) = answer.bytes else {
            break Stop::Closed;
        };
        let Ok(len) = u16::try_from(resp.len()) else {
            break Stop::Closed;
        };

        // One write, so the length and the message leave in one TLS record.
        let mut framed = Vec::with_capacity(resp.len() + 2);
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(&resp);

        let sent = tokio::time::timeout(WRITE_TIMEOUT, async {
            stream.write_all(&framed).await?;
            stream.flush().await
        })
        .await;
        match sent {
            Ok(Ok(())) => {}
            Ok(Err(_)) => break Stop::Closed,
            Err(_) => break Stop::Stalled,
        }

        // Answered, but not necessarily served: a refusal of a stranger, or
        // of `version.bind`, is not what a client asks.
        if answer.counts {
            tally.add(Conduct::Served(1));
        }
    };

    match stop {
        Stop::Closed => tally.conduct(),
        Stop::Stalled => Conduct::Wasted,
    }
}

/// Reads the rest of one length-prefixed message whose first byte has
/// arrived.
///
/// The buffer grows with what actually arrives rather than being allocated
/// at the length the client claims, so a claim of 64 KiB followed by nothing
/// costs nothing.  A message cut short is an error.
async fn read_message<S: AsyncRead + Unpin>(stream: &mut S, first: u8) -> io::Result<Vec<u8>> {
    let second = stream.read_u8().await?;
    let len = u16::from_be_bytes([first, second]);

    let mut wire = Vec::new();
    (&mut *stream)
        .take(u64::from(len))
        .read_to_end(&mut wire)
        .await?;
    if wire.len() != usize::from(len) {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }

    Ok(wire)
}

/// Binds a UDP socket, allowing address reuse so restarts do not fail.
pub async fn bind_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    UdpSocket::bind(addr).await
}

/// Binds a TCP listener.
pub async fn bind_tcp(addr: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(addr).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{Cache, Config as CacheConfig};
    use crate::pool::{Mode, Pool, SharedPool};
    use crate::ratelimit::Config as RlConfig;
    use crate::resolver::Settings;
    use crate::rewrite::Table;
    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RecordType};
    use sift_filter::engine::Engine;

    fn test_server(rules: &str, per_second: u32) -> Arc<Server> {
        test_server_with(rules, per_second, Settings::default())
    }

    fn test_server_with(rules: &str, per_second: u32, settings: Settings) -> Arc<Server> {
        let resolver = Resolver::new(
            Engine::build([(1i64, rules)], sift_filter::engine::NO_LISTS),
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
            settings,
        );

        Arc::new(Server::new(
            Arc::new(resolver),
            Arc::new(Limiter::new(RlConfig {
                per_second,
                ..Default::default()
            })),
            Arc::new(NoopObserver),
        ))
    }

    fn wire_query(name: &str, qt: RecordType) -> Vec<u8> {
        let mut m = Message::query();
        m.metadata.id = 0x2222;
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_utf8(name).unwrap(), qt));

        m.to_bytes().unwrap()
    }

    fn peer() -> SocketAddr {
        "192.0.2.10:5000".parse().unwrap()
    }

    #[tokio::test]
    async fn answers_a_blocked_query_over_udp() {
        let s = test_server("||ads.example.com^\n", 0);
        let out = s
            .handle(
                &wire_query("ads.example.com.", RecordType::A),
                peer(),
                Proto::Udp,
            )
            .await
            .expect("should answer");

        let resp = Message::from_bytes(&out).unwrap();
        assert_eq!(resp.metadata.id, 0x2222);
        assert_eq!(resp.answers.len(), 1);
    }

    #[tokio::test]
    async fn garbage_input_produces_no_response() {
        let s = test_server("", 0);
        assert!(
            s.handle(b"not a dns message", peer(), Proto::Udp)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn access_control_blocks_disallowed_clients() {
        let s = test_server("||ads.example.com^\n", 0);
        s.access.write().disallowed = AccessList::parse(&[peer().ip().to_string()]);
        assert!(
            s.handle(
                &wire_query("ads.example.com.", RecordType::A),
                peer(),
                Proto::Udp
            )
            .await
            .is_none()
        );
    }

    #[tokio::test]
    async fn a_blocked_client_is_refused_rather_than_cut_off_on_stream_transports() {
        // Upstream drops only on UDP and DNSCrypt, where a spoofed source
        // would make the answer amplification; every connected transport gets
        // REFUSED.  Returning nothing closed the connection instead, which
        // `dig +tcp` reports as "communications error: end of file".
        use hickory_proto::op::ResponseCode;

        let s = test_server("||ads.example.com^\n", 0);
        s.access.write().disallowed = AccessList::parse(&[peer().ip().to_string()]);
        let q = wire_query("example.com.", RecordType::A);

        for proto in [Proto::Tcp, Proto::Tls, Proto::Https, Proto::Quic] {
            let out = s
                .handle(&q, peer(), proto)
                .await
                .unwrap_or_else(|| panic!("{proto:?} must answer, not hang up"));
            let resp = Message::from_bytes(&out).unwrap();
            assert_eq!(
                resp.metadata.response_code,
                ResponseCode::Refused,
                "{proto:?}"
            );
        }

        // UDP still says nothing at all.
        assert!(s.handle(&q, peer(), Proto::Udp).await.is_none());
    }

    #[tokio::test]
    async fn allowlist_mode_rejects_everyone_else() {
        let s = test_server("||ads.example.com^\n", 0);
        s.access.write().allowed = AccessList::parse(&["10.0.0.1".to_string()]);
        assert!(
            s.handle(
                &wire_query("ads.example.com.", RecordType::A),
                peer(),
                Proto::Udp
            )
            .await
            .is_none()
        );

        s.access.write().allowed = AccessList::parse(&[peer().ip().to_string()]);
        assert!(
            s.handle(
                &wire_query("ads.example.com.", RecordType::A),
                peer(),
                Proto::Udp
            )
            .await
            .is_some()
        );
    }

    #[tokio::test]
    async fn rate_limiting_drops_excess_queries() {
        let s = test_server("||ads.example.com^\n", 2);
        let q = wire_query("ads.example.com.", RecordType::A);
        assert!(s.handle(&q, peer(), Proto::Udp).await.is_some());
        assert!(s.handle(&q, peer(), Proto::Udp).await.is_some());
        assert!(
            s.handle(&q, peer(), Proto::Udp).await.is_none(),
            "third should be limited"
        );
    }

    #[tokio::test]
    async fn rate_limiting_leaves_the_stream_transports_alone() {
        // Upstream gates the limit on `d.Proto == ProtoUDP`, because it is
        // there to stop a spoofed datagram being turned into amplification and
        // a client that completed a handshake has already proved its address.
        // Limiting one anyway cut off everyone behind a single busy address,
        // and silently: a stream client got a closed connection, not an answer.
        for proto in [Proto::Tcp, Proto::Tls, Proto::Https, Proto::Quic] {
            let s = test_server("||ads.example.com^\n", 2);
            let q = wire_query("ads.example.com.", RecordType::A);

            for i in 0..8 {
                assert!(
                    s.handle(&q, peer(), proto).await.is_some(),
                    "{proto:?} query {i} went unanswered",
                );
            }
        }
    }

    #[tokio::test]
    async fn a_datagram_flood_does_not_spend_a_stream_clients_allowance() {
        // One limiter, one address, two transports: the datagrams are limited
        // and the connection is not.
        let s = test_server("||ads.example.com^\n", 2);
        let q = wire_query("ads.example.com.", RecordType::A);

        while s.handle(&q, peer(), Proto::Udp).await.is_some() {}
        assert!(
            s.handle(&q, peer(), Proto::Tcp).await.is_some(),
            "the connection should still be answered"
        );
    }

    #[tokio::test]
    async fn access_blocked_hosts_are_silent_on_udp() {
        let s = test_server("", 0);
        let q = wire_query("version.bind.", RecordType::TXT);
        assert!(s.handle(&q, peer(), Proto::Udp).await.is_none());
        assert!(
            s.handle(&q, peer(), Proto::Tcp).await.is_some(),
            "TCP gets REFUSED"
        );
    }

    #[tokio::test]
    async fn udp_listener_round_trips() {
        let s = test_server("||ads.example.com^\n", 0);
        let sock = bind_udp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = sock.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            serve_udp(sock, s, async {
                let _ = rx.await;
            })
            .await;
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(addr).await.unwrap();
        client
            .send(&wire_query("ads.example.com.", RecordType::A))
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(3), client.recv(&mut buf))
            .await
            .expect("should not time out")
            .unwrap();

        let resp = Message::from_bytes(&buf[..n]).unwrap();
        assert_eq!(resp.metadata.id, 0x2222);
        assert_eq!(resp.answers.len(), 1);

        let _ = tx.send(());
    }

    #[tokio::test]
    async fn tcp_listener_round_trips_and_reuses_the_connection() {
        let s = test_server("||ads.example.com^\n", 0);
        let listener = bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            serve_tcp(listener, s, async {
                let _ = rx.await;
            })
            .await;
        });

        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Two queries on the same connection, as a real client would.
        for _ in 0..2 {
            let q = wire_query("ads.example.com.", RecordType::A);
            c.write_all(&(q.len() as u16).to_be_bytes()).await.unwrap();
            c.write_all(&q).await.unwrap();
            c.flush().await.unwrap();

            let mut lenbuf = [0u8; 2];
            tokio::time::timeout(Duration::from_secs(3), c.read_exact(&mut lenbuf))
                .await
                .expect("should not time out")
                .unwrap();
            let n = usize::from(u16::from_be_bytes(lenbuf));
            let mut buf = vec![0u8; n];
            c.read_exact(&mut buf).await.unwrap();

            let resp = Message::from_bytes(&buf).unwrap();
            assert_eq!(resp.answers.len(), 1);
        }

        let _ = tx.send(());
    }

    /// Points the guard at loopback with a low threshold, so the tests can
    /// drive a refusal the way the internet does.
    fn watch_loopback(s: &Server, strikes: u32) {
        s.set_probe_config(crate::probe::Config {
            strikes,
            exempt_local: false,
            ..Default::default()
        });
    }

    #[tokio::test]
    async fn a_connection_that_asks_nothing_costs_a_strike_and_a_query_clears_it() {
        let s = test_server("||ads.example.com^\n", 0);
        watch_loopback(&s, 3);

        let listener = bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let probes = s.probes.clone();
        tokio::spawn(async move {
            serve_tcp(listener, s, async {
                let _ = rx.await;
            })
            .await;
        });

        // Connect, send something that is not a question, and leave.  One
        // that sends nothing at all is not counted on plain TCP: see
        // `a_tcp_connection_that_closes_before_its_first_byte_costs_nothing`.
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        c.write_all(&[0x00]).await.unwrap();
        drop(c);
        for _ in 0..100 {
            if probes.tracked() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(probes.tracked(), 1, "the connection asked nothing");

        // Then ask something on a new connection, which is what a client is
        // for -- and what a scanner never does.
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let q = wire_query("ads.example.com.", RecordType::A);
        c.write_all(&(q.len() as u16).to_be_bytes()).await.unwrap();
        c.write_all(&q).await.unwrap();
        c.flush().await.unwrap();

        let mut lenbuf = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(3), c.read_exact(&mut lenbuf))
            .await
            .expect("the query must be answered")
            .unwrap();
        drop(c);

        for _ in 0..100 {
            if probes.tracked() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(probes.tracked(), 0, "an answered query clears the record");

        let _ = tx.send(());
    }

    #[tokio::test]
    async fn a_refused_source_is_closed_before_the_handshake() {
        // The handshake is the cost, so the connection has to go before it:
        // the client sees end-of-file rather than a certificate.
        let (cert, key) = test_cert();
        let loaded = crate::tls::load(&crate::tls::Source {
            certificate_chain: cert,
            private_key: key,
            ..Default::default()
        })
        .expect("the test pair must load");

        let s = test_server("", 0);
        watch_loopback(&s, 2);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        s.probes.wasted(ip);
        s.probes.wasted(ip);
        assert!(!s.probes.admits(ip), "the source is out of strikes");

        let listener = bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            serve_dot(listener, loaded.dot, s, async {
                let _ = rx.await;
            })
            .await;
        });

        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(3), c.read(&mut buf))
            .await
            .expect("a refused connection is closed at once, not left hanging");
        assert_eq!(read.unwrap(), 0, "the server closed without a handshake");

        let _ = tx.send(());
    }

    /// A self-signed certificate for `dns.example.com`.
    fn test_cert() -> (String, String) {
        let c = rcgen::generate_simple_self_signed(vec!["dns.example.com".to_string()])
            .expect("generating a certificate");

        (c.cert.pem(), c.signing_key.serialize_pem())
    }

    #[tokio::test]
    async fn dot_listener_answers_a_query() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (cert, key) = test_cert();
        let loaded = crate::tls::load(&crate::tls::Source {
            certificate_chain: cert.clone(),
            private_key: key,
            ..Default::default()
        })
        .expect("the test pair must load");

        let s = test_server("||ads.example.com^\n", 0);
        let listener = bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            serve_dot(listener, loaded.dot, s, async {
                let _ = rx.await;
            })
            .await;
        });

        // Trust only the certificate the server presents.
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut cert.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        let client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
        let name = rustls_pki_types::ServerName::try_from("dns.example.com").unwrap();
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls = connector.connect(name, tcp).await.expect("handshake");

        let q = wire_query("ads.example.com.", RecordType::A);
        tls.write_all(&(q.len() as u16).to_be_bytes())
            .await
            .unwrap();
        tls.write_all(&q).await.unwrap();
        tls.flush().await.unwrap();

        let mut lenbuf = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(5), tls.read_exact(&mut lenbuf))
            .await
            .expect("should not time out")
            .unwrap();
        let mut buf = vec![0u8; usize::from(u16::from_be_bytes(lenbuf))];
        tls.read_exact(&mut buf).await.unwrap();

        let resp = Message::from_bytes(&buf).unwrap();
        assert_eq!(resp.metadata.id, 0x2222);
        assert_eq!(resp.answers.len(), 1, "the blocked name should be answered");

        let _ = tx.send(());
    }

    #[tokio::test]
    async fn dot_records_the_query_as_encrypted() {
        // The query log distinguishes transports, so the listener must pass
        // the right one through.
        assert_eq!(Proto::Tls.log_name(), "tls");
        assert!(!Proto::Tls.is_datagram(), "DoT is connection-oriented");
    }

    #[tokio::test]
    async fn a_client_that_never_completes_the_handshake_is_dropped() {
        let (cert, key) = test_cert();
        let loaded = crate::tls::load(&crate::tls::Source {
            certificate_chain: cert,
            private_key: key,
            ..Default::default()
        })
        .unwrap();

        let s = test_server("", 0);
        let listener = bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            serve_dot(listener, loaded.dot, s, async {
                let _ = rx.await;
            })
            .await;
        });

        // Connect and send nothing.  The listener must stay available.
        let _silent = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(tokio::net::TcpStream::connect(addr).await.is_ok());

        let _ = tx.send(());
    }

    #[test]
    fn access_defaults_to_permitting_everyone() {
        let a = Access::default();
        assert!(a.permits("1.2.3.4".parse().unwrap(), None));
    }

    /// The three forms the field documents, in one list.
    fn mixed_allowlist() -> Access {
        Access::new(
            &[
                "mi12t".to_string(),
                "hoangnc-chrome".to_string(),
                "172.17.0.0/16".to_string(),
                "192.168.99.2/31".to_string(),
                "10.0.0.7".to_string(),
            ],
            &[],
        )
    }

    #[test]
    fn an_allowlist_of_cidrs_and_clientids_is_not_an_empty_allowlist() {
        // The defect: every entry that was not a bare address was dropped, so
        // a list written entirely in CIDRs and ClientIDs parsed to nothing --
        // and an empty allowlist admits everybody, which is the opposite of
        // what the operator asked for.
        let a = mixed_allowlist();
        assert!(!a.allowed.is_empty(), "nothing parsed");

        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(a.permits(ip("172.17.0.5"), None), "inside the /16");
        assert!(a.permits(ip("192.168.99.3"), None), "inside the /31");
        assert!(a.permits(ip("10.0.0.7"), None), "the bare address");

        assert!(!a.permits(ip("172.18.0.5"), None), "outside the /16");
        assert!(!a.permits(ip("192.168.99.4"), None), "outside the /31");
        assert!(!a.permits(ip("8.8.8.8"), None), "not listed at all");
    }

    #[test]
    fn a_listed_clientid_gets_in_from_an_unlisted_address() {
        // Upstream refuses in allowlist mode only when *both* checks refuse,
        // which is what makes a ClientID worth listing: the phone is on a
        // different network every day.
        let a = mixed_allowlist();
        let elsewhere = "203.0.113.9".parse().unwrap();

        assert!(a.permits(elsewhere, Some("mi12t")));
        assert!(a.permits(elsewhere, Some("hoangnc-chrome")));
        assert!(!a.permits(elsewhere, Some("someone-else")));
        assert!(!a.permits(elsewhere, None));

        // And an allowed address still gets in carrying no ClientID at all,
        // which is every plain UDP query.
        assert!(a.permits("172.17.0.5".parse().unwrap(), None));
    }

    #[test]
    fn a_blocklist_refuses_on_either_check() {
        // The other half of upstream's asymmetry: with no allowlist, one
        // match is enough to refuse.
        let a = Access::new(&[], &["10.0.0.0/8".to_string(), "guest-tablet".to_string()]);

        assert!(!a.permits("10.1.2.3".parse().unwrap(), None));
        assert!(!a.permits("203.0.113.9".parse().unwrap(), Some("guest-tablet")));
        assert!(a.permits("203.0.113.9".parse().unwrap(), Some("laptop")));
        assert!(a.permits("203.0.113.9".parse().unwrap(), None));
    }

    #[test]
    fn access_entries_are_sorted_the_way_upstream_sorts_them() {
        use AccessEntry::*;

        assert_eq!(
            parse_access_entry("10.0.0.1"),
            Some(Ip("10.0.0.1".parse().unwrap()))
        );
        assert_eq!(
            parse_access_entry("2001:db8::1"),
            Some(Ip("2001:db8::1".parse().unwrap()))
        );
        assert_eq!(
            parse_access_entry("172.17.0.0/16"),
            Some(Net("172.17.0.0".parse().unwrap(), 16))
        );
        assert_eq!(
            parse_access_entry("2001:db8::/32"),
            Some(Net("2001:db8::".parse().unwrap(), 32))
        );
        assert_eq!(parse_access_entry("mi12t"), Some(Id("mi12t".to_string())));

        // A prefix too long for its family is not a network, and is not a
        // label either.
        assert_eq!(parse_access_entry("10.0.0.0/33"), None);
        assert_eq!(parse_access_entry("2001:db8::/129"), None);

        // Neither is anything that is not a single DNS label.
        for bad in [
            "",
            "-x",
            "x-",
            "a.b",
            "has space",
            "under_score",
            &"x".repeat(64),
        ] {
            assert_eq!(parse_access_entry(bad), None, "{bad:?} must be refused");
        }
        assert!(is_valid_client_id(&"x".repeat(63)));
    }

    #[test]
    fn an_ipv6_network_matches_only_its_own_family() {
        let a = Access::new(&["2001:db8::/32".to_string()], &[]);
        assert!(a.permits("2001:db8::1".parse().unwrap(), None));
        assert!(!a.permits("2001:db9::1".parse().unwrap(), None));
        // A v4 address must not fall into a v6 prefix through the masking.
        assert!(!a.permits("10.0.0.1".parse().unwrap(), None));
    }

    #[test]
    fn a_zero_length_prefix_matches_its_whole_family() {
        let a = Access::new(&["0.0.0.0/0".to_string()], &[]);
        assert!(a.permits("8.8.8.8".parse().unwrap(), None));
        assert!(!a.permits("2001:db8::1".parse().unwrap(), None));
    }

    #[tokio::test]
    async fn a_clientid_opens_the_allowlist_over_a_named_transport() {
        // The check runs in `handle_as`, so the ClientID a DoH path segment
        // or a DoT server name carries has to reach it.
        let s = test_server("||ads.example.com^\n", 0);
        *s.access.write() = Access::new(&["kids-tablet".to_string()], &[]);
        let q = wire_query("example.com.", RecordType::A);

        assert!(
            s.handle_as(&q, peer(), Proto::Https, Some("kids-tablet".to_string()))
                .await
                .is_some(),
            "the listed ClientID must get in"
        );
        assert!(
            s.handle_as(&q, peer(), Proto::Https, Some("other".to_string()))
                .await
                .is_some_and(|w| {
                    let m = Message::from_bytes(&w).unwrap();

                    m.metadata.response_code == hickory_proto::op::ResponseCode::Refused
                }),
            "an unlisted one must be refused"
        );
        assert!(
            s.handle(&q, peer(), Proto::Udp).await.is_none(),
            "and a query carrying no ClientID is not on the allowlist"
        );
    }

    #[test]
    fn a_client_id_is_the_label_below_the_server_name() {
        assert_eq!(
            client_id_from_sni("kids-tablet.dns.example", "dns.example").as_deref(),
            Some("kids-tablet")
        );
        assert_eq!(
            client_id_from_sni("KIDS-TABLET.DNS.EXAMPLE.", "dns.example").as_deref(),
            Some("kids-tablet"),
            "case and a trailing dot do not matter"
        );
    }

    #[test]
    fn the_server_name_itself_carries_no_client_id() {
        assert_eq!(client_id_from_sni("dns.example", "dns.example"), None);
    }

    #[test]
    fn a_deeper_or_unrelated_name_yields_nothing() {
        // Taking a label out of an unrelated name would let a client claim
        // any identifier it liked.
        assert_eq!(client_id_from_sni("a.b.dns.example", "dns.example"), None);
        assert_eq!(client_id_from_sni("evil.example", "dns.example"), None);
        assert_eq!(client_id_from_sni("xdns.example", "dns.example"), None);
    }

    #[test]
    fn without_a_configured_name_no_identifier_is_taken() {
        assert_eq!(client_id_from_sni("anything.example", ""), None);
    }

    /// A source on the internet, which nothing exempts.
    fn public() -> SocketAddr {
        "198.51.100.7:5000".parse().unwrap()
    }

    fn rcode(a: &Answer) -> ResponseCode {
        Message::from_bytes(a.bytes.as_ref().expect("something was sent"))
            .unwrap()
            .metadata
            .response_code
    }

    /// Frames `q`, sends it, and reads the framed answer.
    async fn ask<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, q: &[u8]) -> io::Result<Message> {
        let mut framed = (q.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(q);
        s.write_all(&framed).await?;
        s.flush().await?;

        let mut len = [0u8; 2];
        s.read_exact(&mut len).await?;
        let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
        s.read_exact(&mut buf).await?;

        Ok(Message::from_bytes(&buf).expect("a DNS message"))
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

    /// A listener that fails on demand before handing over real connections.
    struct Flaky {
        inner: TcpListener,
        /// Returned before anything is accepted, from the end.
        errors: parking_lot::Mutex<Vec<io::Error>>,
    }

    impl Accept for Flaky {
        type Conn = TcpStream;

        fn accept(&self) -> impl Future<Output = io::Result<(TcpStream, SocketAddr)>> + Send {
            let failure = self.errors.lock().pop();

            async move {
                match failure {
                    Some(e) => Err(e),
                    None => self.inner.accept().await,
                }
            }
        }
    }

    #[tokio::test]
    async fn a_listener_rides_out_errors_accepting() {
        // What used to close the port for good: one `EMFILE` returned from
        // the loop, and the caller threw the error away.  A connection that
        // died in the queue is passed over at once; running out of
        // descriptors is waited out; and the listener then serves as before.
        let s = test_server("||ads.example.com^\n", 0);
        let inner = bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = inner.local_addr().unwrap();
        let flaky = Flaky {
            inner,
            errors: parking_lot::Mutex::new(vec![
                io::Error::from_raw_os_error(24), // EMFILE
                io::ErrorKind::ConnectionAborted.into(),
            ]),
        };

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let listening = tokio::spawn(tcp_loop(flaky, s, async {
            let _ = rx.await;
        }));

        let mut c = TcpStream::connect(addr).await.unwrap();
        let q = wire_query("ads.example.com.", RecordType::A);
        let resp = tokio::time::timeout(Duration::from_secs(5), ask(&mut c, &q))
            .await
            .expect("the listener is still serving")
            .unwrap();
        assert_eq!(resp.answers.len(), 1);

        let _ = tx.send(());
        tokio::time::timeout(Duration::from_secs(3), listening)
            .await
            .expect("and it stops when asked to")
            .unwrap();
    }

    #[test]
    fn an_error_about_one_connection_is_passed_over_and_one_about_the_process_waited_out() {
        let errors = AcceptErrors::new("test");

        for kind in [
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::Interrupted,
        ] {
            assert_eq!(errors.pause_after(&kind.into()), None, "{kind:?}");
        }

        // EMFILE and ENFILE, which clear only when something else closes.
        for errno in [24, 23] {
            assert_eq!(
                errors.pause_after(&io::Error::from_raw_os_error(errno)),
                Some(ACCEPT_BACKOFF),
                "errno {errno}"
            );
        }
    }

    #[test]
    fn a_recurring_warning_is_said_once_a_minute_with_its_count() {
        let t = Throttle::new();

        assert_eq!(t.due_at(0), Some(1), "the first is said");
        for s in 0..59 {
            assert_eq!(t.due_at(s), None, "the flood is not");
        }
        assert_eq!(
            t.due_at(60),
            Some(60),
            "a minute on, one line says how many there were"
        );
        assert_eq!(t.due_at(61), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_message_that_stalls_after_its_length_is_dropped_within_the_deadline() {
        // A length of 65,535 and three bytes of it: this used to allocate
        // the whole 64 KiB and wait for the rest for ever.
        let s = test_server("||ads.example.com^\n", 0);
        let (server_side, mut client) = tokio::io::duplex(1024);
        client.write_all(&[0xFF, 0xFF, 1, 2, 3]).await.unwrap();

        let started = tokio::time::Instant::now();
        let served = serve_stream(server_side, &s, public(), Proto::Tls, Ok(None)).await;
        let took = started.elapsed();

        assert_eq!(served, Conduct::Wasted);
        assert!(
            took >= MESSAGE_TIMEOUT && took < MESSAGE_TIMEOUT + Duration::from_secs(1),
            "took {took:?}"
        );
        drop(client);
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_that_stalls_mid_message_asked_nothing_whatever_it_asked_before() {
        // Otherwise a slowloris would ask one real question per connection
        // to buy a clean record for every connection it then holds open.
        let s = test_server("||ads.example.com^\n", 0);
        let (server_side, mut client) = tokio::io::duplex(4096);
        let serving = tokio::spawn({
            let s = s.clone();
            async move { serve_stream(server_side, &s, public(), Proto::Tcp, Ok(None)).await }
        });

        let q = wire_query("ads.example.com.", RecordType::A);
        assert_eq!(ask(&mut client, &q).await.unwrap().answers.len(), 1);

        // Half a length prefix, and nothing more.
        client.write_all(&[0x00]).await.unwrap();
        assert_eq!(serving.await.unwrap(), Conduct::Wasted);
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_that_goes_quiet_between_messages_keeps_what_it_asked() {
        // Idle is not stalled: holding a connection open between queries is
        // what DoT clients do.
        let s = test_server("||ads.example.com^\n", 0);
        let (server_side, mut client) = tokio::io::duplex(4096);
        let serving = tokio::spawn({
            let s = s.clone();
            async move { serve_stream(server_side, &s, public(), Proto::Tls, Ok(None)).await }
        });

        let q = wire_query("ads.example.com.", RecordType::A);
        ask(&mut client, &q).await.unwrap();

        let started = tokio::time::Instant::now();
        assert_eq!(serving.await.unwrap(), Conduct::Served(1));
        assert!(
            started.elapsed() >= TCP_IDLE,
            "closed only once it went idle"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_never_reads_its_answers_is_dropped() {
        let s = test_server("||ads.example.com^\n", 0);
        // Room for one answer on the way back and not two.
        let (server_side, mut client) = tokio::io::duplex(64);
        let serving = tokio::spawn({
            let s = s.clone();
            async move { serve_stream(server_side, &s, public(), Proto::Tls, Ok(None)).await }
        });

        let q = wire_query("ads.example.com.", RecordType::A);
        let mut framed = (q.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&q);
        for _ in 0..3 {
            client.write_all(&framed).await.unwrap();
        }

        let started = tokio::time::Instant::now();
        let served = serving.await.unwrap();
        let took = started.elapsed();

        assert_eq!(
            served,
            Conduct::Wasted,
            "an answer it would not take was not served"
        );
        assert!(
            took >= WRITE_TIMEOUT - Duration::from_secs(1)
                && took <= WRITE_TIMEOUT + Duration::from_secs(1),
            "took {took:?}"
        );
        drop(client);
    }

    #[tokio::test]
    async fn a_message_cut_short_is_an_error_not_a_query() {
        let (mut server_side, mut client) = tokio::io::duplex(64);
        client.write_all(&[0x00, 0x05, 1, 2]).await.unwrap();
        drop(client);

        let first = server_side.read_u8().await.unwrap();
        let err = read_message(&mut server_side, first).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_that_closes_at_once_without_a_byte_is_silent_and_one_that_lingers_is_not() {
        let s = test_server("||ads.example.com^\n", 0);

        let (server_side, client) = tokio::io::duplex(64);
        drop(client);
        let started = tokio::time::Instant::now();
        assert_eq!(
            serve_stream(server_side, &s, public(), Proto::Tcp, Ok(None)).await,
            Conduct::Silent
        );
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "and it is let go at once"
        );

        // Held open in silence and then closed: otherwise connecting and
        // leaving just before each deadline would hold a descriptor for ever
        // at no charge.
        let (server_side, client) = tokio::io::duplex(64);
        tokio::spawn(async move {
            tokio::time::sleep(SILENT_GRACE + Duration::from_millis(500)).await;
            drop(client);
        });
        assert_eq!(
            serve_stream(server_side, &s, public(), Proto::Tcp, Ok(None)).await,
            Conduct::Wasted
        );

        // Held open for `TCP_IDLE` without a word: the same.
        let (server_side, _client) = tokio::io::duplex(64);
        assert_eq!(
            serve_stream(server_side, &s, public(), Proto::Tcp, Ok(None)).await,
            Conduct::Wasted
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_whose_every_answer_was_busy_is_neither_served_nor_wasted() {
        // The shape of an overload: another source's slow lookups hold the
        // share, and this one's questions are answered SERVFAIL after a wait.
        // Neither of those is its fault.
        let s = test_server("||ads.example.com^\n", 0);
        let q = wire_query("ads.example.com.", RecordType::A);
        let held = s.fill_share(public().ip()).await;

        let (server_side, mut client) = tokio::io::duplex(4096);
        let serving = tokio::spawn({
            let s = s.clone();
            async move { serve_stream(server_side, &s, public(), Proto::Tls, Ok(None)).await }
        });
        for _ in 0..3 {
            let resp = ask(&mut client, &q).await.unwrap();
            assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
        }
        drop(client);
        assert_eq!(serving.await.unwrap(), Conduct::Busy);

        // And one answer that counts, among busy ones, is a served connection.
        let (server_side, mut client) = tokio::io::duplex(4096);
        let serving = tokio::spawn({
            let s = s.clone();
            async move { serve_stream(server_side, &s, public(), Proto::Tls, Ok(None)).await }
        });
        ask(&mut client, &q).await.unwrap();
        drop(held);
        ask(&mut client, &q).await.unwrap();
        drop(client);
        assert_eq!(serving.await.unwrap(), Conduct::Served(1));
    }

    #[test]
    fn what_a_connection_came_to_is_reported_to_the_guard_as_it_should_be() {
        let g = crate::probe::Guard::new(crate::probe::Config {
            strikes: 1,
            exempt_local: false,
            ..Default::default()
        });
        let ip: IpAddr = "198.51.100.7".parse().unwrap();

        for nothing in [Conduct::Busy, Conduct::Silent] {
            nothing.report(&g, ip);
            assert_eq!(g.tracked(), 0, "{nothing:?} is reported as nothing");
        }

        Conduct::Wasted.report(&g, ip);
        assert!(!g.admits(ip), "and nothing asked is a strike");

        let mut t = Tally::default();
        assert_eq!(t.conduct(), Conduct::Wasted);
        t.add(Conduct::Busy);
        t.add(Conduct::Wasted);
        assert_eq!(t.conduct(), Conduct::Busy);
        t.add(Conduct::Served(1));
        t.add(Conduct::Served(1));
        assert_eq!(t.conduct(), Conduct::Served(2));
    }

    #[tokio::test(start_paused = true)]
    async fn a_source_over_its_share_is_answered_servfail_after_a_short_wait() {
        let s = test_server("||ads.example.com^\n", 0);
        let q = wire_query("ads.example.com.", RecordType::A);
        let _held = s.fill_share(public().ip()).await;

        for proto in [Proto::Tcp, Proto::Tls, Proto::Https, Proto::Quic] {
            let started = tokio::time::Instant::now();
            let a = s.answer(&q, public(), proto, None).await;
            let took = started.elapsed();

            assert_eq!(
                rcode(&a),
                ResponseCode::ServFail,
                "{proto:?} must hear something"
            );
            assert!(!a.counts, "{proto:?} was not served");
            assert!(
                took >= IN_FLIGHT_WAIT && took < IN_FLIGHT_WAIT + Duration::from_millis(100),
                "{proto:?} took {took:?}"
            );
        }

        // Nobody else is held to this source's share, and neither are its
        // datagrams, which the rate limit governs.
        let other: SocketAddr = "203.0.113.9:5000".parse().unwrap();
        assert!(s.answer(&q, other, Proto::Tls, None).await.counts);
        assert!(s.answer(&q, public(), Proto::Udp, None).await.counts);
    }

    #[tokio::test(start_paused = true)]
    async fn a_query_waiting_for_its_sources_share_goes_ahead_when_a_slot_frees() {
        // A burst waits rather than fails.
        let s = test_server("||ads.example.com^\n", 0);
        let mut held = s.fill_share(public().ip()).await;

        let waiting = tokio::spawn({
            let s = s.clone();
            async move {
                let q = wire_query("ads.example.com.", RecordType::A);
                s.answer(&q, public(), Proto::Https, None).await
            }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        held.pop();

        let a = waiting.await.unwrap();
        assert_eq!(rcode(&a), ResponseCode::NoError);
        assert!(a.counts);
    }

    #[tokio::test(start_paused = true)]
    async fn a_local_or_allowlisted_source_is_never_held_to_a_share() {
        let s = test_server("||ads.example.com^\n", 0);
        let listed: SocketAddr = "198.51.100.8:5000".parse().unwrap();
        s.set_probe_config(crate::probe::Config {
            allowlist: vec![listed.ip()],
            ..Default::default()
        });
        let q = wire_query("ads.example.com.", RecordType::A);

        for src in [
            "192.168.1.10:5000".parse::<SocketAddr>().unwrap(),
            "[fd00::1]:5000".parse().unwrap(),
            "[::ffff:10.0.0.1]:5000".parse().unwrap(),
            listed,
        ] {
            let mut seats = Vec::new();
            for _ in 0..(3 * IN_FLIGHT_PER_SOURCE) {
                seats.push(s.in_flight.enter(src.ip()).await.expect("never refused"));
            }
            assert!(s.answer(&q, src, Proto::Tcp, None).await.counts, "{src}");
        }

        assert_eq!(s.in_flight.sources(), 0, "and nothing about them is kept");
    }

    #[tokio::test(start_paused = true)]
    async fn an_ipv6_slash_64_shares_one_allowance() {
        let s = test_server("||ads.example.com^\n", 0);
        let q = wire_query("ads.example.com.", RecordType::A);
        let _held = s.fill_share("2001:db8:1:2::1".parse().unwrap()).await;

        let neighbour: SocketAddr = "[2001:db8:1:2::ffff]:5000".parse().unwrap();
        assert_eq!(
            rcode(&s.answer(&q, neighbour, Proto::Quic, None).await),
            ResponseCode::ServFail,
            "a fresh address in the same /64 is the same source"
        );

        let next: SocketAddr = "[2001:db8:1:3::1]:5000".parse().unwrap();
        assert!(s.answer(&q, next, Proto::Quic, None).await.counts);
    }

    #[tokio::test(start_paused = true)]
    async fn the_share_table_forgets_a_source_once_its_queries_are_done() {
        // So a scan from a million addresses costs nothing once answered.
        let s = test_server("||ads.example.com^\n", 0);
        let q = wire_query("ads.example.com.", RecordType::A);

        let held = s.fill_share(public().ip()).await;
        assert_eq!(s.in_flight.sources(), 1);

        // A query that waits and gives up leaves nothing extra behind.
        let _ = s.answer(&q, public(), Proto::Tcp, None).await;
        drop(held);
        assert_eq!(s.in_flight.sources(), 0);

        assert!(s.answer(&q, public(), Proto::Tcp, None).await.counts);
        assert_eq!(s.in_flight.sources(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_query_no_worker_is_free_for_is_told_on_a_stream_and_dropped_on_udp() {
        let s = test_server("||ads.example.com^\n", 0);
        s.set_max_concurrent(1);
        let only = s.concurrency.read().clone().unwrap();
        let _busy = only.acquire_owned().await.unwrap();
        let q = wire_query("ads.example.com.", RecordType::A);

        let started = tokio::time::Instant::now();
        let a = s.answer(&q, public(), Proto::Tls, None).await;
        assert_eq!(rcode(&a), ResponseCode::ServFail);
        assert!(!a.counts);
        assert!(started.elapsed() >= WORKER_WAIT);

        // What a full socket buffer does to a datagram under dnsproxy.
        assert!(
            s.answer(&q, public(), Proto::Udp, None)
                .await
                .bytes
                .is_none()
        );
    }

    #[tokio::test]
    async fn what_a_scanner_asks_is_answered_but_not_served() {
        // The default `dns.blocked_hosts`, which is what a scanner
        // fingerprinting a DNS server asks for.
        let s = test_server("", 0);
        for name in ["version.bind.", "id.server.", "hostname.bind."] {
            let a = s
                .answer(
                    &wire_query(name, RecordType::TXT),
                    public(),
                    Proto::Tcp,
                    None,
                )
                .await;
            assert_eq!(rcode(&a), ResponseCode::Refused, "{name}");
            assert!(!a.counts, "{name}");
        }

        // Nor is a stranger the access list refuses.
        s.access.write().disallowed = AccessList::parse(&[public().ip().to_string()]);
        let a = s
            .answer(
                &wire_query("example.com.", RecordType::A),
                public(),
                Proto::Tls,
                None,
            )
            .await;
        assert_eq!(rcode(&a), ResponseCode::Refused);
        assert!(!a.counts);
    }

    #[tokio::test]
    async fn a_query_refused_by_a_filtering_rule_is_served_like_any_other() {
        // `blocking_mode: refused` sends the same rcode as `blocked_hosts`,
        // and is an answer to a client all the same.
        let settings = Settings {
            blocking: crate::msg::BlockingConfig {
                mode: crate::msg::BlockingMode::Refused,
                ..Default::default()
            },
            ..Default::default()
        };
        let s = test_server_with("||ads.example.com^\n", 0, settings);

        let a = s
            .answer(
                &wire_query("ads.example.com.", RecordType::A),
                public(),
                Proto::Tcp,
                None,
            )
            .await;
        assert_eq!(rcode(&a), ResponseCode::Refused);
        assert!(a.counts);
    }

    /// Serves plain TCP from `s` on loopback until the sender is dropped.
    async fn listen_tcp(s: Arc<Server>) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
        let listener = bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(serve_tcp(listener, s, async {
            let _ = rx.await;
        }));

        (addr, tx)
    }

    #[tokio::test]
    async fn a_connection_that_only_asks_version_bind_is_a_strike() {
        let s = test_server("||ads.example.com^\n", 0);
        watch_loopback(&s, 6);
        let probes = s.probes.clone();
        let (addr, _stop) = listen_tcp(s).await;

        let mut c = TcpStream::connect(addr).await.unwrap();
        let resp = ask(&mut c, &wire_query("version.bind.", RecordType::TXT))
            .await
            .unwrap();
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::Refused,
            "answered, as upstream answers it"
        );
        drop(c);
        assert!(
            settle(|| probes.tracked() == 1).await,
            "but it asked nothing a client asks"
        );

        let mut c = TcpStream::connect(addr).await.unwrap();
        ask(&mut c, &wire_query("ads.example.com.", RecordType::A))
            .await
            .unwrap();
        drop(c);
        assert!(
            settle(|| probes.tracked() == 0).await,
            "a real question clears it"
        );
    }

    #[tokio::test]
    async fn a_source_at_its_connection_allowance_is_closed_before_anything_is_read() {
        let s = test_server("||ads.example.com^\n", 0);
        s.set_probe_config(crate::probe::Config {
            exempt_local: false,
            max_per_source: 1,
            ..Default::default()
        });
        let probes = s.probes.clone();
        let _held = probes.open("127.0.0.1".parse().unwrap()).unwrap();
        let (addr, _stop) = listen_tcp(s).await;

        let mut c = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(3), c.read(&mut buf))
            .await
            .expect("closed at once, not left hanging");
        assert!(matches!(read, Ok(0) | Err(_)));
        assert_eq!(probes.tracked(), 0, "being busy is not an offence");
    }

    #[tokio::test]
    async fn a_dot_connection_is_closed_before_the_handshake_when_none_is_free() {
        let (cert, key) = test_cert();
        let loaded = crate::tls::load(&crate::tls::Source {
            certificate_chain: cert,
            private_key: key,
            ..Default::default()
        })
        .unwrap();

        let s = test_server("", 0);
        s.set_probe_config(crate::probe::Config {
            exempt_local: false,
            max_handshakes: 1,
            ..Default::default()
        });
        let probes = s.probes.clone();
        let _slot = probes.handshake("203.0.113.1".parse().unwrap()).unwrap();

        let listener = bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_dot(listener, loaded.dot, s, std::future::pending()));

        let mut c = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(3), c.read(&mut buf))
            .await
            .expect("closed at once");
        assert!(matches!(read, Ok(0) | Err(_)), "no certificate was sent");
        assert!(
            settle(|| probes.stats().open == 0).await,
            "and its ticket went back"
        );
        assert_eq!(probes.tracked(), 0);
    }

    /// A DoT client that trusts only `cert_pem` and asks for `name`.
    async fn dot_connect(
        addr: SocketAddr,
        cert_pem: &str,
        name: &str,
    ) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut cert_pem.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"dot".to_vec()];

        let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
        let name = rustls_pki_types::ServerName::try_from(name.to_string()).unwrap();
        let tcp = TcpStream::connect(addr).await?;

        connector.connect(name, tcp).await
    }

    #[tokio::test]
    async fn a_dot_client_that_sends_a_length_and_stalls_is_dropped_within_the_deadline() {
        // Handshake, then `FF FF` and silence: the cheapest way to hold a
        // descriptor and 64 KiB for ever, before there was a deadline.
        let (cert, key) = test_cert();
        let loaded = crate::tls::load(&crate::tls::Source {
            certificate_chain: cert.clone(),
            private_key: key,
            ..Default::default()
        })
        .unwrap();

        let s = test_server("", 0);
        watch_loopback(&s, 6);
        let probes = s.probes.clone();
        let listener = bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_dot(listener, loaded.dot, s, std::future::pending()));

        let mut tls = dot_connect(addr, &cert, "dns.example.com").await.unwrap();
        tls.write_all(&[0xFF, 0xFF]).await.unwrap();
        tls.flush().await.unwrap();

        let started = std::time::Instant::now();
        let mut buf = [0u8; 1];
        let read =
            tokio::time::timeout(MESSAGE_TIMEOUT + Duration::from_secs(3), tls.read(&mut buf))
                .await
                .expect("dropped within the deadline");
        assert!(matches!(read, Ok(0) | Err(_)));
        assert!(started.elapsed() >= MESSAGE_TIMEOUT - Duration::from_millis(500));
        assert!(
            settle(|| probes.tracked() == 1).await,
            "and it asked nothing"
        );
    }

    #[test]
    fn a_server_name_is_judged_as_upstream_judges_it() {
        // Upstream's `TestServer_clientIDFromDNSContext`, case by case, and
        // the lenient half of each besides.
        let long = format!(
            "{}.example.com",
            "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789"
        );
        let judge = |host: &str, sent: Option<&str>, strict: bool| match client_id_from_server_name(
            host, sent, strict,
        ) {
            Ok(None) => "none".to_string(),
            Ok(Some(id)) => format!("id:{id}"),
            Err(ServerNameError::Mismatch { .. }) => "mismatch".to_string(),
            Err(ServerNameError::InvalidClientId(_)) => "invalid".to_string(),
        };

        let cases: &[(&str, Option<&str>, bool, &str)] = &[
            ("", None, false, "none"),
            ("", Some("anything.example"), true, "none"),
            ("example.com", Some("example.com"), true, "none"),
            ("example.com", None, true, "mismatch"),
            ("example.com", None, false, "none"),
            ("example.com", Some("cli.example.com"), true, "id:cli"),
            ("example.com", Some("cli.example.net"), true, "mismatch"),
            ("example.com", Some("cli.example.net"), false, "none"),
            ("example.com", Some("!!!.example.com"), true, "invalid"),
            ("example.com", Some(&long), true, "invalid"),
            ("example.com", Some("cli.myexample.com"), true, "mismatch"),
            (
                "example.com",
                Some("InSeNsItIvE.example.com"),
                true,
                "id:insensitive",
            ),
            ("example.com", Some("a.b.example.com"), true, "mismatch"),
            ("example.com", Some("a.b.example.com"), false, "none"),
            // rustls lets an underscore through; upstream refuses the label
            // whether or not the check is strict.
            (
                "example.com",
                Some("under_score.example.com"),
                false,
                "invalid",
            ),
        ];

        for &(host, sent, strict, want) in cases {
            assert_eq!(
                judge(host, sent, strict),
                want,
                "host {host:?}, sent {sent:?}, strict {strict}"
            );
        }
    }

    #[test]
    fn the_server_name_is_read_only_while_one_is_set() {
        let s = test_server("", 0);
        assert_eq!(s.client_id_for(Some("kid.dns.example")), Ok(None));

        s.set_server_name("dns.example", true);
        assert_eq!(
            s.client_id_for(Some("kid.dns.example")),
            Ok(Some("kid".to_string()))
        );
        assert!(s.client_id_for(None).is_err(), "strict refuses no name");

        s.set_server_name("", true);
        assert_eq!(
            s.client_id_for(None),
            Ok(None),
            "encryption off: nothing read"
        );
    }

    #[tokio::test]
    async fn a_dot_client_named_by_the_certificate_but_not_the_server_is_answered_servfail() {
        // The case a strict check leaves to the query: the certificate covers
        // the name, but it is neither the server's name nor a ClientID below
        // it.  Upstream answers every query SERVFAIL, and so does this.
        let c = rcgen::generate_simple_self_signed(vec![
            "dns.example.com".to_string(),
            "other.example.net".to_string(),
        ])
        .unwrap();
        let cert = c.cert.pem();
        let slot = Arc::new(crate::tls::Reloadable::new());
        crate::tls::install(
            &crate::tls::Source {
                certificate_chain: cert.clone(),
                private_key: c.signing_key.serialize_pem(),
                ..Default::default()
            },
            &slot,
        )
        .unwrap();
        slot.set_strict_sni(true);
        let tls = crate::tls::reloadable(slot);

        let s = test_server("||ads.example.com^\n", 0);
        s.set_server_name("dns.example.com", true);
        let listener = bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_dot(listener, tls.dot, s, std::future::pending()));
        let q = wire_query("ads.example.com.", RecordType::A);

        let mut ours = dot_connect(addr, &cert, "dns.example.com").await.unwrap();
        let resp = ask(&mut ours, &q).await.unwrap();
        assert_eq!(resp.answers.len(), 1, "the server's own name is answered");

        let mut other = dot_connect(addr, &cert, "other.example.net").await.unwrap();
        let resp = ask(&mut other, &q).await.unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(resp.metadata.id, 0x2222, "and each query gets its answer");
    }

    /// Opens a connection to `addr` and closes it without sending a byte,
    /// once `probes` shows it was accepted, and waits for it to be let go.
    async fn connect_and_close(addr: SocketAddr, probes: &Guard) {
        let c = TcpStream::connect(addr).await.unwrap();
        assert!(settle(|| probes.stats().open == 1).await, "accepted");
        drop(c);
        assert!(settle(|| probes.stats().open == 0).await, "let go");
    }

    /// Serves DoT from `s` on loopback, with `handshake` for each connection
    /// to begin and finish its handshake in, returning the address and the
    /// certificate a client should trust.
    async fn listen_dot(s: Arc<Server>, handshake: Duration) -> (SocketAddr, String) {
        let (cert, key) = test_cert();
        let loaded = crate::tls::load(&crate::tls::Source {
            certificate_chain: cert.clone(),
            private_key: key,
            ..Default::default()
        })
        .unwrap();
        let listener = bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(dot_loop(
            listener,
            loaded.dot,
            s,
            handshake,
            std::future::pending(),
        ));

        (addr, cert)
    }

    #[tokio::test]
    async fn a_tcp_connection_that_closes_before_its_first_byte_costs_nothing() {
        // What a port monitor does, every few seconds, for ever.
        let s = test_server("||ads.example.com^\n", 0);
        watch_loopback(&s, 1);
        let probes = s.probes.clone();
        let (addr, _stop) = listen_tcp(s).await;

        for _ in 0..3 {
            connect_and_close(addr, &probes).await;
        }
        assert_eq!(probes.tracked(), 0);

        // Half a length prefix is not nothing: that is a stalled message.
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(&[0x00]).await.unwrap();
        drop(c);
        assert!(settle(|| probes.tracked() == 1).await, "a strike");
    }

    #[tokio::test]
    async fn a_dot_connection_that_closes_before_its_first_byte_costs_nothing() {
        let s = test_server("", 0);
        watch_loopback(&s, 1);
        let probes = s.probes.clone();
        let (addr, _) = listen_dot(s, TLS_HANDSHAKE_TIMEOUT).await;

        for _ in 0..3 {
            connect_and_close(addr, &probes).await;
        }
        assert_eq!(probes.tracked(), 0, "nothing was spent on it");
        assert!(probes.admits("127.0.0.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn a_dot_connection_that_says_nothing_until_the_deadline_is_a_strike() {
        let s = test_server("", 0);
        watch_loopback(&s, 6);
        let probes = s.probes.clone();
        let (addr, _) = listen_dot(s, Duration::from_millis(200)).await;

        let _silent = TcpStream::connect(addr).await.unwrap();
        assert!(
            settle(|| probes.tracked() == 1).await,
            "it held a slot for the whole deadline"
        );
        assert!(settle(|| probes.stats().handshakes == 0).await);
    }

    #[tokio::test]
    async fn a_dot_connection_that_lingers_in_silence_before_leaving_is_a_strike() {
        // It held a handshake slot all that time; leaving just before the
        // deadline must not make that free.
        let s = test_server("", 0);
        watch_loopback(&s, 6);
        let probes = s.probes.clone();
        let (addr, _) = listen_dot(s, TLS_HANDSHAKE_TIMEOUT).await;

        let c = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(SILENT_GRACE + Duration::from_millis(200)).await;
        drop(c);
        assert!(settle(|| probes.tracked() == 1).await);
    }

    #[tokio::test]
    async fn a_dot_client_that_handshakes_and_leaves_without_asking_is_a_strike() {
        // After the handshake, silence is the scanner's shape: the cost the
        // guard exists to refuse has already been paid.
        let s = test_server("", 0);
        watch_loopback(&s, 6);
        let probes = s.probes.clone();
        let (addr, cert) = listen_dot(s, TLS_HANDSHAKE_TIMEOUT).await;

        drop(dot_connect(addr, &cert, "dns.example.com").await.unwrap());
        assert!(settle(|| probes.tracked() == 1).await);
    }

    #[tokio::test]
    async fn a_dot_connection_answered_only_busy_leaves_no_strike() {
        // A flood of slow lookups from elsewhere holds the workers; a client
        // that asks during it is told SERVFAIL and leaves.  One strike each
        // used to ban it within seconds, while the flood's own queries
        // counted as served.
        let s = test_server("||ads.example.com^\n", 0);
        watch_loopback(&s, 1);
        let probes = s.probes.clone();
        let held = s.fill_share("127.0.0.1".parse().unwrap()).await;
        let (addr, cert) = listen_dot(s, TLS_HANDSHAKE_TIMEOUT).await;

        let mut tls = dot_connect(addr, &cert, "dns.example.com").await.unwrap();
        let resp = ask(&mut tls, &wire_query("ads.example.com.", RecordType::A))
            .await
            .unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
        drop(tls);

        assert!(settle(|| probes.stats().open == 0).await);
        assert_eq!(probes.tracked(), 0, "no strike");
        assert!(probes.admits("127.0.0.1".parse().unwrap()));
        drop(held);
    }

    /// A server whose host has the global address `2001:db8:aa:bb::53`.
    fn server_on_host() -> Arc<Server> {
        let s = test_server("||ads.example.com^\n", 0);
        s.set_probe_config(crate::probe::Config {
            host_networks: crate::probe::host_networks(["2001:db8:aa:bb::53".parse().unwrap()]),
            ..Default::default()
        });

        s
    }

    #[tokio::test(start_paused = true)]
    async fn the_share_and_the_guard_agree_about_what_is_local() {
        // The shared address space is local by default, to both.
        let s = server_on_host();
        let q = wire_query("ads.example.com.", RecordType::A);
        let tailscale: SocketAddr = "100.64.0.1:5000".parse().unwrap();
        assert!(s.probes.exempts(tailscale.ip()));

        let mut seats = Vec::new();
        for _ in 0..(3 * IN_FLIGHT_PER_SOURCE) {
            seats.push(
                s.in_flight
                    .enter(tailscale.ip())
                    .await
                    .expect("never refused"),
            );
        }
        assert!(s.answer(&q, tailscale, Proto::Tcp, None).await.counts);
        assert_eq!(s.in_flight.sources(), 0);

        // The host's own /64 is not local to either: it is held to a share.
        let device: SocketAddr = "[2001:db8:aa:bb::1234]:5000".parse().unwrap();
        assert!(!s.probes.exempts(device.ip()));
        let _held = s.fill_share(device.ip()).await;
        assert!(s.answer(&q, device, Proto::Tcp, None).await.busy);
    }

    #[tokio::test(start_paused = true)]
    async fn the_share_is_kept_per_source_the_way_the_guard_keeps_it() {
        let s = server_on_host();
        let q = wire_query("ads.example.com.", RecordType::A);

        // One device in the host's /64 holding its whole share leaves the
        // next device's alone.
        let device: SocketAddr = "[2001:db8:aa:bb::1234]:5000".parse().unwrap();
        let _held = s.fill_share(device.ip()).await;
        let other: SocketAddr = "[2001:db8:aa:bb::5678]:5000".parse().unwrap();
        assert!(s.answer(&q, other, Proto::Tls, None).await.counts);
        assert_ne!(s.probes.source(device.ip()), s.probes.source(other.ip()));

        // Anywhere else a /64 is still one source.
        let noisy: SocketAddr = "[2001:db8:aa:bc::1]:5000".parse().unwrap();
        let _theirs = s.fill_share(noisy.ip()).await;
        let fresh: SocketAddr = "[2001:db8:aa:bc::2]:5000".parse().unwrap();
        assert!(s.answer(&q, fresh, Proto::Tls, None).await.busy);
        assert_eq!(s.in_flight.sources(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn datagrams_waiting_for_a_worker_are_bounded_and_the_rest_dropped_at_once() {
        let s = test_server("||ads.example.com^\n", 0);
        s.set_max_concurrent(1);
        let only = s.concurrency.read().clone().unwrap();
        let taken = only.acquire_owned().await.unwrap();
        let q = wire_query("ads.example.com.", RecordType::A);

        // A flood from as many forged sources as it likes: the rate limit,
        // counting per source, sees none of them twice.
        let mut waiting = Vec::new();
        for i in 0..UDP_WAITING {
            let s = s.clone();
            let q = q.clone();
            let from = SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::from_bits(0xc633_6400 + i as u32)),
                53,
            );
            waiting.push(tokio::spawn(async move {
                s.answer(&q, from, Proto::Udp, None).await
            }));
        }
        while s.udp_waiting.load(Ordering::Relaxed) < UDP_WAITING {
            tokio::task::yield_now().await;
        }

        let started = tokio::time::Instant::now();
        let a = s.answer(&q, public(), Proto::Udp, None).await;
        assert!(a.bytes.is_none() && a.busy, "dropped");
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "at once, not after waiting"
        );

        // A connection is not held to the datagrams' bound.
        let stream = tokio::spawn({
            let s = s.clone();
            let q = q.clone();
            async move { s.answer(&q, public(), Proto::Tls, None).await }
        });

        // The ones that were let wait are answered once a worker frees.
        drop(taken);
        for w in waiting {
            assert!(w.await.unwrap().counts);
        }
        assert!(stream.await.unwrap().counts);
        assert_eq!(s.udp_waiting.load(Ordering::Relaxed), 0);
    }
}
