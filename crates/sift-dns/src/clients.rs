//! Clients: the persistent ones from the config and the ones discovered at
//! run time.
//!
//! A persistent client is matched by address, subnet, MAC or ClientID and
//! carries its own filtering settings; upstream lets those settings override
//! the global ones per query, which is what makes "no YouTube for the kids'
//! tablet" work.  A runtime client is only a name, learned from the hosts
//! file, the ARP table or a reverse lookup, and is what the query log shows
//! next to an address.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use ahash::AHashMap;
use parking_lot::RwLock;
use sift_core::schedule::Weekly;
use sift_filter::engine::Engine;
use sift_filter::safesearch;

/// How a runtime client's name was discovered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    /// The system hosts file.
    Hosts,
    /// A reverse DNS lookup.
    Rdns,
    /// The system ARP table.
    Arp,
    /// A DHCP lease.  Never produced by this build, which serves no DHCP.
    Dhcp,
    /// A WHOIS lookup.
    Whois,
}

impl Source {
    /// The name the API reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Source::Hosts => "etc_hosts",
            Source::Rdns => "rdns",
            Source::Arp => "arp",
            Source::Dhcp => "dhcp",
            Source::Whois => "whois",
        }
    }
}

/// A client discovered while running.
#[derive(Clone, Debug, Default)]
pub struct RuntimeClient {
    /// The name, if one was found.
    pub name: String,
    /// Where the name came from.
    pub source: Option<Source>,
    /// The hardware address, when the ARP table supplied one.
    pub mac: Option<String>,
    /// WHOIS fields, in the order the API reports them.
    pub whois: Vec<(String, String)>,
}

/// Which discovery sources are switched on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sources {
    /// Look names up over WHOIS.
    pub whois: bool,
    /// Read the system ARP table.
    pub arp: bool,
    /// Resolve addresses back to names.
    pub rdns: bool,
    /// Use DHCP leases.  Ignored: this build serves no DHCP.
    pub dhcp: bool,
    /// Read the system hosts file.
    pub hosts: bool,
}

/// The most runtime clients the network may add.
///
/// Upstream keeps every address it has ever named, for the life of the
/// process (`runtimeIndex`, `internal/client/runtimeindex.go`), which a home
/// network bounds by itself -- 19 addresses on the deployment `TASK.md`
/// measured.  A resolver reachable from the internet has no such bound: every
/// distinct source that asks it anything is looked up, and one rotating
/// through its own /64 is a new source per query.
///
/// Ten thousand is five hundred times what a home network holds, so an
/// installation that never saw a stranger never reaches it and behaves exactly
/// as before; it is also the size upstream gives its own reverse-lookup and
/// WHOIS caches (`defaultCacheSize`, `internal/client/addrproc.go`).  At the
/// cap the table costs about 4.6 MB, measured: 112 bytes an entry in a table
/// that has grown to 16,384 slots, 1.9 MB, and 273 bytes more on the heap for
/// an entry carrying a reverse name and a full WHOIS record, before the
/// allocator rounds them up.
///
/// What this machine supplied -- a name from the hosts file, a name or a
/// hardware address from the ARP table -- is not counted and never given up.
/// It is bounded by those files, and a persistent client identified by MAC
/// is recognised only while its address keeps the hardware address the ARP
/// table gave it.
pub const MAX_RUNTIME: usize = 10_000;

/// How long after it was first recorded an address must ask again to count
/// as returning, in seconds.
///
/// A source rotating through addresses uses each one for a moment and never
/// again; a device asks for as long as it is switched on.
const RETURNING_AFTER: u32 = 600;

/// How long a returning address may stay silent before it stops counting as
/// one, in seconds, so the protection goes to devices that are still around.
const STALE_AFTER: u32 = 86_400;

/// A runtime client and what the eviction order needs to know about it.
struct Slot {
    client: RuntimeClient,
    /// When the address was recorded, on the store's clock.
    first: u32,
    /// When it last asked something.  Atomic so the query path can move it
    /// forward under the read lock.
    seen: AtomicU32,
}

/// The table and its count of what may be evicted, behind one lock so the
/// two cannot disagree.
#[derive(Default)]
struct Table {
    map: AHashMap<IpAddr, Slot>,
    /// How many entries the network taught, which is what `MAX_RUNTIME`
    /// bounds and `evict` may give up.
    learned: usize,
}

impl Table {
    /// Gives up learned entries until `keep` are left, the least worth
    /// keeping first and the least recently seen first among equals.
    ///
    /// It walks the whole table, which is why the caller makes room for a
    /// tenth of the cap at a time: the walk is paid once per thousand new
    /// addresses rather than once per address, and it is paid by discovery,
    /// never by a query.
    fn evict(&mut self, keep: usize, now: u32) {
        let mut order: Vec<(u8, u32, IpAddr)> = self
            .map
            .iter()
            .filter(|(_, s)| !anchored(&s.client))
            .map(|(a, s)| {
                let seen = s.seen.load(Ordering::Relaxed);

                (worth(*a, s.first, seen, now), seen, *a)
            })
            .collect();
        // Counted rather than trusted, so a count that ever drifted is put
        // right by the next eviction instead of being carried forward.
        self.learned = order.len();

        let excess = self.learned.saturating_sub(keep);
        if excess == 0 {
            return;
        }

        order.select_nth_unstable(excess - 1);
        for (_, _, a) in &order[..excess] {
            self.map.remove(a);
        }
        self.learned -= excess;
    }
}

/// How much an operator would miss a learned entry, lowest first.
///
/// A public address seen once is what a flood is made of and goes first; a
/// public address that came back is somebody's phone or laptop; a local
/// address is on the operator's own network, where its reverse name is the
/// one the router gave it, and outranks both.  A stranger cannot buy that
/// rank by forging a local source: the reverse lookup of a local address goes
/// to the local resolvers, which answer only for the operator's own devices,
/// and WHOIS is never asked about one, so a forged address nobody on the
/// network holds learns nothing and is never recorded.
fn worth(addr: IpAddr, first: u32, seen: u32, now: u32) -> u8 {
    let returning =
        seen.saturating_sub(first) >= RETURNING_AFTER && now.saturating_sub(seen) < STALE_AFTER;

    2 * u8::from(is_local(addr)) + u8::from(returning)
}

/// Reports whether this machine rather than the network supplied what is
/// known: a hosts-file or ARP name, a DHCP lease, or a hardware address.
const fn anchored(c: &RuntimeClient) -> bool {
    c.mac.is_some() || matches!(c.source, Some(Source::Hosts | Source::Arp | Source::Dhcp))
}

/// The store of clients discovered at run time.
///
/// Bounded by [`MAX_RUNTIME`]: when the network has taught it that many, the
/// entries least worth keeping are given up to make room.  An evicted
/// address that asks again is simply looked up again.
pub struct Runtime {
    /// What is known, by address.
    table: RwLock<Table>,
    /// Which sources may contribute.
    sources: RwLock<Sources>,
    /// The most entries the network may add.
    cap: usize,
    /// What the store's clock counts from.
    epoch: Instant,
    /// Seconds added to the clock, so the tests do not have to wait.
    #[cfg(test)]
    skew: AtomicU32,
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}

impl Runtime {
    /// An empty store.
    pub fn new() -> Self {
        Self::with_cap(MAX_RUNTIME)
    }

    /// An empty store that holds at most `cap` learned entries.
    fn with_cap(cap: usize) -> Self {
        Self {
            table: RwLock::new(Table::default()),
            sources: RwLock::new(Sources::default()),
            cap: cap.max(1),
            epoch: Instant::now(),
            #[cfg(test)]
            skew: AtomicU32::new(0),
        }
    }

    /// Replaces the enabled sources.
    pub fn set_sources(&self, s: Sources) {
        *self.sources.write() = s;
    }

    /// The enabled sources.
    pub fn sources(&self) -> Sources {
        *self.sources.read()
    }

    /// Records a name for an address.
    ///
    /// A name from a more authoritative source wins: the hosts file and the
    /// ARP table are configured locally, while a reverse lookup is whatever
    /// the network happens to answer.
    pub fn set_name(&self, addr: IpAddr, name: impl Into<String>, source: Source) {
        let name = name.into();
        if name.is_empty() {
            return;
        }

        self.update(addr, |e| {
            if e.name.is_empty() || rank(source) >= rank_of(e.source) {
                e.name = name;
                e.source = Some(source);
            }
        });
    }

    /// Records the hardware address the ARP table reports.
    ///
    /// It is what lets a persistent client identified by MAC be recognised:
    /// a DNS query carries only an address.
    pub fn set_mac(&self, addr: IpAddr, mac: impl Into<String>) {
        let mac = mac.into().to_ascii_lowercase();
        if mac.is_empty() {
            return;
        }

        self.update(addr, |e| e.mac = Some(mac));
    }

    /// The hardware address known for an address, if any.
    pub fn mac_of(&self, addr: IpAddr) -> Option<String> {
        self.table
            .read()
            .map
            .get(&addr)
            .and_then(|s| s.client.mac.clone())
    }

    /// Records WHOIS fields for an address.
    ///
    /// An empty record for an address nothing is known about adds nothing:
    /// an entry is worth its slot only when it has something to show.
    pub fn set_whois(&self, addr: IpAddr, fields: Vec<(String, String)>) {
        self.update(addr, |e| e.whois = fields);
    }

    /// Applies a change to an address's entry, making one if it has none and
    /// making room if the network has already filled the table.
    fn update(&self, addr: IpAddr, f: impl FnOnce(&mut RuntimeClient)) {
        let now = self.now();
        let mut guard = self.table.write();
        let t = &mut *guard;

        if let Some(slot) = t.map.get_mut(&addr) {
            let before = anchored(&slot.client);
            f(&mut slot.client);
            match (before, anchored(&slot.client)) {
                (false, true) => t.learned = t.learned.saturating_sub(1),
                (true, false) => t.learned += 1,
                _ => {}
            }

            return;
        }

        let mut client = RuntimeClient::default();
        f(&mut client);
        if client.name.is_empty() && client.mac.is_none() && client.whois.is_empty() {
            return;
        }

        if !anchored(&client) {
            if t.learned >= self.cap {
                t.evict(self.cap - (self.cap / 10).max(1), now);
            }
            t.learned += 1;
        }

        t.map.insert(
            addr,
            Slot {
                client,
                first: now,
                seen: AtomicU32::new(now),
            },
        );
    }

    /// Looks an address up.
    pub fn get(&self, addr: IpAddr) -> Option<RuntimeClient> {
        self.table.read().map.get(&addr).map(|s| s.client.clone())
    }

    /// The name known for an address, or an empty string.
    pub fn name_of(&self, addr: IpAddr) -> String {
        self.table
            .read()
            .map
            .get(&addr)
            .map(|s| s.client.name.clone())
            .unwrap_or_default()
    }

    /// Every known client, sorted by address, as the API reports them.
    pub fn all(&self) -> Vec<(IpAddr, RuntimeClient)> {
        let mut v: Vec<(IpAddr, RuntimeClient)> = self
            .table
            .read()
            .map
            .iter()
            .map(|(k, s)| (*k, s.client.clone()))
            .collect();
        v.sort_by_key(|(a, _)| *a);

        v
    }

    /// Reports whether an address has already been looked at, so a discovery
    /// pass can skip it.
    pub fn is_known(&self, addr: IpAddr) -> bool {
        self.table.read().map.contains_key(&addr)
    }

    /// Notes that an address asked something, and reports whether anything
    /// is known about it.
    ///
    /// This runs for every query, so it takes only the read lock, and it
    /// writes the time only when the time has moved: a busy client costs one
    /// store a second rather than one per query.  It is what keeps a device
    /// that is in use ahead of a flood of addresses that asked once.
    pub fn touch(&self, addr: IpAddr) -> bool {
        let t = self.table.read();
        let Some(slot) = t.map.get(&addr) else {
            return false;
        };

        let now = self.now();
        if slot.seen.load(Ordering::Relaxed) < now {
            slot.seen.fetch_max(now, Ordering::Relaxed);
        }

        true
    }

    /// How many addresses the store holds.
    pub fn len(&self) -> usize {
        self.table.read().map.len()
    }

    /// Reports whether the store holds nothing.
    pub fn is_empty(&self) -> bool {
        self.table.read().map.is_empty()
    }

    /// How many addresses the store holds, and how many of those carry a
    /// WHOIS record.
    ///
    /// The first is at most [`MAX_RUNTIME`] plus what the hosts file and the
    /// ARP table supplied, however many sources have reached the server: a
    /// count standing at the cap on a resolver open to the internet is
    /// eviction doing its job, not a leak.
    pub fn sizes(&self) -> (usize, usize) {
        let t = self.table.read();

        (
            t.map.len(),
            t.map
                .values()
                .filter(|s| !s.client.whois.is_empty())
                .count(),
        )
    }

    /// Forgets everything.
    pub fn clear(&self) {
        let mut t = self.table.write();
        t.map.clear();
        t.learned = 0;
    }

    /// The store's clock, in whole seconds since it was built.
    fn now(&self) -> u32 {
        let now = u32::try_from(self.epoch.elapsed().as_secs()).unwrap_or(u32::MAX);
        #[cfg(test)]
        let now = now.saturating_add(self.skew.load(Ordering::Relaxed));

        now
    }

    /// Moves the clock on, so the tests do not have to wait.
    #[cfg(test)]
    fn advance(&self, secs: u32) {
        self.skew.fetch_add(secs, Ordering::Relaxed);
    }
}

/// How much a source is trusted, higher being better.
const fn rank(s: Source) -> u8 {
    match s {
        Source::Whois => 0,
        Source::Rdns => 1,
        Source::Arp => 2,
        Source::Dhcp => 3,
        Source::Hosts => 4,
    }
}

/// The rank of an optional source, treating "unknown" as the lowest.
const fn rank_of(s: Option<Source>) -> u8 {
    match s {
        Some(s) => rank(s),
        None => 0,
    }
}

/// One way of identifying a client.
#[derive(Clone, Debug)]
enum Id {
    /// A single address.
    Addr(IpAddr),
    /// A subnet.
    Net(IpAddr, u8),
    /// A MAC address, normalised to lowercase hex with colons.
    Mac(String),
    /// A ClientID, as carried by a DoH path segment or a DoT server name.
    Named(String),
}

impl Id {
    /// Parses an identifier as upstream's client list writes them.
    fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }

        if let Ok(a) = s.parse::<IpAddr>() {
            return Some(Id::Addr(a));
        }

        if let Some((net, bits)) = s.split_once('/')
            && let (Ok(a), Ok(b)) = (net.parse::<IpAddr>(), bits.parse::<u8>())
        {
            return Some(Id::Net(a, b));
        }

        if is_mac(s) {
            return Some(Id::Mac(s.to_ascii_lowercase()));
        }

        Some(Id::Named(s.to_ascii_lowercase()))
    }

    /// How specific this identifier is; a more specific match wins.
    const fn specificity(&self) -> u16 {
        match self {
            Id::Named(_) => 1000,
            Id::Mac(_) => 900,
            Id::Addr(_) => 800,
            Id::Net(_, bits) => *bits as u16,
        }
    }

    /// Reports whether this identifier matches a request's client.
    ///
    /// A DNS query carries no hardware address, so a MAC identifier matches
    /// only when the ARP table has already tied one to the client's address.
    fn matches(&self, addr: Option<IpAddr>, client_id: Option<&str>, mac: Option<&str>) -> bool {
        match self {
            Id::Addr(a) => addr == Some(*a),
            Id::Net(net, bits) => addr.is_some_and(|a| in_subnet(a, *net, *bits)),
            Id::Mac(want) => mac.is_some_and(|m| m.eq_ignore_ascii_case(want)),
            Id::Named(want) => client_id.is_some_and(|c| c.eq_ignore_ascii_case(want)),
        }
    }
}

/// Reports whether a string looks like a MAC address.
fn is_mac(s: &str) -> bool {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    (parts.len() == 6 || parts.len() == 8)
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// The networks an address is local in: upstream's defaults, the list
/// [`crate::resolver::default_private_networks`] builds, held as a constant so
/// the query path can ask without allocating.
const LOCAL_NETWORKS: [(IpAddr, u8); 9] = [
    (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
    (IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12),
    (IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16),
    (IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)), 16),
    (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8),
    (IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), 10),
    (IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0)), 8),
    (IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)), 10),
    (IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
];

/// Reports whether an address is on a local network.
///
/// An IPv4 address carried in IPv6 is judged as the IPv4 address it is, which
/// is how a dual-stack socket hands one over.
pub fn is_local(addr: IpAddr) -> bool {
    let addr = addr.to_canonical();

    LOCAL_NETWORKS
        .iter()
        .any(|&(net, bits)| in_subnet(addr, net, bits))
}

/// Reports whether an address is inside a subnet.
pub fn in_subnet(addr: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (addr, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) if bits <= 32 => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(bits))
            };

            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) if bits <= 128 => {
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(bits))
            };

            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

/// The filtering settings a persistent client overrides.
#[derive(Clone)]
pub struct Persistent {
    /// The client's display name.
    pub name: String,
    /// Its tags, which `$ctag` rules match against.
    pub tags: Vec<String>,
    /// Its own upstream resolvers, if any.
    pub upstreams: Vec<String>,
    /// The identity of those upstreams, or `None` when it uses the global
    /// ones.  See [`upstream_key`].
    pub upstream_key: Option<Arc<str>>,
    /// Whether the global settings apply instead of the ones below.
    pub use_global_settings: bool,
    /// Whether blocklists are consulted.
    pub filtering_enabled: bool,
    /// Whether the global blocked-services settings apply.
    pub use_global_blocked_services: bool,
    /// When this client's blocked services are paused.
    pub schedule: Weekly,
    /// This client's queries are kept out of the query log.
    pub ignore_querylog: bool,
    /// This client's queries are kept out of the statistics.
    pub ignore_statistics: bool,
    /// The blocked-services engine, when the client has its own list.
    pub services: Option<Arc<Engine>>,
    /// The safe-search engine, when the client enforces it.
    pub safe_search: Option<Arc<Engine>>,
    /// The identifiers this client is recognised by.
    ids: Vec<Id>,
}

impl std::fmt::Debug for Persistent {
    /// Prints the settings without the compiled engines, which are large and
    /// say nothing useful.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Persistent")
            .field("name", &self.name)
            .field("tags", &self.tags)
            .field("ids", &self.ids)
            .finish_non_exhaustive()
    }
}

/// The identity of a set of per-client upstreams, or `None` for none.
///
/// It is the upstream lines themselves, normalised: blank lines and comments
/// dropped, the rest trimmed and joined.  Two clients configured with the same
/// servers therefore share one pool and one set of cache entries, which is
/// both cheaper and what an operator would expect — they are the same
/// resolvers.  Renaming a client changes nothing.
///
/// The resolver keys its pool map by this, and so does the cache: see
/// [`crate::cache::Key::upstreams`].
#[must_use]
pub fn upstream_key(lines: &[String]) -> Option<Arc<str>> {
    let kept: Vec<&str> = lines
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    (!kept.is_empty()).then(|| Arc::from(kept.join("\n").as_str()))
}

/// How a persistent client is described before its engines are built.
#[derive(Clone, Debug, Default)]
pub struct PersistentSpec {
    /// The client's display name.
    pub name: String,
    /// Addresses, subnets, MACs and ClientIDs.
    pub ids: Vec<String>,
    /// Tags for `$ctag` rules.
    pub tags: Vec<String>,
    /// Per-client upstreams.
    pub upstreams: Vec<String>,
    /// Whether the global settings apply.
    pub use_global_settings: bool,
    /// Whether blocklists are consulted.
    pub filtering_enabled: bool,
    /// Whether the global blocked-services settings apply.
    pub use_global_blocked_services: bool,
    /// The client's own blocked services.
    pub blocked_services: Vec<String>,
    /// When the client's blocked services are paused.
    pub schedule: Weekly,
    /// The client's safe-search settings.
    pub safe_search: safesearch::Config,
    /// Keep this client out of the query log.
    pub ignore_querylog: bool,
    /// Keep this client out of the statistics.
    pub ignore_statistics: bool,
}

impl Persistent {
    /// Builds a client, compiling its own rule sets.
    pub fn build(spec: &PersistentSpec) -> Self {
        let services = (!spec.use_global_blocked_services && !spec.blocked_services.is_empty())
            .then(|| {
                let rules = sift_filter::services::rules_for(&spec.blocked_services);

                Arc::new(Engine::build(
                    [(sift_filter::lists::BLOCKED_SERVICE_LIST_ID, rules.as_str())],
                    sift_filter::engine::NO_LISTS,
                ))
            });

        let safe_search = (!spec.use_global_settings)
            .then(|| safesearch::engine(&spec.safe_search))
            .flatten()
            .map(Arc::new);

        Self {
            name: spec.name.clone(),
            tags: spec.tags.clone(),
            upstream_key: upstream_key(&spec.upstreams),
            upstreams: spec.upstreams.clone(),
            use_global_settings: spec.use_global_settings,
            filtering_enabled: spec.filtering_enabled,
            use_global_blocked_services: spec.use_global_blocked_services,
            schedule: spec.schedule.clone(),
            ignore_querylog: spec.ignore_querylog,
            ignore_statistics: spec.ignore_statistics,
            services,
            safe_search,
            ids: spec.ids.iter().filter_map(|s| Id::parse(s)).collect(),
        }
    }

    /// How well this client matches a request, if at all.
    fn score(
        &self,
        addr: Option<IpAddr>,
        client_id: Option<&str>,
        mac: Option<&str>,
    ) -> Option<u16> {
        self.ids
            .iter()
            .filter(|id| id.matches(addr, client_id, mac))
            .map(Id::specificity)
            .max()
    }
}

/// The configured persistent clients.
#[derive(Clone, Default)]
pub struct Registry {
    /// The clients, in configuration order.
    clients: Vec<Arc<Persistent>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.clients.iter().map(|c| &c.name))
            .finish()
    }
}

impl Registry {
    /// Builds a registry from the configured clients.
    pub fn build(specs: &[PersistentSpec]) -> Self {
        Self {
            clients: specs
                .iter()
                .map(|s| Arc::new(Persistent::build(s)))
                .collect(),
        }
    }

    /// Reports whether anything is configured.
    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    /// How many clients are configured.
    pub fn len(&self) -> usize {
        self.clients.len()
    }

    /// Finds the client a request belongs to.
    ///
    /// The most specific identifier wins, so a `/32` entry beats the `/24` it
    /// sits inside and a ClientID beats both.
    pub fn find(
        &self,
        addr: Option<IpAddr>,
        client_id: Option<&str>,
        mac: Option<&str>,
    ) -> Option<Arc<Persistent>> {
        self.clients
            .iter()
            .filter_map(|c| c.score(addr, client_id, mac).map(|s| (s, c)))
            .max_by_key(|(s, _)| *s)
            .map(|(_, c)| c.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str, ids: &[&str]) -> PersistentSpec {
        PersistentSpec {
            name: name.into(),
            ids: ids.iter().map(|s| (*s).to_string()).collect(),
            use_global_settings: true,
            use_global_blocked_services: true,
            ..Default::default()
        }
    }

    #[test]
    fn an_address_matches_its_client() {
        let r = Registry::build(&[spec("laptop", &["192.0.2.5"])]);
        assert_eq!(
            r.find(Some("192.0.2.5".parse().unwrap()), None, None)
                .map(|c| c.name.clone())
                .as_deref(),
            Some("laptop")
        );
        assert!(
            r.find(Some("192.0.2.6".parse().unwrap()), None, None)
                .is_none()
        );
    }

    #[test]
    fn a_subnet_matches_every_address_in_it() {
        let r = Registry::build(&[spec("guests", &["192.0.2.0/24"])]);
        assert!(
            r.find(Some("192.0.2.77".parse().unwrap()), None, None)
                .is_some()
        );
        assert!(
            r.find(Some("198.51.100.1".parse().unwrap()), None, None)
                .is_none()
        );
    }

    #[test]
    fn the_most_specific_identifier_wins() {
        let r = Registry::build(&[
            spec("guests", &["192.0.2.0/24"]),
            spec("laptop", &["192.0.2.5"]),
        ]);

        assert_eq!(
            r.find(Some("192.0.2.5".parse().unwrap()), None, None)
                .map(|c| c.name.clone())
                .as_deref(),
            Some("laptop")
        );
    }

    #[test]
    fn a_client_id_beats_an_address() {
        let r = Registry::build(&[
            spec("by-address", &["192.0.2.5"]),
            spec("by-id", &["kids-tablet"]),
        ]);

        assert_eq!(
            r.find(
                Some("192.0.2.5".parse().unwrap()),
                Some("kids-tablet"),
                None
            )
            .map(|c| c.name.clone())
            .as_deref(),
            Some("by-id")
        );
    }

    #[test]
    fn client_ids_are_matched_without_regard_to_case() {
        let r = Registry::build(&[spec("tablet", &["Kids-Tablet"])]);
        assert!(r.find(None, Some("kids-tablet"), None).is_some());
    }

    #[test]
    fn a_mac_matches_only_once_the_arp_table_supplies_one() {
        // A DNS query carries no hardware address, so the identifier hits only
        // when discovery has tied a MAC to the client's address.
        let r = Registry::build(&[spec("printer", &["aa:bb:cc:dd:ee:ff"])]);
        let ip: IpAddr = "192.0.2.9".parse().unwrap();

        assert!(r.find(Some(ip), None, None).is_none());
        assert!(
            r.find(None, Some("aa:bb:cc:dd:ee:ff"), None).is_none(),
            "a MAC is not a ClientID"
        );
        assert_eq!(
            r.find(Some(ip), None, Some("AA:BB:CC:DD:EE:FF"))
                .map(|c| c.name.clone())
                .as_deref(),
            Some("printer")
        );
    }

    #[test]
    fn the_arp_table_supplies_a_hardware_address() {
        let r = Runtime::new();
        let ip: IpAddr = "192.0.2.5".parse().unwrap();
        assert_eq!(r.mac_of(ip), None);

        r.set_mac(ip, "AA:BB:CC:DD:EE:FF");
        assert_eq!(r.mac_of(ip).as_deref(), Some("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn ipv6_subnets_match() {
        let r = Registry::build(&[spec("v6", &["2001:db8::/32"])]);
        assert!(
            r.find(Some("2001:db8::1".parse().unwrap()), None, None)
                .is_some()
        );
        assert!(
            r.find(Some("2001:db9::1".parse().unwrap()), None, None)
                .is_none()
        );
    }

    #[test]
    fn a_client_with_its_own_services_gets_an_engine() {
        let c = Persistent::build(&PersistentSpec {
            name: "kid".into(),
            ids: vec!["192.0.2.5".into()],
            use_global_blocked_services: false,
            blocked_services: vec!["youtube".into()],
            ..Default::default()
        });

        assert!(c.services.is_some(), "a per-client list must compile");
    }

    #[test]
    fn a_client_using_global_services_has_no_engine_of_its_own() {
        let c = Persistent::build(&PersistentSpec {
            use_global_blocked_services: true,
            blocked_services: vec!["youtube".into()],
            ..Default::default()
        });

        assert!(c.services.is_none());
    }

    #[test]
    fn a_client_enforcing_safe_search_gets_an_engine() {
        let c = Persistent::build(&PersistentSpec {
            use_global_settings: false,
            safe_search: safesearch::Config {
                enabled: true,
                ..safesearch::Config::default()
            },
            ..Default::default()
        });

        assert!(c.safe_search.is_some());
    }

    #[test]
    fn runtime_names_prefer_the_more_authoritative_source() {
        let r = Runtime::new();
        let ip: IpAddr = "192.0.2.5".parse().unwrap();

        r.set_name(ip, "from-rdns", Source::Rdns);
        assert_eq!(r.name_of(ip), "from-rdns");

        r.set_name(ip, "from-hosts", Source::Hosts);
        assert_eq!(r.name_of(ip), "from-hosts");

        r.set_name(ip, "later-rdns", Source::Rdns);
        assert_eq!(
            r.name_of(ip),
            "from-hosts",
            "a hosts-file name is not overwritten by a reverse lookup"
        );
    }

    #[test]
    fn an_empty_runtime_name_is_ignored() {
        let r = Runtime::new();
        let ip: IpAddr = "192.0.2.5".parse().unwrap();
        r.set_name(ip, "", Source::Rdns);

        assert!(!r.is_known(ip));
        assert_eq!(r.name_of(ip), "");
    }

    #[test]
    fn runtime_clients_come_back_sorted() {
        let r = Runtime::new();
        r.set_name("192.0.2.9".parse().unwrap(), "b", Source::Arp);
        r.set_name("192.0.2.1".parse().unwrap(), "a", Source::Arp);

        let all = r.all();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].1.name, "a");
    }

    #[test]
    fn mac_addresses_are_recognised() {
        assert!(is_mac("aa:bb:cc:dd:ee:ff"));
        assert!(is_mac("AA-BB-CC-DD-EE-FF"));
        assert!(!is_mac("aa:bb:cc:dd:ee"));
        assert!(!is_mac("kids-tablet"));
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// A stranger's address: one per /64, which is what a source rotating
    /// through a routed /48 has to spend.
    fn stranger(i: u32) -> IpAddr {
        let bits = (0x2001_0db8_u128 << 96) | (u128::from(i) << 64) | 1;

        IpAddr::V6(Ipv6Addr::from_bits(bits))
    }

    /// What WHOIS says about a typical broadband address.
    fn whois_record() -> Vec<(String, String)> {
        vec![
            ("orgname".into(), "Example Broadband Networks Ltd".into()),
            ("city".into(), "Amsterdam".into()),
            ("country".into(), "NL".into()),
        ]
    }

    #[test]
    fn the_table_never_holds_more_than_the_cap_whatever_floods_it() {
        // A hundred thousand sources, each in a /64 of its own, each named by
        // a reverse lookup and described by WHOIS -- ten times the cap, and
        // the most expensive entry there is.
        let r = Runtime::new();
        let mut most = 0;
        for i in 0..100_000 {
            let a = stranger(i);
            r.set_name(a, format!("host-{i}.dyn.example.net"), Source::Rdns);
            r.set_whois(a, whois_record());
            most = most.max(r.len());
            if i % 100 == 0 {
                r.advance(1);
            }
        }

        assert!(most <= MAX_RUNTIME, "held {most}");
        assert!(
            r.len() > MAX_RUNTIME - MAX_RUNTIME / 10,
            "room is made a batch at a time, not by emptying the table"
        );
        assert!(r.is_known(stranger(99_999)), "the newest is kept");
        assert_eq!(r.sizes().1, r.len(), "every entry kept its record");
    }

    #[test]
    fn a_local_client_and_a_busy_one_outlive_a_flood_of_strangers() {
        let r = Runtime::with_cap(1_000);

        // Seen once and never again, but on the operator's own network.
        let nas = ip("192.168.1.20");
        r.set_name(nas, "nas.lan", Source::Rdns);
        let laptop = ip("fd00::1234");
        r.set_name(laptop, "laptop.lan", Source::Rdns);

        // A phone on mobile data: it asked, came back ten minutes later, and
        // then went quiet for the whole of the flood.
        let phone = ip("203.0.113.7");
        r.set_name(phone, "phone.mobile.example", Source::Rdns);
        r.advance(RETURNING_AFTER);
        assert!(r.touch(phone));

        // A public client that is in use the whole time.
        let busy = ip("198.51.100.9");
        r.set_whois(busy, whois_record());

        for i in 0..20_000 {
            r.set_name(stranger(i), format!("s{i}.example"), Source::Rdns);
            if i % 10 == 0 {
                r.advance(1);
                r.touch(busy);
            }
            assert!(r.len() <= 1_000);
        }

        for (a, what) in [
            (nas, "a local address"),
            (laptop, "a local IPv6 address"),
            (phone, "a client that came back"),
            (busy, "a client in use"),
        ] {
            assert!(r.is_known(a), "{what} was given up for strangers");
        }
    }

    #[test]
    fn what_this_machine_supplied_is_never_given_up() {
        // A persistent client identified by its hardware address is only
        // recognised while the ARP table's MAC stays in the runtime store, so
        // evicting it would quietly drop the operator's settings for it.
        let registry = Registry::build(&[spec("kids-tablet", &["aa:bb:cc:dd:ee:ff"])]);
        let r = Runtime::with_cap(100);

        let tablet = ip("192.0.2.50");
        r.set_mac(tablet, "AA:BB:CC:DD:EE:FF");
        for i in 0..150 {
            r.set_name(
                IpAddr::V4(Ipv4Addr::new(198, 18, 0, i)),
                format!("h{i}"),
                Source::Hosts,
            );
        }

        for i in 0..5_000 {
            r.set_name(stranger(i), "s.example", Source::Rdns);
        }

        assert_eq!(r.mac_of(tablet).as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert!(
            registry
                .find(Some(tablet), None, r.mac_of(tablet).as_deref())
                .is_some(),
            "the persistent client is still recognised"
        );
        assert_eq!(r.name_of(ip("198.18.0.149")), "h149");
        assert!(
            r.len() <= 151 + 100,
            "the cap binds what the network taught, beside what the machine did"
        );
    }

    #[test]
    fn a_learned_entry_the_arp_table_names_stops_counting_against_the_cap() {
        let r = Runtime::with_cap(10);
        let printer = ip("192.0.2.9");
        r.set_name(printer, "printer.rdns.example", Source::Rdns);
        r.set_mac(printer, "aa:bb:cc:00:00:01");

        for i in 0..100 {
            r.set_name(stranger(i), "s.example", Source::Rdns);
        }

        assert!(r.is_known(printer));
        assert!(r.len() <= 11);
    }

    #[test]
    fn the_least_recently_seen_stranger_goes_first() {
        let r = Runtime::with_cap(10);
        for i in 0..10 {
            r.set_name(stranger(i), "s.example", Source::Rdns);
            r.advance(1);
        }
        // The first one asks again, so the second is now the oldest.
        assert!(r.touch(stranger(0)));

        r.set_name(stranger(10), "s.example", Source::Rdns);

        assert!(r.is_known(stranger(0)), "seen a moment ago");
        assert!(!r.is_known(stranger(1)), "the least recently seen");
        assert!(r.is_known(stranger(10)), "the newcomer");
        assert_eq!(r.len(), 10);
    }

    #[test]
    fn a_client_gone_a_day_is_no_longer_protected() {
        let r = Runtime::with_cap(10);
        let gone = ip("203.0.113.7");
        r.set_name(gone, "old-phone.example", Source::Rdns);
        r.advance(RETURNING_AFTER);
        r.touch(gone);
        r.advance(STALE_AFTER);

        for i in 0..10 {
            r.set_name(stranger(i), "s.example", Source::Rdns);
        }

        assert!(
            !r.is_known(gone),
            "a device silent for a day ranks with the strangers, and is the oldest of them"
        );
    }

    #[test]
    fn a_learned_entry_is_refused_nothing_when_the_machine_filled_the_table() {
        // The hosts file does not count against the cap, so however large it
        // is there is still room for the network's own entries.
        let r = Runtime::with_cap(10);
        for i in 0..50 {
            r.set_name(IpAddr::V4(Ipv4Addr::new(198, 18, 0, i)), "h", Source::Hosts);
        }
        r.set_name(stranger(0), "s.example", Source::Rdns);

        assert!(r.is_known(stranger(0)));
    }

    #[test]
    fn touching_an_unknown_address_records_nothing() {
        let r = Runtime::new();
        assert!(!r.touch(ip("192.0.2.1")));
        assert!(r.is_empty());
    }

    #[test]
    fn an_empty_whois_record_for_an_unknown_address_adds_nothing() {
        let r = Runtime::new();
        let a = ip("203.0.113.1");
        r.set_whois(a, Vec::new());
        assert!(!r.is_known(a));

        r.set_whois(a, whois_record());
        assert_eq!(r.sizes(), (1, 1));
    }

    #[test]
    fn clearing_the_store_resets_the_cap() {
        let r = Runtime::with_cap(10);
        for i in 0..10 {
            r.set_name(stranger(i), "s.example", Source::Rdns);
        }
        r.clear();
        for i in 10..20 {
            r.set_name(stranger(i), "s.example", Source::Rdns);
        }

        assert_eq!(r.len(), 10, "nothing was evicted to make room");
    }

    #[test]
    fn an_entry_stays_small() {
        // The table is sized for ten thousand of these; see `MAX_RUNTIME`.
        let slot = std::mem::size_of::<(IpAddr, Slot)>();
        assert!(slot <= 112, "{slot} bytes");
    }

    #[test]
    fn local_networks_are_the_resolvers_defaults() {
        assert_eq!(
            LOCAL_NETWORKS.to_vec(),
            crate::resolver::default_private_networks()
        );
    }

    #[test]
    fn local_addresses_are_recognised() {
        assert!(is_local(ip("192.168.1.1")));
        assert!(is_local(ip("10.1.2.3")));
        assert!(is_local(ip("fd00::1")));
        assert!(
            is_local(ip("::ffff:192.168.1.1")),
            "an IPv4 address in IPv6"
        );
        assert!(!is_local(ip("93.184.216.34")));
        assert!(!is_local(ip("2001:db8::1")));
    }
}
