//! Clients: the persistent ones from the config and the ones discovered at
//! run time.
//!
//! A persistent client is matched by address, subnet, MAC or ClientID and
//! carries its own filtering settings; upstream lets those settings override
//! the global ones per query, which is what makes "no YouTube for the kids'
//! tablet" work.  A runtime client is only a name, learned from the hosts
//! file, the ARP table or a reverse lookup, and is what the query log shows
//! next to an address.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

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
#[derive(Clone, Copy, Debug, Default)]
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

/// The store of clients discovered at run time.
#[derive(Default)]
pub struct Runtime {
    /// What is known, by address.
    clients: RwLock<HashMap<IpAddr, RuntimeClient>>,
    /// Which sources may contribute.
    sources: RwLock<Sources>,
}

impl Runtime {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
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

        let mut map = self.clients.write();
        let e = map.entry(addr).or_default();
        if e.name.is_empty() || rank(source) >= rank_of(e.source) {
            e.name = name;
            e.source = Some(source);
        }
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

        self.clients.write().entry(addr).or_default().mac = Some(mac);
    }

    /// The hardware address known for an address, if any.
    pub fn mac_of(&self, addr: IpAddr) -> Option<String> {
        self.clients.read().get(&addr).and_then(|c| c.mac.clone())
    }

    /// Records WHOIS fields for an address.
    pub fn set_whois(&self, addr: IpAddr, fields: Vec<(String, String)>) {
        let mut map = self.clients.write();
        map.entry(addr).or_default().whois = fields;
    }

    /// Looks an address up.
    pub fn get(&self, addr: IpAddr) -> Option<RuntimeClient> {
        self.clients.read().get(&addr).cloned()
    }

    /// The name known for an address, or an empty string.
    pub fn name_of(&self, addr: IpAddr) -> String {
        self.clients
            .read()
            .get(&addr)
            .map(|c| c.name.clone())
            .unwrap_or_default()
    }

    /// Every known client, sorted by address, as the API reports them.
    pub fn all(&self) -> Vec<(IpAddr, RuntimeClient)> {
        let mut v: Vec<(IpAddr, RuntimeClient)> = self
            .clients
            .read()
            .iter()
            .map(|(k, c)| (*k, c.clone()))
            .collect();
        v.sort_by_key(|(a, _)| *a);

        v
    }

    /// Reports whether an address has already been looked at, so a discovery
    /// pass can skip it.
    pub fn is_known(&self, addr: IpAddr) -> bool {
        self.clients.read().contains_key(&addr)
    }

    /// How many addresses the store holds, and how many of those carry a
    /// WHOIS record.
    ///
    /// Nothing evicts from here: an address is added the first time it asks
    /// something and kept for the life of the process, so on a resolver open
    /// to the internet this grows with the number of distinct sources that
    /// have ever reached it.  That is upstream's behaviour too, and it is
    /// bounded by the network on a home installation -- but it is the first
    /// number to read when a resolver that is exposed keeps growing.
    pub fn sizes(&self) -> (usize, usize) {
        let map = self.clients.read();

        (
            map.len(),
            map.values().filter(|c| !c.whois.is_empty()).count(),
        )
    }

    /// Forgets everything.
    pub fn clear(&self) {
        self.clients.write().clear();
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
}
