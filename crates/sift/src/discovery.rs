//! Working out who a client is.
//!
//! A DNS query carries only an address.  Upstream gives that address a name
//! from whatever source it can — the hosts file, the ARP table, a reverse
//! lookup — and a WHOIS record for addresses from outside the network.  The
//! result is what the web interface shows next to a query and what
//! `/control/clients` reports as an automatic client.
//!
//! Every source is best-effort: a failure leaves the address nameless rather
//! than failing a query.
//!
//! What reaches the lookups is rationed, because on a resolver open to the
//! internet the addresses are a stranger's to choose, and every lookup is a
//! query to somebody else's server.  An address waits in one of two lanes, the
//! local one served first; one source's repeats, and every address of one
//! public IPv6 /64, hold a single place in them; a key whose lookup found
//! nothing is left alone for an hour; and a /64 is looked up at most
//! [`PER_PREFIX`] times an hour.  Lookups run one at a time, so however many
//! sources arrive, this holds at most one exchange with a WHOIS server open.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use parking_lot::{Mutex, RwLock};
use sift_dns::clients::{Runtime, Source, Sources, is_local};
use sift_dns::resolver::{ClientInfo, Proto, Resolver};
use tokio::sync::mpsc;

/// How long a WHOIS exchange may take.
const WHOIS_TIMEOUT: Duration = Duration::from_secs(5);

/// The WHOIS server asked first.
const WHOIS_ROOT: &str = "whois.arin.net:43";

/// How many addresses may wait in each lane before new ones are dropped.
///
/// Dropping is the right failure: the address will be seen again on the next
/// query from that client.  Upstream's single queue holds 255 and drops the
/// same way (`defaultQueueSize`, `internal/client/addrproc.go`).
const QUEUE: usize = 256;

/// How long a key whose lookup found nothing is left alone, in seconds.
///
/// Upstream's reverse-lookup and WHOIS caches keep a result, found or not, for
/// an hour (`defaultIPTTL`, `internal/client/addrproc.go`).  Without it an
/// address with no reverse name was queued again by its very next query, and
/// a handful of such sources kept the queue full for everybody else.
const RETRY_AFTER: u32 = 3_600;

/// How many addresses in one public IPv6 /64 are looked up per
/// [`RETRY_AFTER`].
///
/// A /64 is what one subscriber is given, and every address in it is theirs
/// to use.  Without a limit, a source that rotates through its /64 and answers
/// the reverse lookups for it costs a lookup and a WHOIS query per question.
/// Sixteen covers a household's devices and their temporary addresses.
const PER_PREFIX: u16 = 16;

/// The most keys remembered at once.
///
/// The size of each of upstream's two caches (`defaultCacheSize`).  Forgetting
/// a key early costs only a lookup that comes sooner than it would have, so
/// the bound is on memory -- under half a megabyte -- not on correctness.
const MAX_REMEMBERED: usize = 10_000;

/// The fields the API reports from a WHOIS record.
///
/// Upstream keeps only these three, so a record's other fields are read only
/// to fill in an organisation name that was not given directly.
const WHOIS_KEYS: &[&str] = &["orgname", "city", "country"];

/// Discovers client names in the background.
pub struct Discoverer {
    /// The resolver, used for reverse lookups.
    pub resolver: Arc<Resolver>,
    /// Where discovered names are recorded.
    pub runtime: Arc<Runtime>,
}

/// The handle a caller uses to submit addresses for discovery.
#[derive(Clone)]
pub struct Queue(Arc<Gate>);

impl Queue {
    /// Submits an address, dropping it if there is nothing to learn about it
    /// yet or no room to wait.  Never waits: this is on the query path.
    pub fn submit(&self, addr: IpAddr) {
        self.0.submit(addr);
    }
}

/// What a lookup is remembered by.
///
/// An IPv4 address is itself, and so is a local IPv6 address: the devices on
/// the operator's own network each have a name of their own, and leaving one
/// unnamed because its neighbour had none would hide exactly what the
/// operator wants to see.  A public IPv6 address is its /64, the unit the
/// connection guard in `sift-dns` judges a source by too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Key {
    /// One address.
    Addr(IpAddr),
    /// A public /64, by its top half.
    Net([u8; 8]),
}

impl Key {
    /// The key `addr` is remembered by.
    fn of(addr: IpAddr) -> Self {
        match addr.to_canonical() {
            IpAddr::V6(a) if !is_local(addr) => {
                let prefix = u64::try_from(a.to_bits() >> 64).expect("the top half fits");

                Self::Net(prefix.to_be_bytes())
            }
            a => Self::Addr(a),
        }
    }
}

/// What was learned lately under one key.
#[derive(Clone, Copy, Debug)]
struct Mark {
    /// When the mark lapses, on the gate's clock.
    until: u32,
    /// Lookups made under the key since the mark was made.
    lookups: u16,
    /// The last lookup under the key left nothing in the store.
    empty: bool,
}

impl Mark {
    /// A mark made now.
    const fn new(now: u32) -> Self {
        Self {
            until: now.saturating_add(RETRY_AFTER),
            lookups: 0,
            empty: false,
        }
    }

    /// Reports whether the mark still holds new lookups back.
    const fn holds(&self, now: u32) -> bool {
        now < self.until && (self.empty || self.lookups >= PER_PREFIX)
    }
}

/// What was looked up lately.
struct Recent {
    marks: HashMap<Key, Mark>,
    /// The sources in force when the marks were made.  Switching one on is a
    /// reason to look again, so a change forgets them.
    sources: Sources,
}

impl Recent {
    /// Makes room for one more key: forgets what has lapsed, and then as many
    /// of those nearest to lapsing as leaves a quarter of the table free, so
    /// the walk is paid once per thousands of keys rather than once per key.
    fn make_room(&mut self, now: u32) {
        if self.marks.len() < MAX_REMEMBERED {
            return;
        }

        self.marks.retain(|_, m| now < m.until);
        let excess = self
            .marks
            .len()
            .saturating_sub(MAX_REMEMBERED - MAX_REMEMBERED / 4);
        if excess == 0 {
            return;
        }

        let mut order: Vec<(u32, Key)> = self.marks.iter().map(|(k, m)| (m.until, *k)).collect();
        order.select_nth_unstable_by_key(excess - 1, |(until, _)| *until);
        for (_, k) in &order[..excess] {
            self.marks.remove(k);
        }
    }
}

/// What stands between the query path and the lookups.
///
/// An address nobody can name is offered here by every query it sends, so
/// every check is cheap and none of them waits.
struct Gate {
    runtime: Arc<Runtime>,
    /// Addresses on a local network, looked up before anything in `remote`.
    local: mpsc::Sender<IpAddr>,
    /// Everything else.
    remote: mpsc::Sender<IpAddr>,
    /// The keys with an address waiting or being looked up.
    pending: Mutex<HashSet<Key>>,
    recent: RwLock<Recent>,
    /// What the gate's clock counts from.
    epoch: Instant,
    /// Seconds added to the clock, so the tests do not have to wait.
    #[cfg(test)]
    skew: AtomicU32,
}

impl Gate {
    fn new(
        runtime: Arc<Runtime>,
        local: mpsc::Sender<IpAddr>,
        remote: mpsc::Sender<IpAddr>,
    ) -> Self {
        let sources = runtime.sources();

        Self {
            runtime,
            local,
            remote,
            pending: Mutex::new(HashSet::new()),
            recent: RwLock::new(Recent {
                marks: HashMap::new(),
                sources,
            }),
            epoch: Instant::now(),
            #[cfg(test)]
            skew: AtomicU32::new(0),
        }
    }

    /// Offers an address for lookup.
    ///
    /// It is dropped when no enabled source could say anything about it, when
    /// its key was looked up lately to no effect, when its key is already
    /// waiting, and when its lane is full.
    fn submit(&self, addr: IpAddr) {
        let sources = self.runtime.sources();
        let local = is_local(addr);
        if !sources.rdns && !(sources.whois && !local) {
            return;
        }

        let key = Key::of(addr);
        let now = self.now();
        {
            let recent = self.recent.read();
            if recent.sources == sources && recent.marks.get(&key).is_some_and(|m| m.holds(now)) {
                return;
            }
        }

        let lane = if local { &self.local } else { &self.remote };
        let mut pending = self.pending.lock();
        if pending.insert(key) && lane.try_send(addr).is_err() {
            pending.remove(&key);
        }
    }

    /// Records how a lookup went: `found` when it left something in the
    /// store.
    fn done(&self, addr: IpAddr, found: bool) {
        let key = Key::of(addr);
        let now = self.now();
        let sources = self.runtime.sources();
        {
            let mut recent = self.recent.write();
            if recent.sources != sources {
                recent.marks.clear();
                recent.sources = sources;
            }

            if found && matches!(key, Key::Addr(_)) {
                // A known address is not offered again, so there is nothing
                // to hold back -- and if the store later gives it up, it is
                // looked up again when it next asks, as it should be.
                recent.marks.remove(&key);
            } else {
                if !recent.marks.contains_key(&key) {
                    recent.make_room(now);
                }

                let m = recent.marks.entry(key).or_insert_with(|| Mark::new(now));
                if now >= m.until {
                    *m = Mark::new(now);
                }
                m.lookups = m.lookups.saturating_add(1);
                m.empty = !found;
                if !found {
                    m.until = now.saturating_add(RETRY_AFTER);
                }
            }
        }

        // Only now, so an address offered in between finds either its key
        // waiting or the mark in place, never neither.
        self.pending.lock().remove(&key);
    }

    /// The gate's clock, in whole seconds since it was built.
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

/// The receiving ends of the two lanes.
struct Lanes {
    local: mpsc::Receiver<IpAddr>,
    remote: mpsc::Receiver<IpAddr>,
}

impl Lanes {
    /// The next address to look up: a local one whenever one is waiting, so
    /// a flood from outside delays the operator's own devices by the lookup in
    /// progress at most.
    async fn next(&mut self) -> Option<IpAddr> {
        tokio::select! {
            biased;
            a = self.local.recv() => a,
            a = self.remote.recv() => a,
        }
    }
}

impl Discoverer {
    /// Reads the sources that need no network: the hosts file and the ARP
    /// table.
    pub fn prime(&self) {
        let sources = self.runtime.sources();

        if sources.hosts {
            for (addr, name) in parse_hosts(&crate::app::read_system_hosts()) {
                self.runtime.set_name(addr, name, Source::Hosts);
            }
        }

        if sources.arp {
            for (addr, mac) in read_arp_table() {
                self.runtime.set_mac(addr, mac);
            }
        }
    }

    /// Starts the discovery task and returns the queue that feeds it.
    pub fn start(
        self: Arc<Self>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> (Queue, tokio::task::JoinHandle<()>) {
        let (local, local_rx) = mpsc::channel(QUEUE);
        let (remote, remote_rx) = mpsc::channel(QUEUE);
        let gate = Arc::new(Gate::new(self.runtime.clone(), local, remote));
        let mut lanes = Lanes {
            local: local_rx,
            remote: remote_rx,
        };
        let queue = Queue(gate.clone());

        let handle = tokio::spawn(async move {
            // The local sources are cheap and worth having before the first
            // query arrives.
            self.prime();

            let mut refresh = tokio::time::interval(Duration::from_secs(300));
            refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // The first tick fires immediately; the priming above covers it.
            refresh.tick().await;

            loop {
                tokio::select! {
                    _ = shutdown.changed() => return,
                    _ = refresh.tick() => self.prime(),
                    addr = lanes.next() => match addr {
                        Some(a) => {
                            self.discover(a).await;
                            gate.done(a, self.runtime.is_known(a));
                        }
                        None => return,
                    },
                }
            }
        });

        (queue, handle)
    }

    /// Looks one address up through every enabled source.
    async fn discover(&self, addr: IpAddr) {
        let sources = self.runtime.sources();

        if sources.rdns
            && self.runtime.name_of(addr).is_empty()
            && let Some(name) = self.reverse_lookup(addr).await
        {
            self.runtime.set_name(addr, name, Source::Rdns);
        }

        if sources.whois && !is_local(addr) {
            let fields = whois(addr).await;
            if !fields.is_empty() {
                self.runtime.set_whois(addr, fields);
            }
        }
    }

    /// Resolves an address back to a name through this server's own resolver.
    ///
    /// Going through the resolver rather than a separate client means the
    /// lookup honours the private-network routing: a `PTR` for a local address
    /// is answered by the local resolvers, not a public one.
    async fn reverse_lookup(&self, addr: IpAddr) -> Option<String> {
        let name = Name::from_utf8(reverse_name(addr)).ok()?;
        let mut req = Message::query();
        req.metadata.id = rand::random::<u16>();
        req.metadata.recursion_desired = true;
        req.add_query(Query::query(name, RecordType::PTR));

        let out = self
            .resolver
            .resolve(&req, Proto::Udp, &ClientInfo::default())
            .await;

        out.response()?.answers.iter().find_map(|r| match &r.data {
            RData::PTR(p) => {
                let n = p.0.to_ascii().trim_end_matches('.').to_string();
                (!n.is_empty()).then_some(n)
            }
            _ => None,
        })
    }
}

/// The `in-addr.arpa` or `ip6.arpa` name for an address.
pub fn reverse_name(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(a) => {
            let o = a.octets();

            format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(a) => {
            let mut s = String::with_capacity(74);
            for b in a.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", b & 0x0f, b >> 4));
            }
            s.push_str("ip6.arpa.");

            s
        }
    }
}

/// Parses a hosts file into address-to-name pairs.
///
/// Only the first name on a line is taken, which is the canonical one.
pub fn parse_hosts(text: &str) -> Vec<(IpAddr, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        let Some(addr) = parts.next().and_then(|a| a.parse::<IpAddr>().ok()) else {
            continue;
        };
        let Some(name) = parts.next() else {
            continue;
        };

        out.push((addr, name.to_string()));
    }

    out
}

/// Reads the system ARP table, returning address-to-MAC pairs.
///
/// On Linux this is `/proc/net/arp`; elsewhere `arp -an` is parsed, which is
/// the BSD and macOS form.  Anything unrecognised yields nothing.
pub fn read_arp_table() -> Vec<(IpAddr, String)> {
    if let Ok(text) = std::fs::read_to_string("/proc/net/arp") {
        return parse_proc_arp(&text);
    }

    let Ok(out) = std::process::Command::new("arp").arg("-an").output() else {
        return Vec::new();
    };

    parse_arp_command(&String::from_utf8_lossy(&out.stdout))
}

/// Parses Linux's `/proc/net/arp`.
pub fn parse_proc_arp(text: &str) -> Vec<(IpAddr, String)> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 {
                return None;
            }

            let addr = f[0].parse::<IpAddr>().ok()?;
            let mac = f[3];
            if mac == "00:00:00:00:00:00" {
                return None;
            }

            Some((addr, mac.to_ascii_lowercase()))
        })
        .collect()
}

/// Parses the BSD and macOS `arp -an` output.
///
/// Lines look like `? (192.168.1.1) at 0:11:22:aa:bb:cc on en0 ifscope`, and
/// the octets are written without leading zeroes.
pub fn parse_arp_command(text: &str) -> Vec<(IpAddr, String)> {
    text.lines()
        .filter_map(|line| {
            let start = line.find('(')? + 1;
            let end = line[start..].find(')')? + start;
            let addr = line[start..end].parse::<IpAddr>().ok()?;

            let rest = line[end + 1..].trim_start();
            let mac = rest.strip_prefix("at ")?.split_whitespace().next()?;
            if mac.eq_ignore_ascii_case("(incomplete)") {
                return None;
            }

            let parts: Vec<&str> = mac.split(':').collect();
            if parts.len() != 6
                || !parts
                    .iter()
                    .all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
            {
                return None;
            }

            let normalised = parts
                .iter()
                .map(|p| format!("{:0>2}", p.to_ascii_lowercase()))
                .collect::<Vec<_>>()
                .join(":");

            Some((addr, normalised))
        })
        .collect()
}

/// Looks an address up over WHOIS, following one referral.
pub async fn whois(addr: IpAddr) -> Vec<(String, String)> {
    let Some(text) = whois_query(WHOIS_ROOT, &addr.to_string()).await else {
        return Vec::new();
    };

    let mut fields = parse_whois(&text);

    // The regional registry usually points at the one that actually holds the
    // record; one hop is enough and stops a redirect loop.
    if let Some(referral) = referral_of(&text)
        && let Some(more) = whois_query(&referral, &addr.to_string()).await
    {
        let deeper = parse_whois(&more);
        if !deeper.is_empty() {
            fields = deeper;
        }
    }

    fields
}

/// Sends one WHOIS query and reads the reply.
async fn whois_query(server: &str, query: &str) -> Option<String> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let fut = async {
        let mut s = tokio::net::TcpStream::connect(server).await.ok()?;
        s.write_all(format!("{query}\r\n").as_bytes()).await.ok()?;
        s.flush().await.ok()?;

        let mut buf = Vec::new();
        // A WHOIS record is small; a server that streams forever is a fault.
        s.take(256 * 1024).read_to_end(&mut buf).await.ok()?;

        Some(String::from_utf8_lossy(&buf).into_owned())
    };

    tokio::time::timeout(WHOIS_TIMEOUT, fut).await.ok()?
}

/// The referral server a WHOIS record names, if any.
fn referral_of(text: &str) -> Option<String> {
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        let Some(rest) = lower
            .strip_prefix("referralserver:")
            .or_else(|| lower.strip_prefix("refer:"))
        else {
            continue;
        };

        let host = rest
            .trim()
            .trim_start_matches("whois://")
            .trim_end_matches('/');
        if host.is_empty() {
            continue;
        }

        return Some(if host.contains(':') {
            host.to_string()
        } else {
            format!("{host}:43")
        });
    }

    None
}

/// Extracts the fields the API reports from a WHOIS record.
///
/// `descr` and `netname` stand in for a missing `orgname`, which is what
/// upstream does: the registries that omit `OrgName` put the operator's name
/// in one of those instead.
pub fn parse_whois(text: &str) -> Vec<(String, String)> {
    let mut found: BTreeMap<&str, String> = BTreeMap::new();

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('%') || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };

        let value = v.trim();
        if value.is_empty() {
            continue;
        }

        let key = match k.trim().to_ascii_lowercase().as_str() {
            "orgname" | "org-name" | "descr" | "netname" => "orgname",
            "city" => "city",
            "country" => "country",
            _ => continue,
        };

        // The first value wins: later blocks describe wider allocations.
        found.entry(key).or_insert_with(|| value.to_string());
    }

    // Report them in upstream's order rather than alphabetically.
    WHOIS_KEYS
        .iter()
        .filter_map(|k| found.get(k).map(|v| ((*k).to_string(), v.clone())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_names_are_built_the_way_dns_expects() {
        assert_eq!(
            reverse_name("1.2.3.4".parse().unwrap()),
            "4.3.2.1.in-addr.arpa."
        );
        assert_eq!(
            reverse_name("2001:db8::1".parse().unwrap()),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
        );
    }

    #[test]
    fn hosts_files_yield_the_canonical_name() {
        let text = "\
# a comment
127.0.0.1   localhost localhost.localdomain
192.168.1.7 printer.lan printer

not-an-address foo
192.168.1.8
";
        let got = parse_hosts(text);
        assert_eq!(
            got,
            vec![
                ("127.0.0.1".parse().unwrap(), "localhost".to_string()),
                ("192.168.1.7".parse().unwrap(), "printer.lan".to_string()),
            ]
        );
    }

    #[test]
    fn a_trailing_comment_is_stripped() {
        let got = parse_hosts("10.0.0.1 gateway # the router\n");
        assert_eq!(got, vec![("10.0.0.1".parse().unwrap(), "gateway".into())]);
    }

    #[test]
    fn the_linux_arp_table_parses() {
        let text = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0
";
        let got = parse_proc_arp(text);
        assert_eq!(
            got,
            vec![(
                "192.168.1.1".parse().unwrap(),
                "aa:bb:cc:dd:ee:ff".to_string()
            )],
            "an incomplete entry is skipped"
        );
    }

    #[test]
    fn the_bsd_arp_output_parses_and_pads_octets() {
        let text = "\
? (192.168.1.1) at 0:11:22:aa:bb:cc on en0 ifscope [ethernet]
? (192.168.1.5) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.6) at aa:bb:cc:dd:ee:ff on en0 [ethernet]
";
        let got = parse_arp_command(text);
        assert_eq!(
            got,
            vec![
                (
                    "192.168.1.1".parse().unwrap(),
                    "00:11:22:aa:bb:cc".to_string()
                ),
                (
                    "192.168.1.6".parse().unwrap(),
                    "aa:bb:cc:dd:ee:ff".to_string()
                ),
            ]
        );
    }

    #[test]
    fn whois_records_yield_the_reported_fields() {
        let text = "\
% this is a comment
NetRange:       93.184.216.0 - 93.184.216.255
OrgName:        MCI Communications Services, Inc.
OrgId:          MCICS
City:           Ashburn
Country:        US
OrgName:        A later, wider block
";
        let got = parse_whois(text);
        assert_eq!(
            got,
            vec![
                (
                    "orgname".to_string(),
                    "MCI Communications Services, Inc.".to_string()
                ),
                ("city".to_string(), "Ashburn".to_string()),
                ("country".to_string(), "US".to_string()),
            ],
            "the first value of each field wins, in upstream's order"
        );
    }

    #[test]
    fn a_registry_without_orgname_falls_back_to_netname() {
        // RIPE and APNIC records name the operator in netname or descr.
        let got = parse_whois("netname: EXAMPLE-NET\ncountry: NL\n");
        assert_eq!(
            got,
            vec![
                ("orgname".to_string(), "EXAMPLE-NET".to_string()),
                ("country".to_string(), "NL".to_string()),
            ]
        );
    }

    #[test]
    fn a_referral_is_recognised_in_either_spelling() {
        assert_eq!(
            referral_of("ReferralServer:  whois://whois.ripe.net\n").as_deref(),
            Some("whois.ripe.net:43")
        );
        assert_eq!(
            referral_of("refer:        whois.apnic.net\n").as_deref(),
            Some("whois.apnic.net:43")
        );
        assert_eq!(referral_of("OrgName: nothing here\n"), None);
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// An address in its own public /64.
    fn subscriber(i: u32) -> IpAddr {
        IpAddr::V6(std::net::Ipv6Addr::from_bits(
            (0x2001_0db8_u128 << 96) | (u128::from(i) << 64) | 1,
        ))
    }

    /// The `n`th address inside one public /64.
    fn rotation(n: u32) -> IpAddr {
        IpAddr::V6(std::net::Ipv6Addr::from_bits(
            (0x2001_0db8_0001_0002_u128 << 64) | u128::from(n),
        ))
    }

    /// A gate with both network sources on, and the lanes it feeds.
    fn gate() -> (Gate, Lanes) {
        let runtime = Arc::new(Runtime::new());
        runtime.set_sources(Sources {
            rdns: true,
            whois: true,
            ..Sources::default()
        });

        let (local, local_rx) = mpsc::channel(QUEUE);
        let (remote, remote_rx) = mpsc::channel(QUEUE);

        (
            Gate::new(runtime, local, remote),
            Lanes {
                local: local_rx,
                remote: remote_rx,
            },
        )
    }

    /// Everything waiting, local lane first, as the worker would take it.
    fn drain(lanes: &mut Lanes) -> Vec<IpAddr> {
        let mut out = Vec::new();
        while let Ok(a) = lanes.local.try_recv() {
            out.push(a);
        }
        while let Ok(a) = lanes.remote.try_recv() {
            out.push(a);
        }

        out
    }

    #[test]
    fn one_sources_repeats_hold_one_place_in_the_queue() {
        let (g, mut lanes) = gate();
        let a = ip("198.51.100.7");
        for _ in 0..1_000 {
            g.submit(a);
        }

        assert_eq!(drain(&mut lanes), vec![a]);
    }

    #[test]
    fn a_source_rotating_through_its_64_holds_one_place_for_all_of_it() {
        let (g, mut lanes) = gate();
        for n in 0..1_000 {
            g.submit(rotation(n));
        }
        let neighbour = ip("2001:db8:1:3::1");
        g.submit(neighbour);

        assert_eq!(
            drain(&mut lanes),
            vec![rotation(0), neighbour],
            "the next /64 is somebody else"
        );
    }

    #[test]
    fn devices_on_the_local_ipv6_network_are_each_looked_up() {
        // They share a /64 too, but each has its own name on the operator's
        // own network.
        let (g, mut lanes) = gate();
        g.submit(ip("fd00::1"));
        g.submit(ip("fd00::2"));

        assert_eq!(drain(&mut lanes).len(), 2);
    }

    #[test]
    fn a_failed_lookup_is_not_retried_on_every_query_but_is_after_an_hour() {
        let (g, mut lanes) = gate();
        let a = ip("198.51.100.7");
        g.submit(a);
        assert_eq!(drain(&mut lanes), vec![a]);
        g.done(a, false);

        for _ in 0..100 {
            g.submit(a);
        }
        g.advance(RETRY_AFTER - 1);
        g.submit(a);
        assert!(drain(&mut lanes).is_empty(), "left alone for the hour");

        g.advance(1);
        g.submit(a);
        assert_eq!(drain(&mut lanes), vec![a], "and asked again after it");
    }

    #[test]
    fn a_64_whose_lookup_found_nothing_is_left_alone_for_an_hour() {
        let (g, mut lanes) = gate();
        g.submit(rotation(1));
        drain(&mut lanes);
        g.done(rotation(1), false);

        g.submit(rotation(2));
        assert!(drain(&mut lanes).is_empty());

        g.submit(subscriber(7));
        assert_eq!(drain(&mut lanes), vec![subscriber(7)]);
    }

    #[test]
    fn a_64_is_looked_up_a_limited_number_of_times_an_hour() {
        // A source that answers its own reverse lookups is found every time,
        // so nothing marks it empty; the budget is what stops it.
        let (g, mut lanes) = gate();
        for n in 0..u32::from(PER_PREFIX) {
            g.submit(rotation(n));
            assert_eq!(drain(&mut lanes), vec![rotation(n)]);
            g.done(rotation(n), true);
        }

        g.submit(rotation(1_000));
        assert!(drain(&mut lanes).is_empty(), "the /64 has had its share");

        g.advance(RETRY_AFTER);
        g.submit(rotation(1_000));
        assert_eq!(drain(&mut lanes), vec![rotation(1_000)]);
    }

    #[test]
    fn an_address_the_store_gave_up_is_looked_up_again() {
        // A found address is held back by the store knowing it, not by a mark
        // here, so one the store evicted is named again when it next asks.
        let (g, mut lanes) = gate();
        let a = ip("198.51.100.7");
        g.submit(a);
        drain(&mut lanes);
        g.done(a, true);

        g.submit(a);
        assert_eq!(drain(&mut lanes), vec![a]);
    }

    #[tokio::test]
    async fn local_addresses_are_looked_up_before_a_flood_from_outside() {
        let (g, mut lanes) = gate();
        for i in 0..=u32::try_from(QUEUE).unwrap() {
            g.submit(subscriber(i));
        }
        let nas = ip("192.168.1.20");
        g.submit(nas);

        assert_eq!(lanes.next().await, Some(nas));
        assert_eq!(lanes.next().await, Some(subscriber(0)));
    }

    #[test]
    fn a_full_lane_drops_the_address_and_forgets_it_was_offered() {
        let (g, mut lanes) = gate();
        let queue = u32::try_from(QUEUE).unwrap();
        for i in 0..queue {
            g.submit(subscriber(i));
        }
        let late = subscriber(queue);
        g.submit(late);

        let waiting = drain(&mut lanes);
        assert_eq!(waiting.len(), QUEUE);
        assert!(!waiting.contains(&late), "dropped, not waited for");
        for a in waiting {
            g.done(a, true);
        }

        g.submit(late);
        assert_eq!(
            drain(&mut lanes),
            vec![late],
            "a dropped address is not left looking as if it were waiting"
        );
    }

    #[test]
    fn nothing_is_queued_that_no_enabled_source_could_name() {
        let (g, mut lanes) = gate();
        g.runtime.set_sources(Sources {
            whois: true,
            ..Sources::default()
        });
        g.submit(ip("192.168.1.20"));
        assert!(
            drain(&mut lanes).is_empty(),
            "WHOIS is never asked about a local address"
        );

        g.runtime.set_sources(Sources::default());
        g.submit(ip("198.51.100.7"));
        assert!(drain(&mut lanes).is_empty());
    }

    #[test]
    fn switching_a_source_on_forgets_what_was_found_missing() {
        let (g, mut lanes) = gate();
        g.runtime.set_sources(Sources {
            whois: true,
            ..Sources::default()
        });
        let a = ip("198.51.100.7");
        g.submit(a);
        drain(&mut lanes);
        g.done(a, false);

        g.runtime.set_sources(Sources {
            whois: true,
            rdns: true,
            ..Sources::default()
        });
        g.submit(a);
        assert_eq!(drain(&mut lanes), vec![a]);
    }

    #[test]
    fn what_is_remembered_is_bounded() {
        let (g, _lanes) = gate();
        for i in 0..3 * u32::try_from(MAX_REMEMBERED).unwrap() {
            g.done(IpAddr::V4(std::net::Ipv4Addr::from_bits(i)), false);
            assert!(g.recent.read().marks.len() <= MAX_REMEMBERED);
        }
    }

    #[test]
    fn keys_are_addresses_except_for_public_ipv6() {
        assert_eq!(
            Key::of(ip("::ffff:198.51.100.7")),
            Key::of(ip("198.51.100.7")),
            "an IPv4 address carried in IPv6 is the IPv4 address"
        );
        assert_eq!(Key::of(rotation(1)), Key::of(rotation(2)));
        assert_ne!(Key::of(ip("fd00::1")), Key::of(ip("fd00::2")));
        assert_ne!(Key::of(ip("192.0.2.1")), Key::of(ip("192.0.2.2")));
    }
}
