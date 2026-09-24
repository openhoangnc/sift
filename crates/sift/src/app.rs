//! Building a running server from a configuration file.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use sift_config::Config;
use sift_config::model::{BlockingMode as CfgBlockingMode, UpstreamMode};
use sift_dns::addr;
use sift_dns::cache::{Cache, Config as CacheConfig};
use sift_dns::client::{Client, tls_config};
use sift_dns::msg::{BlockingConfig, BlockingMode};
use sift_dns::pool::{self, Mode, Pool, SharedPool};
use sift_dns::ratelimit::{Config as RlConfig, Limiter};
use sift_dns::resolver::{Resolver, Settings};
use sift_dns::rewrite::Table;
use sift_dns::server::{
    Access, NoopObserver, Observer, Server, bind_tcp, bind_udp, serve_tcp, serve_udp,
};

use sift_config::Paths;
use sift_filter::lists::Manager;

/// A startup failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The configuration could not be read or written.
    #[error(transparent)]
    Config(#[from] sift_config::file::Error),

    /// A listener could not be bound.
    #[error("binding {addr}: {source}")]
    Bind {
        /// The address that could not be bound.
        addr: SocketAddr,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// A filesystem operation failed.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

/// A configured, not-yet-running server.
pub struct App {
    /// Where everything lives on disk.
    pub paths: Paths,
    /// The parsed configuration.
    pub config: Config,
    /// The loaded filter lists.
    pub filters: Manager,
    /// The resolver.
    pub resolver: Arc<Resolver>,
    /// The listener front end.
    pub server: Arc<Server>,
}

impl App {
    /// Builds an application from a configuration file.
    ///
    /// Upstream resolution happens here, so a misconfigured upstream is
    /// reported at startup rather than on the first query.
    pub async fn build(
        paths: Paths,
        config: Config,
        observer: Arc<dyn Observer>,
    ) -> Result<Self, Error> {
        paths.ensure()?;

        // Said before the work, not after: a large installation — 37 lists
        // and a couple of million rules is real — spends seconds here with
        // nothing else to show, and silence between "starting" and "serving"
        // reads as a hang.
        let enabled = config.filters.iter().filter(|f| f.enabled).count()
            + config
                .whitelist_filters
                .iter()
                .filter(|f| f.enabled)
                .count();
        tracing::info!(lists = enabled, "loading filter lists");

        let mut filters = Manager::load(
            &paths,
            &config.filters,
            &config.whitelist_filters,
            &config.user_rules,
        );
        filters.set_blocked_services(&config.filtering.blocked_services.ids);
        if config.dns.hostsfile_enabled {
            filters.set_hosts(read_system_hosts());
        }
        let engine = filters.build_engine();

        let rewrites = Table::build(
            config
                .filtering
                .rewrites
                .iter()
                .map(|r| (r.domain.as_str(), r.answer.as_str(), r.enabled)),
        );

        let cache = Cache::new(cache_config(&config));
        let pool = SharedPool::new(build_pool(&config).await);
        let resolver = Arc::new(Resolver::new(
            engine,
            rewrites,
            cache,
            pool,
            settings(&config),
        ));
        // Background cache refreshes.  The worker holds an `Arc<Resolver>`,
        // which is why it is spawned from here rather than from inside the
        // resolver: handling a request only ever reaches the queue's sender.
        let (refresh_tx, refresh_rx) = sift_dns::refresh::channel();
        resolver.set_refresh_sender(refresh_tx);
        tokio::spawn(sift_dns::refresh::run(resolver.clone(), refresh_rx));

        resolver.set_services(filters.build_services_engine());
        resolver.set_safe_search(sift_filter::safesearch::engine(&safe_search(
            &config.filtering.safe_search,
        )));
        resolver.set_clients(clients(&config));
        // Before anything is served, so a client with its own upstreams never
        // has a window where its queries go to the global ones.
        resolver.set_client_pools(build_client_pools(&config).await);
        resolver.runtime.set_sources(sift_dns::clients::Sources {
            whois: config.clients.runtime_sources.whois,
            arp: config.clients.runtime_sources.arp,
            rdns: config.clients.runtime_sources.rdns,
            // This build serves no DHCP, so there are no leases to read.
            dhcp: false,
            hosts: config.clients.runtime_sources.hosts,
        });
        resolver.set_private_pool(build_private_pool(&config).await);

        let limiter = Arc::new(Limiter::new(RlConfig {
            per_second: config.dns.ratelimit,
            subnet_len_v4: config.dns.ratelimit_subnet_len_ipv4,
            subnet_len_v6: config.dns.ratelimit_subnet_len_ipv6,
            allowlist: config.dns.ratelimit_whitelist.clone(),
        }));

        let server = Arc::new(Server::new(resolver.clone(), limiter, observer));
        server.set_max_concurrent(config.dns.max_goroutines);
        server.set_probe_config(probe_config(&config));
        let (name, strict) = server_name(&config);
        server.set_server_name(name, strict);
        *server.access.write() =
            Access::new(&config.dns.allowed_clients, &config.dns.disallowed_clients);

        Ok(Self {
            paths,
            config,
            filters,
            resolver,
            server,
        })
    }

    /// Builds an application with no query observer.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn build_quiet(paths: Paths, config: Config) -> Result<Self, Error> {
        Self::build(paths, config, Arc::new(NoopObserver)).await
    }

    /// The addresses the DNS server should listen on.
    pub fn dns_addrs(&self) -> Vec<SocketAddr> {
        self.config
            .dns
            .bind_hosts
            .iter()
            .map(|ip| SocketAddr::new(*ip, self.config.dns.port))
            .collect()
    }

    /// Starts every DNS listener and serves until `shutdown` resolves.
    pub async fn serve_dns(
        &self,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<Vec<tokio::task::JoinHandle<()>>, Error> {
        let mut tasks = Vec::new();

        for addr in self.dns_addrs() {
            if self.config.dns.serve_plain_dns {
                let sock = bind_udp(addr)
                    .await
                    .map_err(|source| Error::Bind { addr, source })?;
                let server = self.server.clone();
                let mut rx = shutdown.clone();
                tasks.push(tokio::spawn(async move {
                    // Returns only at shutdown: an error reading the socket
                    // is ridden out rather than closing the port.
                    serve_udp(sock, server, async move {
                        let _ = rx.changed().await;
                    })
                    .await;
                }));

                let listener = bind_tcp(addr)
                    .await
                    .map_err(|source| Error::Bind { addr, source })?;
                let server = self.server.clone();
                let mut rx = shutdown.clone();
                tasks.push(tokio::spawn(async move {
                    // Likewise: an error accepting is waited out, so this
                    // ends only when asked to.
                    serve_tcp(listener, server, async move {
                        let _ = rx.changed().await;
                    })
                    .await;
                }));
            }
        }

        Ok(tasks)
    }
}

/// Reads the system hosts file, returning its contents or an empty string.
///
/// A missing or unreadable file is not an error: the hosts file is advisory
/// here, and failing startup over it would be worse than ignoring it.
pub fn read_system_hosts() -> String {
    #[cfg(unix)]
    const PATH: &str = "/etc/hosts";
    #[cfg(not(unix))]
    const PATH: &str = r"C:\Windows\System32\drivers\etc\hosts";

    match std::fs::read_to_string(PATH) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(path = PATH, error = %e, "reading the system hosts file");

            String::new()
        }
    }
}

/// Parses a list of addresses or CIDRs into networks.
///
/// A bare address becomes a host route, which is how upstream reads the
/// `bogus_nxdomain` list.
pub fn parse_networks(v: &[String]) -> Vec<(std::net::IpAddr, u8)> {
    v.iter()
        .filter_map(|s| {
            let s = s.trim();
            if let Some((net, bits)) = s.split_once('/') {
                let a: std::net::IpAddr = net.parse().ok()?;
                let b: u8 = bits.parse().ok()?;

                return Some((a, b));
            }

            let a: std::net::IpAddr = s.parse().ok()?;
            let bits = if a.is_ipv4() { 32 } else { 128 };

            Some((a, bits))
        })
        .collect()
}

/// Builds the weekly schedule from its configured form.
pub fn schedule(s: &sift_config::model::Schedule) -> sift_core::schedule::Weekly {
    use sift_core::schedule::DayRange;

    let day = |d: &Option<sift_config::model::DayRange>| -> Option<DayRange> {
        d.as_ref().map(|r| DayRange {
            start_ms: r.start.as_millis(),
            end_ms: r.end.as_millis(),
        })
    };

    sift_core::schedule::Weekly::new(
        s.time_zone.clone(),
        [
            day(&s.mon),
            day(&s.tue),
            day(&s.wed),
            day(&s.thu),
            day(&s.fri),
            day(&s.sat),
            day(&s.sun),
        ],
    )
}

/// Converts the config's safe-search block into the filter crate's form.
pub fn safe_search(c: &sift_config::model::SafeSearchConfig) -> sift_filter::safesearch::Config {
    sift_filter::safesearch::Config {
        enabled: c.enabled,
        bing: c.bing,
        duckduckgo: c.duckduckgo,
        ecosia: c.ecosia,
        google: c.google,
        pixabay: c.pixabay,
        yandex: c.yandex,
        youtube: c.youtube,
    }
}

/// Builds the persistent client registry from the configuration.
pub fn clients(c: &Config) -> sift_dns::clients::Registry {
    let specs: Vec<sift_dns::clients::PersistentSpec> = c
        .clients
        .persistent
        .iter()
        .map(|p| sift_dns::clients::PersistentSpec {
            name: p.name.clone(),
            ids: p.ids.clone(),
            tags: p.tags.clone(),
            upstreams: p.upstreams.clone(),
            use_global_settings: p.use_global_settings,
            filtering_enabled: p.filtering_enabled,
            use_global_blocked_services: p.use_global_blocked_services,
            blocked_services: p.blocked_services.ids.clone(),
            schedule: schedule(&p.blocked_services.schedule),
            safe_search: safe_search(&p.safe_search),
            ignore_querylog: p.ignore_querylog,
            ignore_statistics: p.ignore_statistics,
        })
        .collect();

    sift_dns::clients::Registry::build(&specs)
}

/// Describes the encrypted endpoints DDR should advertise.
///
/// Empty when no certificate names the server or no encrypted listener is
/// configured — there would be nothing to point at.  Whether the DDR name is
/// answered at all is `dns.handle_ddr`, and it is a separate question: the name
/// is answered either way, because a DDR query that reaches an upstream comes
/// back naming *that* resolver.
pub fn ddr_endpoints(c: &Config) -> sift_dns::ddr::Endpoints {
    if !c.tls.enabled || c.tls.server_name.is_empty() {
        return sift_dns::ddr::Endpoints::default();
    }

    let ep = sift_dns::ddr::Endpoints {
        server_name: c.tls.server_name.clone(),
        https: (c.tls.port_https != 0).then_some(c.tls.port_https),
        // Upstream only advertises DoT when the certificate names IP
        // addresses, because a client that found this resolver by address has
        // no hostname to validate against.
        tls: (c.tls.port_dns_over_tls != 0 && certificate_names_an_ip(c))
            .then_some(c.tls.port_dns_over_tls),
        quic: (c.tls.port_dns_over_quic != 0).then_some(c.tls.port_dns_over_quic),
    };

    if ep.is_empty() {
        return sift_dns::ddr::Endpoints::default();
    }

    ep
}

/// Where the configured certificate and key are to be read from.
pub fn tls_source(c: &Config) -> sift_dns::tls::Source {
    sift_dns::tls::Source {
        certificate_chain: c.tls.certificate_chain.clone(),
        private_key: c.tls.private_key.clone(),
        certificate_path: c.tls.certificate_path.clone(),
        private_key_path: c.tls.private_key_path.clone(),
    }
}

/// Reports whether the configured certificate carries an IP address.
fn certificate_names_an_ip(c: &Config) -> bool {
    let src = tls_source(c);
    if src.is_empty() {
        return false;
    }

    sift_dns::tls::inspect(&src).has_ip_addresses
}

/// Derives resolver settings from the configuration.
pub fn settings(c: &Config) -> Settings {
    Settings {
        protection_enabled: c.filtering.protection_enabled,
        filtering_enabled: c.filtering.filtering_enabled,
        rewrites_enabled: c.filtering.rewrites_enabled,
        blocking: BlockingConfig {
            mode: match c.filtering.blocking_mode {
                CfgBlockingMode::Default => BlockingMode::Default,
                CfgBlockingMode::CustomIp => BlockingMode::CustomIp,
                CfgBlockingMode::Nxdomain => BlockingMode::Nxdomain,
                CfgBlockingMode::NullIp => BlockingMode::NullIp,
                CfgBlockingMode::Refused => BlockingMode::Refused,
            },
            custom_v4: match c.filtering.blocking_ipv4.get() {
                Some(std::net::IpAddr::V4(a)) => Some(a),
                _ => None,
            },
            custom_v6: match c.filtering.blocking_ipv6.get() {
                Some(std::net::IpAddr::V6(a)) => Some(a),
                _ => None,
            },
            ttl: c.filtering.blocked_response_ttl,
        },
        blocked_hosts: sift_dns::blocked::BlockedHosts::shared(&c.dns.blocked_hosts),
        aaaa_disabled: c.dns.aaaa_disabled,
        refuse_any: c.dns.refuse_any,
        cache_ttl_min: c.dns.cache_ttl_min,
        cache_ttl_max: c.dns.cache_ttl_max,
        ecs_enabled: c.dns.edns_client_subnet.enabled,
        ecs_custom: c
            .dns
            .edns_client_subnet
            .use_custom
            .then(|| c.dns.edns_client_subnet.custom_ip.get())
            .flatten(),
        dnssec_enabled: c.dns.enable_dnssec,
        bogus_nxdomain: parse_networks(&c.dns.bogus_nxdomain),
        dns64: sift_dns::dns64::Prefixes::new(
            c.dns.use_dns64,
            c.dns.dns64_prefixes.iter().map(|p| (p.addr, p.bits)),
        ),
        handle_ddr: c.dns.handle_ddr,
        ddr: ddr_endpoints(c),
        pending_enabled: c.dns.pending_requests.enabled,
        services_schedule: schedule(&c.filtering.blocked_services.schedule),
        private_networks: private_networks(c),
        use_private_ptr_resolvers: c.dns.use_private_ptr_resolvers,
    }
}

/// The networks the operator calls private: `dns.private_networks`, or
/// upstream's defaults when it is empty.
///
/// One list for both things that ask: the resolver, which routes a `PTR`
/// for these to the local resolvers, and the connection guard, which treats
/// a client from them as local.
pub fn private_networks(c: &Config) -> Vec<(IpAddr, u8)> {
    if c.dns.private_networks.is_empty() {
        sift_dns::resolver::default_private_networks()
    } else {
        c.dns
            .private_networks
            .iter()
            .map(|p| (p.addr, p.bits))
            .collect()
    }
}

/// The connection guard's settings, which are the defaults plus the
/// operator's own exemptions, with the connection budget sized to the
/// descriptors the process has.
///
/// `ratelimit_whitelist` is reused rather than a setting of our own: an
/// address the operator has already exempted from one defence is exempt from
/// this one, and the config file stays exactly what the Go build writes.
/// What counts as local is [`private_networks`].  The /64s of this host's
/// own global IPv6 addresses, read from its interfaces now, are not local
/// but judged one address at a time -- see
/// [`sift_dns::probe::Config::host_networks`] for why not exempt, and
/// [`sift_dns::probe::host_networks`] for why nothing wider.  The interfaces
/// can change under a running server -- an ISP renumbers a delegated prefix
/// -- so the maintenance tick reads them again.
pub fn probe_config(config: &Config) -> sift_dns::probe::Config {
    probe_config_for(config, host_networks())
}

/// [`probe_config`] with the host's networks given rather than read.
pub fn probe_config_for(config: &Config, host: Vec<(IpAddr, u8)>) -> sift_dns::probe::Config {
    sift_dns::probe::Config {
        allowlist: config.dns.ratelimit_whitelist.clone(),
        local_networks: private_networks(config),
        host_networks: host,
        max_connections: connection_budget(crate::osconf::nofile_limit()),
        ..Default::default()
    }
}

/// The /64 of each global IPv6 address this host's interfaces carry now.
pub fn host_networks() -> Vec<(IpAddr, u8)> {
    sift_dns::probe::host_networks(sift_api::netiface::addresses())
}

/// How many connections the internet may hold open at once, given the soft
/// descriptor limit.
///
/// Each one is a descriptor, and so is everything else the process does --
/// the listening sockets, a socket per upstream query in flight, the log and
/// the databases -- and running out of them is what stops a listener
/// accepting anything at all.  So connections get at most half, and never
/// more than the guard's own default: under a systemd unit's 1,024 that is
/// 512, and with the half-million Go's runtime raises the limit to, the
/// default of 4,096.  An unlimited or unknown limit leaves the default.
pub fn connection_budget(soft_limit: Option<u64>) -> usize {
    let default = sift_dns::probe::Config::default().max_connections;

    soft_limit.map_or(default, |limit| {
        // Never zero, which the guard reads as no limit at all.
        usize::try_from(limit / 2)
            .unwrap_or(usize::MAX)
            .clamp(1, default)
    })
}

/// The name encrypted clients connect to, and whether they must: what the
/// DNS server is given as `tls.server_name` and `tls.strict_sni_check`.
///
/// Both empty while encryption is off, as upstream's `newDNSTLSConfig`
/// hands its DNS server an empty TLS configuration then -- so no ClientID is
/// read from a name and none is refused.
pub fn server_name(c: &Config) -> (&str, bool) {
    if c.tls.enabled {
        (c.tls.server_name.as_str(), c.tls.strict_sni_check)
    } else {
        ("", false)
    }
}

/// Derives cache settings from the configuration.
pub fn cache_config(c: &Config) -> CacheConfig {
    CacheConfig {
        size_bytes: if c.dns.cache_enabled {
            c.dns.cache_size as usize
        } else {
            0
        },
        ttl_min: c.dns.cache_ttl_min,
        ttl_max: c.dns.cache_ttl_max,
        optimistic: c.dns.cache_optimistic,
        optimistic_answer_ttl: c.dns.cache_optimistic_answer_ttl.to_std(),
        optimistic_max_age: c.dns.cache_optimistic_max_age.to_std(),
    }
}

/// Resolves every configured upstream and builds the pool.
///
/// Upstreams that fail to resolve are skipped with a warning rather than
/// aborting startup, so one dead resolver cannot keep the server down.
pub async fn build_pool(c: &Config) -> Pool {
    build_pool_from(c, upstream_lines(c)).await
}

/// Builds a pool from an explicit upstream list.
///
/// The global pool and every per-client pool go through here, so a client's
/// own servers get the same bootstrap resolvers, the same mode, the same
/// timeouts and the same fallbacks as the global ones.  That is what upstream
/// does: `client.UpstreamConfig` replaces the servers, not the options around
/// them.
pub async fn build_pool_from(c: &Config, lines: Vec<String>) -> Pool {
    let timeout = c.dns.upstream_timeout.to_std();
    let bootstrap = bootstrap_addrs(&c.dns.bootstrap_dns);
    let tls = tls_config();

    let (bad_lines, entries) = {
        let (entries, bad) = addr::parse_list(lines.iter().map(String::as_str));
        (bad, entries)
    };
    for (line, err) in bad_lines {
        tracing::warn!(upstream = %line, error = %err, "ignoring invalid upstream");
    }

    let (default_specs, group_specs) = pool::partition(entries);

    let connect = async |specs: Vec<addr::Upstream>| -> Vec<Arc<Client>> {
        let mut out = Vec::new();
        for s in specs {
            let label = s.original.clone();
            match Client::connect(
                s,
                &bootstrap,
                timeout,
                c.dns.bootstrap_prefer_ipv6,
                tls.clone(),
            )
            .await
            {
                Ok(cl) => out.push(Arc::new(cl.with_http3(c.dns.use_http3_upstreams))),
                Err(e) => tracing::warn!(upstream = %label, error = %e, "upstream unavailable"),
            }
        }

        out
    };

    let defaults = connect(default_specs).await;

    let mut groups = Vec::new();
    for (domains, specs) in group_specs {
        groups.push((domains, connect(specs).await));
    }

    let (fallback_entries, _) = addr::parse_list(c.dns.fallback_dns.iter().map(String::as_str));
    let (fallback_specs, _) = pool::partition(fallback_entries);
    let fallbacks = connect(fallback_specs).await;

    Pool::new(
        defaults,
        groups,
        fallbacks,
        match c.dns.upstream_mode {
            UpstreamMode::LoadBalance => Mode::LoadBalance,
            UpstreamMode::Parallel => Mode::Parallel,
            UpstreamMode::FastestAddr => Mode::FastestAddr,
        },
        timeout,
        c.dns.fastest_timeout.to_std(),
    )
}

/// Builds one pool per distinct set of per-client upstreams.
///
/// Keyed by `sift_dns::clients::upstream_key`, so two clients configured with
/// the same servers share a pool — and, because the cache key carries the same
/// identity, share cache entries too.  A client with no upstreams of its own
/// contributes nothing here and resolves through the global pool.
pub async fn build_client_pools(
    c: &Config,
) -> std::collections::HashMap<Arc<str>, Arc<sift_dns::pool::Pool>> {
    let mut out = std::collections::HashMap::new();

    for p in &c.clients.persistent {
        let Some(key) = sift_dns::clients::upstream_key(&p.upstreams) else {
            continue;
        };
        if out.contains_key(&key) {
            continue;
        }

        tracing::debug!(client = %p.name, "building the client's own upstreams");
        out.insert(key, Arc::new(build_pool_from(c, p.upstreams.clone()).await));
    }

    out
}

/// The upstream specifications to use, including any read from a file.
///
/// `upstream_dns_file` is read fresh at every reload rather than merged into
/// the config: it exists so a script can maintain the list without rewriting
/// `AdGuardHome.yaml`.
pub fn upstream_lines(c: &Config) -> Vec<String> {
    let mut out = c.dns.upstream_dns.clone();

    if c.dns.upstream_dns_file.is_empty() {
        return out;
    }

    match std::fs::read_to_string(&c.dns.upstream_dns_file) {
        Ok(text) => out.extend(
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string),
        ),
        Err(e) => {
            tracing::warn!(
                path = %c.dns.upstream_dns_file,
                error = %e,
                "reading upstream_dns_file"
            );
        }
    }

    out
}

/// Builds the pool used for private reverse lookups.
///
/// When the feature is on but no resolvers are named, the ones the operating
/// system is configured with are used, as upstream does: those are the
/// resolvers that know the local network.
pub async fn build_private_pool(c: &Config) -> Option<SharedPool> {
    if !c.dns.use_private_ptr_resolvers {
        return None;
    }

    let specs: Vec<String> = if c.dns.local_ptr_upstreams.is_empty() {
        system_resolvers()
    } else {
        c.dns.local_ptr_upstreams.clone()
    };
    if specs.is_empty() {
        return None;
    }

    let timeout = c.dns.upstream_timeout.to_std();
    let bootstrap = bootstrap_addrs(&c.dns.bootstrap_dns);
    let tls = tls_config();

    let (entries, _) = addr::parse_list(specs.iter().map(String::as_str));
    let (default_specs, _) = pool::partition(entries);

    let mut clients = Vec::new();
    for spec in default_specs {
        let label = spec.original.clone();
        match Client::connect(
            spec,
            &bootstrap,
            timeout,
            c.dns.bootstrap_prefer_ipv6,
            tls.clone(),
        )
        .await
        {
            Ok(cl) => clients.push(Arc::new(cl)),
            Err(e) => {
                tracing::warn!(upstream = %label, error = %e, "private ptr resolver unavailable")
            }
        }
    }

    if clients.is_empty() {
        return None;
    }

    Some(SharedPool::new(Pool::new(
        clients,
        vec![],
        vec![],
        Mode::LoadBalance,
        timeout,
        c.dns.fastest_timeout.to_std(),
    )))
}

/// The resolvers the operating system is configured with.
///
/// Only `/etc/resolv.conf` is read; on a platform without one the list is
/// empty and private reverse lookups are answered locally instead.
pub fn system_resolvers() -> Vec<String> {
    let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };

    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.starts_with('#') || l.starts_with(';') {
                return None;
            }

            let rest = l.strip_prefix("nameserver")?.trim();
            rest.parse::<std::net::IpAddr>().ok().map(|a| a.to_string())
        })
        .collect()
}

/// Turns bootstrap specifications into plain socket addresses.
fn bootstrap_addrs(specs: &[String]) -> Vec<SocketAddr> {
    specs
        .iter()
        .filter_map(|s| {
            let e = addr::parse(s).ok()?;
            let u = e.upstream?;
            let ip: std::net::IpAddr = u.host.parse().ok()?;

            Some(SocketAddr::new(ip, u.port))
        })
        .collect()
}

/// Parses the address entries of the access lists, ignoring CIDRs and
/// ClientIDs, which are matched elsewhere.
/// Loads the configuration, writing a default one on a fresh installation.
///
/// An older schema is migrated and the upgraded file written back, as upstream
/// does, so the next start reads the current shape.
pub fn load_or_init(paths: &Paths) -> Result<Config, Error> {
    if paths.is_first_run() {
        let c = Config::default();
        paths.ensure()?;
        sift_config::save(&paths.config, &c)?;

        return Ok(c);
    }

    let ctx = sift_config::migrate::Context::new(paths.work.clone());

    Ok(sift_config::file::load_migrating(&paths.config, &ctx)?)
}

/// A timeout used when downloading filter lists.
pub const LIST_TIMEOUT: Duration = Duration::from_secs(60);

#[cfg(test)]
mod tests {
    use super::*;
    use sift_config::model::Rewrite;

    /// A config that binds nothing privileged.
    fn test_config() -> Config {
        let mut c = Config::default();
        c.dns.bind_hosts = vec!["127.0.0.1".parse().unwrap()];
        c.dns.port = 0;
        c.dns.upstream_dns = vec![];
        c.dns.bootstrap_dns = vec![];
        c.filters = vec![];

        c
    }

    fn tmp_paths(tag: &str) -> Paths {
        let base = std::env::temp_dir().join(format!("sift-app-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let p = Paths::new(base.join("work"), base.join("conf/AdGuardHome.yaml"));
        p.ensure().unwrap();

        p
    }

    #[test]
    fn settings_map_from_the_config() {
        let mut c = test_config();
        c.filtering.blocking_mode = CfgBlockingMode::Nxdomain;
        c.filtering.blocked_response_ttl = 42;
        c.dns.aaaa_disabled = true;
        c.dns.refuse_any = false;

        let s = settings(&c);
        assert_eq!(s.blocking.mode, BlockingMode::Nxdomain);
        assert_eq!(s.blocking.ttl, 42);
        assert!(s.aaaa_disabled);
        assert!(!s.refuse_any);
    }

    #[test]
    fn custom_ip_blocking_takes_the_configured_addresses() {
        let mut c = test_config();
        c.filtering.blocking_mode = CfgBlockingMode::CustomIp;
        c.filtering.blocking_ipv4 = "10.0.0.1".parse::<std::net::IpAddr>().unwrap().into();
        c.filtering.blocking_ipv6 = "::1".parse::<std::net::IpAddr>().unwrap().into();

        let s = settings(&c);
        assert_eq!(s.blocking.custom_v4.unwrap().to_string(), "10.0.0.1");
        assert_eq!(s.blocking.custom_v6.unwrap().to_string(), "::1");
    }

    #[test]
    fn connections_get_half_the_descriptors_and_never_more_than_the_default() {
        let default = sift_dns::probe::Config::default().max_connections;

        assert_eq!(
            connection_budget(Some(1024)),
            512,
            "a systemd unit's soft limit"
        );
        assert_eq!(connection_budget(Some(256)), 128, "darwin's default");
        assert_eq!(connection_budget(Some(524_287)), default);
        assert_eq!(connection_budget(None), default, "unlimited, or unknown");
        // Zero is no limit at all to the guard, so it is never that.
        assert_eq!(connection_budget(Some(1)), 1);
        assert_eq!(connection_budget(Some(0)), 1);
    }

    #[test]
    fn the_guard_is_sized_to_the_process() {
        let c = test_config();
        assert_eq!(
            probe_config(&c).max_connections,
            connection_budget(crate::osconf::nofile_limit())
        );
    }

    /// A guard built from `c`, on a host whose one global address is
    /// `2001:db8:aa:bb::53` beside a public IPv4 one.
    fn guard_for(c: &Config) -> sift_dns::probe::Guard {
        let host = sift_dns::probe::host_networks(
            ["2001:db8:aa:bb::53", "203.0.113.53"]
                .iter()
                .map(|s| s.parse().unwrap()),
        );

        sift_dns::probe::Guard::new(probe_config_for(c, host))
    }

    #[test]
    fn the_guard_calls_local_what_the_resolver_calls_private() {
        let mut c = test_config();
        let g = guard_for(&c);
        let local = |ip: &str| g.exempts(ip.parse().unwrap());

        assert!(
            local("100.64.0.1"),
            "the defaults, shared address space too"
        );
        assert!(!local("203.0.113.54"), "not a public IPv4 neighbour");

        c.dns.private_networks = vec![sift_config::types::Prefix {
            addr: "198.51.100.0".parse().unwrap(),
            bits: 24,
        }];
        let g = guard_for(&c);
        let local = |ip: &str| g.exempts(ip.parse().unwrap());
        assert!(local("198.51.100.9"), "the operator's own list");
        assert!(!local("100.64.0.1"), "which replaces the defaults");
        assert!(local("192.168.1.1"), "but not what every host has");
        assert_eq!(
            private_networks(&c),
            settings(&c).private_networks,
            "and the resolver reads the same list"
        );
    }

    #[test]
    fn the_guard_judges_each_address_in_the_hosts_own_slash_64_on_its_own() {
        // Not exempt: on a rented server the /64 may be shared with other
        // customers.  But not one source either, which a household reaching
        // the server by its global address would all have to share.
        let g = guard_for(&test_config());
        let ip = |s: &str| -> std::net::IpAddr { s.parse().unwrap() };

        for device in ["2001:db8:aa:bb:1c2d::1", "2001:db8:aa:bb:1c2d::2"] {
            assert!(!g.exempts(ip(device)), "{device} is judged");
        }
        assert_ne!(
            g.source(ip("2001:db8:aa:bb:1c2d::1")),
            g.source(ip("2001:db8:aa:bb:1c2d::2"))
        );
        assert_eq!(
            g.source(ip("2001:db8:aa:bc::1")),
            g.source(ip("2001:db8:aa:bc::2")),
            "the next /64 is one source, as anywhere else"
        );

        let host = vec![(ip("2001:db8:aa:bb::"), 64)];
        let cfg = probe_config_for(&test_config(), host.clone());
        assert_eq!(cfg.host_networks, host);
        assert!(!cfg.local_networks.contains(&host[0]));
    }

    #[test]
    fn the_server_name_reaches_dns_only_while_encryption_is_on() {
        let mut c = test_config();
        c.tls.server_name = "dns.example.com".into();
        c.tls.strict_sni_check = true;

        c.tls.enabled = false;
        assert_eq!(server_name(&c), ("", false));

        c.tls.enabled = true;
        assert_eq!(server_name(&c), ("dns.example.com", true));
    }

    #[test]
    fn a_disabled_cache_gets_a_zero_budget() {
        let mut c = test_config();
        c.dns.cache_enabled = false;
        assert_eq!(cache_config(&c).size_bytes, 0);

        c.dns.cache_enabled = true;
        c.dns.cache_size = 1024;
        assert_eq!(cache_config(&c).size_bytes, 1024);
    }

    #[test]
    fn bootstrap_specs_become_socket_addresses() {
        let got = bootstrap_addrs(&[
            "9.9.9.10".into(),
            "2620:fe::10".into(),
            "dns.example".into(),
            "1.1.1.1:5353".into(),
        ]);

        // The hostname is not usable as a bootstrap address and is dropped.
        assert_eq!(got.len(), 3);
        assert!(got.contains(&"9.9.9.10:53".parse().unwrap()));
        assert!(got.contains(&"[2620:fe::10]:53".parse().unwrap()));
        assert!(got.contains(&"1.1.1.1:5353".parse().unwrap()));
    }

    #[tokio::test]
    async fn builds_and_serves_on_an_ephemeral_port() {
        let paths = tmp_paths("serve");
        let mut c = test_config();
        c.dns.port = 0;

        let app = App::build_quiet(paths.clone(), c).await.unwrap();
        let (tx, rx) = tokio::sync::watch::channel(false);
        let tasks = app.serve_dns(rx).await.unwrap();
        assert_eq!(tasks.len(), 2, "one UDP and one TCP listener");

        let _ = tx.send(true);
        std::fs::remove_dir_all(paths.work.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn rewrites_reach_the_resolver() {
        let paths = tmp_paths("rewrite");
        let mut c = test_config();
        c.filtering.rewrites = vec![Rewrite {
            domain: "nas.lan".into(),
            answer: "192.168.1.5".into(),
            enabled: true,
        }];

        let app = App::build_quiet(paths.clone(), c).await.unwrap();
        let mut req = hickory_proto::op::Message::query();
        req.add_query(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_utf8("nas.lan.").unwrap(),
            hickory_proto::rr::RecordType::A,
        ));

        let out = app
            .resolver
            .resolve(&req, sift_dns::resolver::Proto::Udp, &Default::default())
            .await;
        assert_eq!(out.reason, sift_core::Reason::Rewritten);

        std::fs::remove_dir_all(paths.work.parent().unwrap()).ok();
    }

    #[test]
    fn a_fresh_installation_writes_a_default_config() {
        let paths = tmp_paths("init");
        std::fs::remove_file(&paths.config).ok();
        assert!(paths.is_first_run());

        let c = load_or_init(&paths).unwrap();
        assert_eq!(c.schema_version, sift_core::SCHEMA_VERSION);
        assert!(!paths.is_first_run(), "the config should now exist");

        // And it must be readable back by the same parser.
        let again = load_or_init(&paths).unwrap();
        assert_eq!(again.dns.port, c.dns.port);

        std::fs::remove_dir_all(paths.work.parent().unwrap()).ok();
    }
}
