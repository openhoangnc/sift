//! Connecting the DNS server to the query log, the statistics collector and
//! the HTTP API.

use std::sync::Arc;
use std::time::Duration;

use sift_api::state::{FetchFuture, ListFetcher, Reloader};
use sift_config::{Config, Paths};
use sift_dns::resolver::Action;
use sift_dns::server::{Event, Observer};
use sift_filter::lists::Manager;
use sift_querylog::entry::{ClientProto, Entry, Result as EntryResult, ResultRule};
use sift_querylog::log::QueryLog;
use sift_stats::stats::Stats;
use sift_stats::unit::{Entry as StatEntry, Result as StatResult, UpstreamStat};

/// Feeds every handled query into the log and the statistics.
pub struct Recorder {
    /// The query log.
    pub querylog: Arc<QueryLog>,
    /// The statistics collector.
    pub stats: Arc<Stats>,
    /// Whether client addresses are anonymised.
    pub anonymize: std::sync::atomic::AtomicBool,
    /// Where unknown client addresses are sent to be named.
    discovery: parking_lot::RwLock<Option<crate::discovery::Queue>>,
    /// The store of names already known, so discovery is asked only once.
    runtime: parking_lot::RwLock<Option<Arc<sift_dns::clients::Runtime>>>,
    /// Feeds resolved addresses into the configured ipsets.
    ipset: parking_lot::RwLock<Option<Arc<crate::ipset::Manager>>>,
}

impl Recorder {
    /// Creates a recorder.
    pub fn new(querylog: Arc<QueryLog>, stats: Arc<Stats>, anonymize: bool) -> Self {
        Self {
            querylog,
            stats,
            anonymize: std::sync::atomic::AtomicBool::new(anonymize),
            discovery: parking_lot::RwLock::new(None),
            runtime: parking_lot::RwLock::new(None),
            ipset: parking_lot::RwLock::new(None),
        }
    }

    /// Connects the recorder to the ipset manager.
    ///
    /// The observer is the point where an answer is complete, which is where
    /// upstream adds the addresses too.
    pub fn set_ipset(&self, m: Option<Arc<crate::ipset::Manager>>) {
        *self.ipset.write() = m;
    }

    /// Connects the recorder to client discovery.
    ///
    /// Done after construction because discovery needs the resolver, which is
    /// built from this recorder.
    pub fn set_discovery(
        &self,
        queue: crate::discovery::Queue,
        runtime: Arc<sift_dns::clients::Runtime>,
    ) {
        *self.discovery.write() = Some(queue);
        *self.runtime.write() = Some(runtime);
    }

    /// Notes that a client asked something, and asks for a name for one that
    /// has none yet.
    ///
    /// Noting it is what keeps a device in use in the runtime table when a
    /// flood of strangers fills it.  An address that is still unknown is
    /// offered to discovery on every query, which is cheap: discovery holds
    /// back one it is already looking up or has lately failed to name, rather
    /// than this re-queueing it each time and crowding out everybody else.
    fn note_client(&self, addr: std::net::IpAddr) {
        let known = self.runtime.read().as_ref().is_some_and(|r| r.touch(addr));
        if known {
            return;
        }

        if let Some(q) = self.discovery.read().as_ref() {
            q.submit(addr);
        }
    }
}

impl Observer for Recorder {
    fn observe(&self, ev: &Event<'_>) {
        use hickory_proto::serialize::binary::BinEncodable as _;
        use std::sync::atomic::Ordering;

        let Some(q) = ev.request.queries.first() else {
            return;
        };

        let host = q
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let client = if self.anonymize.load(Ordering::Relaxed) {
            anonymize_ip(ev.client.ip())
        } else {
            ev.client.ip().to_string()
        };

        let answer = match &ev.outcome.action {
            Action::Respond(m) => m.to_bytes().ok().map(|w| Entry::encode_answer(&w)),
            Action::Drop => None,
        };

        self.note_client(ev.client.ip());

        if let Some(m) = self.ipset.read().as_ref()
            && let Some(resp) = ev.outcome.response()
        {
            let addrs = sift_dns::resolver::answer_addrs(resp);
            let n = m.add(&host, &addrs);
            if n > 0 {
                tracing::debug!(host = %host, added = n, "ipset updated");
            }
        }

        let entry = Entry {
            time: sift_core::gotime::format_local(jiff::Timestamp::now()),
            question_host: host.clone(),
            question_type: q.query_type().to_string(),
            question_class: q.query_class().to_string(),
            req_ecs: ev.outcome.req_ecs.clone(),
            client_id: ev.outcome.client_id.clone(),
            client_proto: proto_of(ev.proto),
            upstream: ev.outcome.upstream.clone().unwrap_or_default(),
            answer,
            orig_answer: None,
            ip: client.clone(),
            result: EntryResult {
                service_name: ev.outcome.service_name.clone(),
                rules: ev
                    .outcome
                    .rules
                    .iter()
                    .map(|r| ResultRule {
                        text: r.text.clone(),
                        ip: r.ip,
                        filter_list_id: r.list_id,
                    })
                    .collect(),
                reason: ev.outcome.reason,
                is_filtered: ev.outcome.reason.is_filtered(),
                ..Default::default()
            },
            elapsed: ev.outcome.elapsed.as_nanos().min(u128::from(u64::MAX)) as u64,
            cached: ev.outcome.cached,
            authenticated_data: ev
                .outcome
                .response()
                .is_some_and(|m| m.metadata.authentic_data),
        };

        // A client may ask to be left out of one or both records.
        if !ev.outcome.ignore_querylog {
            self.querylog.push(entry);
        }

        if ev.outcome.ignore_statistics {
            return;
        }

        let upstreams = ev
            .outcome
            .upstream
            .as_ref()
            .map(|a| {
                vec![UpstreamStat {
                    address: a.clone(),
                    duration: ev.outcome.elapsed,
                    cached: ev.outcome.cached,
                    failed: false,
                }]
            })
            .unwrap_or_default();

        // A ClientID identifies the device; an address identifies whatever
        // shares it. Upstream's `updateStats` counts by the ClientID when the
        // query carried one, so several devices behind one address — a phone
        // and a laptop both on DoH — are counted apart rather than lumped
        // together under the router's address.
        let stats_client = if ev.outcome.client_id.is_empty() {
            client
        } else {
            ev.outcome.client_id.clone()
        };

        self.stats.add(&StatEntry {
            client: stats_client,
            domain: host,
            result: StatResult::from_reason(ev.outcome.reason),
            processing_time: ev.outcome.elapsed,
            upstreams,
        });
    }
}

/// Masks a client address for the query log, as `anonymize_client_ip` does.
fn anonymize_ip(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(a) => {
            let o = a.octets();

            std::net::Ipv4Addr::new(o[0], o[1], o[2], 0).to_string()
        }
        std::net::IpAddr::V6(a) => {
            let mut o = a.octets();
            o[8..].fill(0);

            std::net::Ipv6Addr::from(o).to_string()
        }
    }
}

/// Maps a transport onto the query log's `CP` value.
fn proto_of(p: sift_dns::resolver::Proto) -> ClientProto {
    use sift_dns::resolver::Proto;

    match p {
        Proto::Udp | Proto::Tcp => ClientProto::Plain,
        Proto::Tls => ClientProto::Dot,
        Proto::Https => ClientProto::Doh,
        Proto::Quic => ClientProto::Doq,
    }
}

/// Downloads filter lists on the API's behalf.
pub struct Downloader {
    /// Where lists are stored.
    pub paths: Paths,
    /// The largest list this will accept.
    pub max_bytes: u64,
    /// How long a download may take.
    pub timeout: Duration,
}

impl ListFetcher for Downloader {
    fn fetch(&self, url: String) -> FetchFuture {
        let paths = self.paths.clone();
        let max = self.max_bytes;
        let timeout = self.timeout;

        Box::pin(async move {
            crate::lists::fetch(&paths, &url, max, timeout)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

/// Where the latest release is announced.
///
/// This build has its own release history, so asking AdGuard's announcement
/// server would report an AdGuard Home version — always newer than this one,
/// and not something this binary could become.  GitHub answers 404 until the
/// first release is published, which the handler treats as "nothing newer".
const VERSION_URL: &str = "https://api.github.com/repos/openhoangnc/sift/releases/latest";

/// The environment variable that points the check at another announcement.
///
/// The counterpart of [`crate::update::RELEASES_ENV`]: together they let the
/// whole update path run against a mirror, or against a release that is not
/// published yet.
pub const VERSION_ENV: &str = "SIFT_VERSION_URL";

/// Where the announcement is fetched from.
fn version_url() -> String {
    std::env::var(VERSION_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| VERSION_URL.to_string())
}

/// How large an announcement may be.
const VERSION_MAX_BYTES: u64 = 64 * 1024;

/// How long a version check may take.
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);

/// Reports what the latest sift release is.
///
/// The announcement is only read, never acted on: replacing a running binary
/// is the job of whatever installed it, so the interface is told a new version
/// exists but is not offered a button to install it.
pub struct ReleaseChecker {
    /// Whether `--no-check-update` was given.
    pub disabled: bool,
}

impl sift_api::state::VersionChecker for ReleaseChecker {
    fn fetch(&self) -> sift_api::state::VersionFuture {
        Box::pin(async move {
            let body = crate::fetch::get(&version_url(), VERSION_MAX_BYTES, VERSION_TIMEOUT)
                .await
                .map_err(|e| e.to_string())?;

            String::from_utf8(body).map_err(|e| e.to_string())
        })
    }

    fn disabled(&self) -> bool {
        self.disabled
    }
}

/// Everything the upstream pools are built from, as one comparable string.
///
/// Every settings save runs the whole reload, and reconnecting every upstream
/// because someone toggled protection would be slow and noisy, so the pools
/// are rebuilt only when one of these changed.  `upstream_dns_file` counts by
/// its *contents*, not its name: it exists so a script can change the
/// upstreams without touching `AdGuardHome.yaml`.
pub fn upstream_fingerprint(cfg: &Config) -> String {
    format!(
        "{:?}",
        (
            crate::app::upstream_lines(cfg),
            &cfg.dns.fallback_dns,
            &cfg.dns.bootstrap_dns,
            cfg.dns.bootstrap_prefer_ipv6,
            cfg.dns.upstream_mode,
            cfg.dns.upstream_timeout,
            cfg.dns.fastest_timeout,
            cfg.dns.use_http3_upstreams,
            &cfg.dns.local_ptr_upstreams,
            cfg.dns.use_private_ptr_resolvers,
            // Per-client upstreams are pools too, so editing one has to
            // rebuild.  Only the lists matter: renaming a client does not
            // change which servers it talks to.
            cfg.clients
                .persistent
                .iter()
                .map(|p| p.upstreams.clone())
                .collect::<Vec<_>>(),
        )
    )
}

/// Pushes configuration changes into the running server.
pub struct LiveReloader {
    /// The resolver to reconfigure.
    pub resolver: Arc<sift_dns::resolver::Resolver>,
    /// The listener front end, for access control and the concurrency bound.
    pub server: Arc<sift_dns::server::Server>,
    /// The certificate the encrypted listeners serve.
    pub certificate: Arc<sift_dns::tls::Reloadable>,
    /// Counts upstream rebuilds, so a slow one cannot install a pool the
    /// configuration has already moved past.
    pub upstream_generation: Arc<std::sync::atomic::AtomicU64>,
    /// What the upstreams were built from last time.
    ///
    /// Every settings save runs the whole reload, and reconnecting every
    /// upstream because someone toggled protection would be slow and noisy.
    pub upstream_fingerprint: Arc<parking_lot::Mutex<Option<String>>>,
}

impl Reloader for LiveReloader {
    fn reload(&self, cfg: &Config) {
        self.resolver.set_settings(crate::app::settings(cfg));
        self.resolver.set_rewrites(sift_dns::rewrite::Table::build(
            cfg.filtering
                .rewrites
                .iter()
                .map(|r| (r.domain.as_str(), r.answer.as_str(), r.enabled)),
        ));
        self.resolver.set_clients(crate::app::clients(cfg));
        self.resolver
            .set_safe_search(sift_filter::safesearch::engine(&crate::app::safe_search(
                &cfg.filtering.safe_search,
            )));
        self.resolver
            .runtime
            .set_sources(sift_dns::clients::Sources {
                whois: cfg.clients.runtime_sources.whois,
                arp: cfg.clients.runtime_sources.arp,
                rdns: cfg.clients.runtime_sources.rdns,
                dhcp: false,
                hosts: cfg.clients.runtime_sources.hosts,
            });
        self.server.set_max_concurrent(cfg.dns.max_goroutines);
        self.reload_certificate(cfg);
        *self.server.access.write() =
            sift_dns::server::Access::new(&cfg.dns.allowed_clients, &cfg.dns.disallowed_clients);

        self.server.limiter.set_config(sift_dns::ratelimit::Config {
            per_second: cfg.dns.ratelimit,
            subnet_len_v4: cfg.dns.ratelimit_subnet_len_ipv4,
            subnet_len_v6: cfg.dns.ratelimit_subnet_len_ipv6,
            allowlist: cfg.dns.ratelimit_whitelist.clone(),
        });
        // Through the server, whose bound on queries in flight asks the guard
        // whom it exempts.  This rereads the host's own networks too, so a
        // save picks up a renumbered prefix without waiting for the tick.
        self.server.set_probe_config(crate::app::probe_config(cfg));
        self.resolver
            .cache
            .set_config(crate::app::cache_config(cfg));
        self.reload_upstreams(cfg);
    }

    fn reload_filters(&self, filters: &Manager) {
        // The expressions built so far belong to the engine about to be
        // replaced, so they go before the new one is built rather than with
        // the old one afterwards: holding them through the rebuild puts them
        // inside its peak for nothing.
        sift_filter::rule::drop_compiled();

        // Built from the engine being replaced, so the lists this refresh
        // did not change are carried over rather than parsed again.
        self.resolver
            .set_engine(filters.build_engine_with(&self.resolver.engine()));
        self.resolver.set_services(filters.build_services_engine());
    }
}

impl LiveReloader {
    /// Rebuilds the upstream pools from the new configuration.
    ///
    /// Connecting an upstream resolves its host through the bootstrap
    /// resolvers, so this cannot run inside the synchronous `reload`; it is
    /// spawned, and the pools swap in when the last one is ready.  Until then
    /// queries keep going to the old upstreams rather than failing, which is
    /// the behaviour to want from a settings change.
    ///
    /// Everything the upstream section of the interface can change is here:
    /// the servers themselves, the per-client groups, the upstream mode, the
    /// fallbacks, the bootstraps, the timeout, the per-client pools, and the
    /// private resolvers used for reverse lookups.
    fn reload_upstreams(&self, cfg: &Config) {
        use std::sync::atomic::Ordering;

        let fingerprint = upstream_fingerprint(cfg);
        {
            let mut last = self.upstream_fingerprint.lock();
            if last.as_deref() == Some(fingerprint.as_str()) {
                return;
            }

            *last = Some(fingerprint);
        }

        let cfg = cfg.clone();
        let resolver = self.resolver.clone();
        let generation = self.upstream_generation.clone();
        let mine = generation.fetch_add(1, Ordering::SeqCst) + 1;

        tokio::spawn(async move {
            let pool = crate::app::build_pool(&cfg).await;
            let clients = crate::app::build_client_pools(&cfg).await;
            let private = crate::app::build_private_pool(&cfg).await;

            // Two saves in quick succession start two rebuilds, and the
            // slower one must not win.
            if generation.load(Ordering::SeqCst) != mine {
                tracing::debug!("a newer configuration superseded this upstream reload");

                return;
            }

            resolver.pool.store(pool);
            resolver.set_client_pools(clients);
            resolver.set_private_pool(private);
            tracing::info!("upstreams reloaded");
        });
    }

    /// Installs the configured certificate into the running listeners.
    ///
    /// The certificate, the server name a ClientID is read from and
    /// `strict_sni_check` are live: upstream restarts its DNS server with
    /// them on a TLS change.  Which ports are bound is decided when the
    /// listeners start, so changing a port still needs a restart.
    fn reload_certificate(&self, cfg: &Config) {
        // Before the early return: switching encryption off clears the name,
        // as upstream's empty TLS configuration does.
        let (name, strict) = crate::app::server_name(cfg);
        self.server.set_server_name(name, strict);
        self.certificate.set_strict_sni(cfg.tls.strict_sni_check);

        let src = crate::app::tls_source(cfg);

        if !cfg.tls.enabled || src.is_empty() {
            return;
        }

        match sift_dns::tls::install(&src, &self.certificate) {
            Ok(st) => tracing::info!(names = ?st.dns_names, "certificate reloaded"),
            Err(e) => tracing::error!(error = %e, "reloading the certificate"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_upstream_fingerprint_moves_with_every_field_the_pools_use() {
        let base = sift_config::Config::default();
        let same = upstream_fingerprint(&base);
        assert_eq!(same, upstream_fingerprint(&base.clone()), "stable");

        // Changing anything the pools are built from must rebuild them; a
        // save that touches nothing else must not, or toggling protection
        // would reconnect every upstream.
        let mut c = base.clone();
        c.filtering.protection_enabled = !c.filtering.protection_enabled;
        assert_eq!(upstream_fingerprint(&c), same, "an unrelated change");

        for change in [
            |c: &mut sift_config::Config| c.dns.upstream_dns = vec!["1.1.1.1".into()],
            |c: &mut sift_config::Config| c.dns.fallback_dns = vec!["8.8.8.8".into()],
            |c: &mut sift_config::Config| c.dns.bootstrap_dns = vec!["9.9.9.9".into()],
            |c: &mut sift_config::Config| c.dns.bootstrap_prefer_ipv6 = true,
            |c: &mut sift_config::Config| {
                c.dns.upstream_mode = sift_config::model::UpstreamMode::Parallel;
            },
            |c: &mut sift_config::Config| {
                c.dns.upstream_timeout = sift_core::duration::GoDuration::parse("3s").unwrap()
            },
            |c: &mut sift_config::Config| c.dns.use_http3_upstreams = true,
            |c: &mut sift_config::Config| c.dns.local_ptr_upstreams = vec!["10.0.0.1".into()],
            |c: &mut sift_config::Config| c.dns.use_private_ptr_resolvers = false,
        ] {
            let mut c = base.clone();
            change(&mut c);
            assert_ne!(
                upstream_fingerprint(&c),
                same,
                "a change the pools are built from must be noticed"
            );
        }
    }

    #[test]
    fn anonymisation_masks_the_host_part() {
        assert_eq!(anonymize_ip("192.168.1.77".parse().unwrap()), "192.168.1.0");
        assert_eq!(
            anonymize_ip("2001:db8::dead:beef".parse().unwrap()),
            "2001:db8::"
        );
    }

    #[test]
    fn protocols_map_onto_the_log_field() {
        use sift_dns::resolver::Proto;

        assert_eq!(proto_of(Proto::Udp), ClientProto::Plain);
        assert_eq!(proto_of(Proto::Tcp), ClientProto::Plain);
        assert_eq!(proto_of(Proto::Tls), ClientProto::Dot);
        assert_eq!(proto_of(Proto::Https), ClientProto::Doh);
        assert_eq!(proto_of(Proto::Quic), ClientProto::Doq);
    }

    /// Several devices reach the server through one address whenever DoH or
    /// DoT is proxied, and each carries its own ClientID.  Upstream counts
    /// those apart, and the interface resolves the ClientID to the client's
    /// name, so the dashboard names the device rather than the router.
    #[test]
    fn statistics_count_a_client_id_apart_from_the_address_it_shares() {
        use hickory_proto::op::{Message, Query};
        use hickory_proto::rr::{Name, RecordType};
        use sift_dns::resolver::Proto;

        let dir = std::env::temp_dir().join("sift-wiring-stats-client");
        let rec = Recorder::new(
            Arc::new(QueryLog::new(
                dir.join("querylog.json"),
                dir.join("querylog.json.1"),
                sift_querylog::log::Config::default(),
            )),
            Arc::new(Stats::new(sift_stats::stats::Config::default())),
            false,
        );

        let mut req = Message::query();
        req.add_query(Query::query(
            Name::from_utf8("example.com.").unwrap(),
            RecordType::A,
        ));

        let client: std::net::SocketAddr = "192.168.1.1:5353".parse().unwrap();
        for id in ["phone", "laptop", "laptop", ""] {
            let outcome = sift_dns::resolver::Outcome {
                client_id: id.to_string(),
                ..Default::default()
            };
            rec.observe(&Event {
                request: &req,
                outcome: &outcome,
                client,
                proto: Proto::Https,
            });
        }

        let top = rec.stats.data().top_clients;
        let count = |k: &str| top.iter().find_map(|m| m.get(k)).copied();
        assert_eq!(count("phone"), Some(1));
        assert_eq!(count("laptop"), Some(2));
        assert_eq!(count("192.168.1.1"), Some(1), "no ClientID, so the address");

        // The query log keeps recording the address, with the ClientID in its
        // own field, which is where the interface reads it.
        let recent = rec.querylog.read(0, 4);
        assert_eq!(recent.len(), 4);
        assert!(recent.iter().all(|e| e.ip == "192.168.1.1"));
    }
}
