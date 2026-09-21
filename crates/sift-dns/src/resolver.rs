//! Request handling: validation, filtering, rewrites, cache, upstreams.
//!
//! The order of steps mirrors `internal/dnsforward`, because the order is
//! observable: a rewrite applies even when protection is off, an allowlist
//! match short-circuits filtering, and an access-blocked host is dropped
//! outright on UDP rather than answered.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use parking_lot::RwLock;
use sift_core::Reason;
use sift_core::schedule::Weekly;
use sift_filter::engine::{Engine, MatchedRule, Request as FilterRequest};

use crate::cache::{Cache, Freshness, Key};
use crate::clients::{Persistent, Registry, Runtime};
use crate::ddr;
use crate::dns64;
use crate::edns;
use crate::msg::{self, BlockingConfig};
use crate::pending::{Entry as PendingEntry, Pending, PendingKey};
use crate::pool::{Pool, SharedPool};
use crate::refresh;
use crate::rewrite::{self, Table};

/// The transport a request arrived on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Proto {
    /// Plain DNS over UDP.
    Udp,
    /// Plain DNS over TCP.
    Tcp,
    /// DNS-over-TLS.
    Tls,
    /// DNS-over-HTTPS.
    Https,
    /// DNS-over-QUIC.
    Quic,
}

impl Proto {
    /// The value written to the query log's `CP` field.
    pub const fn log_name(self) -> &'static str {
        match self {
            // Upstream writes an empty string for plain DNS.
            Proto::Udp | Proto::Tcp => "",
            Proto::Tls => "tls",
            Proto::Https => "doh",
            Proto::Quic => "doq",
        }
    }

    /// Reports whether the transport is connectionless, and therefore
    /// spoofable for amplification.
    ///
    /// Two things turn on it, both because a stream client has already proved
    /// its address by completing a handshake: an access-blocked client is
    /// dropped here and told `REFUSED` there, and the rate limit applies here
    /// and not there.
    pub const fn is_datagram(self) -> bool {
        matches!(self, Proto::Udp)
    }
}

/// The address blocks whose reverse lookups stay on the local network.
///
/// RFC 6303's locally-served zones, which upstream uses as the default for
/// `private_networks`: forwarding a `PTR` for one of these to a public
/// resolver leaks the shape of the local network and gets nothing useful back.
pub fn default_private_networks() -> Vec<(IpAddr, u8)> {
    [
        ("10.0.0.0", 8),
        ("172.16.0.0", 12),
        ("192.168.0.0", 16),
        ("169.254.0.0", 16),
        ("127.0.0.0", 8),
        ("100.64.0.0", 10),
        ("fd00::", 8),
        ("fe80::", 10),
        ("::1", 128),
    ]
    .iter()
    .filter_map(|(a, b)| a.parse::<IpAddr>().ok().map(|a| (a, *b)))
    .collect()
}

/// Settings that affect how a query is handled.
#[derive(Clone, Debug)]
pub struct Settings {
    /// The master protection switch.
    pub protection_enabled: bool,
    /// Whether blocklists are consulted.
    pub filtering_enabled: bool,
    /// Whether rewrites are applied.
    pub rewrites_enabled: bool,
    /// How blocked queries are answered.
    pub blocking: BlockingConfig,
    /// Hosts refused before any other processing.
    pub blocked_hosts: Arc<crate::blocked::BlockedHosts>,
    /// Whether `AAAA` queries are answered with nothing.
    pub aaaa_disabled: bool,
    /// Whether `ANY` queries are refused.
    pub refuse_any: bool,
    /// Lower bound applied to answer TTLs.
    pub cache_ttl_min: u32,
    /// Upper bound applied to answer TTLs.
    pub cache_ttl_max: u32,
    /// Whether the client's subnet is passed to the upstream.
    pub ecs_enabled: bool,
    /// The address sent instead of the client's, when one is configured.
    pub ecs_custom: Option<IpAddr>,
    /// Whether the DNSSEC OK bit is set on upstream queries.
    pub dnssec_enabled: bool,
    /// Networks whose appearance in an answer means `NXDOMAIN`.
    pub bogus_nxdomain: Vec<(IpAddr, u8)>,
    /// The NAT64 prefixes used for DNS64 synthesis.
    pub dns64: dns64::Prefixes,
    /// Whether `_dns.resolver.arpa` is answered here rather than forwarded.
    ///
    /// Separate from the endpoints below, because they answer separate
    /// questions: this one decides whether the name is answered at all, and
    /// the endpoints decide whether the answer carries anything.  A server with
    /// no encrypted listener still has to answer it -- empty -- since a
    /// forwarded DDR query comes back with the *upstream's* designated
    /// resolvers and points the client away from here.
    pub handle_ddr: bool,
    /// The encrypted endpoints advertised over DDR, when there are any.
    pub ddr: ddr::Endpoints,
    /// Whether identical in-flight requests are coalesced.
    pub pending_enabled: bool,
    /// When the global blocked-services list is paused.
    pub services_schedule: Weekly,
    /// Networks whose reverse lookups stay local.
    pub private_networks: Vec<(IpAddr, u8)>,
    /// Whether private reverse lookups are sent to the local resolvers.
    pub use_private_ptr_resolvers: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            protection_enabled: true,
            filtering_enabled: true,
            rewrites_enabled: true,
            blocking: BlockingConfig::default(),
            blocked_hosts: crate::blocked::BlockedHosts::shared(&[
                "version.bind".into(),
                "id.server".into(),
                "hostname.bind".into(),
            ]),
            aaaa_disabled: false,
            refuse_any: true,
            cache_ttl_min: 0,
            cache_ttl_max: 0,
            ecs_enabled: false,
            ecs_custom: None,
            dnssec_enabled: false,
            bogus_nxdomain: Vec::new(),
            dns64: dns64::Prefixes::default(),
            handle_ddr: false,
            ddr: ddr::Endpoints::default(),
            pending_enabled: false,
            services_schedule: Weekly::default(),
            private_networks: default_private_networks(),
            use_private_ptr_resolvers: false,
        }
    }
}

/// What the server should do with a request.
#[derive(Debug)]
pub enum Action {
    /// Send this response.
    Respond(Box<Message>),
    /// Send nothing, to avoid amplifying a spoofed request.
    Drop,
}

/// Everything the query log and statistics need about one request.
#[derive(Debug)]
pub struct Outcome {
    /// What to do with the request.
    pub action: Action,
    /// Why the request was filtered, allowed or rewritten.
    pub reason: Reason,
    /// The rules that matched.
    pub rules: Vec<MatchedRule>,
    /// The upstream that answered, if any.
    pub upstream: Option<String>,
    /// Whether the answer came from the cache.
    pub cached: bool,
    /// How long handling took.
    pub elapsed: Duration,
    /// The upstream's original answer, when filtering replaced it.
    pub orig_response: Option<Box<Message>>,
    /// The persistent client's name, when one matched.
    pub client_name: String,
    /// The ClientID the request carried.
    pub client_id: String,
    /// The client subnet sent upstream, in CIDR form.
    pub req_ecs: String,
    /// The blocked service's name, when one matched.
    pub service_name: String,
    /// Whether the client is excluded from the query log.
    pub ignore_querylog: bool,
    /// Whether the client is excluded from the statistics.
    pub ignore_statistics: bool,
}

impl Default for Outcome {
    fn default() -> Self {
        Self {
            action: Action::Drop,
            reason: Reason::NotFilteredNotFound,
            rules: Vec::new(),
            upstream: None,
            cached: false,
            elapsed: Duration::ZERO,
            orig_response: None,
            client_name: String::new(),
            client_id: String::new(),
            req_ecs: String::new(),
            service_name: String::new(),
            ignore_querylog: false,
            ignore_statistics: false,
        }
    }
}

impl Outcome {
    /// The response, if one is being sent.
    pub fn response(&self) -> Option<&Message> {
        match &self.action {
            Action::Respond(m) => Some(m),
            Action::Drop => None,
        }
    }
}

/// Details of the client a request came from.
#[derive(Clone, Debug, Default)]
pub struct ClientInfo {
    /// The client's address.
    pub addr: Option<IpAddr>,
    /// The ClientID a DoH path segment or DoT server name carried.
    pub id: Option<String>,
    /// The client's name, which `$client` rules match against.
    pub name: Option<String>,
    /// The client's tags, which `$ctag` rules match against.
    pub tags: Vec<String>,
}

/// The settings in force for one request, after the client is resolved.
struct Effective {
    /// Whether blocklists are consulted.
    filtering_enabled: bool,
    /// The blocked-services engine to use, if any.
    services: Option<Arc<Engine>>,
    /// The safe-search engine to use, if any.
    safe_search: Option<Arc<Engine>>,
    /// The client's own upstreams, when it has any.
    upstreams: Option<Arc<str>>,
    /// The persistent client's name.
    name: String,
    /// Whether the client is excluded from the query log.
    ignore_querylog: bool,
    /// Whether the client is excluded from the statistics.
    ignore_statistics: bool,
}

/// The DNS resolver.
pub struct Resolver {
    /// The filtering engine, replaceable while running.
    engine: RwLock<Arc<Engine>>,
    /// The global blocked-services engine, replaceable while running.
    services: RwLock<Option<Arc<Engine>>>,
    /// The global safe-search engine, replaceable while running.
    safe_search: RwLock<Option<Arc<Engine>>>,
    /// The rewrite table, replaceable while running.
    rewrites: RwLock<Arc<Table>>,
    /// The persistent clients, replaceable while running.
    clients: RwLock<Arc<Registry>>,
    /// Clients discovered while running, shared with the API.
    pub runtime: Arc<Runtime>,
    /// The response cache.
    pub cache: Cache,
    /// The upstream pool.
    pub pool: SharedPool,
    /// Pools for clients that resolve through their own upstreams, keyed by
    /// [`crate::clients::upstream_key`].
    ///
    /// Built out of band like the global pool, because connecting an upstream
    /// resolves its host.  A client whose pool is not installed yet — a
    /// settings save that added it seconds ago — falls back to the global one
    /// rather than failing, which is how the global reload behaves too.
    client_pools: RwLock<Arc<HashMap<Arc<str>, Arc<Pool>>>>,
    /// The resolvers used for private reverse lookups.
    private_pool: RwLock<Option<Arc<SharedPool>>>,
    /// Identical in-flight requests.
    pending: Pending,
    /// Where background cache refreshes are queued, when a worker is running.
    ///
    /// The worker owns an `Arc<Resolver>` and this end is only a `Sender`, so
    /// handling a request never has to reach a `'static` copy of `self`.
    refresh: RwLock<Option<refresh::Sender>>,
    /// Handling settings, replaceable while running.
    settings: RwLock<Arc<Settings>>,
}

impl Resolver {
    /// Builds a resolver.
    pub fn new(
        engine: Engine,
        rewrites: Table,
        cache: Cache,
        pool: SharedPool,
        settings: Settings,
    ) -> Self {
        Self {
            engine: RwLock::new(Arc::new(engine)),
            services: RwLock::new(None),
            safe_search: RwLock::new(None),
            rewrites: RwLock::new(Arc::new(rewrites)),
            clients: RwLock::new(Arc::new(Registry::default())),
            runtime: Arc::new(Runtime::new()),
            cache,
            pool,
            client_pools: RwLock::new(Arc::new(HashMap::new())),
            private_pool: RwLock::new(None),
            pending: Pending::new(),
            refresh: RwLock::new(None),
            settings: RwLock::new(Arc::new(settings)),
        }
    }

    /// Replaces the filtering engine.
    pub fn set_engine(&self, e: Engine) {
        *self.engine.write() = Arc::new(e);
    }

    /// Replaces the global blocked-services engine.
    pub fn set_services(&self, e: Option<Engine>) {
        *self.services.write() = e.map(Arc::new);
    }

    /// Replaces the global safe-search engine.
    pub fn set_safe_search(&self, e: Option<Engine>) {
        *self.safe_search.write() = e.map(Arc::new);
    }

    /// Replaces the rewrite table.
    pub fn set_rewrites(&self, t: Table) {
        *self.rewrites.write() = Arc::new(t);
    }

    /// Replaces the persistent client registry.
    pub fn set_clients(&self, r: Registry) {
        *self.clients.write() = Arc::new(r);
    }

    /// Replaces the resolvers used for private reverse lookups.
    /// Replaces the per-client upstream pools.
    pub fn set_client_pools(&self, p: HashMap<Arc<str>, Arc<Pool>>) {
        *self.client_pools.write() = Arc::new(p);
    }

    /// The pool a query should use, and whether it is the one it asked for.
    ///
    /// `false` means a client with its own upstreams is being answered from
    /// the global ones, which happens only in the seconds between a settings
    /// save adding that client and its pool finishing its connections.
    /// Answering is better than failing there — but the answer must not be
    /// stored, because it would then be served as that client's own long
    /// after its real resolvers were ready.
    fn pool_for(&self, upstreams: Option<&Arc<str>>) -> (Arc<Pool>, bool) {
        let Some(k) = upstreams else {
            return (self.pool.load(), true);
        };

        match self.client_pools.read().get(k) {
            Some(p) => (p.clone(), true),
            None => (self.pool.load(), false),
        }
    }

    pub fn set_private_pool(&self, p: Option<SharedPool>) {
        *self.private_pool.write() = p.map(Arc::new);
    }

    /// Replaces the settings.
    pub fn set_settings(&self, s: Settings) {
        *self.settings.write() = Arc::new(s);
    }

    /// Attaches the queue a [`crate::refresh`] worker is draining.
    ///
    /// Until one is attached, an expired entry is never served: see the cache
    /// step in [`Resolver::resolve`].
    pub fn set_refresh_sender(&self, tx: refresh::Sender) {
        *self.refresh.write() = Some(tx);
    }

    /// Reports whether background refreshes are running.
    fn refreshes(&self) -> bool {
        self.refresh.read().is_some()
    }

    /// Queues a background refresh, dropping it when the queue is full.
    ///
    /// Never waits.  A client waiting for its own answer must not also wait
    /// for somebody else's entry to be refreshed, so a saturated worker
    /// simply loses the job -- the entry is still served, and the next
    /// lookup asks again.
    fn queue_refresh(&self, job: refresh::Job) {
        let Some(tx) = self.refresh.read().clone() else {
            return;
        };

        if let Err(e) = tx.try_send(job) {
            self.cache.end_refresh(&e.into_inner().key);
        }
    }

    /// A snapshot of the current settings.
    pub fn settings(&self) -> Arc<Settings> {
        self.settings.read().clone()
    }

    /// A snapshot of the current filtering engine.
    pub fn engine(&self) -> Arc<Engine> {
        self.engine.read().clone()
    }

    /// How many identical requests are being coalesced right now.
    pub fn inflight(&self) -> usize {
        self.pending.len()
    }

    /// A snapshot of the persistent client registry.
    pub fn clients(&self) -> Arc<Registry> {
        self.clients.read().clone()
    }

    /// Works out which settings apply to a request.
    ///
    /// A persistent client that does not use the global settings overrides the
    /// filtering toggles, its own blocked services and its own safe search.
    fn effective(&self, settings: &Settings, client: Option<&Persistent>) -> Effective {
        // The schedule is only consulted when there is something to pause;
        // resolving a time zone on every query would be a waste.
        let global_services = self
            .services
            .read()
            .clone()
            .filter(|_| settings.services_schedule.blocks_at(jiff::Timestamp::now()));

        let Some(c) = client else {
            return Effective {
                filtering_enabled: settings.filtering_enabled,
                services: global_services,
                safe_search: self.safe_search.read().clone(),
                upstreams: None,
                name: String::new(),
                ignore_querylog: false,
                ignore_statistics: false,
            };
        };

        let services = if c.use_global_blocked_services {
            global_services
        } else {
            c.services
                .clone()
                .filter(|_| c.schedule.blocks_at(jiff::Timestamp::now()))
        };

        let (filtering, safe_search) = if c.use_global_settings {
            (settings.filtering_enabled, self.safe_search.read().clone())
        } else {
            (c.filtering_enabled, c.safe_search.clone())
        };

        Effective {
            filtering_enabled: filtering,
            services,
            safe_search,
            // Independent of `use_global_settings`: upstream treats a client's
            // upstreams as a separate field, and an operator who filled it in
            // means it whether or not the filtering toggles are overridden.
            upstreams: c.upstream_key.clone(),
            name: c.name.clone(),
            ignore_querylog: c.ignore_querylog,
            ignore_statistics: c.ignore_statistics,
        }
    }

    /// Handles one request.
    pub async fn resolve(&self, req: &Message, proto: Proto, client: &ClientInfo) -> Outcome {
        let started = Instant::now();
        let settings = self.settings();

        // The persistent client decides which settings apply, so it is
        // resolved before anything consults them.
        let mac = client.addr.and_then(|a| self.runtime.mac_of(a));
        let persistent = self
            .clients()
            .find(client.addr, client.id.as_deref(), mac.as_deref());
        let eff = self.effective(&settings, persistent.as_deref());

        let mut who = client.clone();
        if let Some(c) = &persistent {
            who.name = Some(c.name.clone());
            who.tags.clone_from(&c.tags);
        } else if let Some(addr) = client.addr {
            let name = self.runtime.name_of(addr);
            if !name.is_empty() {
                who.name = Some(name);
            }
        }

        let base = || Outcome {
            client_name: eff.name.clone(),
            client_id: client.id.clone().unwrap_or_default(),
            ignore_querylog: eff.ignore_querylog,
            ignore_statistics: eff.ignore_statistics,
            ..Default::default()
        };
        let finish = |mut o: Outcome| {
            // Every path out of here goes through this, which is the point:
            // what leaves is shaped to the question the client asked rather
            // than to the one this server asked an upstream.  It runs before
            // the query log and the statistics observe the outcome, so what is
            // recorded is what the client was actually sent -- which is what a
            // running AdGuard Home stores too.
            if let Action::Respond(resp) = &mut o.action {
                msg::shape_to_request(req, resp);

                // Plain UDP is the only transport here that carries no length
                // of its own, so it is the only one where an answer too large
                // for the client is simply lost.  Cutting it here rather than
                // at the listener keeps it inside what the query log records:
                // a running Go build stores the truncated answer, so its log
                // shows what the client got rather than what it might have.
                if proto == Proto::Udp {
                    msg::truncate(resp, msg::udp_limit(req));
                }
            }
            o.elapsed = started.elapsed();

            o
        };

        // 1. Validate.  A request without exactly one question is malformed.
        if req.queries.len() != 1 {
            return finish(Outcome {
                action: Action::Respond(Box::new(msg::reply(req, ResponseCode::FormErr))),
                reason: Reason::FilteredInvalid,
                ..base()
            });
        }

        let q = &req.queries[0];
        let qtype = q.query_type();
        let host = q
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .to_ascii_lowercase();

        // 2. `ANY` queries are refused as an amplification guard.
        if settings.refuse_any && qtype == RecordType::ANY {
            return finish(Outcome {
                action: Action::Respond(Box::new(msg::reply(req, ResponseCode::NotImp))),
                ..base()
            });
        }

        // 3. Access-blocked hosts.  On UDP the request is dropped rather than
        //    answered, so a spoofed source address gains nothing.
        if settings.blocked_hosts.blocks(&host, u16::from(qtype)) {
            let action = if proto.is_datagram() {
                Action::Drop
            } else {
                Action::Respond(Box::new(msg::refused(req)))
            };

            return finish(Outcome {
                action,
                reason: Reason::FilteredBlockList,
                ..base()
            });
        }

        // 4. Discovery of Designated Resolvers, answered locally -- whether or
        //    not there is anything to advertise.  A query that reaches an
        //    upstream is answered with *its* designated resolvers, which would
        //    hand the client a different server to talk to.
        if settings.handle_ddr && ddr::is_query(req) {
            return finish(Outcome {
                action: Action::Respond(Box::new(ddr::respond(req, &settings.ddr))),
                ..base()
            });
        }

        // 5. Rewrites, which apply even when protection is off.
        if settings.rewrites_enabled
            && let Some((action, rules)) = self.apply_rewrites(req, &host, qtype, &settings)
        {
            return finish(Outcome {
                action,
                reason: Reason::Rewritten,
                rules,
                ..base()
            });
        }

        // 6. Filtering.
        //
        // An allowlist match does not stop resolution, but it *is* the
        // query's verdict: upstream records the `@@` rule and reason 1
        // alongside the upstream answer, and the UI shows the query as
        // explicitly allowed.
        let mut allowed: Option<(Reason, Vec<MatchedRule>)> = None;

        if settings.protection_enabled {
            let filter_req = FilterRequest {
                hostname: &host,
                qtype: qtype.into(),
                client_ip: who.addr,
                client_name: who.name.as_deref(),
                client_tags: &who.tags,
            };

            if eff.filtering_enabled {
                let engine = self.engine();
                let m = engine.match_request(&filter_req);

                match m.reason {
                    Reason::FilteredBlockList | Reason::FilteredBlockedService => {
                        return finish(self.blocked(req, &settings, m.reason, m.rules, base()));
                    }
                    Reason::RewrittenRule => {
                        if let Some(resp) =
                            self.apply_dnsrewrite(req, qtype, &m.rewrites, &settings)
                        {
                            return finish(Outcome {
                                action: Action::Respond(Box::new(resp)),
                                reason: Reason::RewrittenRule,
                                rules: m.rules,
                                ..base()
                            });
                        }
                    }
                    Reason::NotFilteredAllowList => {
                        allowed = Some((Reason::NotFilteredAllowList, m.rules));
                    }
                    _ => {}
                }
            }

            // Blocked services, which are separate from the blocklists so the
            // weekly schedule can pause them without rebuilding anything.
            if allowed.is_none()
                && let Some(svc) = &eff.services
            {
                let m = svc.match_request(&filter_req);
                if m.reason == Reason::FilteredBlockList {
                    let mut out = self.blocked(
                        req,
                        &settings,
                        Reason::FilteredBlockedService,
                        m.rules,
                        base(),
                    );
                    out.service_name = service_name_of(&out.rules);

                    return finish(out);
                }
            }

            // Safe search, which rewrites rather than blocks.
            if allowed.is_none()
                && let Some(ss) = &eff.safe_search
            {
                let m = ss.match_request(&filter_req);
                if m.reason == Reason::RewrittenRule
                    && let Some(resp) = self.apply_dnsrewrite(req, qtype, &m.rewrites, &settings)
                {
                    return finish(Outcome {
                        action: Action::Respond(Box::new(resp)),
                        reason: Reason::FilteredSafeSearch,
                        rules: m.rules,
                        ..base()
                    });
                }
            }
        }

        // 7. `AAAA` suppression.
        if settings.aaaa_disabled && qtype == RecordType::AAAA {
            let (reason, rules) = allowed.clone().unwrap_or_default();

            return finish(Outcome {
                action: Action::Respond(Box::new(msg::nodata(req, settings.blocking.ttl))),
                reason,
                rules,
                ..base()
            });
        }

        // 8. Private reverse lookups, which must not reach a public resolver.
        if qtype == RecordType::PTR && self.is_private_ptr(&settings, req) {
            let private = self.private_pool.read().clone();
            match private.filter(|_| settings.use_private_ptr_resolvers) {
                Some(pool) => {
                    let (reason, rules) = allowed.clone().unwrap_or_default();
                    let loaded = pool.load();

                    return finish(match loaded.exchange(req, &host).await {
                        Ok((mut resp, won)) => {
                            resp.metadata.id = req.metadata.id;

                            Outcome {
                                action: Action::Respond(Box::new(resp)),
                                reason,
                                rules,
                                upstream: Some(won.client.upstream.label()),
                                ..base()
                            }
                        }
                        Err(_) => Outcome {
                            action: Action::Respond(Box::new(msg::nxdomain(
                                req,
                                settings.blocking.ttl,
                            ))),
                            reason,
                            rules,
                            ..base()
                        },
                    });
                }
                None => {
                    let (reason, rules) = allowed.clone().unwrap_or_default();

                    return finish(Outcome {
                        action: Action::Respond(Box::new(msg::nxdomain(
                            req,
                            settings.blocking.ttl,
                        ))),
                        reason,
                        rules,
                        ..base()
                    });
                }
            }
        }

        // 9. Cache.  Scoped to the client's upstreams, so an answer from one
        // client's own resolvers is never handed to a client using different
        // ones.
        let key = Key::from_request(req)
            .filter(|_| crate::cache::is_cacheable_type(qtype))
            .map(|k| k.for_upstreams(eff.upstreams.clone()));
        if let Some(k) = &key
            && let Some(hit) = self.cache.get(k)
        {
            // An expired entry is only worth serving if it can be replaced.
            // Without a refresh worker the honest answer is the slow one, so
            // a resolver built without one behaves as it did before.
            let serve = hit.freshness == Freshness::Fresh || self.refreshes();

            if hit.refresh {
                if serve {
                    self.queue_refresh(refresh::Job {
                        req: req.clone(),
                        host: host.clone(),
                        client: who.clone(),
                        key: k.clone(),
                    });
                } else {
                    // The claim was made inside the lookup; nothing will
                    // release it if the refresh is not going to happen.
                    self.cache.end_refresh(k);
                }
            }

            if serve {
                let mut cached = hit.msg;
                cached.metadata.id = req.metadata.id;
                let (reason, rules) = allowed.clone().unwrap_or_default();

                return finish(Outcome {
                    action: Action::Respond(Box::new(cached)),
                    reason,
                    rules,
                    cached: true,
                    ..base()
                });
            }
        }

        // 10. Upstream.
        let (reason, rules) = allowed.unwrap_or_default();
        let forwarded = self
            .forward(req, &host, &settings, &who, key, eff.upstreams.as_ref())
            .await;

        finish(match forwarded {
            Some((resp, upstream, ecs)) => Outcome {
                action: Action::Respond(Box::new(resp)),
                reason,
                rules,
                upstream,
                req_ecs: ecs,
                ..base()
            },
            None => Outcome {
                action: Action::Respond(Box::new(msg::servfail(req))),
                reason,
                rules,
                ..base()
            },
        })
    }

    /// Sends the query upstream, applying every setting that shapes it.
    ///
    /// Returns the answer, the upstream that gave it and the client subnet
    /// that was sent, or `None` when nothing answered.
    pub(crate) async fn forward(
        &self,
        req: &Message,
        host: &str,
        settings: &Settings,
        client: &ClientInfo,
        key: Option<Key>,
        upstreams: Option<&Arc<str>>,
    ) -> Option<(Message, Option<String>, String)> {
        // Resolved once, up front: whether the client's own upstreams are
        // ready decides both which pool answers and whether the answer may be
        // stored under this client's key.
        let (pool, own) = self.pool_for(upstreams);
        let key = if own {
            key
        } else {
            tracing::debug!(
                "a client's own upstreams are not ready yet; answering from the global \
                 ones and not caching the result"
            );

            None
        };

        let mut out = req.clone();

        // EDNS Client Subnet, so a geo-aware upstream answers for the client's
        // network rather than this server's.
        let mut ecs_text = String::new();
        let mut ecs_key = None;
        if settings.ecs_enabled
            && let Some(addr) = settings.ecs_custom.or(client.addr)
            && !is_loopback_or_unspecified(addr)
        {
            let prefix = edns::default_prefix(addr);
            let subnet = edns::set_subnet(&mut out, addr, prefix);
            ecs_text = subnet.to_cidr();
            ecs_key = Some((subnet.addr, subnet.prefix));
        } else {
            // A subnet the client sent must not be forwarded when the feature
            // is off: it would leak the client's network regardless.
            edns::strip_subnet(&mut out);
        }

        if settings.dnssec_enabled {
            edns::set_dnssec_ok(&mut out, true);
        }

        // Coalesce identical in-flight questions, so a burst from a dozen
        // devices costs one upstream exchange.
        let pending_key = (settings.pending_enabled && key.is_some()).then(|| PendingKey {
            key: key.clone().expect("checked above"),
            subnet: ecs_key,
        });

        let leader = match pending_key.map(|k| self.pending.enter(k)) {
            Some(PendingEntry::Follow(w)) => {
                let mut resp = w.wait().await?;
                resp.metadata.id = req.metadata.id;

                return Some((resp, None, ecs_text));
            }
            Some(PendingEntry::Lead(l)) => Some(l),
            None => None,
        };

        let result = self.exchange(&out, host, req, settings, &pool).await;

        if let Some(l) = leader {
            l.finish(result.as_ref().map(|(m, _)| m));
        }

        let (mut resp, upstream) = result?;
        resp.metadata.id = req.metadata.id;
        msg::clamp_ttls(&mut resp, settings.cache_ttl_min, settings.cache_ttl_max);

        if let Some(k) = key {
            self.cache.put(k, &resp);
        }

        Some((resp, upstream, ecs_text))
    }

    /// One upstream exchange, including the answer rewriting that follows it.
    async fn exchange(
        &self,
        out: &Message,
        host: &str,
        orig: &Message,
        settings: &Settings,
        pool: &Pool,
    ) -> Option<(Message, Option<String>)> {
        // The upstream that answered, not the first one configured: under
        // every mode but a one-member `load_balance` they differ, and this is
        // the one the query log and the per-upstream statistics name.
        let (mut resp, won) = pool.exchange(out, host).await.ok()?;
        let upstream = Some(won.client.upstream.label());

        // A "bogus" address is what some ISPs hand back instead of NXDOMAIN
        // for a name that does not exist; the answer is worse than none.
        if is_bogus_nxdomain(&settings.bogus_nxdomain, &resp) {
            return Some((msg::nxdomain(orig, settings.blocking.ttl), upstream));
        }

        // DNS64: an AAAA question that came back empty is retried as A and the
        // answers are mapped into the NAT64 prefix.
        if dns64::needs_synthesis(&settings.dns64, out, &mut resp) {
            let mut a_req = out.clone();
            if let Some(q) = a_req.queries.first_mut() {
                q.set_query_type(RecordType::A);
            }
            a_req.metadata.id = rand::random::<u16>();

            if let Ok((a_resp, _)) = pool.exchange(&a_req, host).await {
                dns64::synthesize(&settings.dns64, out, &mut resp, &a_resp);
            }
        }

        Some((resp, upstream))
    }

    /// Reports whether a `PTR` query names an address that stays local.
    fn is_private_ptr(&self, settings: &Settings, req: &Message) -> bool {
        let Some(q) = req.queries.first() else {
            return false;
        };
        let Some(addr) = dns64::addr_from_reverse(&q.name().to_ascii()) else {
            return false;
        };

        settings
            .private_networks
            .iter()
            .any(|&(net, bits)| crate::clients::in_subnet(addr, net, bits))
    }

    /// Builds the outcome for a blocked query.
    fn blocked(
        &self,
        req: &Message,
        settings: &Settings,
        reason: Reason,
        rules: Vec<MatchedRule>,
        base: Outcome,
    ) -> Outcome {
        let addrs: Vec<IpAddr> = rules.iter().filter_map(|r| r.ip).collect();
        let resp = msg::blocked(req, &settings.blocking, &addrs);
        let reason = reason_for_list(reason, &rules);

        Outcome {
            action: Action::Respond(Box::new(resp)),
            reason,
            rules,
            ..base
        }
    }

    /// Applies the legacy rewrite table, if it matches.
    fn apply_rewrites(
        &self,
        req: &Message,
        host: &str,
        qtype: RecordType,
        settings: &Settings,
    ) -> Option<(Action, Vec<MatchedRule>)> {
        let table = self.rewrites.read().clone();
        let (outcome, matched) = table.apply(host, qtype)?;

        let rules: Vec<MatchedRule> = matched
            .iter()
            .map(|r| MatchedRule {
                text: format!("{} -> {}", r.domain, r.answer_text),
                list_id: 0,
                ip: None,
            })
            .collect();

        let ttl = settings.blocking.ttl.max(1);
        let resp = match outcome {
            rewrite::Outcome::Addrs(addrs) => msg::with_addrs(req, &addrs, ttl),
            rewrite::Outcome::CName(c) => msg::with_cname(req, &c, &[], ttl),
            rewrite::Outcome::Empty => msg::nodata(req, ttl),
        };

        Some((Action::Respond(Box::new(resp)), rules))
    }

    /// Builds a response from `$dnsrewrite` rules.
    fn apply_dnsrewrite(
        &self,
        req: &Message,
        qtype: RecordType,
        rewrites: &[sift_filter::rule::DnsRewrite],
        settings: &Settings,
    ) -> Option<Message> {
        use sift_filter::rule::DnsRewrite as R;

        let ttl = settings.blocking.ttl.max(1);

        // A response code other than NOERROR wins over anything else. NOERROR
        // does not: a running v0.107.79 answers `1.2.3.4` for
        // `||a.example^$dnsrewrite=1.2.3.4` beside
        // `||a.example^$dnsrewrite=NOERROR`, citing both rules. On its own
        // that NOERROR is an empty answer, which is the fall-through below.
        if let Some(R::RCode(rc)) = rewrites
            .iter()
            .find(|r| matches!(r, R::RCode(c) if *c != 0))
        {
            let code = ResponseCode::from(0, *rc as u8);
            let mut resp = msg::reply(req, code);
            if code == ResponseCode::NXDomain {
                resp.authorities = vec![msg::soa_record(req, ttl)];
            }

            return Some(resp);
        }

        if let Some(R::CName(c)) = rewrites.iter().find(|r| matches!(r, R::CName(_))) {
            return Some(msg::with_cname(req, c, &[], ttl));
        }

        let addrs: Vec<IpAddr> = rewrites
            .iter()
            .filter_map(|r| match r {
                R::Addr(ip) => Some(*ip),
                _ => None,
            })
            .filter(|ip| match qtype {
                RecordType::A => ip.is_ipv4(),
                RecordType::AAAA => ip.is_ipv6(),
                _ => false,
            })
            .collect();

        if !addrs.is_empty() {
            return Some(msg::with_addrs(req, &addrs, ttl));
        }

        // A rewrite with no records of its own -- `$dnsrewrite`,
        // `$dnsrewrite=`, `$dnsrewrite=NOERROR` -- answers NOERROR and
        // nothing else, and so does an arbitrary record type, which is
        // matched here but not served.
        rewrites
            .iter()
            .any(|r| matches!(r, R::Record { .. } | R::RCode(0)))
            .then(|| msg::nodata(req, ttl))
    }
}

/// The list identifier for rules derived from the system hosts file.
const ETC_HOSTS_LIST_ID: i64 = -1;

/// The list identifier for the blocked-services rules.
const BLOCKED_SERVICE_LIST_ID: i64 = -2;

/// Reports whether an address is one no upstream should be told about.
fn is_loopback_or_unspecified(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => a.is_loopback() || a.is_unspecified() || a.is_private(),
        IpAddr::V6(a) => a.is_loopback() || a.is_unspecified() || (a.octets()[0] & 0xfe) == 0xfc,
    }
}

/// Reports whether a response carries an address in one of the bogus networks.
pub fn is_bogus_nxdomain(networks: &[(IpAddr, u8)], resp: &Message) -> bool {
    if networks.is_empty() {
        return false;
    }

    answer_addrs(resp).iter().any(|a| {
        networks
            .iter()
            .any(|&(n, b)| crate::clients::in_subnet(*a, n, b))
    })
}

/// The service name recorded for a blocked-services match.
///
/// The rules are generated from the catalogue, so the service is recovered
/// from the rule's own text rather than carried alongside it.
fn service_name_of(rules: &[MatchedRule]) -> String {
    rules
        .iter()
        .find(|r| r.list_id == BLOCKED_SERVICE_LIST_ID)
        .and_then(|r| sift_filter::services::name_for_rule(&r.text))
        .unwrap_or_default()
}

/// Refines a filtering reason using the list the winning rule came from.
///
/// The engine reports every blocking match as a blocklist match; upstream
/// distinguishes the built-in lists by their reserved identifiers, and the web
/// UI labels a query by that reason.
fn reason_for_list(reason: Reason, rules: &[MatchedRule]) -> Reason {
    let Some(first) = rules.first() else {
        return reason;
    };

    match first.list_id {
        BLOCKED_SERVICE_LIST_ID => Reason::FilteredBlockedService,
        ETC_HOSTS_LIST_ID => Reason::RewrittenAutoHosts,
        _ => reason,
    }
}

/// Extracts the addresses from a response, for statistics and DNS64.
pub fn answer_addrs(m: &Message) -> Vec<IpAddr> {
    m.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::Config as CacheConfig;
    use crate::clients::{PersistentSpec, Registry};
    use crate::pool::{Mode, Pool};
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;
    use sift_core::schedule::{DayRange, Weekly};

    fn request(name: &str, qt: RecordType) -> Message {
        let mut m = Message::query();
        m.metadata.id = 0x1111;
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_utf8(name).unwrap(), qt));

        m
    }

    /// A resolver with no upstreams, so anything reaching the upstream step
    /// fails loudly.
    fn resolver(block_rules: &str, rewrites: Table, settings: Settings) -> Resolver {
        Resolver::new(
            Engine::build([(1i64, block_rules)], sift_filter::engine::NO_LISTS),
            rewrites,
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
        )
    }

    async fn resolve(r: &Resolver, name: &str, qt: RecordType, proto: Proto) -> Outcome {
        r.resolve(&request(name, qt), proto, &ClientInfo::default())
            .await
    }

    async fn resolve_as(r: &Resolver, name: &str, client: &ClientInfo) -> Outcome {
        r.resolve(&request(name, RecordType::A), Proto::Udp, client)
            .await
    }

    #[tokio::test]
    async fn blocks_a_filtered_host_with_a_null_address() {
        let r = resolver(
            "||ads.example.com^\n",
            Table::default(),
            Settings::default(),
        );
        let out = resolve(&r, "ads.example.com.", RecordType::A, Proto::Udp).await;
        assert_eq!(out.reason, Reason::FilteredBlockList);
        let resp = out.response().unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(
            answer_addrs(resp),
            vec!["0.0.0.0".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(out.rules.len(), 1);
    }

    #[tokio::test]
    async fn a_malformed_question_count_gets_formerr() {
        let r = resolver("", Table::default(), Settings::default());
        let mut req = Message::query();
        req.metadata.id = 7;
        let out = r.resolve(&req, Proto::Udp, &ClientInfo::default()).await;
        assert_eq!(
            out.response().unwrap().metadata.response_code,
            ResponseCode::FormErr
        );
        assert_eq!(out.reason, Reason::FilteredInvalid);
    }

    #[tokio::test]
    async fn any_queries_are_refused_when_configured() {
        let r = resolver("", Table::default(), Settings::default());
        let out = resolve(&r, "example.com.", RecordType::ANY, Proto::Udp).await;
        assert_eq!(
            out.response().unwrap().metadata.response_code,
            ResponseCode::NotImp
        );

        let s = Settings {
            refuse_any: false,
            ..Default::default()
        };
        let r = resolver("", Table::default(), s);
        let out = resolve(&r, "example.com.", RecordType::ANY, Proto::Udp).await;
        // Falls through to the upstream step, which has no upstreams.
        assert_eq!(
            out.response().unwrap().metadata.response_code,
            ResponseCode::ServFail
        );
    }

    #[tokio::test]
    async fn access_blocked_hosts_are_dropped_on_udp_and_refused_on_tcp() {
        let r = resolver("", Table::default(), Settings::default());

        let out = resolve(&r, "version.bind.", RecordType::TXT, Proto::Udp).await;
        assert!(
            matches!(out.action, Action::Drop),
            "UDP must not be answered"
        );

        let out = resolve(&r, "version.bind.", RecordType::TXT, Proto::Tcp).await;
        assert_eq!(
            out.response().unwrap().metadata.response_code,
            ResponseCode::Refused
        );
    }

    #[tokio::test]
    async fn rewrites_apply_before_filtering() {
        let t = Table::build([("nas.lan", "192.168.1.5", true)]);
        let r = resolver("||nas.lan^\n", t, Settings::default());
        let out = resolve(&r, "nas.lan.", RecordType::A, Proto::Udp).await;
        assert_eq!(out.reason, Reason::Rewritten);
        assert_eq!(
            answer_addrs(out.response().unwrap()),
            vec!["192.168.1.5".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn rewrites_apply_even_with_protection_off() {
        let t = Table::build([("nas.lan", "192.168.1.5", true)]);
        let s = Settings {
            protection_enabled: false,
            ..Default::default()
        };
        let r = resolver("", t, s);
        let out = resolve(&r, "nas.lan.", RecordType::A, Proto::Udp).await;
        assert_eq!(out.reason, Reason::Rewritten);
    }

    #[tokio::test]
    async fn protection_off_disables_blocking() {
        let s = Settings {
            protection_enabled: false,
            ..Default::default()
        };
        let r = resolver("||ads.example.com^\n", Table::default(), s);
        let out = resolve(&r, "ads.example.com.", RecordType::A, Proto::Udp).await;
        assert_ne!(out.reason, Reason::FilteredBlockList);
    }

    #[tokio::test]
    async fn allowlisted_hosts_are_resolved_not_blocked() {
        let r = resolver(
            "||example.com^\n@@||good.example.com^\n",
            Table::default(),
            Settings::default(),
        );
        let out = resolve(&r, "good.example.com.", RecordType::A, Proto::Udp).await;
        // No upstream is configured, so it reaches SERVFAIL rather than being blocked.
        assert_eq!(
            out.response().unwrap().metadata.response_code,
            ResponseCode::ServFail
        );
    }

    #[tokio::test]
    async fn an_allowlist_match_stays_the_recorded_verdict() {
        // Upstream writes the `@@` rule and reason 1 into the query log even
        // though the query is then resolved normally, and the UI relies on it.
        let r = resolver(
            "||example.com^\n@@||good.example.com^\n",
            Table::default(),
            Settings::default(),
        );
        let out = resolve(&r, "good.example.com.", RecordType::A, Proto::Udp).await;

        assert_eq!(out.reason, Reason::NotFilteredAllowList);
        assert_eq!(out.rules.len(), 1);
        assert_eq!(out.rules[0].text, "@@||good.example.com^");
    }

    #[tokio::test]
    async fn an_unmatched_query_records_no_rules() {
        let r = resolver("||example.com^\n", Table::default(), Settings::default());
        let out = resolve(&r, "unrelated.org.", RecordType::A, Proto::Udp).await;
        assert_eq!(out.reason, Reason::NotFilteredNotFound);
        assert!(out.rules.is_empty());
    }

    #[tokio::test]
    async fn aaaa_can_be_suppressed() {
        let s = Settings {
            aaaa_disabled: true,
            ..Default::default()
        };
        let r = resolver("", Table::default(), s);
        let out = resolve(&r, "example.com.", RecordType::AAAA, Proto::Udp).await;
        let resp = out.response().unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(resp.answers.is_empty());
    }

    #[tokio::test]
    async fn dnsrewrite_rules_synthesise_answers() {
        let r = resolver(
            "||a.example.com^$dnsrewrite=1.2.3.4\n",
            Table::default(),
            Settings::default(),
        );
        let out = resolve(&r, "a.example.com.", RecordType::A, Proto::Udp).await;
        assert_eq!(out.reason, Reason::RewrittenRule);
        assert_eq!(
            answer_addrs(out.response().unwrap()),
            vec!["1.2.3.4".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn a_dnsrewrite_with_no_value_answers_noerror_and_nothing() {
        // Captured from a running v0.107.79: `$dnsrewrite`, `$dnsrewrite=`
        // and `$dnsrewrite=NOERROR` all report `RewriteRule` and answer
        // NOERROR with an empty answer section. This build used to read them
        // as cancelling every rewrite for the host, and so resolved the name
        // upstream instead.
        for rule in [
            "||a.example.com^$dnsrewrite\n",
            "||a.example.com^$dnsrewrite=\n",
            "||a.example.com^$dnsrewrite=NOERROR\n",
        ] {
            let r = resolver(rule, Table::default(), Settings::default());
            let out = resolve(&r, "a.example.com.", RecordType::A, Proto::Udp).await;

            assert_eq!(out.reason, Reason::RewrittenRule, "{rule}");

            let resp = out.response().unwrap();
            assert_eq!(resp.metadata.response_code, ResponseCode::NoError, "{rule}");
            assert!(resp.answers.is_empty(), "{rule}: {:?}", resp.answers);
        }
    }

    #[tokio::test]
    async fn an_address_rewrite_outranks_a_noerror_one() {
        // Both rules match and both are cited, and the answer is the address:
        // a NOERROR rewrite contributes no records rather than suppressing
        // the ones beside it.
        let r = resolver(
            "||a.example.com^$dnsrewrite=1.2.3.4\n||a.example.com^$dnsrewrite=NOERROR\n",
            Table::default(),
            Settings::default(),
        );
        let out = resolve(&r, "a.example.com.", RecordType::A, Proto::Udp).await;

        assert_eq!(out.reason, Reason::RewrittenRule);
        assert_eq!(
            answer_addrs(out.response().unwrap()),
            vec!["1.2.3.4".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn an_exception_leaves_the_name_to_resolve_normally() {
        // `@@||host^$dnsrewrite` removes the rewrite rather than applying one
        // of its own, so nothing is synthesised and the query goes on as if
        // no rule had matched.
        let r = resolver(
            "||a.example.com^$dnsrewrite=1.2.3.4\n@@||a.example.com^$dnsrewrite\n",
            Table::default(),
            Settings::default(),
        );
        let out = resolve(&r, "a.example.com.", RecordType::A, Proto::Udp).await;

        assert_eq!(out.reason, Reason::NotFilteredNotFound);
    }

    #[tokio::test]
    async fn dnsrewrite_can_force_a_response_code() {
        let r = resolver(
            "||a.example.com^$dnsrewrite=REFUSED\n",
            Table::default(),
            Settings::default(),
        );
        let out = resolve(&r, "a.example.com.", RecordType::A, Proto::Udp).await;
        assert_eq!(
            out.response().unwrap().metadata.response_code,
            ResponseCode::Refused
        );
    }

    #[tokio::test]
    async fn hosts_rules_answer_with_their_own_address() {
        let r = resolver(
            "192.168.1.7 printer.lan\n",
            Table::default(),
            Settings::default(),
        );
        let out = resolve(&r, "printer.lan.", RecordType::A, Proto::Udp).await;
        assert_eq!(out.reason, Reason::FilteredBlockList);
        assert_eq!(
            answer_addrs(out.response().unwrap()),
            vec!["192.168.1.7".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn a_blocked_service_is_reported_as_such() {
        // The blocked-services rules carry the reserved list identifier, and
        // the UI labels the query by the reason that implies.
        let r = resolver("", Table::default(), Settings::default());
        r.set_services(Some(Engine::build(
            [(-2i64, "||youtube.com^")],
            sift_filter::engine::NO_LISTS,
        )));

        let out = resolve(&r, "www.youtube.com.", RecordType::A, Proto::Udp).await;
        assert_eq!(out.reason, Reason::FilteredBlockedService);
    }

    #[tokio::test]
    async fn a_hosts_file_entry_is_reported_as_a_rewrite() {
        let r = resolver("", Table::default(), Settings::default());
        r.set_engine(Engine::build(
            [(-1i64, "192.168.1.7 printer.lan")],
            sift_filter::engine::NO_LISTS,
        ));

        let out = resolve(&r, "printer.lan.", RecordType::A, Proto::Udp).await;
        assert_eq!(out.reason, Reason::RewrittenAutoHosts);
        assert_eq!(
            answer_addrs(out.response().unwrap()),
            vec!["192.168.1.7".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn the_schedule_pauses_the_blocked_services() {
        // A full-day window means the block is paused all day, which is the
        // easy thing to get backwards: the schedule says when *not* to block.
        let mut days = [Some(DayRange::FULL); 7];
        let r = resolver(
            "",
            Table::default(),
            Settings {
                services_schedule: Weekly::new("UTC", days),
                ..Default::default()
            },
        );
        r.set_services(Some(Engine::build(
            [(-2i64, "||youtube.com^")],
            sift_filter::engine::NO_LISTS,
        )));

        let out = resolve(&r, "www.youtube.com.", RecordType::A, Proto::Udp).await;
        assert_ne!(out.reason, Reason::FilteredBlockedService);

        // Outside the window it blocks again.
        days = [None; 7];
        r.set_settings(Settings {
            services_schedule: Weekly::new("UTC", days),
            ..Default::default()
        });
        let out = resolve(&r, "www.youtube.com.", RecordType::A, Proto::Udp).await;
        assert_eq!(out.reason, Reason::FilteredBlockedService);
    }

    #[tokio::test]
    async fn a_blocked_service_records_its_name() {
        let r = resolver("", Table::default(), Settings::default());
        let rules = sift_filter::services::rules_for(&["youtube".to_string()]);
        r.set_services(Some(Engine::build(
            [(-2i64, rules.as_str())],
            sift_filter::engine::NO_LISTS,
        )));

        let out = resolve(&r, "www.youtube.com.", RecordType::A, Proto::Udp).await;
        assert_eq!(out.reason, Reason::FilteredBlockedService);
        assert_eq!(out.service_name, "YouTube");
    }

    #[tokio::test]
    async fn safe_search_rewrites_rather_than_blocks() {
        let r = resolver("", Table::default(), Settings::default());
        r.set_safe_search(sift_filter::safesearch::engine(
            &sift_filter::safesearch::Config {
                enabled: true,
                ..Default::default()
            },
        ));

        let out = resolve(&r, "www.google.com.", RecordType::A, Proto::Udp).await;
        assert_eq!(out.reason, Reason::FilteredSafeSearch);
        let resp = out.response().unwrap();
        assert!(
            resp.answers
                .iter()
                .any(|a| matches!(&a.data, RData::CNAME(c)
                    if c.0.to_ascii().starts_with("forcesafesearch.google.com"))),
            "expected the forcing CNAME, got {:?}",
            resp.answers
        );
    }

    #[tokio::test]
    async fn a_client_can_turn_its_own_filtering_off() {
        let r = resolver(
            "||ads.example.com^\n",
            Table::default(),
            Settings::default(),
        );
        r.set_clients(Registry::build(&[PersistentSpec {
            name: "unfiltered".into(),
            ids: vec!["192.0.2.5".into()],
            use_global_settings: false,
            filtering_enabled: false,
            use_global_blocked_services: true,
            ..Default::default()
        }]));

        let blocked = resolve_as(
            &r,
            "ads.example.com.",
            &ClientInfo {
                addr: Some("192.0.2.9".parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(blocked.reason, Reason::FilteredBlockList);

        let allowed = resolve_as(
            &r,
            "ads.example.com.",
            &ClientInfo {
                addr: Some("192.0.2.5".parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
        assert_ne!(allowed.reason, Reason::FilteredBlockList);
        assert_eq!(allowed.client_name, "unfiltered");
    }

    #[tokio::test]
    async fn a_client_with_its_own_upstreams_does_not_read_the_shared_cache() {
        // The resolver here has no upstreams, so anything that reaches the
        // upstream step SERVFAILs -- which is exactly how a cache miss shows
        // up.  Priming the global entry and then asking as a client with its
        // own resolvers must miss.
        let r = resolver("", Table::default(), Settings::default());
        r.set_clients(Registry::build(&[PersistentSpec {
            name: "work-laptop".into(),
            ids: vec!["192.0.2.5".into()],
            upstreams: vec!["10.0.0.1".into()],
            use_global_settings: true,
            use_global_blocked_services: true,
            ..Default::default()
        }]));

        let name = "intranet.example.com.";
        let req = request(name, RecordType::A);
        let key = Key::from_request(&req).unwrap();
        let mut answer = crate::msg::reply(&req, ResponseCode::NoError);
        answer.answers = vec![hickory_proto::rr::Record::from_rdata(
            Name::from_utf8(name).unwrap(),
            300,
            RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(
                203, 0, 113, 1,
            ))),
        )];
        assert!(r.cache.put(key, &answer), "the global entry is primed");

        // A client with no upstreams of its own is served it.
        let shared = resolve_as(
            &r,
            name,
            &ClientInfo {
                addr: Some("192.0.2.9".parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
        assert!(shared.cached, "the global client reads the shared entry");

        // The one with its own upstreams is not.
        let own = resolve_as(
            &r,
            name,
            &ClientInfo {
                addr: Some("192.0.2.5".parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(own.client_name, "work-laptop");
        assert!(
            !own.cached,
            "a client's own resolvers must not inherit the shared answer"
        );
    }

    #[tokio::test]
    async fn an_answer_from_the_wrong_pool_is_not_stored_as_the_clients_own() {
        // A settings save that adds a client with its own upstreams leaves a
        // few seconds before those upstreams are connected.  Queries in that
        // window are answered from the global pool rather than failing — but
        // storing one would hand it back as the client's own answer for the
        // whole TTL, long after its real resolvers were ready.
        let r = resolver("", Table::default(), Settings::default());
        r.set_clients(Registry::build(&[PersistentSpec {
            name: "work-laptop".into(),
            ids: vec!["192.0.2.5".into()],
            upstreams: vec!["10.0.0.1".into()],
            use_global_settings: true,
            use_global_blocked_services: true,
            ..Default::default()
        }]));
        // Deliberately no set_client_pools: this is the window.

        let key = crate::clients::upstream_key(&["10.0.0.1".to_string()]);
        assert!(
            !r.pool_for(key.as_ref()).1,
            "the client's own pool is not installed"
        );
        assert!(
            r.pool_for(None).1,
            "a client without its own upstreams always has the pool it asked for"
        );

        r.set_client_pools(HashMap::from([(
            key.clone().unwrap(),
            Arc::new(crate::pool::Pool::new(
                vec![],
                vec![],
                vec![],
                crate::pool::Mode::LoadBalance,
                Duration::from_millis(50),
                Duration::from_millis(50),
            )),
        )]));
        assert!(
            r.pool_for(key.as_ref()).1,
            "once installed, the client gets its own"
        );
    }

    #[test]
    fn the_upstream_identity_ignores_noise_and_not_substance() {
        use crate::clients::upstream_key;

        assert_eq!(upstream_key(&[]), None);
        assert_eq!(
            upstream_key(&["".into(), "  ".into(), "# note".into()]),
            None
        );

        // Whitespace and comments do not change which servers are used.
        let plain = upstream_key(&["10.0.0.1".into(), "10.0.0.2".into()]);
        let noisy = upstream_key(&[
            "  10.0.0.1 ".into(),
            "# a comment".into(),
            "".into(),
            "10.0.0.2".into(),
        ]);
        assert_eq!(plain, noisy);

        // Different servers, different identity -- and so a different pool
        // and different cache entries.
        assert_ne!(plain, upstream_key(&["10.0.0.2".into(), "10.0.0.1".into()]));
        assert_ne!(plain, upstream_key(&["10.0.0.1".into()]));
    }

    #[tokio::test]
    async fn a_client_id_selects_the_client() {
        let r = resolver("", Table::default(), Settings::default());
        r.set_clients(Registry::build(&[PersistentSpec {
            name: "tablet".into(),
            ids: vec!["kids-tablet".into()],
            use_global_settings: true,
            use_global_blocked_services: true,
            ignore_querylog: true,
            ..Default::default()
        }]));

        let out = resolve_as(
            &r,
            "example.com.",
            &ClientInfo {
                addr: Some("192.0.2.5".parse().unwrap()),
                id: Some("kids-tablet".into()),
                ..Default::default()
            },
        )
        .await;

        assert_eq!(out.client_name, "tablet");
        assert_eq!(out.client_id, "kids-tablet");
        assert!(out.ignore_querylog);
    }

    #[tokio::test]
    async fn a_clients_own_blocked_services_apply() {
        let r = resolver("", Table::default(), Settings::default());
        r.set_clients(Registry::build(&[PersistentSpec {
            name: "kid".into(),
            ids: vec!["192.0.2.5".into()],
            use_global_settings: true,
            use_global_blocked_services: false,
            blocked_services: vec!["youtube".into()],
            ..Default::default()
        }]));

        let out = resolve_as(
            &r,
            "www.youtube.com.",
            &ClientInfo {
                addr: Some("192.0.2.5".parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(out.reason, Reason::FilteredBlockedService);

        // Another client is unaffected.
        let out = resolve_as(
            &r,
            "www.youtube.com.",
            &ClientInfo {
                addr: Some("192.0.2.9".parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
        assert_ne!(out.reason, Reason::FilteredBlockedService);
    }

    #[tokio::test]
    async fn a_ddr_query_is_answered_locally() {
        let s = Settings {
            handle_ddr: true,
            ddr: ddr::Endpoints {
                server_name: "dns.example".into(),
                https: Some(443),
                tls: None,
                quic: Some(853),
            },
            ..Default::default()
        };
        let r = resolver("", Table::default(), s);

        let out = resolve(&r, "_dns.resolver.arpa.", RecordType::SVCB, Proto::Udp).await;
        let resp = out.response().unwrap();
        assert_eq!(resp.answers.len(), 2);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    }

    #[tokio::test]
    async fn ddr_is_not_answered_when_it_is_off() {
        let r = resolver("", Table::default(), Settings::default());
        let out = resolve(&r, "_dns.resolver.arpa.", RecordType::SVCB, Proto::Udp).await;

        // Falls through to the upstream step, which has none configured.
        assert_eq!(
            out.response().unwrap().metadata.response_code,
            ResponseCode::ServFail
        );
    }

    #[tokio::test]
    async fn the_ddr_name_is_answered_even_with_nothing_to_advertise() {
        // With no encrypted listener there is nothing to point a client at --
        // but the query must not reach an upstream, which would answer it with
        // *its* designated resolvers and move the client off this server.  A
        // running AdGuard Home answers the name itself, empty, whenever
        // `handle_ddr` is on; with it off, it forwards.
        let s = Settings {
            handle_ddr: true,
            ..Default::default()
        };
        let r = resolver("", Table::default(), s);

        for qtype in [RecordType::SVCB, RecordType::A, RecordType::HTTPS] {
            let out = resolve(&r, "_dns.resolver.arpa.", qtype, Proto::Udp).await;
            let resp = out.response().expect("an answer");

            assert_eq!(
                resp.metadata.response_code,
                ResponseCode::NoError,
                "{qtype} should be answered here, not forwarded"
            );
            assert!(resp.answers.is_empty(), "{qtype} has nothing to advertise");
            assert!(resp.authorities.is_empty(), "{qtype}");
        }
    }

    #[tokio::test]
    async fn only_the_ddr_name_itself_is_answered_here() {
        // The rest of `resolver.arpa` is forwarded, which is what upstream
        // does: `resolver.arpa` and `foo.resolver.arpa` both came back with the
        // upstream's own negative answer.
        let s = Settings {
            handle_ddr: true,
            ..Default::default()
        };
        let r = resolver("", Table::default(), s);

        for name in [
            "resolver.arpa.",
            "foo.resolver.arpa.",
            "_dns.foo.resolver.arpa.",
        ] {
            let out = resolve(&r, name, RecordType::SVCB, Proto::Udp).await;

            // No upstream is configured, so a forwarded query fails here.
            assert_eq!(
                out.response().unwrap().metadata.response_code,
                ResponseCode::ServFail,
                "{name} should have gone upstream"
            );
        }
    }

    #[tokio::test]
    async fn a_private_reverse_lookup_is_answered_locally() {
        // Forwarding it would leak the local network's shape and get nothing
        // useful back, so it is answered NXDOMAIN rather than sent upstream.
        let r = resolver("", Table::default(), Settings::default());
        let out = resolve(&r, "1.1.168.192.in-addr.arpa.", RecordType::PTR, Proto::Udp).await;

        assert_eq!(
            out.response().unwrap().metadata.response_code,
            ResponseCode::NXDomain
        );
    }

    #[tokio::test]
    async fn a_public_reverse_lookup_still_goes_upstream() {
        let r = resolver("", Table::default(), Settings::default());
        let out = resolve(
            &r,
            "34.216.184.93.in-addr.arpa.",
            RecordType::PTR,
            Proto::Udp,
        )
        .await;

        assert_eq!(
            out.response().unwrap().metadata.response_code,
            ResponseCode::ServFail,
            "no upstream is configured, so it fails there rather than locally"
        );
    }

    #[test]
    fn bogus_nxdomain_matches_an_answer_address() {
        let mut m = Message::query();
        m.answers = vec![hickory_proto::rr::Record::from_rdata(
            Name::from_utf8("example.com.").unwrap(),
            60,
            RData::A(hickory_proto::rr::rdata::A("192.0.2.7".parse().unwrap())),
        )];

        let nets = vec![("192.0.2.0".parse::<IpAddr>().unwrap(), 24)];
        assert!(is_bogus_nxdomain(&nets, &m));
        assert!(!is_bogus_nxdomain(&[], &m));

        let other = vec![("198.51.100.0".parse::<IpAddr>().unwrap(), 24)];
        assert!(!is_bogus_nxdomain(&other, &m));
    }

    #[tokio::test]
    async fn a_blocked_host_entry_reaches_the_resolver_with_the_query_type() {
        // The step feeds the question's type to the matcher, because the
        // entries are rules and a rule may carry `$dnstype`.  Measured on the
        // Go build: `||typed.example.org^$dnstype=AAAA` refuses AAAA and
        // answers A.  `crate::blocked` holds the matching rules themselves.
        let s = Settings {
            blocked_hosts: crate::blocked::BlockedHosts::shared(&[
                "||typed.example.org^$dnstype=AAAA".into(),
            ]),
            ..Settings::default()
        };
        let r = resolver("", Table::default(), s);

        let out = resolve(&r, "typed.example.org.", RecordType::AAAA, Proto::Tcp).await;
        assert_eq!(
            out.response().unwrap().metadata.response_code,
            ResponseCode::Refused,
            "AAAA is the type the rule names"
        );

        let out = resolve(&r, "typed.example.org.", RecordType::A, Proto::Tcp).await;
        assert_ne!(
            out.response().unwrap().metadata.response_code,
            ResponseCode::Refused,
            "A is not"
        );
    }

    #[test]
    fn protocol_log_names_match_upstream() {
        assert_eq!(Proto::Udp.log_name(), "");
        assert_eq!(Proto::Tcp.log_name(), "");
        assert_eq!(Proto::Tls.log_name(), "tls");
        assert_eq!(Proto::Https.log_name(), "doh");
        assert_eq!(Proto::Quic.log_name(), "doq");
    }

    #[test]
    fn private_networks_cover_the_usual_local_ranges() {
        let nets = default_private_networks();
        for ip in ["10.1.2.3", "192.168.0.1", "172.16.5.5", "127.0.0.1"] {
            let a: IpAddr = ip.parse().unwrap();
            assert!(
                nets.iter()
                    .any(|&(n, b)| crate::clients::in_subnet(a, n, b)),
                "{ip} should be private"
            );
        }

        let public: IpAddr = "93.184.216.34".parse().unwrap();
        assert!(
            !nets
                .iter()
                .any(|&(n, b)| crate::clients::in_subnet(public, n, b))
        );
    }
}
