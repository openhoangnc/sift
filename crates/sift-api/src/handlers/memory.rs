//! What the process is holding, and where.
//!
//! Ours, not upstream's.  Every memory question this build has had was
//! answered the same way: run it, watch the resident size climb, and work out
//! which structure the climb belongs to.  Doing that by reading the code found
//! the statistics window and then the expression cache, and both times the
//! evidence was a number somebody had to add a print statement to see.  This
//! reports those numbers directly, so two snapshots an hour apart name the
//! thing that grew between them instead of suggesting where to look next.
//!
//! What it deliberately does not do is estimate bytes per subsystem.  Only the
//! response cache knows its own size; everything else reports a count, which
//! is honest, and a count that stands still while the resident size climbs is
//! just as much of an answer as one that does not.

use axum::Json;
use axum::extract::State;
use serde::Serialize;

use crate::state::Shared;

/// The `/control/debug/memory` response.
#[derive(Serialize)]
pub struct MemoryResp {
    /// How long the server has been up, in seconds.
    ///
    /// A climb only means something against this.
    pub uptime: i64,
    /// What the kernel says this process is holding.
    pub process: crate::procmem::Process,
    /// What the container runtime charges it, where there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<crate::procmem::Cgroup>,
    /// The filtering engine.
    pub filters: Filters,
    /// The response cache.
    pub cache: Cache,
    /// The statistics.
    pub stats: Stats,
    /// The query log.
    pub querylog: QueryLog,
    /// The per-address tables, which grow with the network rather than with
    /// the configuration.
    pub clients: Clients,
    /// Everything else that is kept per peer.
    pub server: Server,
}

/// The filtering engine's size.
#[derive(Serialize)]
pub struct Filters {
    /// Lists configured, enabled or not.
    pub lists: usize,
    /// Rules the lists report between them.
    pub rules: usize,
    /// Bytes of list text held.
    ///
    /// The engine's rules point into these bytes rather than copying them, so
    /// this is held for as long as the engine is -- and it is doubled for as
    /// long as a refresh has a new engine built beside the old one.
    pub list_bytes: usize,
    /// Rules the engine in force actually holds.
    pub engine_rules: usize,
    /// The user's own rules.
    pub user_rules: usize,
    /// Bytes of blocked-service rules held as text.
    pub service_rules_bytes: usize,
    /// Bytes of the system hosts file held as text.
    pub hosts_rules_bytes: usize,
    /// Expressions compiled and held right now.
    ///
    /// Bounded, and the bound is the next field: this is the number that grew
    /// without one and took the process from 269 MB to 537 MB in a day.
    pub compiled_expressions: usize,
    /// The ceiling the previous field is kept under.
    pub compiled_ceiling: usize,
}

/// The response cache's size.
#[derive(Serialize)]
pub struct Cache {
    /// Entries held.
    pub entries: usize,
    /// Bytes held, by the cache's own accounting.
    pub bytes: usize,
    /// The budget those bytes are kept under, from `dns.cache_size`.
    pub budget: usize,
    /// Eviction slots held across every shard.
    ///
    /// Reported beside the entry count because these two drifting apart is a
    /// leak that has happened here before: a cache inside its budget never
    /// evicts, and the slots were only collected by eviction.
    pub eviction_slots: usize,
}

/// What the statistics hold.
#[derive(Serialize)]
pub struct Stats {
    /// Hours held, the live one included.
    pub hours: usize,
    /// Finished hours, each capped to the hundred names it is stored with.
    pub past_hours: usize,
    /// Distinct names counted in the hour in progress.
    pub live_domains: usize,
    /// Distinct blocked names counted in the hour in progress.
    pub live_blocked_domains: usize,
    /// Distinct clients counted in the hour in progress.
    pub live_clients: usize,
    /// Distinct upstreams counted in the hour in progress.
    pub live_upstreams: usize,
}

/// What the query log holds in memory.
#[derive(Serialize)]
pub struct QueryLog {
    /// Entries waiting to be written.
    pub buffered: usize,
    /// Entries in the ring the API reads the newest page from.
    pub recent: usize,
}

/// The client tables.
#[derive(Serialize)]
pub struct Clients {
    /// Clients configured by the operator.
    pub persistent: usize,
    /// Addresses discovery has recorded something about.
    ///
    /// Nothing evicts from this: an address is kept for the life of the
    /// process, so on a resolver reachable from the internet it counts the
    /// distinct sources that have ever asked it anything.
    pub runtime: usize,
    /// How many of those carry a WHOIS record, which is the expensive half.
    pub runtime_whois: usize,
}

/// The per-peer tables the server keeps.
#[derive(Serialize)]
pub struct Server {
    /// Identical requests being coalesced right now.
    pub inflight: usize,
    /// Addresses the rate limiter is holding a bucket for.
    pub ratelimit_buckets: usize,
    /// Addresses the connection probe is holding a mark for.
    pub probe_marks: usize,
    /// Live web sessions.
    pub sessions: usize,
}

/// `GET /control/debug/memory`.
pub async fn memory(State(s): State<Shared>) -> Json<MemoryResp> {
    let filters = s.filters.read();
    let engine = s.resolver.engine();
    let stats = s.stats.sizes();
    let (runtime, runtime_whois) = s.resolver.runtime.sizes();

    Json(MemoryResp {
        uptime: jiff::Timestamp::now().as_second() - s.started.as_second(),
        process: crate::procmem::process(),
        cgroup: crate::procmem::cgroup(),
        filters: Filters {
            lists: filters.blocklists.len() + filters.allowlists.len(),
            rules: filters.rules_count(),
            list_bytes: filters
                .blocklists
                .iter()
                .chain(&filters.allowlists)
                .map(|l| l.text.len())
                .sum(),
            engine_rules: engine.len(),
            user_rules: filters.user_rules.len(),
            service_rules_bytes: filters.service_rules.len(),
            hosts_rules_bytes: filters.hosts_rules.len(),
            compiled_expressions: sift_filter::rule::compiled_count(),
            compiled_ceiling: sift_filter::rule::MAX_COMPILED,
        },
        cache: Cache {
            entries: s.resolver.cache.len(),
            bytes: s.resolver.cache.bytes(),
            budget: s.config.read().dns.cache_size as usize,
            eviction_slots: s.resolver.cache.order_len(),
        },
        stats: Stats {
            hours: s.stats.len(),
            past_hours: stats.past_hours,
            live_domains: stats.live_domains,
            live_blocked_domains: stats.live_blocked_domains,
            live_clients: stats.live_clients,
            live_upstreams: stats.live_upstreams,
        },
        querylog: QueryLog {
            buffered: s.querylog.buffered(),
            recent: s.querylog.recent(),
        },
        clients: Clients {
            persistent: s.resolver.clients().len(),
            runtime,
            runtime_whois,
        },
        server: Server {
            inflight: s.resolver.inflight(),
            ratelimit_buckets: s.dns_server.limiter.tracked(),
            probe_marks: s.dns_server.probes.tracked(),
            sessions: s.sessions.len(),
        },
    })
}
