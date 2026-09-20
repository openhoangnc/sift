//! What `/control/debug/memory` reports, and where each number comes from.
//!
//! The endpoint's whole value is that its numbers are the real ones, so the
//! state here is seeded with a different amount in every subsystem: a field
//! wired to the wrong source reads another subsystem's number and the count
//! it should have carried is nowhere in the response.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use sift_api::state::{AppState, NoFetcher, NoReloader, Shared};

/// Builds a state with a distinguishable amount in each subsystem.
///
/// With `user`, the setup wizard is past and `/control` needs a session; the
/// gate check is the only test that wants that.
fn state(user: bool) -> Shared {
    let mut config = sift_config::Config::default();
    config.dns.upstream_dns = vec![];
    config.dns.bootstrap_dns = vec![];
    config.filters = vec![];
    // Distinctive, so the reported budget cannot be anything else's number.
    config.dns.cache_size = 1_234_567;
    if user {
        config.users = vec![sift_config::model::WebUser {
            name: "admin".to_string(),
            password: sift_api::auth::hash_password("unused").expect("hashing"),
        }];
    }

    // Three rules in the engine, against two lists and four user rules in the
    // manager: the engine in force and the configuration are counted
    // separately, because a save that has not been applied is exactly when
    // the two differ.
    let resolver = Arc::new(sift_dns::resolver::Resolver::new(
        sift_filter::engine::Engine::build(
            [(1i64, "||a.example^\n||b.example^\n||c.example^")],
            sift_filter::engine::NO_LISTS,
        ),
        sift_dns::rewrite::Table::default(),
        sift_dns::cache::Cache::new(sift_dns::cache::Config::default()),
        sift_dns::pool::SharedPool::new(sift_dns::pool::Pool::new(
            vec![],
            vec![],
            vec![],
            sift_dns::pool::Mode::LoadBalance,
            Duration::from_millis(50),
            Duration::from_millis(50),
        )),
        sift_dns::resolver::Settings::default(),
    ));

    // Two addresses discovered, one of them with a WHOIS record.
    let known: IpAddr = "192.0.2.1".parse().unwrap();
    resolver
        .runtime
        .set_name(known, "one", sift_dns::clients::Source::Rdns);
    resolver.runtime.set_name(
        "192.0.2.2".parse().unwrap(),
        "two",
        sift_dns::clients::Source::Rdns,
    );
    resolver
        .runtime
        .set_whois(known, vec![("orgname".to_string(), "Example".to_string())]);

    let dns_server = Arc::new(sift_dns::server::Server::new(
        resolver.clone(),
        Arc::new(sift_dns::ratelimit::Limiter::new(
            sift_dns::ratelimit::Config {
                per_second: 0,
                ..Default::default()
            },
        )),
        Arc::new(sift_dns::server::NoopObserver),
    ));

    let base = std::env::temp_dir().join(format!("sift-memory-{}", std::process::id()));
    let paths = sift_config::Paths::new(base.join("work"), base.join("conf/AdGuardHome.yaml"));
    paths.ensure().expect("preparing the working directory");

    let querylog = Arc::new(sift_querylog::log::QueryLog::new(
        paths.query_log(""),
        paths.query_log_rotated(""),
        sift_querylog::log::Config::default(),
    ));
    // Seven entries seen, five of them already written: the ring and the
    // unwritten buffer are different numbers, so neither can stand in for
    // the other.
    for i in 0..5 {
        querylog.push(sift_querylog::entry::Entry {
            question_host: format!("q{i}.example"),
            ..Default::default()
        });
    }
    querylog.flush().expect("writing the buffered entries");
    for i in 5..7 {
        querylog.push(sift_querylog::entry::Entry {
            question_host: format!("q{i}.example"),
            ..Default::default()
        });
    }

    // Six distinct names in the hour in progress, from two clients.
    let stats = Arc::new(sift_stats::stats::Stats::new(
        sift_stats::stats::Config::default(),
    ));
    for i in 0..6 {
        stats.add(&sift_stats::unit::Entry {
            client: format!("198.51.100.{}", i % 2),
            domain: format!("s{i}.example"),
            result: sift_stats::unit::Result::NotFiltered,
            processing_time: Duration::from_millis(1),
            upstreams: vec![],
        });
    }

    let filters = sift_filter::lists::Manager {
        blocklists: vec![list(1, 10), list(2, 20)],
        allowlists: vec![list(3, 30)],
        user_rules: (0..4).map(|i| format!("||u{i}.example^")).collect(),
        ..Default::default()
    };

    let login_limiter = sift_api::auth::LoginLimiter::from_config(&config);

    Arc::new(AppState {
        paths: paths.clone(),
        config: parking_lot::RwLock::new(config),
        resolver,
        dns_server,
        filters: parking_lot::RwLock::new(filters),
        querylog,
        stats,
        sessions: sift_api::auth::Sessions::new(),
        login_limiter,
        started: jiff::Timestamp::now(),
        fetcher: Arc::new(NoFetcher),
        reloader: Arc::new(NoReloader),
        dns_addresses: parking_lot::RwLock::new(vec![]),
        version: Arc::new(sift_api::state::NoVersionCheck),
        updater: Arc::new(sift_api::state::NoSelfUpdate),
        version_cache: parking_lot::RwLock::new(None),
    })
}

/// A list carrying a rule count, which is what the manager sums, and a body
/// of the given size, which is what it holds.
fn list(id: i64, rules: usize) -> sift_filter::lists::List {
    sift_filter::lists::List {
        id,
        url: format!("https://example/{id}.txt"),
        name: format!("list {id}"),
        enabled: true,
        allowlist: false,
        text: "x".repeat(rules * 10).into(),
        rules_count: rules,
        last_updated: None,
    }
}

#[tokio::test]
async fn every_number_comes_from_its_own_subsystem() {
    let s = state(false);
    let axum::Json(m) = sift_api::handlers::memory::memory(axum::extract::State(s.clone())).await;

    assert_eq!(m.filters.lists, 3, "two blocklists and one allowlist");
    assert_eq!(m.filters.rules, 64, "10 + 20 + 30 rules, and 4 user rules");
    assert_eq!(
        m.filters.engine_rules, 3,
        "the engine in force, not the config"
    );
    assert_eq!(m.filters.user_rules, 4);
    assert_eq!(m.filters.list_bytes, 600, "10 bytes a rule, over 60 rules");
    assert_eq!(
        m.filters.compiled_ceiling,
        sift_filter::rule::MAX_COMPILED,
        "the ceiling is reported so the count above it means something"
    );

    assert_eq!(m.cache.entries, 0, "nothing was cached");
    assert_eq!(m.cache.eviction_slots, 0);
    assert_eq!(m.cache.budget, 1_234_567, "from dns.cache_size");

    assert_eq!(m.stats.hours, 1, "the hour in progress");
    assert_eq!(m.stats.past_hours, 0, "nothing has rolled yet");
    assert_eq!(m.stats.live_domains, 6);
    assert_eq!(m.stats.live_clients, 2);

    assert_eq!(m.querylog.buffered, 2, "written entries leave the buffer");
    assert_eq!(m.querylog.recent, 7, "the ring keeps them all");

    assert_eq!(m.clients.runtime, 2, "two addresses discovered");
    assert_eq!(m.clients.runtime_whois, 1, "one of them with a record");

    assert_eq!(m.server.inflight, 0);
    assert_eq!(m.server.sessions, 0);

    // The process fields are whatever the kernel says, and nothing is
    // reported off Linux; what must hold everywhere is that asking does not
    // fail and a reported size is a real one.
    if let Some(rss) = m.process.rss {
        assert!(rss > 0);
    }
}

#[tokio::test]
async fn a_finished_hour_is_reported_apart_from_the_live_one() {
    // The distinction is the whole point of the statistics fields: a finished
    // hour is capped at a hundred names and a live one is not, so a snapshot
    // that lumped them together could not say which was growing.
    let s = state(false);
    s.stats.load([(
        sift_stats::unit::current_hour() - 1,
        sift_stats::unit::UnitDb::default(),
    )]);

    let axum::Json(m) = sift_api::handlers::memory::memory(axum::extract::State(s)).await;

    assert_eq!(m.stats.past_hours, 1);
    assert_eq!(m.stats.hours, 2, "the finished hour and the live one");
    assert_eq!(m.stats.live_domains, 6, "the live hour is untouched");
}

#[tokio::test]
async fn the_snapshot_needs_a_session_like_everything_else_under_control() {
    // It reports a client count, a session count and the shape of the
    // network: gated with the rest of `/control` rather than served to
    // anyone who can reach the port.
    use tower::ServiceExt as _;

    let app = sift_api::routes::router(state(true), false);
    let req = axum::http::Request::builder()
        .uri("/control/debug/memory")
        .extension(axum::extract::ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            5555,
        ))))
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
}
