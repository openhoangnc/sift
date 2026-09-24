//! sift — a drop-in Rust backend for AdGuard Home.

mod app;
mod cli;
mod discovery;
mod fetch;
mod ipset;
mod lists;
mod logging;
mod osconf;
mod service;
mod update;
mod wiring;

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use sift_api::state::{AppState, Shared};
use sift_config::Paths;
use tracing_subscriber::EnvFilter;

use crate::app::App;
use crate::cli::Args;

fn main() -> std::process::ExitCode {
    let args = Args::parse();

    // Before anything reads or writes a file: an installer asks a binary what
    // it is, and creating a config as a side effect of the question would be
    // rude to the directory it was asked in.
    if args.version {
        println!("{}", cli::version_line());

        return std::process::ExitCode::SUCCESS;
    }

    let paths = Paths::new(args.work_dir_or_default(), args.config_or_default());

    // The configuration is read before the runtime starts, because two of the
    // things it decides — where the log goes and which user to run as — have
    // to be settled while the process is still single-threaded.
    let config = match app::load_or_init(&paths) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sift: reading {}: {e}", paths.config.display());

            return std::process::ExitCode::FAILURE;
        }
    };

    init_logging(&args, &config.log);

    // A service action neither starts the server nor needs the runtime —
    // except `run`, which is how an init system starts it in the foreground,
    // and which upstream's own unit file passes.
    if let Some(action) = args.service.as_deref()
        && action != service::RUN
    {
        return match service::run(action, &args) {
            Ok(message) => {
                println!("{message}");

                std::process::ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("sift: {e}");

                std::process::ExitCode::FAILURE
            }
        };
    }

    // Checking the configuration is a read-only action: it neither drops
    // privileges nor needs a runtime.
    if args.check_config {
        println!("configuration at {} is valid", paths.config.display());

        return std::process::ExitCode::SUCCESS;
    }

    osconf::apply(&config.os);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sift: starting the runtime: {e}");

            return std::process::ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(args, paths, config)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "fatal");

            std::process::ExitCode::FAILURE
        }
    }
}

/// The dependency levels folded into the default log filter.
///
/// `rustls::msgs` is quieted below its warnings on purpose. Every warning that
/// module emits reports a *peer's* malformed handshake message, and the common
/// one -- "Illegal SNI extension: ignoring IP address presented as hostname"
/// -- is written once per connection, so a single client dialling the DoT or
/// HTTPS port by address rather than by name fills the log at whatever rate it
/// reconnects. There is nothing for an operator to act on: the warning names
/// the address the client dialled rather than the client, so it does not even
/// say who is doing it, and rustls decides on its own terms whether to carry
/// on with the handshake. Warnings from the rest of rustls, which are about
/// *this* server's configuration and keys, still come through.
const DEP_FILTER: &str =
    "hyper=warn,rustls=warn,rustls::msgs=error,h2=warn,hickory_proto=warn,tokio_util=warn";

/// Configures tracing from the flags and the environment.
///
/// The default filter sets a global level rather than naming this crate: the
/// binary target is `AdGuardHome`, so `module_path!` reports that rather than
/// the package name, and a per-crate filter spelled `sift=info` would
/// silently drop every message the server logs.
fn init_logging(args: &Args, log: &sift_config::model::LogConfig) {
    let default = if args.verbose || log.verbose {
        "debug"
    } else {
        "info"
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // Quiet the dependencies that are chatty at these levels.
        EnvFilter::new(format!("{default},{DEP_FILTER}"))
    });

    // `--logfile` wins over the configured file, which is what upstream does:
    // the flag is how an init script overrides the file for one run.
    let target = args.logfile.clone().unwrap_or_else(|| {
        if log.enabled {
            log.file.clone()
        } else {
            String::new()
        }
    });

    let rotation = logging::Rotation {
        max_size_mb: log.max_size,
        max_backups: log.max_backups,
        max_age_days: log.max_age,
        compress: log.compress,
    };

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);

    match logging::Sink::choose(&target, rotation) {
        logging::Sink::Stderr => builder.init(),
        logging::Sink::File(f) => builder.with_ansi(false).with_writer(move || f).init(),
        #[cfg(unix)]
        logging::Sink::Syslog(s) => builder
            .with_ansi(false)
            // The system log stamps its own time and level.
            .without_time()
            .with_writer(move || s)
            .init(),
    }
}

/// Starts the server and runs until a shutdown signal arrives.
async fn run(args: Args, paths: Paths, mut config: sift_config::Config) -> anyhow::Result<()> {
    // rustls needs a process-wide crypto provider before any TLS is set up.
    let _ = rustls::crypto::ring::default_provider().install_default();

    if let Some(addr) = args.web_override()
        && let Ok(parsed) = addr.parse::<std::net::SocketAddr>()
    {
        config.http.address = sift_config::types::AddrPort(parsed);
    }

    tracing::info!(
        version = sift_core::VERSION,
        config = %paths.config.display(),
        work_dir = %paths.work.display(),
        "starting sift"
    );

    if let Some(p) = &args.pidfile {
        match osconf::write_pidfile(p) {
            Ok(()) => tracing::info!(path = %p.display(), "pid file written"),
            Err(e) => tracing::warn!(path = %p.display(), error = %e, "writing the pid file"),
        }
    }

    // The query log and statistics are shared between the DNS observer and the
    // HTTP API, so they are built before either.
    let querylog = Arc::new(sift_querylog::log::QueryLog::new(
        paths.query_log(&config.querylog.dir_path),
        paths.query_log_rotated(&config.querylog.dir_path),
        sift_querylog::log::Config {
            enabled: config.querylog.enabled,
            file_enabled: config.querylog.file_enabled,
            size_memory: config.querylog.size_memory as usize,
            ignored: config.querylog.ignored.clone(),
            ignored_enabled: config.querylog.ignored_enabled,
            anonymize_client_ip: config.dns.anonymize_client_ip,
        },
    ));

    let stats = Arc::new(sift_stats::stats::Stats::new(sift_stats::stats::Config {
        enabled: config.statistics.enabled,
        limit_hours: config.statistics.interval.as_hours().max(0) as u32,
        ignored: config.statistics.ignored.clone(),
        ignored_enabled: config.statistics.ignored_enabled,
    }));

    // Pick up the statistics a previous run left behind, including one
    // written by the Go implementation.
    let stats_path = paths.stats_db(&config.statistics.dir_path);
    match sift_stats::store::load(&stats_path) {
        Ok(units) if !units.is_empty() => {
            tracing::info!(units = units.len(), "loaded statistics");
            stats.load(units);
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, path = %stats_path.display(), "loading statistics"),
    }

    let recorder = Arc::new(wiring::Recorder::new(
        querylog.clone(),
        stats.clone(),
        config.dns.anonymize_client_ip,
    ));
    let recorder_handle = recorder.clone();

    let web_addr = config.http.address.0;
    let max_list_bytes = config.filtering.max_http_size.bytes();

    let application = App::build(paths.clone(), config, recorder).await?;

    tracing::info!(
        rules = application.filters.rules_count(),
        lists = application.filters.blocklists.len() + application.filters.allowlists.len(),
        "filter lists loaded"
    );

    let certificate = Arc::new(sift_dns::tls::Reloadable::new());

    let dns_addrs: Vec<String> = application
        .dns_addrs()
        .iter()
        .map(|a| a.to_string())
        .collect();

    let state: Shared = Arc::new(AppState {
        paths: application.paths.clone(),
        config: parking_lot::RwLock::new(application.config.clone()),
        resolver: application.resolver.clone(),
        dns_server: application.server.clone(),
        filters: parking_lot::RwLock::new(application.filters.clone()),
        querylog: querylog.clone(),
        stats: stats.clone(),
        sessions: sift_api::auth::Sessions::open(application.paths.sessions_db()),
        login_limiter: login_limiter(&application.config),
        started: jiff::Timestamp::now(),
        fetcher: Arc::new(wiring::Downloader {
            paths: application.paths.clone(),
            max_bytes: max_list_bytes,
            timeout: app::LIST_TIMEOUT,
        }),
        reloader: Arc::new(wiring::LiveReloader {
            resolver: application.resolver.clone(),
            server: application.server.clone(),
            certificate: certificate.clone(),
            upstream_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            // Seeded from the config the pools were just built from, so the
            // first settings save does not reconnect every upstream for
            // nothing.
            upstream_fingerprint: Arc::new(parking_lot::Mutex::new(Some(
                wiring::upstream_fingerprint(&application.config),
            ))),
        }),
        dns_addresses: parking_lot::RwLock::new(dns_addrs),
        version: Arc::new(wiring::ReleaseChecker {
            disabled: args.no_check_update,
        }),
        updater: Arc::new(update::Updater {
            disabled: args.no_check_update,
            work: application.paths.work.clone(),
            config: application.paths.config.clone(),
            // Captured now, before an update can move the running binary out
            // of the way; see the field's comment.
            exe: std::env::current_exe().ok(),
        }),
        version_cache: parking_lot::RwLock::new(None),
    });

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut tasks = application.serve_dns(shutdown_rx.clone()).await?;

    // ipset, if any sets are configured.
    let ipset_lines = ipset::lines(
        &application.config.dns.ipset,
        &application.config.dns.ipset_file,
    );
    if let Some(m) = ipset::Manager::new(ipset::parse(&ipset_lines)) {
        tracing::info!(rules = ipset_lines.len(), "ipset enabled");
        recorder_handle.set_ipset(Some(Arc::new(m)));
    }

    // Client discovery: names for the addresses that show up in the log.
    let discoverer = Arc::new(discovery::Discoverer {
        resolver: application.resolver.clone(),
        runtime: application.resolver.runtime.clone(),
    });
    let (queue, discovery_task) = discoverer.start(shutdown_rx.clone());
    recorder_handle.set_discovery(queue, application.resolver.runtime.clone());
    tasks.push(discovery_task);

    for addr in application.dns_addrs() {
        tracing::info!(%addr, "serving dns");
    }

    // Encryption, if a usable certificate is configured.  A broken one is a
    // warning rather than a fatal error: plain DNS and the web interface
    // should keep working while the operator fixes it.
    //
    // The listeners are given a resolver rather than a certificate, so one
    // replaced through the API reaches them without a restart.
    let tls = load_tls(&application.config, &certificate)
        .then(|| sift_dns::tls::reloadable(certificate.clone()));
    // Watching the files for a renewal is only worth it once something is
    // serving them; the listeners below are what decides that.
    let watched = tls.is_some().then(|| certificate.clone());

    // The web interface over plain HTTP.
    let listener = tokio::net::TcpListener::bind(web_addr).await?;
    tracing::info!(addr = %web_addr, "serving web interface");
    if state.needs_install() {
        tracing::info!("no user configured yet; open the web interface to finish setup");
    }

    let app_router = sift_api::routes::router(state.clone(), false);
    let mut web_shutdown = shutdown_rx.clone();
    tasks.push(tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = web_shutdown.changed().await;
        })
        .await;
    }));

    if let Some(tls) = tls {
        let cfg = &application.config;

        // HTTPS carries both the web interface and DNS-over-HTTPS, as upstream
        // serves them.
        if cfg.tls.port_https != 0 {
            for ip in &cfg.dns.bind_hosts {
                let addr = std::net::SocketAddr::new(*ip, cfg.tls.port_https);
                match sift_api::https::serve(
                    addr,
                    tls.https.clone(),
                    sift_api::routes::router(state.clone(), true),
                    application.server.probes.clone(),
                    shutdown_rx.clone(),
                )
                .await
                {
                    Ok(t) => {
                        tracing::info!(%addr, "serving https and dns-over-https");
                        tasks.push(t);
                    }
                    Err(e) => tracing::error!(%addr, error = %e, "binding https"),
                }

                // HTTP/3 runs over QUIC, so it needs its own listener on the
                // same port number — the UDP one rather than the TCP one.
                if cfg.dns.serve_http3 {
                    match sift_api::http3::endpoint(addr, tls.h3.clone()) {
                        Ok(ep) => {
                            tracing::info!(%addr, "serving http/3");
                            let router = sift_api::routes::router(state.clone(), true);
                            let mut rx = shutdown_rx.clone();
                            let probes = application.server.probes.clone();
                            tasks.push(tokio::spawn(async move {
                                sift_api::http3::serve(ep, router, probes, async move {
                                    let _ = rx.changed().await;
                                })
                                .await;
                            }));
                        }
                        Err(e) => tracing::error!(%addr, error = %e, "binding http/3"),
                    }
                }
            }
        }

        if cfg.tls.port_dns_over_quic != 0 {
            for ip in &cfg.dns.bind_hosts {
                let addr = std::net::SocketAddr::new(*ip, cfg.tls.port_dns_over_quic);
                match sift_dns::doq::endpoint(addr, tls.doq.clone()) {
                    Ok(ep) => {
                        tracing::info!(%addr, "serving dns-over-quic");
                        let server = application.server.clone();
                        let mut rx = shutdown_rx.clone();
                        // A ClientID reaches it as a label below
                        // `tls.server_name`, which the server holds.
                        tasks.push(tokio::spawn(async move {
                            sift_dns::doq::serve(ep, server, async move {
                                let _ = rx.changed().await;
                            })
                            .await;
                        }));
                    }
                    Err(e) => tracing::error!(%addr, error = %e, "binding dns-over-quic"),
                }
            }
        }

        if cfg.tls.port_dns_over_tls != 0 {
            for ip in &cfg.dns.bind_hosts {
                let addr = std::net::SocketAddr::new(*ip, cfg.tls.port_dns_over_tls);
                match sift_dns::server::bind_tcp(addr).await {
                    Ok(l) => {
                        tracing::info!(%addr, "serving dns-over-tls");
                        let server = application.server.clone();
                        let dot = tls.dot.clone();
                        let mut rx = shutdown_rx.clone();
                        // Returns only at shutdown: an error accepting is
                        // waited out rather than closing the port.
                        tasks.push(tokio::spawn(async move {
                            sift_dns::server::serve_dot(l, dot, server, async move {
                                let _ = rx.changed().await;
                            })
                            .await;
                        }));
                    }
                    Err(e) => tracing::error!(%addr, error = %e, "binding dns-over-tls"),
                }
            }
        }
    }

    // Protection can be paused for a set time; this is what ends the pause.
    tasks.push(tokio::spawn(protection_watch(
        state.clone(),
        shutdown_rx.clone(),
    )));

    // Periodic maintenance: flush the log, prune statistics, refresh lists.
    tasks.push(tokio::spawn(maintenance(
        state.clone(),
        stats_path.clone(),
        watched,
        application.server.clone(),
        shutdown_rx.clone(),
    )));

    wait_for_shutdown().await;
    tracing::info!("shutting down");
    let _ = shutdown_tx.send(true);

    // Persist whatever is still buffered before the process exits.
    state.sessions.persist();
    if let Err(e) = querylog.flush() {
        tracing::warn!(error = %e, "flushing the query log");
    }
    if let Err(e) = sift_stats::store::save(&stats_path, &stats.snapshot()) {
        tracing::warn!(error = %e, "saving statistics");
    }

    for t in tasks {
        let _ = tokio::time::timeout(Duration::from_secs(5), t).await;
    }

    if let Some(p) = &args.pidfile {
        osconf::remove_pidfile(p);
    }

    Ok(())
}

/// Builds the login throttle, saying so when the config switches it off.
///
/// `auth_attempts: 0` or `block_auth_min: 0` disables it, as upstream's
/// `emptyRateLimiter` does -- and upstream warns when it happens, because an
/// admin password nothing throttles can be guessed at line rate.
fn login_limiter(cfg: &sift_config::Config) -> sift_api::auth::LoginLimiter {
    let limiter = sift_api::auth::LoginLimiter::from_config(cfg);
    if !limiter.is_enabled() {
        tracing::warn!("login rate limiting is disabled");
    }

    limiter
}

/// Installs the configured certificate, reporting whether encryption can run.
fn load_tls(cfg: &sift_config::Config, into: &sift_dns::tls::Reloadable) -> bool {
    // DNS-over-TLS and DNS-over-QUIC read it from the slot on every
    // handshake; a settings save sets it again through the reloader.
    into.set_strict_sni(cfg.tls.strict_sni_check);

    if !cfg.tls.enabled {
        return false;
    }

    let src = app::tls_source(cfg);
    if src.is_empty() {
        tracing::warn!("encryption is enabled but no certificate is configured");

        return false;
    }

    match sift_dns::tls::install(&src, into) {
        Ok(st) => {
            tracing::info!(names = ?st.dns_names, "certificate loaded");

            true
        }
        Err(e) => {
            tracing::error!(error = %e, "encryption is enabled but the certificate is unusable");

            false
        }
    }
}

/// How close to expiry is worth complaining about.
///
/// Renewal normally happens with a month to spare -- Let's Encrypt issues for
/// ninety days and certbot renews at thirty -- so by the time a week is left,
/// whatever was meant to rewrite the files has stopped doing it and nobody
/// has noticed yet.
const EXPIRY_WARNING: i64 = 7 * 24 * 3600;

/// How often that warning is repeated.
const EXPIRY_WARNING_EVERY: Duration = Duration::from_secs(3600);

/// Watches the certificate files, so a renewal is served without a restart.
///
/// Whatever renews the certificate -- certbot, acme.sh, a mounted secret --
/// rewrites the files underneath a running server and has no way to tell it.
/// Nothing else notices: `/control/tls/configure` is the only other path that
/// installs a certificate, and a renewal does not go through the API.  So the
/// files are compared with what is being served, on the maintenance tick, and
/// a changed pair is installed for the next handshake.
///
/// The cost is two small files and a digest a minute, which is less than the
/// statistics prune it runs beside; checking rarely and then racing the expiry
/// would buy nothing back.
struct CertWatch {
    /// The slot the listeners resolve their certificate from.
    slot: Arc<sift_dns::tls::Reloadable>,
    /// The last failure reported, so a file caught halfway through being
    /// rewritten does not repeat the same line every minute until it is not.
    last_error: Option<String>,
    /// When expiry was last complained about.
    warned: Option<std::time::Instant>,
}

/// What a certificate's remaining life is worth saying.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expiry {
    /// It expires within [`EXPIRY_WARNING`], in this many seconds.
    Soon(i64),
    /// It has already expired.
    Gone,
}

impl CertWatch {
    fn new(slot: Arc<sift_dns::tls::Reloadable>) -> Self {
        Self {
            slot,
            last_error: None,
            warned: None,
        }
    }

    /// Reloads the certificate when the files have changed, and says so when
    /// it is running out of time and nothing has replaced it.
    fn check(&mut self, state: &Shared) {
        // The config lock is released before anything touches the disk: a
        // settings save must not wait on a certificate read.
        let src = {
            let cfg = state.config.read();

            cfg.tls.enabled.then(|| app::tls_source(&cfg))
        };

        if let Some(src) = src.filter(sift_dns::tls::Source::reads_files) {
            self.reload(&src);
        }

        self.warn_if_expiring();
    }

    /// Installs what is on disk, if it is not what is already being served.
    fn reload(&mut self, src: &sift_dns::tls::Source) {
        match sift_dns::tls::refresh(src, &self.slot) {
            Ok(Some(st)) => {
                tracing::info!(
                    names = ?st.dns_names,
                    expires = %st.not_after,
                    "certificate renewed on disk and reloaded"
                );
                self.last_error = None;
                // A new certificate gets its own warning when its own time
                // comes, rather than inheriting the silence of the old one.
                self.warned = None;
            }
            Ok(None) => self.last_error = None,
            Err(e) => {
                // The running certificate is untouched -- nothing is installed
                // until the new pair has been proven -- so this is a warning
                // rather than an error.  A renewal that writes the certificate
                // and the key separately is a mismatched pair in between, and
                // the next check finds it whole.
                let text = e.to_string();
                if self.last_error.as_deref() != Some(text.as_str()) {
                    tracing::warn!(
                        error = %text,
                        "rereading the certificate; keeping the one in use"
                    );
                }
                self.last_error = Some(text);
            }
        }
    }

    /// Reports a certificate that is running out of time, once an hour.
    ///
    /// Nothing here can fix it: renewal is somebody else's job, and by this
    /// point they are not doing it.  Saying so is what gives the operator the
    /// chance to act before their clients refuse to connect.
    fn warn_if_expiring(&mut self) {
        let left = self
            .slot
            .expires_at()
            .map(|at| at - jiff::Timestamp::now().as_second());

        match self.expiry(std::time::Instant::now(), left) {
            Some(Expiry::Gone) => {
                tracing::error!("the certificate has expired; clients will refuse to connect");
            }
            Some(Expiry::Soon(left)) => tracing::warn!(
                hours_left = left / 3600,
                "the certificate expires soon and nothing has renewed it"
            ),
            None => {}
        }
    }

    /// Decides what to say about a certificate with `left` seconds to run,
    /// and records having said it.
    ///
    /// `None` is either time still in hand, nothing installed, or a warning
    /// already given within the hour.
    fn expiry(&mut self, now: std::time::Instant, left: Option<i64>) -> Option<Expiry> {
        let left = left?;
        if left > EXPIRY_WARNING {
            // Back in hand, which is what a renewal looks like from here.
            self.warned = None;

            return None;
        }

        if self.warned.is_some_and(|w| now - w < EXPIRY_WARNING_EVERY) {
            return None;
        }
        self.warned = Some(now);

        Some(if left <= 0 {
            Expiry::Gone
        } else {
            Expiry::Soon(left)
        })
    }
}

/// Keeps the connection guard's idea of this host's own networks current.
///
/// Inside the /64 of each of the host's global IPv6 addresses the guard
/// judges every address on its own rather than the /64 as one source, and
/// those addresses are not fixed: an ISP renumbers the prefix it delegates,
/// sometimes daily, and a household that suddenly reaches the server from a
/// /64 the guard does not know is one shared source again.  Reading
/// the interfaces is one system call, so the maintenance tick does it every
/// minute and hands the guard a new configuration only when something moved.
/// A settings save rereads them as well, through `app::probe_config`.
#[derive(Default)]
struct HostWatch {
    /// What the guard was last given, or `None` before the first tick.
    last: Option<Vec<(std::net::IpAddr, u8)>>,
}

impl HostWatch {
    /// Takes the networks read now, and returns them when the guard should
    /// be given them: on the first tick, and whenever they change.
    fn changed(&mut self, now: Vec<(std::net::IpAddr, u8)>) -> Option<Vec<(std::net::IpAddr, u8)>> {
        if self.last.as_ref() == Some(&now) {
            return None;
        }

        // The first reading is what startup already used, so only a change
        // after it is news.
        if self.last.is_some() {
            let nets: Vec<String> = now.iter().map(|(a, b)| format!("{a}/{b}")).collect();
            tracing::info!(
                networks = ?nets,
                "this host's IPv6 prefixes changed; each address in them is judged on its own"
            );
        }
        self.last = Some(now.clone());

        Some(now)
    }
}

/// Turns protection back on when a timed pause runs out.
///
/// Its own task rather than a line in `maintenance`, because that ticks once a
/// minute and the shortest pause the interface offers is thirty seconds --
/// a pause that ends up to a minute late is a pause that lied.  The check
/// itself is a read lock and a comparison, so a second's tick costs nothing.
///
/// The first tick fires immediately, which is also what catches a pause that
/// elapsed while the process was not running.
async fn protection_watch(state: Shared, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => return,
        }

        state.expire_protection_pause();
    }
}

/// Runs the periodic upkeep the server needs.
async fn maintenance(
    state: Shared,
    stats_path: std::path::PathBuf,
    certificate: Option<Arc<sift_dns::tls::Reloadable>>,
    server: Arc<sift_dns::server::Server>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    // Only when encrypted listeners are actually running: replacing a
    // certificate nothing serves would log a reload that reached nobody.
    let mut certificate = certificate.map(CertWatch::new);
    let mut host = HostWatch::default();

    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Upstream's `periodicRotate` checks once when it starts and then every
    // hour, however short the configured interval is.  The first tick of a
    // fresh `interval` fires at once, so the loop covers the check at start.
    const ROTATION_CHECK: Duration = Duration::from_secs(3600);
    let mut next_rotation_check = tokio::time::Instant::now();

    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => return,
        }

        state.stats.prune();
        state.sessions.sweep();

        // Only when something happened that the file does not hold, which is
        // an hour rotating or a reset rather than every query counted.  The
        // query log is not flushed here at all: it is written when its
        // in-memory buffer fills, which is when a running AdGuard Home writes
        // it, and on the way out.  Both were measured against one.
        if state.stats.claim_save()
            && let Err(e) = sift_stats::store::save(&stats_path, &state.stats.snapshot())
        {
            tracing::warn!(error = %e, "saving statistics");
        }

        if tokio::time::Instant::now() >= next_rotation_check {
            next_rotation_check = tokio::time::Instant::now() + ROTATION_CHECK;

            let ivl = state.config.read().querylog.interval.to_std();
            match state.querylog.rotate_if_due(ivl) {
                Ok(true) => tracing::info!("query log rotated"),
                Ok(false) => {}
                Err(e) => tracing::warn!(error = %e, "rotating the query log"),
            }
        }

        if let Some(w) = certificate.as_mut() {
            w.check(&state);
        }

        if let Some(nets) = host.changed(app::host_networks()) {
            let cfg = app::probe_config_for(&state.config.read(), nets);
            server.set_probe_config(cfg);
        }

        // Refresh any list whose own interval has elapsed, checked every
        // tick.  Firing on a multiple of uptime instead left a fresh install
        // unfiltered until the first interval passed, and never refreshed a
        // server that restarts more often than the interval.
        let hours = state.config.read().filtering.filters_update_interval;
        if hours > 0 {
            let interval = jiff::SignedDuration::from_hours(i64::from(hours));
            let due = state.filters.read().stale_ids(interval);
            if !due.is_empty() {
                refresh_lists(&state, due).await;
            }
        }
    }
}

/// Downloads every enabled list and rebuilds the engine.
async fn refresh_lists(state: &Shared, ids: Vec<i64>) {
    let mut updated = 0;

    for id in ids {
        let Some(url) = state.filters.read().url_of(id) else {
            continue;
        };
        match state.fetcher.fetch(url.clone()).await {
            Ok(text) => {
                let mut filters = state.filters.write();
                // Only a list whose contents actually differ counts: the
                // engine is rebuilt from all of them, and rebuilding it for a
                // download that matched is seconds of work and a copy of every
                // rule in memory for nothing.
                if filters
                    .apply_fetched(&state.paths, id, text)
                    .is_ok_and(sift_filter::lists::Fetched::changed)
                {
                    updated += 1;
                }
            }
            Err(e) => tracing::warn!(list = id, %url, error = %e, "refreshing filter list"),
        }
    }

    if updated > 0 {
        tracing::info!(updated, "filter lists refreshed");
        if let Err(e) = state.save_filters() {
            tracing::warn!(error = %e, "saving filter lists");
        }
    }
}

/// Resolves when the process is asked to stop.
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;

                return;
            }
        };

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use tracing::Level;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::{EnvFilter, Registry};

    /// The default filter, as `init_logging` builds it when RUST_LOG is unset.
    fn default_filter(verbose: bool) -> EnvFilter {
        let default = if verbose { "debug" } else { "info" };

        EnvFilter::new(format!("{default},{}", super::DEP_FILTER))
    }

    /// Reports whether the filter would let an INFO event from `target`
    /// through.
    fn enables(filter: EnvFilter, target: &str, level: Level) -> bool {
        use tracing::subscriber::with_default;

        let subscriber = Registry::default().with(filter);
        with_default(subscriber, || {
            tracing::dispatcher::get_default(|d| {
                let meta = tracing::Metadata::new(
                    "probe",
                    target,
                    level,
                    None,
                    None,
                    None,
                    tracing::field::FieldSet::new(&[], tracing::callsite::Identifier(&PROBE)),
                    tracing::metadata::Kind::EVENT,
                );

                d.enabled(&meta)
            })
        })
    }

    /// A callsite stand-in for the probe metadata.
    struct Probe;
    impl tracing::Callsite for Probe {
        fn set_interest(&self, _: tracing::subscriber::Interest) {}
        fn metadata(&self) -> &tracing::Metadata<'_> {
            unreachable!("the probe metadata is constructed directly")
        }
    }
    static PROBE: Probe = Probe;

    /// A watch over a slot holding nothing, so the expiry decision can be
    /// driven with a remaining life rather than a real certificate.
    fn watch() -> super::CertWatch {
        super::CertWatch::new(std::sync::Arc::new(sift_dns::tls::Reloadable::new()))
    }

    #[test]
    fn a_certificate_with_time_in_hand_is_not_complained_about() {
        let mut w = watch();
        let now = std::time::Instant::now();

        assert_eq!(w.expiry(now, None), None, "nothing is installed");
        assert_eq!(
            w.expiry(now, Some(super::EXPIRY_WARNING + 1)),
            None,
            "a week and a second is still routine"
        );
    }

    #[test]
    fn a_certificate_running_out_is_reported_once_an_hour() {
        // Every minute would bury the log; never would leave the operator to
        // find out from their clients.
        let mut w = watch();
        let start = std::time::Instant::now();
        let left = Some(super::EXPIRY_WARNING - 1);

        assert_eq!(w.expiry(start, left), Some(super::Expiry::Soon(604_799)));
        assert_eq!(
            w.expiry(start + std::time::Duration::from_secs(59 * 60), left),
            None
        );
        assert_eq!(
            w.expiry(start + super::EXPIRY_WARNING_EVERY, left),
            Some(super::Expiry::Soon(604_799)),
            "an hour on, it is worth saying again"
        );
    }

    #[test]
    fn the_guard_is_given_the_hosts_networks_first_and_then_only_when_they_move() {
        let net = |s: &str| -> Vec<(std::net::IpAddr, u8)> { vec![(s.parse().unwrap(), 64)] };
        let mut w = super::HostWatch::default();

        assert_eq!(
            w.changed(net("2001:db8:1:2::")),
            Some(net("2001:db8:1:2::"))
        );
        assert_eq!(w.changed(net("2001:db8:1:2::")), None, "nothing moved");

        // The ISP renumbers the delegated prefix.
        assert_eq!(
            w.changed(net("2001:db8:9:2::")),
            Some(net("2001:db8:9:2::"))
        );
        assert_eq!(w.changed(Vec::new()), Some(Vec::new()), "or takes it away");
    }

    #[test]
    fn an_expired_certificate_is_reported_as_expired() {
        let mut w = watch();

        assert_eq!(
            w.expiry(std::time::Instant::now(), Some(0)),
            Some(super::Expiry::Gone),
            "the moment it lapses"
        );
    }

    #[test]
    fn a_renewal_earns_its_own_warning() {
        // Otherwise the hour of silence after the last warning would carry
        // over, and a certificate replaced by one that is itself about to
        // expire would say nothing.
        let mut w = watch();
        let start = std::time::Instant::now();

        assert!(w.expiry(start, Some(60)).is_some());
        assert_eq!(w.expiry(start, Some(60)), None, "still within the hour");

        // A certificate with a year on it clears the slate.
        assert_eq!(w.expiry(start, Some(365 * 24 * 3600)), None);
        assert_eq!(
            w.expiry(start, Some(60)),
            Some(super::Expiry::Soon(60)),
            "the next one to run short is reported at once"
        );
    }

    #[test]
    fn the_default_filter_does_not_silence_the_binarys_own_logs() {
        // The binary target is named AdGuardHome, so `module_path!` reports
        // that -- not the package name.  A filter spelled `sift=info`
        // compiles and matches nothing, which is how every startup message
        // once went missing.
        assert!(
            enables(default_filter(false), "AdGuardHome", Level::INFO),
            "the server's own INFO messages must reach the log"
        );
        assert!(enables(default_filter(false), "sift_dns", Level::INFO));
        assert!(enables(default_filter(false), "sift_api", Level::INFO));
    }

    #[test]
    fn verbose_enables_debug() {
        assert!(enables(default_filter(true), "AdGuardHome", Level::DEBUG));
        assert!(!enables(default_filter(false), "AdGuardHome", Level::DEBUG));
    }

    /// A client that dials an encrypted listener by address puts an IP in the
    /// SNI extension, and rustls warns about it once per connection.  One such
    /// client reconnecting twice a second was enough to bury everything else.
    #[test]
    fn a_peers_malformed_handshake_does_not_flood_the_log() {
        for verbose in [false, true] {
            assert!(
                !enables(
                    default_filter(verbose),
                    "rustls::msgs::handshake",
                    Level::WARN
                ),
                "message-parsing warnings are the peer's doing, not the operator's"
            );
            assert!(
                enables(default_filter(verbose), "rustls", Level::WARN),
                "a warning about this server's own TLS must still be seen"
            );
        }
    }

    #[test]
    fn chatty_dependencies_stay_quiet() {
        for dep in ["hyper", "rustls", "h2", "hickory_proto"] {
            assert!(
                !enables(default_filter(false), dep, Level::INFO),
                "{dep} should be filtered to warnings"
            );
        }
    }
}
