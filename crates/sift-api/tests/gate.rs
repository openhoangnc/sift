//! End-to-end checks of the authentication gate and the first-run routing,
//! through the real router.
//!
//! These drive the whole `Router`, not `control_router()` on its own, because
//! the bug they exist for lived in the seam: `Router::nest` strips `/control`
//! before any middleware layered on the inner router sees the path, so an
//! allowlist spelled in full paths matched nothing and `POST /control/login`
//! answered 401 to correct credentials. Nothing short of the assembled router
//! reproduces that.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sift_api::state::{AppState, NoFetcher, NoReloader, Shared};

/// Builds a server state, with a user configured or not.
fn state(user: Option<(&str, &str)>) -> Shared {
    let mut config = sift_config::Config::default();
    config.dns.upstream_dns = vec![];
    config.dns.bootstrap_dns = vec![];
    config.filters = vec![];
    config.users = user
        .map(|(name, password)| sift_config::model::WebUser {
            name: name.to_string(),
            password: sift_api::auth::hash_password(password).expect("hashing"),
        })
        .into_iter()
        .collect();

    let resolver = Arc::new(sift_dns::resolver::Resolver::new(
        sift_filter::engine::Engine::build(
            sift_filter::engine::NO_LISTS,
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

    let base = std::env::temp_dir().join(format!(
        "sift-gate-{}-{:p}",
        std::process::id(),
        &config as *const _
    ));
    let paths = sift_config::Paths::new(base.join("work"), base.join("conf/AdGuardHome.yaml"));
    paths.ensure().expect("preparing the working directory");

    // Built before the config moves into the state, and from the same
    // config, so the tests run against the bounds a real install uses.
    let login_limiter = sift_api::auth::LoginLimiter::from_config(&config);

    Arc::new(AppState {
        paths: paths.clone(),
        config: parking_lot::RwLock::new(config),
        resolver,
        dns_server,
        filters: parking_lot::RwLock::new(sift_filter::lists::Manager::default()),
        querylog: Arc::new(sift_querylog::log::QueryLog::new(
            paths.query_log(""),
            paths.query_log_rotated(""),
            sift_querylog::log::Config {
                file_enabled: false,
                ..Default::default()
            },
        )),
        stats: Arc::new(sift_stats::stats::Stats::new(
            sift_stats::stats::Config::default(),
        )),
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

/// Starts the assembled router on an ephemeral port.
async fn serve(user: Option<(&str, &str)>) -> SocketAddr {
    let app = sift_api::routes::router(state(user), false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    addr
}

/// One request; returns the status, the `location` header and the body.
async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    cookie: Option<&str>,
) -> (u16, Option<String>, String) {
    let extra: Vec<(&str, &str)> = cookie.map(|c| ("cookie", c)).into_iter().collect();
    let (status, headers, body) = send(addr, method, path, body, &extra).await;

    let location = header(&headers, "location");
    // The session cookie is what the caller needs back from a login.
    let out = header(&headers, "set-cookie").unwrap_or(body);

    (status, location, out)
}

/// A response header as a string, if it is present and printable.
fn header(headers: &hyper::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string)
}

/// One request, returning the whole response head as well as the body.
async fn send(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    extra: &[(&str, &str)],
) -> (u16, hyper::HeaderMap, String) {
    use http_body_util::{BodyExt, Full};

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    let task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", addr.to_string());
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }

    let req = builder
        .body(Full::new(hyper::body::Bytes::from(
            body.unwrap_or("").to_string(),
        )))
        .unwrap();

    let res = sender.send_request(req).await.unwrap();
    let status = res.status().as_u16();
    let headers = res.headers().clone();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    task.abort();

    (status, headers, String::from_utf8_lossy(&bytes).to_string())
}

#[tokio::test]
async fn login_is_reachable_without_a_session() {
    // The regression: correct credentials answered 401 because the allowlist
    // was compared against `/control/login` while the middleware, sitting
    // inside the nest, was handed `/login`. Nobody could sign in at all.
    let addr = serve(Some(("admin", "correct horse"))).await;

    let (status, _, cookie) = request(
        addr,
        "POST",
        "/control/login",
        Some(r#"{"name":"admin","password":"correct horse"}"#),
        None,
    )
    .await;
    assert_eq!(status, 200, "login must not require a session");
    assert!(
        cookie.contains("agh_session"),
        "no session cookie: {cookie}"
    );

    // And the session it hands out actually opens the rest of the API.
    let jar = cookie.split(';').next().unwrap().to_string();
    let (status, _, _) = request(addr, "GET", "/control/status", None, Some(&jar)).await;
    assert_eq!(status, 200, "the session from login must be accepted");
}

#[tokio::test]
async fn a_stale_cookie_does_not_shadow_a_fresh_session() {
    // The regression: a browser holding a second `agh_session` on a narrower
    // path sends it first on every API call. Only the first was read, so
    // signing in again answered 401 to everything, the interface bounced
    // between `/` and the login form, and only clearing the site's data
    // got the user back in.
    let addr = serve(Some(("admin", "correct horse"))).await;

    let (_, _, cookie) = request(
        addr,
        "POST",
        "/control/login",
        Some(r#"{"name":"admin","password":"correct horse"}"#),
        None,
    )
    .await;
    let fresh = cookie.split(';').next().unwrap();
    let jar = format!("agh_session=00000000000000000000000000000000; {fresh}");

    let (status, _, _) = request(addr, "GET", "/control/status", None, Some(&jar)).await;
    assert_eq!(
        status, 200,
        "the live session must be found behind a stale one"
    );

    // Logging out expires the narrower paths too, not only `/`.
    let (_, headers, _) = send(addr, "GET", "/control/logout", None, &[("cookie", &jar)]).await;
    let cleared: Vec<_> = headers
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    assert!(
        cleared.iter().any(|c| c.contains("Path=/control;")),
        "{cleared:?}"
    );

    let (status, _, _) = request(addr, "GET", "/control/status", None, Some(&jar)).await;
    assert_eq!(status, 401, "logout ends the session");
}

#[tokio::test]
async fn a_wrong_password_is_still_refused() {
    let addr = serve(Some(("admin", "correct horse"))).await;

    let (status, _, _) = request(
        addr,
        "POST",
        "/control/login",
        Some(r#"{"name":"admin","password":"wrong"}"#),
        None,
    )
    .await;
    // Upstream's `handleLogin` hands `newCookie`'s error to
    // `writeErrorWithIP` with `StatusForbidden`, not 401.
    assert_eq!(status, 403);

    let (status, _, _) = request(addr, "GET", "/control/status", None, None).await;
    assert_eq!(status, 401, "the API stays shut without a session");
}

#[tokio::test]
async fn repeated_failures_are_throttled() {
    // Nothing throttled this, so the admin password could be guessed at line
    // rate. The bounds are the config's, which default to upstream's five
    // attempts and a fifteen-minute block.
    let addr = serve(Some(("admin", "correct horse"))).await;
    let wrong = r#"{"name":"admin","password":"wrong"}"#;

    // Five attempts are answered; it is spending the fifth that starts the
    // block, so the sixth is the first one turned away unexamined.
    for n in 1..=5 {
        let (status, _, _) = request(addr, "POST", "/control/login", Some(wrong), None).await;
        assert_eq!(status, 403, "attempt {n} should be refused, not blocked");
    }

    let (status, headers, _) = send(addr, "POST", "/control/login", Some(wrong), &[]).await;
    assert_eq!(status, 429, "the sixth attempt must be turned away");

    let left: u64 = header(&headers, "retry-after")
        .expect("a 429 must say how long to wait")
        .parse()
        .expect("retry-after is whole seconds");
    assert!(
        left > 0 && left <= 15 * 60,
        "retry-after should be what is left of the block, not {left}s"
    );

    // The block is on the login form and on the Basic credentials every other
    // endpoint accepts -- otherwise an attacker just guesses somewhere else.
    let basic = ("authorization", "Basic YWRtaW46Y29ycmVjdCBob3JzZQ==");
    let (status, _, _) = send(addr, "GET", "/control/status", None, &[basic]).await;
    assert_eq!(status, 429, "correct credentials do not lift a live block");

    // A request that presents no credentials is not an attempt, so it is not
    // throttled -- a signed-out browser must still reach the login page.
    let (status, _, _) = request(addr, "GET", "/control/status", None, None).await;
    assert_eq!(status, 401);
    let (status, _, _) = request(addr, "GET", "/login.html", None, None).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn guessing_basic_credentials_is_throttled_too() {
    // The gate accepts Basic credentials on every endpoint, so leaving that
    // path unthrottled would leave the whole throttle decorative.
    let addr = serve(Some(("admin", "correct horse"))).await;
    let wrong = ("authorization", "Basic YWRtaW46d3Jvbmc="); // admin:wrong

    for n in 1..=5 {
        let (status, _, _) = send(addr, "GET", "/control/status", None, &[wrong]).await;
        assert_eq!(status, 401, "attempt {n} should be refused, not blocked");
    }

    let (status, headers, _) = send(addr, "GET", "/control/status", None, &[wrong]).await;
    assert_eq!(status, 429);
    assert!(header(&headers, "retry-after").is_some());

    // And the login form is shut to that client as well.
    let (status, _, _) = request(
        addr,
        "POST",
        "/control/login",
        Some(r#"{"name":"admin","password":"correct horse"}"#),
        None,
    )
    .await;
    assert_eq!(status, 429);
}

#[tokio::test]
async fn a_successful_sign_in_clears_the_failures() {
    let addr = serve(Some(("admin", "correct horse"))).await;
    let wrong = r#"{"name":"admin","password":"wrong"}"#;

    for _ in 0..4 {
        request(addr, "POST", "/control/login", Some(wrong), None).await;
    }

    let (status, _, cookie) = request(
        addr,
        "POST",
        "/control/login",
        Some(r#"{"name":"admin","password":"correct horse"}"#),
        None,
    )
    .await;
    assert_eq!(status, 200, "four failures must not shut the fifth try out");
    assert!(cookie.contains("agh_session"));

    // The count is back to zero. Were it not cleared, the second slip after
    // this would be the sixth overall and would answer 429.
    for n in 1..=2 {
        let (status, _, _) = request(addr, "POST", "/control/login", Some(wrong), None).await;
        assert_eq!(status, 403, "slip {n} after signing in must not be blocked");
    }
}

#[tokio::test]
async fn the_wizard_is_gone_once_a_user_exists() {
    // Upstream registers the install handlers only on the first launch. Left
    // open, they would let anyone re-run the wizard over a live config.
    let addr = serve(Some(("admin", "correct horse"))).await;

    for path in [
        "/control/install/get_addresses",
        "/control/install/check_config",
        "/control/install/configure",
    ] {
        let (status, _, _) = request(addr, "POST", path, Some("{}"), None).await;
        assert_eq!(status, 404, "{path} must not exist once configured");
    }

    let (status, _, _) = request(addr, "GET", "/install.html", None, None).await;
    assert_eq!(
        status, 403,
        "the wizard page must be refused once configured"
    );
}

#[tokio::test]
async fn the_first_launch_redirects_everything_to_the_wizard() {
    // Without this a fresh install opens on a dashboard for a server that has
    // no user and no settings.
    let addr = serve(None).await;

    for path in ["/", "/index.html", "/login.html"] {
        let (status, location, _) = request(addr, "GET", path, None, None).await;
        assert_eq!(status, 302, "{path} must redirect on the first launch");
        assert_eq!(location.as_deref(), Some("install.html"), "{path}");
    }

    // The wizard itself, and the assets it needs, are served.
    let (status, _, _) = request(addr, "GET", "/install.html", None, None).await;
    assert_eq!(status, 200);

    // And its endpoints are open, because there is nobody to authenticate as.
    let (status, _, _) = request(addr, "GET", "/control/install/get_addresses", None, None).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn the_gate_never_asks_the_browser_for_basic_credentials() {
    // `WWW-Authenticate: Basic` on this 401 hands the exchange to the
    // browser: it answers the interface's own background request with its
    // native sign-in dialog, which becomes the only prompt the user ever
    // sees, and `/login.html` never renders. Upstream writes a bare 401 for
    // that reason.
    let addr = serve(Some(("admin", "correct horse"))).await;

    let (status, headers, _) = send(addr, "GET", "/control/status", None, &[]).await;
    assert_eq!(status, 401);
    assert_eq!(
        header(&headers, "www-authenticate"),
        None,
        "the API must not summon the browser's own sign-in dialog"
    );

    // Not soliciting Basic credentials is not the same as refusing them:
    // the scripted API users send them on every request.
    let basic = ("authorization", "Basic YWRtaW46Y29ycmVjdCBob3JzZQ==");
    let (status, _, _) = send(addr, "GET", "/control/status", None, &[basic]).await;
    assert_eq!(status, 200, "basic credentials must still be accepted");
}

#[tokio::test]
async fn a_signed_out_browser_is_sent_to_the_login_form() {
    // The interface redirects itself to `/login.html` only when an API call
    // answers 403, and the gate answers 401, so without this redirect a
    // signed-out visit to `/` renders a dashboard that can never load.
    let addr = serve(Some(("admin", "correct horse"))).await;

    for path in ["/", "/index.html"] {
        let (status, location, _) = request(addr, "GET", path, None, None).await;
        assert_eq!(status, 302, "{path} must redirect when signed out");
        assert_eq!(location.as_deref(), Some("login.html"), "{path}");
    }

    // The form and what it is built from are served without a session.
    for path in ["/login.html", "/assets/favicon.png"] {
        let (status, _, _) = request(addr, "GET", path, None, None).await;
        assert_eq!(status, 200, "{path} must be reachable when signed out");
    }

    // Anything else is not.
    let (status, _, _) = request(addr, "GET", "/dashboard.html", None, None).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn a_signed_in_browser_gets_the_dashboard_rather_than_the_form() {
    let addr = serve(Some(("admin", "correct horse"))).await;

    let (_, _, cookie) = request(
        addr,
        "POST",
        "/control/login",
        Some(r#"{"name":"admin","password":"correct horse"}"#),
        None,
    )
    .await;
    let jar = cookie.split(';').next().unwrap().to_string();

    let (status, _, _) = request(addr, "GET", "/", None, Some(&jar)).await;
    assert_eq!(status, 200, "a session must open the interface");

    // Upstream bounces a signed-in visitor off the login form.
    let (status, location, _) = request(addr, "GET", "/login.html", None, Some(&jar)).await;
    assert_eq!(status, 302);
    assert_eq!(location.as_deref(), Some("/"));
}
