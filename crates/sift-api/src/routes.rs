//! The control API's routing table and its authentication gate.

use axum::extract::{DefaultBodyLimit, Query, Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::auth::{self, Verdict};
use crate::doh;
use crate::error::{ApiError, ApiResult};
use crate::handlers::{filtering, logs, memory, misc, status};
use crate::state::Shared;

/// The most a request body may carry: upstream's `defaultReqBodySzLim`.
///
/// Every route, DNS-over-HTTPS included, and `/control/login` -- which anyone
/// can reach -- among them.  The limit is enforced while the body is read, so
/// a request that says it is sending more, or says nothing and keeps sending,
/// is cut off at this many bytes rather than buffered first and measured
/// after.  axum's own default was 2 MB.
pub const DEFAULT_BODY_LIMIT: usize = 64 * 1024;

/// The most a body may carry on the routes that take a whole list at once:
/// upstream's `largerReqBodySzLim`.
///
/// Upstream calls these "poorly designed current APIs" and exempts exactly two
/// of them; see [`body_limit`].  A user's own rules can run to megabytes, and
/// under axum's 2 MB default this refused a `set_rules` the Go build takes.
pub const LARGER_BODY_LIMIT: usize = 4 * 1024 * 1024;

/// The most a request's body may carry: upstream's `expectsLargerRequests`.
///
/// Public so a listener that reads a body before handing it to the router --
/// the HTTP/3 one does -- applies the same rule as the router rather than a
/// number of its own.
pub fn body_limit(method: &Method, path: &str) -> usize {
    let larger = method == Method::POST
        && matches!(path, "/control/access/set" | "/control/filtering/set_rules");

    if larger {
        LARGER_BODY_LIMIT
    } else {
        DEFAULT_BODY_LIMIT
    }
}

/// Bounds every request body by [`body_limit`]: upstream's `limitRequestBody`.
///
/// One middleware over the whole router, choosing by method and full path as
/// upstream's does, rather than a layer per route, so the two exemptions are
/// written in one place and the HTTP/3 listener can ask the same function.
/// It sits outside the `/control` nest, where the path still carries its
/// prefix.  The extractors -- `Json`, `Bytes`, `String` -- honour the limit it
/// sets and answer 413 when a body runs past it.
async fn limit_request_body(req: Request, next: Next) -> Response {
    use tower::{Layer as _, ServiceExt as _};

    let limit = body_limit(req.method(), req.uri().path());

    match DefaultBodyLimit::max(limit).layer(next).oneshot(req).await {
        Ok(r) => r,
        Err(never) => match never {},
    }
}

/// Paths reachable without a session, always.
///
/// These are matched against the path *inside* the `/control` router.
/// `Router::nest` strips the prefix before any middleware layered on the
/// inner router sees it, so a full path spelled `/control/login` here matches
/// nothing and silently locks the web interface out — which is exactly what
/// it did.  `login_is_reachable_without_a_session` drives the whole router so
/// the stripping is part of the test.
const PUBLIC: &[&str] = &["/login"];

/// Paths that serve the setup wizard, reachable only until it has run.
///
/// Upstream registers these handlers only on the first launch, so once a user
/// exists they are gone.  Leaving them reachable would let anyone re-run the
/// wizard over a configured server.
const INSTALL: &[&str] = &[
    "/install/get_addresses",
    "/install/check_config",
    "/install/configure",
];

/// Builds the full application router.
///
/// `secure` says whether this router is serving an encrypted listener; it
/// decides whether DNS-over-HTTPS answers, since serving DNS over plain HTTP
/// exposes queries to the network.
pub fn router(state: Shared, secure: bool) -> Router {
    let control = control_router()
        .layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .with_state(state.clone());

    // DNS-over-HTTPS shares the router with the web interface, because
    // upstream serves both on the HTTPS port.  The routes are the defaults in
    // `http.doh.routes`; a ClientID may be appended as a path segment.
    let dns = Router::new()
        .route("/dns-query", get(doh::get).post(doh::post))
        .route(
            "/dns-query/{client_id}",
            get(doh::get_with_client).post(doh::post_with_client),
        );

    let mut app = Router::new()
        .nest("/control", control)
        .merge(dns.with_state(state.clone()))
        .fallback(get(serve_ui));

    // On the plain listener, `force_https` sends browsers to the encrypted
    // one.  The redirect is added only there: applying it to the HTTPS router
    // would send every request back to itself.
    if !secure {
        app = app.layer(middleware::from_fn_with_state(
            state.clone(),
            redirect_to_https,
        ));
    }

    app.layer(middleware::from_fn(limit_request_body))
        .layer(axum::Extension(doh::Secure(secure)))
        .with_state(state)
}

/// Redirects a plain-HTTP request to the HTTPS port when `force_https` is set.
///
/// DNS-over-HTTPS is left alone: a DoH client does not follow redirects, and
/// whether it may use the plain port is already decided by
/// `http.doh.insecure_enabled`.
async fn redirect_to_https(State(s): State<Shared>, req: Request, next: Next) -> Response {
    let (enabled, port) = {
        let cfg = s.config.read();

        (
            cfg.tls.enabled && cfg.tls.force_https && cfg.tls.port_https != 0,
            cfg.tls.port_https,
        )
    };

    let path = req.uri().path();
    if !enabled || path.starts_with("/dns-query") {
        return next.run(req).await;
    }

    let Some(host) = host_without_port(req.headers()) else {
        return next.run(req).await;
    };

    let target = if port == 443 {
        format!("https://{host}{}", path_and_query(&req))
    } else {
        format!("https://{host}:{port}{}", path_and_query(&req))
    };

    match target.parse::<header::HeaderValue>() {
        Ok(v) => (StatusCode::FOUND, [(header::LOCATION, v)]).into_response(),
        Err(_) => next.run(req).await,
    }
}

/// The `Host` header without its port, which the redirect target rebuilds.
fn host_without_port(headers: &HeaderMap) -> Option<String> {
    let host = headers.get(header::HOST)?.to_str().ok()?.trim();
    if host.is_empty() {
        return None;
    }

    // An IPv6 literal is bracketed, so the last colon is only a port
    // separator when it comes after the closing bracket.
    if let Some(end) = host.rfind(']') {
        return Some(host[..=end].to_string());
    }

    Some(match host.rsplit_once(':') {
        Some((h, _)) => h.to_string(),
        None => host.to_string(),
    })
}

/// The path and query of a request, as the redirect target needs them.
fn path_and_query(req: &Request) -> String {
    req.uri()
        .path_and_query()
        .map(ToString::to_string)
        .unwrap_or_else(|| "/".to_string())
}

/// Serves the embedded web interface.
///
/// Before the wizard has run, everything but the wizard's own assets is
/// redirected to it, and afterwards the wizard is gone.  Both halves are
/// upstream's `postInstallHandler`/`preInstallHandler`: without the redirect
/// a new install opens on a dashboard for a server that has no user, and
/// without the 403 the wizard stays reachable over a configured one.
///
/// Once a user exists the pages sit behind the same gate as the API, because
/// upstream's authentication middleware wraps its whole mux rather than only
/// `/control`.  The redirect from `/` is the *only* way a signed-out browser
/// reaches the login form: the shipped interface sends itself to
/// `/login.html` when an API call answers **403**, and the gate answers 401,
/// so a dashboard handed to a signed-out visitor is a dashboard that can
/// never load.
async fn serve_ui(State(s): State<Shared>, headers: HeaderMap, req: Request) -> Response {
    let path = req.uri().path();

    if s.needs_install() {
        if !is_install_page(path) && !path.starts_with("/assets/") {
            return (StatusCode::FOUND, [(header::LOCATION, "install.html")], "").into_response();
        }

        return crate::ui::serve(path, &headers);
    }

    if is_install_page(path) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    let user = match authenticate(&s, &headers, peer_ip(&req)).await {
        Ok(u) => u,
        Err(refusal) => return refusal.into_response(),
    };

    if user.is_some() {
        // Someone who is already signed in has no use for the login form.
        if path == "/login.html" || path == "/forgot_password.html" {
            return (StatusCode::FOUND, [(header::LOCATION, "/")], "").into_response();
        }
    } else if !is_public_page(path) {
        if path == "/" || path == "/index.html" {
            return (StatusCode::FOUND, [(header::LOCATION, "login.html")], "").into_response();
        }

        return (StatusCode::UNAUTHORIZED, "").into_response();
    }

    crate::ui::serve(path, &headers)
}

/// The part of a request path that names an asset.
///
/// The build puts its hashed bundles under `/static/`, so `/login.html` and
/// `/static/login.4b8e.js` are both the login page's — one the document, one
/// what it is built from.  Both gates below reason about the name, so both
/// strip the directory first; matching `/login.` against the raw path missed
/// the script the moment the build started writing it somewhere else, and
/// locked the login form out of its own JavaScript.
fn asset_name(path: &str) -> &str {
    path.strip_prefix("/static/")
        .unwrap_or_else(|| path.trim_start_matches('/'))
}

/// Reports whether a page is served without a session.
///
/// Upstream's `isPublicResource`, minus the API paths it also lists: the
/// login and password-reset pages, the hashed script and stylesheet built
/// beside them, and the icons under `/assets/`.  The dashboard's own
/// `main.<hash>.js` is deliberately not here.
fn is_public_page(path: &str) -> bool {
    let name = asset_name(path);

    path.starts_with("/assets/")
        || name.starts_with("login.")
        || name.starts_with("forgot_password.")
}

/// Reports whether a path belongs to the setup wizard.
///
/// The wizard's document and the bundle it loads, so the first launch can
/// serve them and a configured server can refuse them.
fn is_install_page(path: &str) -> bool {
    asset_name(path).starts_with("install.")
}

/// Why the gate turned a request away without looking at what it asked.
enum Refusal {
    /// The client has spent its attempts, and must wait this long.
    Spent(std::time::Duration),
    /// Every verifier stayed busy for as long as a check waits for one, or
    /// the client is new and the throttle has no room to count it.
    Busy,
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        match self {
            Self::Spent(left) => auth::too_many_attempts(left),
            Self::Busy => auth::verifiers_busy(),
        }
    }
}

/// Identifies the caller, throttling Basic-credential guessing as it goes.
///
/// `Err` is the refusal to send instead of serving the request: a client that
/// has spent its attempts, or a check that could not get a verifier.
///
/// Upstream throttles its Basic path and not its cookie path, and so does
/// this: a session token is sixteen random bytes, so guessing one is not a
/// threat worth slowing down, while guessing a password is.  A request with
/// no `Authorization` header at all therefore costs a client nothing, which
/// is how a signed-out browser can keep asking for `/` without locking the
/// address out.
///
/// A password is checked the way `/control/login` checks one -- see
/// [`auth::LoginLimiter::check`] -- because every endpoint that accepts Basic
/// credentials is a place to guess one.  `client` is [`peer_ip`]'s answer;
/// the request itself is not borrowed across the check, since a body is not
/// `Sync` and a future holding one by reference could not move between
/// threads.
async fn authenticate(
    s: &Shared,
    headers: &HeaderMap,
    client: String,
) -> Result<Option<String>, Refusal> {
    let Some(authorization) = headers.get(header::AUTHORIZATION) else {
        return Ok(misc::session_user(s, headers));
    };

    let key = throttle_key(s, &client);
    let left = s.login_limiter.blocked_for(&key);
    if !left.is_zero() {
        return Err(Refusal::Spent(left));
    }

    if let Some(user) = misc::session_user(s, headers) {
        s.login_limiter.record_success(&key);

        return Ok(Some(user));
    }

    let Some((name, password)) = authorization
        .to_str()
        .ok()
        .and_then(auth::basic_credentials)
    else {
        // Something that is not a name and a password is still an attempt,
        // as it always was here -- and counted the way every other one is,
        // so a newcomer the throttle has no room for is refused rather than
        // answered uncounted.
        return match s.login_limiter.begin(&key, lane(s, &client)) {
            Ok(()) => Ok(None),
            Err(Verdict::Blocked(left)) => Err(Refusal::Spent(left)),
            Err(_) => Err(Refusal::Busy),
        };
    };

    let verdict = s
        .login_limiter
        .check(
            &key,
            lane(s, &client),
            password,
            misc::stored_hash(s, &name),
        )
        .await;
    match verdict {
        Verdict::Accepted => Ok(Some(name)),
        Verdict::Rejected => Ok(None),
        Verdict::Blocked(left) => Err(Refusal::Spent(left)),
        Verdict::Busy => Err(Refusal::Busy),
    }
}

/// Which queue a password check from `client` waits in, as
/// [`auth::Lane`] explains.
///
/// A source the connection guard spares is spared the queue too -- the one
/// notion of "local" the whole server uses, so a device the guard would
/// never refuse is never told the verifiers are busy.  `client` is
/// [`peer_ip`]'s answer; anything that is not an address waits its turn.
pub(crate) fn lane(s: &Shared, client: &str) -> auth::Lane {
    match client.parse::<std::net::IpAddr>() {
        Ok(ip) if s.dns_server.probes.exempts(ip) => auth::Lane::Local,
        _ => auth::Lane::Shared,
    }
}

/// The source the throttle counts `client`'s attempts against.
///
/// The connection guard's own key, so the two defences agree on what one
/// source is: an IPv4 address, an IPv6 /64 -- and one address at a time in
/// this host's own /64, where a household reaching the server over global
/// IPv6 would otherwise share one budget, and one device's wrong passwords
/// lock out every other.  `client` is [`peer_ip`]'s answer; anything that is
/// not an address is kept as it is.
pub(crate) fn throttle_key(s: &Shared, client: &str) -> String {
    match client.parse::<std::net::IpAddr>() {
        Ok(ip) => s.dns_server.probes.source(ip).to_string(),
        Err(_) => client.to_string(),
    }
}

/// The address a request arrived from, which the throttle keys on.
///
/// The connection's own peer, never a forwarded-for header: upstream refuses
/// to read one here because anyone able to set it could otherwise spend
/// someone else's attempts, or dodge their own block by changing it.
/// See <https://github.com/AdguardTeam/AdGuardHome/issues/2799>.
///
/// The port is dropped, or every fresh connection would be a fresh client and
/// the throttle would hold nobody back.  The throttle widens an IPv6 address
/// to its /64 itself, for the same reason.
pub fn peer_ip(req: &Request) -> String {
    req.extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip().to_string())
        .unwrap_or_default()
}

/// Rejects requests that carry no valid session, once a user exists.
///
/// `path` is the path within the `/control` router: see [`PUBLIC`].
async fn require_auth(State(s): State<Shared>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let first_run = s.needs_install();

    // The wizard's own endpoints stop existing once it has run, as upstream's
    // do, rather than staying open for a second pass over a live config.
    if !first_run && INSTALL.contains(&path.as_str()) {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }

    // Before the wizard has run there is nobody to authenticate as.
    let open = first_run || PUBLIC.contains(&path.as_str());
    if open {
        return next.run(req).await;
    }

    let client = peer_ip(&req);
    match authenticate(&s, req.headers(), client).await {
        Ok(Some(user)) => {
            req.extensions_mut().insert(auth::SignedIn(user));

            return next.run(req).await;
        }
        Ok(None) => {}
        Err(refusal) => return refusal.into_response(),
    }

    // A bare 401, as upstream writes.  Adding `WWW-Authenticate: Basic` here
    // -- which this did -- hands the exchange to the browser, which answers
    // the web interface's own background request with its native sign-in
    // dialog and never lets `/login.html` render.  Basic credentials are
    // still *accepted*; they are simply not solicited.
    (StatusCode::UNAUTHORIZED, "forbidden").into_response()
}

/// The `/control` sub-router.
fn control_router() -> Router<Shared> {
    Router::new()
        // Status and DNS settings.
        .route("/status", get(status::status))
        .route("/dns_info", get(status::dns_info))
        .route("/dns_config", post(status::set_dns_config))
        .route("/protection", post(status::set_protection))
        .route("/cache_clear", post(status::cache_clear))
        .route("/test_upstream_dns", post(status::test_upstream))
        .route("/version.json", get(status::version).post(status::version))
        .route("/update", post(status::update))
        // Filtering.
        .route("/filtering/status", get(filtering::status))
        .route("/filtering/config", post(filtering::set_config))
        .route("/filtering/add_url", post(filtering::add_url))
        .route("/filtering/remove_url", post(filtering::remove_url))
        .route("/filtering/set_url", post(filtering::set_url))
        .route("/filtering/refresh", post(filtering::refresh))
        .route("/filtering/set_rules", post(filtering::set_rules))
        .route("/filtering/check_host", get(filtering::check_host))
        .route("/filtering/catalogue", get(filtering::catalogue))
        // Ours too: what the process is holding, and where.  Nothing in the
        // web interface asks for it -- it is for watching a container whose
        // memory climbs, which is how the last two leaks here were found.
        .route("/debug/memory", get(memory::memory))
        // Safe browsing and parental control.  Not implemented: status reports
        // both as off and every change is refused.  See the safe browsing and
        // parental control section of TASK.md.
        .route("/safebrowsing/status", get(filtering::hashprefix_status))
        .route("/safebrowsing/enable", post(hashprefix_unsupported))
        .route("/safebrowsing/disable", post(hashprefix_unsupported))
        .route("/parental/status", get(filtering::hashprefix_status))
        .route("/parental/enable", post(hashprefix_unsupported))
        .route("/parental/disable", post(hashprefix_unsupported))
        // Safe search.
        .route(
            "/safesearch/enable",
            post(|State(s): State<Shared>| filtering::safesearch_set(s, true)),
        )
        .route(
            "/safesearch/disable",
            post(|State(s): State<Shared>| filtering::safesearch_set(s, false)),
        )
        // Upstream answers GET here with 405; only PUT is defined.
        .route("/safesearch/settings", put(filtering::safesearch_settings))
        .route("/safesearch/status", get(filtering::safesearch_status))
        // Rewrites.
        .route("/rewrite/list", get(filtering::rewrite_list))
        .route("/rewrite/add", post(filtering::rewrite_add))
        .route("/rewrite/delete", post(filtering::rewrite_delete))
        .route("/rewrite/update", put(filtering::rewrite_update))
        .route("/rewrite/settings", get(filtering::rewrite_settings))
        .route(
            "/rewrite/settings/update",
            put(filtering::rewrite_settings_update),
        )
        // Query log.
        .route("/querylog", get(logs::querylog))
        .route("/querylog_info", get(logs::querylog_info))
        .route("/querylog_config", post(logs::querylog_config_legacy))
        .route("/querylog_clear", post(logs::querylog_clear))
        .route("/querylog/config", get(logs::querylog_config))
        .route("/querylog/config/update", put(logs::querylog_config_update))
        // Statistics.
        .route("/stats", get(logs::stats))
        .route("/stats_reset", post(logs::stats_reset))
        .route("/stats_info", get(logs::stats_info))
        .route("/stats_config", post(logs::stats_config_legacy))
        .route("/stats/config", get(logs::stats_config))
        .route("/stats/config/update", put(logs::stats_config_update))
        // Clients and access control.
        .route("/clients", get(misc::clients))
        .route("/clients/add", post(misc::clients_add))
        .route("/clients/delete", post(misc::clients_delete))
        .route("/clients/update", post(misc::clients_update))
        .route("/clients/find", get(misc::clients_find))
        .route(
            "/clients/search",
            get(misc::clients_find).post(misc::clients_search),
        )
        .route("/access/list", get(misc::access_list))
        .route("/access/set", post(misc::access_set))
        // Blocked services.
        .route("/blocked_services/services", get(misc::services_ids))
        .route("/blocked_services/all", get(misc::services_all))
        .route("/blocked_services/list", get(misc::services_list))
        .route("/blocked_services/set", post(misc::services_set))
        .route("/blocked_services/get", get(misc::services_get))
        .route("/blocked_services/update", put(misc::services_update))
        // Encryption.
        .route("/tls/status", get(misc::tls_status))
        .route("/tls/configure", post(misc::tls_configure))
        .route("/tls/validate", post(misc::tls_validate))
        // DHCP.  Not implemented: status reports the feature as off and every
        // change is refused.  See the DHCP section of TASK.md.
        .route("/dhcp/status", get(misc::dhcp_status))
        .route("/dhcp/interfaces", get(misc::dhcp_interfaces))
        .route("/dhcp/set_config", post(dhcp_unsupported))
        .route("/dhcp/find_active_dhcp", post(dhcp_unsupported))
        .route("/dhcp/add_static_lease", post(dhcp_unsupported))
        .route("/dhcp/remove_static_lease", post(dhcp_unsupported))
        .route("/dhcp/update_static_lease", put(dhcp_unsupported))
        .route("/dhcp/reset", post(dhcp_unsupported))
        .route("/dhcp/reset_leases", post(dhcp_unsupported))
        // Localisation and profile.
        .route("/i18n/current_language", get(misc::current_language))
        .route("/i18n/change_language", post(misc::change_language))
        .route("/profile", get(misc::profile))
        .route("/profile/update", put(misc::profile_update))
        // Sessions.
        .route("/login", post(misc::login))
        .route("/logout", get(misc::logout))
        // Setup wizard.
        .route("/install/get_addresses", get(misc::install_addresses))
        .route("/install/check_config", post(misc::install_check))
        .route("/install/configure", post(misc::install_configure))
        // Apple profiles.
        .route("/apple/doh.mobileconfig", get(mobileconfig_doh))
        .route("/apple/dot.mobileconfig", get(mobileconfig_dot))
}

/// Answers every DHCP endpoint that would change something.
///
/// This build deliberately ships no DHCP server -- see the DHCP section of
/// TASK.md -- so a request to configure one is refused rather than stored.
/// Accepting it would write settings into the config file that nothing acts
/// on, which reads as a working DHCP server from the web interface.
///
/// 501 is what upstream's own API documents for a build without DHCP support,
/// so the interface already knows how to present it.
async fn dhcp_unsupported() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        "this build of sift has no DHCP server; \
         use your router or a separate DHCP service",
    )
        .into_response()
}

/// Answers the safe browsing and parental control toggles.
///
/// This build makes no hash-prefix lookups -- see the safe browsing and
/// parental control section of TASK.md -- so a request to switch one on is
/// refused rather than stored.  Storing it would leave the config file
/// claiming a protection that nothing performs.
async fn hashprefix_unsupported() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        "this build of sift performs no safe browsing or parental control \
         lookups; block these categories with a filter list instead",
    )
        .into_response()
}

/// The parameters both profile endpoints take.
#[derive(Deserialize, Default)]
struct MobileConfigQuery {
    /// The name to write into the profile, in place of `tls.server_name`.
    ///
    /// It matters when no server name is configured: the listeners run anyway,
    /// serving whatever the certificate covers, so the setup guide has a name
    /// to offer even when the settings name none.
    #[serde(default)]
    host: Option<String>,

    /// The ClientID the device should identify itself as, if any.
    ///
    /// `client_id`, which is what upstream's own handler reads, so a link
    /// someone kept still works.  A profile is per device, which is exactly
    /// the granularity a ClientID has: install it and that phone arrives under
    /// its own name, with its own settings, rather than sharing whatever its
    /// address is that day.
    #[serde(default)]
    client_id: Option<String>,

    /// The HTTPS port to write into the DNS-over-HTTPS profile's URL.
    ///
    /// The listener's own port otherwise.  It is worth overriding when
    /// something in front of this server answers on another one -- a reverse
    /// proxy, or a router forwarding a port inwards -- since the profile has
    /// to name the port the *device* dials, not the one this process bound.
    ///
    /// Apple's DNS-over-TLS profile carries a host name and no port at all, so
    /// this reaches the HTTPS profile and nothing else.
    #[serde(default)]
    port: Option<u16>,
}

/// `GET /control/apple/doh.mobileconfig`
async fn mobileconfig_doh(
    State(s): State<Shared>,
    Query(q): Query<MobileConfigQuery>,
) -> ApiResult<Response> {
    mobileconfig(
        &s,
        "HTTPS",
        q.host.as_deref(),
        q.client_id.as_deref(),
        q.port,
    )
}

/// `GET /control/apple/dot.mobileconfig`
async fn mobileconfig_dot(
    State(s): State<Shared>,
    Query(q): Query<MobileConfigQuery>,
) -> ApiResult<Response> {
    mobileconfig(&s, "TLS", q.host.as_deref(), q.client_id.as_deref(), q.port)
}

/// Whether `host` is a plausible DNS name.
///
/// This is what keeps the name out of trouble once it reaches the plist: the
/// accepted characters cannot close a tag, so nothing below needs escaping.
/// Both of its sources -- a query parameter and a hand-edited config file --
/// are worth checking for that alone.
fn is_dns_name(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }

    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// Builds an Apple DNS settings profile.
///
/// A profile names one host, so it is only meaningful once there is a name to
/// put in it.  Where upstream falls back to the literal `adguardhome`, this
/// refuses: a downloaded profile that quietly points a phone at a host that
/// does not resolve is worse than a button that says why it cannot.
fn mobileconfig(
    s: &Shared,
    proto: &str,
    requested: Option<&str>,
    client_id: Option<&str>,
    port: Option<u16>,
) -> ApiResult<Response> {
    let cfg = s.config.read();
    let host = requested
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .unwrap_or(&cfg.tls.server_name);

    if host.is_empty() {
        return Err(ApiError::bad_request(
            "no server name: set one under encryption, or name one with ?host=",
        ));
    }

    if !is_dns_name(host) {
        return Err(ApiError::bad_request(format!(
            "{host:?} is not a host name"
        )));
    }

    let client_id = client_id.map(str::trim).filter(|c| !c.is_empty());

    // The same rule the listeners apply when they read one off the wire, so a
    // profile cannot carry an identifier the server would then ignore.  It
    // also keeps the name out of trouble in the plist below, which writes both
    // it and the host into elements without escaping them.
    if let Some(id) = client_id
        && !sift_dns::server::is_valid_client_id(id)
    {
        return Err(ApiError::bad_request(format!(
            "{id:?} is not a ClientID: letters, digits and hyphens, \
             up to 63 of them, and not starting or ending with a hyphen"
        )));
    }

    // Zero is what the settings use for "not listening", which is not
    // something a device can dial: as a request it is a mistake, not a port.
    if port == Some(0) {
        return Err(ApiError::bad_request(
            "port 0 is not a port a device can be sent to",
        ));
    }

    let plist = profile_plist(proto, host, port.unwrap_or(cfg.tls.port_https), client_id);

    // The filename upstream sends, so a profile opened straight from its URL
    // lands as `doh.mobileconfig` rather than as the query string it was
    // asked for.
    let filename = if proto == "HTTPS" {
        "attachment; filename=doh.mobileconfig"
    } else {
        "attachment; filename=dot.mobileconfig"
    };

    Ok((
        [
            (header::CONTENT_TYPE, "application/xml"),
            (header::CONTENT_DISPOSITION, filename),
        ],
        plist,
    )
        .into_response())
}

/// The profile itself, for a host that has already been checked.
///
/// A ClientID rides on each protocol the way that protocol's listener reads it
/// back: DNS-over-HTTPS takes it as a path segment below the query route, and
/// DNS-over-TLS as a label below the server's own name, which is the SNI the
/// handshake carries.  The TLS form needs a certificate covering that label;
/// the HTTPS form needs nothing extra.
fn profile_plist(proto: &str, host: &str, port_https: u16, client_id: Option<&str>) -> String {
    let server_entry = if proto == "HTTPS" {
        // Apple's ServerURL carries a port, so a DNS-over-HTTPS listener moved
        // off 443 is still describable.  ServerName, which the TLS profile
        // uses, has no port at all -- a DNS-over-TLS listener elsewhere than
        // 853 cannot be written as a profile, which is Apple's limit rather
        // than one of ours, and the setup guide offers the button only when
        // the port is the standard one.
        let authority = if port_https == 443 || port_https == 0 {
            host.to_string()
        } else {
            format!("{host}:{port_https}")
        };
        let path = match client_id {
            Some(id) => format!("/dns-query/{id}"),
            None => "/dns-query".to_string(),
        };

        format!("<key>ServerURL</key><string>https://{authority}{path}</string>")
    } else {
        let name = match client_id {
            Some(id) => format!("{id}.{host}"),
            None => host.to_string(),
        };

        format!("<key>ServerName</key><string>{name}</string>")
    };

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>DNSSettings</key>
      <dict>
        <key>DNSProtocol</key><string>{proto}</string>
        {server_entry}
      </dict>
      <key>PayloadDescription</key><string>Configures device to use AdGuard Home</string>
      <key>PayloadDisplayName</key><string>AdGuard Home DNS over {proto}</string>
      <key>PayloadIdentifier</key><string>com.apple.dnsSettings.managed.adguardhome</string>
      <key>PayloadType</key><string>com.apple.dnsSettings.managed</string>
      <key>PayloadVersion</key><integer>1</integer>
    </dict>
  </array>
  <key>PayloadDisplayName</key><string>AdGuard Home DNS over {proto}</string>
  <key>PayloadIdentifier</key><string>com.adguardhome.dns</string>
  <key>PayloadRemovalDisallowed</key><false/>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
"#
    )
}

/// A JSON body of `{"enabled": ...}`, used by several toggles.
pub async fn enabled_json(enabled: bool) -> Json<serde_json::Value> {
    Json(json!({ "enabled": enabled }))
}

/// A whole server state, for tests that drive the assembled router.
///
/// The integration tests under `tests/` build their own; this one is for the
/// unit tests that need to reach inside -- the throttle's count, the
/// verifiers, the response extensions a listener reads -- which only code in
/// the crate can.
#[cfg(test)]
pub(crate) mod testing {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::Request;
    use axum::response::Response;

    use crate::auth::LoginLimiter;
    use crate::state::{AppState, NoFetcher, NoReloader, Shared};

    /// A user whose password is hashed at `cost`.
    ///
    /// Upstream's cost is 10; a test that only needs a user to exist uses the
    /// cheapest, and one that needs a check to take a while uses more.
    pub(crate) fn user(name: &str, password: &str, cost: u32) -> sift_config::model::WebUser {
        sift_config::model::WebUser {
            name: name.to_string(),
            password: bcrypt::hash(password, cost).expect("hashing"),
        }
    }

    /// A state with these users, whose engine blocks `ads.example.com`, and
    /// whose throttle is the configuration's, adjusted by `limiter`.
    pub(crate) fn state(
        users: Vec<sift_config::model::WebUser>,
        limiter: impl FnOnce(LoginLimiter) -> LoginLimiter,
    ) -> Shared {
        static NEXT: AtomicUsize = AtomicUsize::new(0);

        let mut config = sift_config::Config::default();
        config.dns.upstream_dns = vec![];
        config.dns.bootstrap_dns = vec![];
        config.filters = vec![];
        config.users = users;

        let resolver = Arc::new(sift_dns::resolver::Resolver::new(
            sift_filter::engine::Engine::build(
                [(1i64, "||ads.example.com^")],
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
            "sift-api-unit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let paths = sift_config::Paths::new(base.join("work"), base.join("conf/AdGuardHome.yaml"));
        paths.ensure().expect("preparing the working directory");

        let login_limiter = limiter(LoginLimiter::from_config(&config));

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
            sessions: crate::auth::Sessions::new(),
            login_limiter,
            started: jiff::Timestamp::now(),
            fetcher: Arc::new(NoFetcher),
            reloader: Arc::new(NoReloader),
            dns_addresses: parking_lot::RwLock::new(vec![]),
            version: Arc::new(crate::state::NoVersionCheck),
            updater: Arc::new(crate::state::NoSelfUpdate),
            version_cache: parking_lot::RwLock::new(None),
        })
    }

    /// Sends one request through the assembled router, as if from `peer`.
    pub(crate) async fn send(
        s: &Shared,
        secure: bool,
        peer: &str,
        req: axum::http::request::Builder,
        body: Body,
    ) -> Response {
        use tower::ServiceExt as _;

        let peer: SocketAddr = peer.parse().expect("a socket address");
        let req: Request<Body> = req
            .extension(axum::extract::ConnectInfo(peer))
            .body(body)
            .expect("a request");

        super::router(s.clone(), secure)
            .oneshot(req)
            .await
            .expect("the router is infallible")
    }

    /// A body that never ends, and counts what has been taken from it.
    ///
    /// What a client that says nothing about its length and keeps sending
    /// looks like to a handler, so a test can tell a limit enforced while
    /// reading from one checked after.
    pub(crate) struct Endless {
        pub(crate) taken: Arc<AtomicUsize>,
    }

    /// Each frame an `Endless` body yields.
    pub(crate) const CHUNK: usize = 16 * 1024;

    impl hyper::body::Body for Endless {
        type Data = bytes::Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
            self.taken.fetch_add(CHUNK, Ordering::Relaxed);

            std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(
                bytes::Bytes::from_static(&[b' '; CHUNK]),
            ))))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_header_loses_its_port() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "example.com:3000".parse().unwrap());
        assert_eq!(host_without_port(&h).as_deref(), Some("example.com"));

        h.insert(header::HOST, "example.com".parse().unwrap());
        assert_eq!(host_without_port(&h).as_deref(), Some("example.com"));

        h.insert(header::HOST, "[2001:db8::1]:3000".parse().unwrap());
        assert_eq!(host_without_port(&h).as_deref(), Some("[2001:db8::1]"));

        h.insert(header::HOST, "".parse().unwrap());
        assert_eq!(host_without_port(&h), None);
    }

    #[test]
    fn a_profile_host_has_to_be_a_host_name() {
        for ok in [
            "dns.example.org",
            "pi-hole",
            "a.b.c.d.example",
            "xn--80ak6aa92e.com",
        ] {
            assert!(is_dns_name(ok), "{ok:?} is a host name");
        }

        // The plist writes the name into an element without escaping it, so
        // anything that could close one has to be refused here.
        for bad in [
            "",
            "dns.example.org/../x",
            "</string><key>PayloadType</key><string>evil",
            "dns example org",
            "-leading.example",
            "trailing-.example",
            "double..dot",
            "2001:db8::1",
        ] {
            assert!(!is_dns_name(bad), "{bad:?} is not a host name");
        }

        assert!(!is_dns_name(&"a".repeat(64)), "a label caps at 63 bytes");
        assert!(is_dns_name(&"a".repeat(63)));
    }

    #[test]
    fn a_client_id_rides_where_its_listener_reads_it_back() {
        // Over HTTPS it is a path segment, which `/dns-query/{client_id}`
        // routes; over TLS it is a label below the server name, which is what
        // the handshake's SNI carries.  A profile that spelled either the
        // other way round would install and then arrive unidentified.
        let doh = profile_plist("HTTPS", "dns.example", 443, Some("kids-tablet"));
        assert!(
            doh.contains("<string>https://dns.example/dns-query/kids-tablet</string>"),
            "{doh}"
        );

        let dot = profile_plist("TLS", "dns.example", 443, Some("kids-tablet"));
        assert!(
            dot.contains("<string>kids-tablet.dns.example</string>"),
            "{dot}"
        );

        // And the name the listener would read back out of that SNI is the one
        // that was asked for.
        assert_eq!(
            sift_dns::server::client_id_from_sni("kids-tablet.dns.example", "dns.example")
                .as_deref(),
            Some("kids-tablet"),
        );
    }

    #[test]
    fn no_client_id_leaves_the_profile_as_it_was() {
        let doh = profile_plist("HTTPS", "dns.example", 443, None);
        assert!(
            doh.contains("<string>https://dns.example/dns-query</string>"),
            "{doh}"
        );

        // A non-standard HTTPS port is still describable, and the ClientID
        // goes after it rather than into it.
        let moved = profile_plist("HTTPS", "dns.example", 8443, Some("phone"));
        assert!(
            moved.contains("<string>https://dns.example:8443/dns-query/phone</string>"),
            "{moved}"
        );

        let dot = profile_plist("TLS", "dns.example", 443, None);
        assert!(dot.contains("<string>dns.example</string>"), "{dot}");
    }

    #[test]
    fn the_https_profile_names_the_port_the_device_dials() {
        // Apple's ServerURL carries one, so a listener behind a proxy or a
        // forwarded port is still describable; its own default is left out.
        let moved = profile_plist("HTTPS", "dns.example", 8443, None);
        assert!(
            moved.contains("<string>https://dns.example:8443/dns-query</string>"),
            "{moved}"
        );

        let standard = profile_plist("HTTPS", "dns.example", 443, None);
        assert!(
            standard.contains("<string>https://dns.example/dns-query</string>"),
            "{standard}"
        );

        // ServerName has no port at all, so the TLS profile is the same
        // whatever the HTTPS listener is on.
        assert_eq!(
            profile_plist("TLS", "dns.example", 8443, None),
            profile_plist("TLS", "dns.example", 443, None),
        );
    }

    #[test]
    fn a_profile_client_id_is_what_the_listeners_accept() {
        // The profile writes the identifier into an element without escaping
        // it, and a server that would ignore it is worse than a refusal, so
        // the endpoint applies the listeners' own rule.  Guarding it here
        // keeps the two from drifting apart.
        for ok in ["kids-tablet", "PHONE", "a", &"a".repeat(63)] {
            assert!(sift_dns::server::is_valid_client_id(ok), "{ok:?}");
        }

        for bad in [
            "",
            "-leading",
            "trailing-",
            "has.dot",
            "has space",
            "</string><key>x</key><string>evil",
            &"a".repeat(64),
        ] {
            assert!(!sift_dns::server::is_valid_client_id(bad), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn every_dhcp_change_is_refused() {
        // Storing DHCP settings nothing acts on would look like a working
        // server from the web interface.
        let r = dhcp_unsupported().await;
        assert_eq!(r.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[test]
    fn status_does_not_advertise_a_dhcp_server() {
        // The interface gates its whole DHCP section on `dhcp_available`:
        // answering true sends it to `/control/dhcp/status` and renders a
        // settings page whose every save answers 501.  Checking the source
        // rather than the value keeps this honest if the handler is rewritten.
        let src = include_str!("handlers/status.rs");
        assert!(
            src.contains("dhcp_available: false"),
            "status must not advertise a DHCP server that does not exist"
        );
    }

    #[test]
    fn the_login_form_can_reach_everything_it_is_built_from() {
        // Checked against the real build, not against names typed here: when
        // the bundler moved its output under static/, `/login.` stopped
        // matching the login bundle and a signed-out browser got a blank page
        // with two 401s in the console.  Nothing in the suite noticed.
        let mut seen_script = false;

        for name in crate::ui::names() {
            let path = format!("/{name}");
            let base = asset_name(&path);

            if base.starts_with("login.") || base.starts_with("forgot_password.") {
                assert!(is_public_page(&path), "{path} must load without a session");
                seen_script |= base.ends_with(".js");
            } else if base.starts_with("main.") {
                // Upstream keeps the dashboard's own bundle behind the gate.
                assert!(!is_public_page(&path), "{path} must need a session");
            }
        }

        assert!(
            seen_script,
            "the build should carry a login bundle for this to mean anything"
        );
    }

    #[test]
    fn the_wizard_owns_its_bundle_wherever_the_build_puts_it() {
        let mut seen = false;
        for name in crate::ui::names() {
            let path = format!("/{name}");
            if asset_name(&path).starts_with("install.") {
                assert!(is_install_page(&path), "{path} belongs to the wizard");
                seen |= path.ends_with(".js");
            }
        }

        assert!(seen, "the build should carry an install bundle");
        assert!(!is_install_page("/index.html"));
        assert!(!is_install_page("/static/main.abc.js"));
    }

    #[tokio::test]
    async fn every_safe_browsing_and_parental_change_is_refused() {
        // Storing the toggle would leave the config file claiming a lookup
        // that this build never makes.
        let r = hashprefix_unsupported().await;
        assert_eq!(r.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn safe_browsing_and_parental_report_themselves_off() {
        // Echoing the stored value would tell the interface a checker is
        // running when none is -- the trap `dhcp_status` avoids.
        let Json(v) = crate::handlers::filtering::hashprefix_status().await;
        assert_eq!(v["enabled"], serde_json::json!(false));
    }

    #[test]
    fn every_hashprefix_mutation_route_refuses() {
        let src = include_str!("routes.rs");
        for route in [
            "/safebrowsing/enable",
            "/safebrowsing/disable",
            "/parental/enable",
            "/parental/disable",
        ] {
            let line = src
                .lines()
                .find(|l| l.contains(&format!("\"{route}\"")))
                .unwrap_or_else(|| panic!("{route} is not routed"));
            assert!(
                line.contains("hashprefix_unsupported"),
                "{route} must refuse, but routes to: {line}"
            );
        }
    }

    mod body_limits {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use axum::body::Body;
        use axum::http::{Method, Request, StatusCode};

        use super::super::testing::{self, CHUNK, Endless};
        use super::super::{DEFAULT_BODY_LIMIT, LARGER_BODY_LIMIT, body_limit};
        use crate::state::Shared;

        /// A signed-in state and the cookie that proves it.
        fn signed_in() -> (Shared, String) {
            let s = testing::state(vec![testing::user("admin", "pw", 4)], |l| l);
            let token = s
                .sessions
                .create("admin", std::time::Duration::from_secs(600));

            (s, format!("agh_session={token}"))
        }

        fn post(path: &str, cookie: &str) -> axum::http::request::Builder {
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header("content-type", "application/json")
                .header("cookie", cookie)
        }

        /// A JSON body of exactly `len` bytes: a list of rules, padded.
        fn rules_body(len: usize) -> String {
            let head = r#"{"rules":["||example.org^"#;
            let tail = r#""]}"#;

            format!("{head}{}{tail}", "x".repeat(len - head.len() - tail.len()))
        }

        #[test]
        fn exactly_upstreams_two_routes_take_the_larger_limit() {
            // Upstream's `expectsLargerRequests`: POST, and these two paths.
            for path in ["/control/access/set", "/control/filtering/set_rules"] {
                assert_eq!(body_limit(&Method::POST, path), LARGER_BODY_LIMIT, "{path}");
                assert_eq!(
                    body_limit(&Method::GET, path),
                    DEFAULT_BODY_LIMIT,
                    "{path}, and only when posted to"
                );
            }

            for path in [
                "/control/login",
                "/control/filtering/add_url",
                "/control/clients/add",
                "/dns-query",
                // The path inside the nest is not the path upstream compares.
                "/filtering/set_rules",
            ] {
                assert_eq!(
                    body_limit(&Method::POST, path),
                    DEFAULT_BODY_LIMIT,
                    "{path}"
                );
            }

            assert_eq!(DEFAULT_BODY_LIMIT, 65_536, "upstream's 64 * datasize.KB");
            assert_eq!(LARGER_BODY_LIMIT, 4_194_304, "upstream's 4 * datasize.MB");
        }

        #[tokio::test]
        async fn a_body_over_64_kib_is_refused_on_an_ordinary_route() {
            let (s, cookie) = signed_in();

            let r = testing::send(
                &s,
                false,
                "192.0.2.1:5000",
                post("/control/dns_config", &cookie),
                Body::from(format!(r#"{{"x":"{}"}}"#, "x".repeat(65 * 1024))),
            )
            .await;
            assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);

            // Including the one route anybody can reach.  axum's own default
            // let a stranger make the login form buffer 2 MB.
            let r = testing::send(
                &s,
                false,
                "192.0.2.1:5000",
                post("/control/login", ""),
                Body::from(format!(r#"{{"name":"{}"}}"#, "x".repeat(65 * 1024))),
            )
            .await;
            assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
        }

        #[tokio::test]
        async fn user_rules_between_2_and_4_mib_are_accepted_as_go_accepts_them() {
            // The drop-in half: under axum's 2 MB default this answered 413 to
            // a set of rules the Go build takes.
            let (s, cookie) = signed_in();

            let body = rules_body(3 * 1024 * 1024);
            let r = testing::send(
                &s,
                false,
                "192.0.2.1:5000",
                post("/control/filtering/set_rules", &cookie),
                Body::from(body),
            )
            .await;
            assert_eq!(r.status(), StatusCode::OK);
            assert_eq!(
                s.filters.read().user_rules.len(),
                1,
                "the rules were stored"
            );

            // And past upstream's 4 MB it is refused, as it is there.
            let r = testing::send(
                &s,
                false,
                "192.0.2.1:5000",
                post("/control/filtering/set_rules", &cookie),
                Body::from(rules_body(LARGER_BODY_LIMIT + 1)),
            )
            .await;
            assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
        }

        #[tokio::test]
        async fn an_access_list_between_2_and_4_mib_is_accepted_too() {
            let (s, cookie) = signed_in();

            // About 220,000 entries, which is what a list that size is.
            let entries: Vec<String> = (0..220_000u32)
                .map(|i| std::net::Ipv4Addr::from(0x0a00_0000 + i).to_string())
                .collect();
            let body = serde_json::json!({ "disallowed_clients": entries }).to_string();
            assert!(body.len() > 2 * 1024 * 1024 && body.len() < LARGER_BODY_LIMIT);

            let r = testing::send(
                &s,
                false,
                "192.0.2.1:5000",
                post("/control/access/set", &cookie),
                Body::from(body),
            )
            .await;
            assert_eq!(r.status(), StatusCode::OK);
            assert_eq!(s.config.read().dns.disallowed_clients.len(), 220_000);
        }

        #[tokio::test]
        async fn a_body_that_never_ends_is_cut_off_while_it_is_read() {
            // A body that declares no length and keeps coming is the case a
            // check made after buffering cannot catch: it is refused once it
            // runs past the limit, having cost at most one frame beyond it.
            let (s, cookie) = signed_in();
            let taken = Arc::new(AtomicUsize::new(0));

            let r = testing::send(
                &s,
                false,
                "192.0.2.1:5000",
                post("/control/dns_config", &cookie),
                Body::new(Endless {
                    taken: taken.clone(),
                }),
            )
            .await;

            assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
            let taken = taken.load(Ordering::Relaxed);
            assert!(
                taken <= DEFAULT_BODY_LIMIT + CHUNK,
                "read {taken} bytes of an endless body"
            );
        }
    }

    mod sign_in {
        use std::time::Duration;

        use axum::body::Body;
        use axum::http::{Method, Request, StatusCode, header};

        use super::super::testing;
        use crate::state::Shared;

        const WRONG: &str = r#"{"name":"admin","password":"wrong"}"#;
        const RIGHT: &str = r#"{"name":"admin","password":"pw"}"#;

        async fn login(s: &Shared, peer: &str, body: &'static str) -> StatusCode {
            let req = Request::builder()
                .method(Method::POST)
                .uri("/control/login")
                .header("content-type", "application/json");

            testing::send(s, false, peer, req, Body::from(body))
                .await
                .status()
        }

        #[tokio::test]
        async fn addresses_in_one_slash_64_share_a_login_budget() {
            // A subscriber is handed a /64 and can send from any address in
            // it; keyed by address, each of those came with five fresh
            // guesses.
            let s = testing::state(vec![testing::user("admin", "pw", 4)], |l| l);

            for n in 1..=5 {
                let peer = format!("[2001:db8:1:2::{n:x}]:5000");
                assert_eq!(
                    login(&s, &peer, WRONG).await,
                    StatusCode::FORBIDDEN,
                    "attempt {n} is examined"
                );
            }

            assert_eq!(
                login(&s, "[2001:db8:1:2:ffff::1]:5000", RIGHT).await,
                StatusCode::TOO_MANY_REQUESTS,
                "a fresh address in the same /64 has nothing left to spend"
            );
            assert_eq!(
                login(&s, "[2001:db8:1:3::1]:5000", RIGHT).await,
                StatusCode::OK,
                "the next /64 is somebody else"
            );

            // An IPv4 client is still judged by its own address, whichever
            // way the socket reports it.
            for _ in 0..5 {
                login(&s, "[::ffff:192.0.2.7]:5000", WRONG).await;
            }
            assert_eq!(
                login(&s, "192.0.2.7:5000", RIGHT).await,
                StatusCode::TOO_MANY_REQUESTS
            );
            assert_eq!(login(&s, "192.0.2.8:5000", RIGHT).await, StatusCode::OK);
        }

        #[tokio::test]
        async fn each_device_in_this_hosts_own_slash_64_has_its_own_login_budget() {
            // A household reaching the server at its global IPv6 address is
            // in the server's own /64.  The connection guard judges each
            // address there on its own, and the throttle keys the same way:
            // one device's wrong passwords must not lock every other out.
            let s = testing::state(vec![testing::user("admin", "pw", 4)], |l| l);
            s.dns_server.probes.set_config(sift_dns::probe::Config {
                host_networks: vec![("2001:db8:1:2::".parse().unwrap(), 64)],
                ..Default::default()
            });

            for _ in 0..5 {
                login(&s, "[2001:db8:1:2::a]:5000", WRONG).await;
            }
            assert_eq!(
                login(&s, "[2001:db8:1:2::a]:5000", RIGHT).await,
                StatusCode::TOO_MANY_REQUESTS,
                "the device that guessed has spent its attempts"
            );
            assert_eq!(
                login(&s, "[2001:db8:1:2::b]:5000", RIGHT).await,
                StatusCode::OK,
                "and its neighbour has not"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn wrong_passwords_sent_at_once_cannot_exceed_the_limit() {
            // Counted after the check, as upstream counts, every one of these
            // passed the threshold before any of them had failed, and all
            // twenty were examined.
            let s = testing::state(vec![testing::user("admin", "pw", 6)], |l| l);

            let tasks: Vec<_> = (0..20)
                .map(|_| {
                    let s = s.clone();
                    tokio::spawn(async move { login(&s, "192.0.2.1:5000", WRONG).await })
                })
                .collect();

            let mut examined = 0;
            let mut turned_away = 0;
            for t in tasks {
                match t.await.unwrap() {
                    StatusCode::FORBIDDEN => examined += 1,
                    StatusCode::TOO_MANY_REQUESTS => turned_away += 1,
                    other => panic!("unexpected {other}"),
                }
            }

            assert_eq!(examined, 5, "no more guesses checked than the limit");
            assert_eq!(turned_away, 15);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn a_script_sending_signed_requests_at_once_is_not_turned_away() {
            // A dashboard polling the API with Basic credentials sends a
            // handful of requests together, each one a password check.  They
            // queue for the two verifiers rather than being refused, and they
            // are counted only once they have one, so a burst of right
            // answers never adds up to a block.
            let s = testing::state(vec![testing::user("admin", "pw", 6)], |l| l);
            let basic = "Basic YWRtaW46cHc="; // admin:pw

            let tasks: Vec<_> = (0..12)
                .map(|_| {
                    let s = s.clone();
                    tokio::spawn(async move {
                        let req = Request::builder()
                            .uri("/control/status")
                            .header(header::AUTHORIZATION, basic);

                        testing::send(&s, false, "192.0.2.1:5000", req, Body::empty())
                            .await
                            .status()
                    })
                })
                .collect();

            for t in tasks {
                assert_eq!(t.await.unwrap(), StatusCode::OK);
            }
            assert_eq!(s.login_limiter.failures("192.0.2.1"), 0);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn checking_a_password_does_not_hold_the_config_lock() {
            // The check ran under `config.read()`, so for the length of every
            // stranger's guess a settings change -- or protection coming back
            // from a pause -- waited behind it.  A deliberately slow hash
            // gives the check time to be caught in the act.
            let s = testing::state(vec![testing::user("admin", "pw", 12)], |l| l);

            let signing_in = {
                let s = s.clone();
                tokio::spawn(async move { login(&s, "192.0.2.1:5000", RIGHT).await })
            };

            // The attempt is counted the moment the check starts, and handed
            // back when it ends.
            let started = std::time::Instant::now();
            while s.login_limiter.failures("192.0.2.1") == 0 {
                assert!(started.elapsed() < Duration::from_secs(10), "never started");
                tokio::task::yield_now().await;
            }

            let writer = s.config.try_write_for(Duration::from_millis(100));
            assert!(
                writer.is_some(),
                "a writer got in while the password was being checked"
            );
            let still_checking = s.login_limiter.failures("192.0.2.1") == 1;
            drop(writer);
            assert!(still_checking, "and the check was still running then");

            assert_eq!(signing_in.await.unwrap(), StatusCode::OK);
            assert_eq!(s.login_limiter.failures("192.0.2.1"), 0, "handed back");
        }

        #[tokio::test]
        async fn a_sign_in_that_finds_every_verifier_busy_is_told_to_come_back() {
            // The same 429 and header a spent client gets, since it asks the
            // same of the client; the login page shows the text.
            let s = testing::state(vec![testing::user("admin", "pw", 4)], |l| l.impatient());
            let held = s
                .login_limiter
                .verifiers()
                .acquire_many_owned(2)
                .await
                .unwrap();

            let req = Request::builder()
                .method(Method::POST)
                .uri("/control/login")
                .header("content-type", "application/json");
            let r = testing::send(&s, false, "192.0.2.1:5000", req, Body::from(RIGHT)).await;

            assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(
                r.headers()
                    .get(header::RETRY_AFTER)
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "1"
            );
            assert_eq!(
                s.login_limiter.failures("192.0.2.1"),
                0,
                "a check that never ran is not held against anyone"
            );

            drop(held);
            assert_eq!(login(&s, "192.0.2.1:5000", RIGHT).await, StatusCode::OK);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_script_on_this_network_is_served_while_the_verifiers_are_held() {
            // Home Assistant polling with Basic credentials: whatever the
            // internet is doing to the verifiers, a device the connection
            // guard spares is checked at once, as upstream checks everyone.
            let s = testing::state(vec![testing::user("admin", "pw", 4)], |l| l.impatient());
            let held = s
                .login_limiter
                .verifiers()
                .acquire_many_owned(2)
                .await
                .unwrap();
            let basic = "Basic YWRtaW46cHc="; // admin:pw

            let status = |peer: &'static str| {
                let s = s.clone();
                async move {
                    let req = Request::builder()
                        .uri("/control/status")
                        .header(header::AUTHORIZATION, basic);

                    testing::send(&s, false, peer, req, Body::empty())
                        .await
                        .status()
                }
            };

            for peer in ["192.168.1.5:5000", "[fd00::5]:5000", "127.0.0.1:5000"] {
                for _ in 0..5 {
                    assert_eq!(status(peer).await, StatusCode::OK, "{peer}");
                }
            }
            assert_eq!(login(&s, "10.0.0.2:5000", RIGHT).await, StatusCode::OK);

            // The same request from the internet waits its turn, and is
            // told to come back.
            assert_eq!(
                status("192.0.2.1:5000").await,
                StatusCode::TOO_MANY_REQUESTS
            );

            drop(held);
        }

        #[tokio::test]
        async fn the_profile_names_the_user_the_gate_signed_in() {
            // Read from what the gate found rather than by checking the
            // credentials again, which for Basic was a second bcrypt per
            // request.  The second user is named so the first-user fallback
            // cannot pass this by accident.
            let s = testing::state(
                vec![
                    testing::user("admin", "pw", 4),
                    testing::user("other", "pw2", 4),
                ],
                |l| l,
            );

            let req = Request::builder()
                .uri("/control/profile")
                .header(header::AUTHORIZATION, "Basic b3RoZXI6cHcy"); // other:pw2
            let r = testing::send(&s, false, "192.0.2.1:5000", req, Body::empty()).await;
            assert_eq!(r.status(), StatusCode::OK);

            let body = axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap();
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(v["name"], "other");
        }
    }

    #[test]
    fn every_dhcp_mutation_route_refuses() {
        // A route added later that forgets this would silently accept
        // settings, so check the table itself.
        let src = include_str!("routes.rs");
        for route in [
            "/dhcp/set_config",
            "/dhcp/find_active_dhcp",
            "/dhcp/add_static_lease",
            "/dhcp/remove_static_lease",
            "/dhcp/update_static_lease",
            "/dhcp/reset",
            "/dhcp/reset_leases",
        ] {
            let line = src
                .lines()
                .find(|l| l.contains(&format!("\"{route}\"")))
                .unwrap_or_else(|| panic!("{route} is not routed"));
            assert!(
                line.contains("dhcp_unsupported"),
                "{route} must refuse, but routes to: {line}"
            );
        }
    }
}
