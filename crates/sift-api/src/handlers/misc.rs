//! Clients, access control, blocked services, encryption, DHCP, the setup
//! wizard and profile endpoints.

use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::auth::{self, Verdict};
use crate::error::{ApiError, ApiResult};
use crate::state::Shared;

/// The tags a client may carry, as the UI offers them.
const SUPPORTED_TAGS: &[&str] = &[
    "device_audio",
    "device_camera",
    "device_gameconsole",
    "device_laptop",
    "device_nas",
    "device_other",
    "device_pc",
    "device_phone",
    "device_printer",
    "device_securityalarm",
    "device_tablet",
    "device_tv",
    "os_android",
    "os_ios",
    "os_linux",
    "os_macos",
    "os_other",
    "os_windows",
    "user_admin",
    "user_child",
    "user_regular",
];

/// A configured client, as the API exchanges it.
/// Every field defaults: Go's `encoding/json` leaves a field the caller
/// omitted at its zero value rather than failing, so a partial body that
/// upstream answers 200 must not become a 422 here.
#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct ClientJson {
    /// The client's display name.
    pub name: String,
    /// Addresses, CIDRs, MACs and ClientIDs identifying the client.
    pub ids: Vec<String>,
    /// Whether global settings apply.
    pub use_global_settings: bool,
    /// Whether filtering applies.
    pub filtering_enabled: bool,
    /// Whether global blocked-service settings apply.
    pub use_global_blocked_services: bool,
    /// Services blocked for this client.
    #[serde(default)]
    pub blocked_services: Vec<String>,
    /// Per-client upstream resolvers.
    #[serde(default)]
    pub upstreams: Vec<String>,
    /// Tags applied to the client.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Whether the client's queries are excluded from the log.
    #[serde(default)]
    pub ignore_querylog: bool,
    /// Whether the client's queries are excluded from statistics.
    #[serde(default)]
    pub ignore_statistics: bool,
    /// Safe-search settings for this client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safe_search: Option<serde_json::Value>,
}

/// Renders the WHOIS fields the interface shows.
///
/// Always an object, even when empty: the interface reads it unconditionally.
pub fn whois_json(fields: &[(String, String)]) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    for (k, v) in fields {
        m.insert(k.clone(), json!(v));
    }

    serde_json::Value::Object(m)
}

/// The clients discovered while running, as `auto_clients`.
fn auto_clients(s: &Shared) -> Vec<serde_json::Value> {
    s.resolver
        .runtime
        .all()
        .into_iter()
        .map(|(ip, c)| {
            json!({
                "whois_info": whois_json(&c.whois),
                "ip": ip.to_string(),
                "name": c.name,
                "source": c.source.map(|s| s.as_str()).unwrap_or(""),
            })
        })
        .collect()
}

/// `GET /control/clients`
pub async fn clients(State(s): State<Shared>) -> Json<serde_json::Value> {
    let auto = auto_clients(&s);
    let cfg = s.config.read();
    let clients: Vec<ClientJson> = cfg
        .clients
        .persistent
        .iter()
        .map(|c| ClientJson {
            name: c.name.clone(),
            ids: c.ids.clone(),
            use_global_settings: c.use_global_settings,
            filtering_enabled: c.filtering_enabled,
            use_global_blocked_services: c.use_global_blocked_services,
            blocked_services: c.blocked_services.ids.clone(),
            upstreams: c.upstreams.clone(),
            tags: c.tags.clone(),
            ignore_querylog: c.ignore_querylog,
            ignore_statistics: c.ignore_statistics,
            safe_search: None,
        })
        .collect();

    Json(json!({
        "clients": if clients.is_empty() { serde_json::Value::Null } else { serde_json::to_value(&clients).unwrap_or(serde_json::Value::Null) },
        "auto_clients": auto,
        "supported_tags": SUPPORTED_TAGS,
    }))
}

/// Converts an API client into its configuration form.
fn to_persistent(c: &ClientJson) -> sift_config::model::PersistentClient {
    sift_config::model::PersistentClient {
        name: c.name.clone(),
        ids: c.ids.clone(),
        tags: c.tags.clone(),
        upstreams: c.upstreams.clone(),
        use_global_settings: c.use_global_settings,
        filtering_enabled: c.filtering_enabled,
        use_global_blocked_services: c.use_global_blocked_services,
        ignore_querylog: c.ignore_querylog,
        ignore_statistics: c.ignore_statistics,
        blocked_services: sift_config::model::BlockedServices {
            schedule: sift_config::model::Schedule::default(),
            ids: c.blocked_services.clone(),
        },
        ..Default::default()
    }
}

/// `POST /control/clients/add`
pub async fn clients_add(State(s): State<Shared>, Json(req): Json<ClientJson>) -> ApiResult<()> {
    if req.name.trim().is_empty() {
        return Err(ApiError::bad_request("the client name must not be empty"));
    }
    if req.ids.is_empty() {
        return Err(ApiError::bad_request(
            "a client needs at least one identifier",
        ));
    }

    {
        let mut cfg = s.config.write();
        if cfg.clients.persistent.iter().any(|c| c.name == req.name) {
            return Err(ApiError::bad_request(
                "a client with this name already exists",
            ));
        }
        cfg.clients.persistent.push(to_persistent(&req));
    }

    s.save_config().map_err(ApiError::internal)
}

/// The `/control/clients/delete` request.
/// Every field defaults: Go's `encoding/json` leaves a field the caller
/// omitted at its zero value rather than failing, so a partial body that
/// upstream answers 200 must not become a 422 here.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct DeleteClientReq {
    /// The client to remove.
    pub name: String,
}

/// `POST /control/clients/delete`
pub async fn clients_delete(
    State(s): State<Shared>,
    Json(req): Json<DeleteClientReq>,
) -> ApiResult<()> {
    {
        let mut cfg = s.config.write();
        let before = cfg.clients.persistent.len();
        cfg.clients.persistent.retain(|c| c.name != req.name);
        if cfg.clients.persistent.len() == before {
            return Err(ApiError::not_found("no client with that name"));
        }
    }

    s.save_config().map_err(ApiError::internal)
}

/// The `/control/clients/update` request.
/// Every field defaults: Go's `encoding/json` leaves a field the caller
/// omitted at its zero value rather than failing, so a partial body that
/// upstream answers 200 must not become a 422 here.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct UpdateClientReq {
    /// The client to change.
    pub name: String,
    /// The new settings.
    pub data: ClientJson,
}

/// `POST /control/clients/update`
pub async fn clients_update(
    State(s): State<Shared>,
    Json(req): Json<UpdateClientReq>,
) -> ApiResult<()> {
    {
        let mut cfg = s.config.write();
        let Some(slot) = cfg
            .clients
            .persistent
            .iter_mut()
            .find(|c| c.name == req.name)
        else {
            return Err(ApiError::not_found("no client with that name"));
        };

        // The safe browsing and parental control toggles are not part of this
        // build's client API, but they are part of the config file, so they
        // are carried across rather than reset: an operator who edits a client
        // here and later switches back to AdGuard Home finds them as they left
        // them.  See the safe browsing and parental control section of TASK.md.
        let carried = (slot.safebrowsing_enabled, slot.parental_enabled);
        *slot = to_persistent(&req.data);
        (slot.safebrowsing_enabled, slot.parental_enabled) = carried;
    }

    s.save_config().map_err(ApiError::internal)
}

/// `GET /control/clients/find`
///
/// The parameters are `ip0`, `ip1`, … and the answer is a list of one-entry
/// objects keyed by the identifier that was asked about, which is the shape
/// the interface reads.
pub async fn clients_find(
    State(s): State<Shared>,
    axum::extract::RawQuery(q): axum::extract::RawQuery,
) -> Json<Vec<serde_json::Value>> {
    let query = q.unwrap_or_default();
    let mut out = Vec::new();

    for i in 0.. {
        let Some(id) = query_param(&query, &format!("ip{i}")) else {
            break;
        };
        if id.is_empty() {
            break;
        }

        out.push(json!({ &id: find_client(&s, &id) }));
    }

    Json(out)
}

/// The `/control/clients/search` request.
#[derive(Deserialize, Default)]
pub struct SearchClientsReq {
    /// The identifiers to look up.
    #[serde(default)]
    pub clients: Vec<SearchClientId>,
}

/// One identifier in a search request.
/// Every field defaults: Go's `encoding/json` leaves a field the caller
/// omitted at its zero value rather than failing, so a partial body that
/// upstream answers 200 must not become a 422 here.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct SearchClientId {
    /// An address, a CIDR, a MAC or a ClientID.
    pub id: String,
}

/// `POST /control/clients/search`
///
/// The same answer as `/control/clients/find`, with the identifiers in a body
/// rather than in the query string.
pub async fn clients_search(
    State(s): State<Shared>,
    Json(req): Json<SearchClientsReq>,
) -> Json<Vec<serde_json::Value>> {
    Json(
        req.clients
            .iter()
            .filter(|c| !c.id.is_empty())
            .map(|c| json!({ &c.id: find_client(&s, &c.id) }))
            .collect(),
    )
}

/// Reads one parameter out of a raw query string.
fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| percent_decode(v))
    })
}

/// Decodes the percent-encoding a query string uses.
fn percent_decode(s: &str) -> String {
    let bytes = s.replace('+', " ").into_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(b) = u8::from_str_radix(hex, 16) {
                out.push(b);
                i += 3;

                continue;
            }
        }

        out.push(bytes[i]);
        i += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

/// Describes whichever client an identifier names, persistent or discovered.
fn find_client(s: &Shared, id: &str) -> serde_json::Value {
    let addr = id.parse::<std::net::IpAddr>().ok();
    // An identifier that is not an address may be the ClientID the access
    // lists match on, which upstream passes to the same check.
    let client_id = (addr.is_none() && sift_dns::server::is_valid_client_id(id)).then_some(id);

    if let Some(c) = s.config.read().clients.persistent.iter().find(|c| {
        c.ids.iter().any(|i| i.eq_ignore_ascii_case(id)) || c.name.eq_ignore_ascii_case(id)
    }) {
        return json!({
            "name": c.name,
            "ids": c.ids,
            "tags": c.tags,
            "upstreams": c.upstreams,
            "blocked_services": c.blocked_services.ids,
            "use_global_settings": c.use_global_settings,
            "use_global_blocked_services": c.use_global_blocked_services,
            "filtering_enabled": c.filtering_enabled,
            "ignore_querylog": c.ignore_querylog,
            "ignore_statistics": c.ignore_statistics,
            "disallowed": addr
                .is_some_and(|a| !s.dns_server.access.read().permits(a, client_id)),
            "disallowed_rule": "",
        });
    }

    let Some(a) = addr else {
        return serde_json::Value::Null;
    };
    let Some(rc) = s.resolver.runtime.get(a) else {
        return serde_json::Value::Null;
    };

    json!({
        "name": rc.name,
        "ids": [id],
        "whois_info": whois_json(&rc.whois),
        "disallowed": !s.dns_server.access.read().permits(a, None),
        "disallowed_rule": "",
    })
}

/// `GET /control/access/list`
pub async fn access_list(State(s): State<Shared>) -> Json<serde_json::Value> {
    let cfg = s.config.read();
    let or_null = |v: &Vec<String>| {
        if v.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::to_value(v).unwrap_or(serde_json::Value::Null)
        }
    };

    Json(json!({
        "allowed_clients": or_null(&cfg.dns.allowed_clients),
        "disallowed_clients": or_null(&cfg.dns.disallowed_clients),
        "blocked_hosts": cfg.dns.blocked_hosts,
    }))
}

/// The `/control/access/set` request.
#[derive(Deserialize, Default)]
pub struct AccessSetReq {
    /// Clients allowed to query, as an allowlist.
    #[serde(default)]
    pub allowed_clients: Option<Vec<String>>,
    /// Clients forbidden from querying.
    #[serde(default)]
    pub disallowed_clients: Option<Vec<String>>,
    /// Hosts refused outright.
    #[serde(default)]
    pub blocked_hosts: Option<Vec<String>>,
}

/// Reports the first duplicated entry of a list, if any.
fn first_duplicate(list: &[String]) -> Option<&str> {
    let mut seen = std::collections::HashSet::new();

    list.iter().find(|s| !seen.insert(*s)).map(String::as_str)
}

/// Checks one side of the access lists, as upstream's `processAccessClients`
/// does before storing it.
///
/// Refusing here is the whole point: an entry nothing can parse used to be
/// accepted, written to the config file and then silently dropped when the
/// lists were built, so an allowlist of CIDRs and ClientIDs became an empty
/// allowlist — which admits everybody.
fn validate_access_clients(field: &str, list: &[String]) -> Result<(), ApiError> {
    if let Some(dup) = first_duplicate(list) {
        return Err(ApiError::bad_request(format!(
            "validating {field}: duplicated values: [{dup}]"
        )));
    }

    for (i, s) in list.iter().enumerate() {
        if sift_dns::server::parse_access_entry(s).is_none() {
            return Err(ApiError::bad_request(format!(
                "adding {field}: value {s:?} at index {i}: bad ip, cidr, or clientid"
            )));
        }
    }

    Ok(())
}

/// `POST /control/access/set`
///
/// Upstream lets both lists hold entries — the disallowed list is simply
/// ignored while the allowed list is non-empty, which is what the interface
/// tells the user — and refuses only an entry appearing in both.
pub async fn access_set(State(s): State<Shared>, Json(req): Json<AccessSetReq>) -> ApiResult<()> {
    let (allowed, disallowed, blocked_hosts) = {
        let cfg = s.config.read();

        (
            req.allowed_clients
                .unwrap_or_else(|| cfg.dns.allowed_clients.clone()),
            req.disallowed_clients
                .unwrap_or_else(|| cfg.dns.disallowed_clients.clone()),
            req.blocked_hosts
                .unwrap_or_else(|| cfg.dns.blocked_hosts.clone()),
        )
    };

    validate_access_clients("allowed clients", &allowed)?;
    validate_access_clients("disallowed clients", &disallowed)?;
    if let Some(dup) = first_duplicate(&blocked_hosts) {
        return Err(ApiError::bad_request(format!(
            "validating blocked hosts: duplicated values: [{dup}]"
        )));
    }

    if let Some(both) = allowed.iter().find(|a| disallowed.contains(a)) {
        return Err(ApiError::bad_request(format!(
            "items in allowed and disallowed clients intersect: {both}"
        )));
    }

    {
        let mut cfg = s.config.write();
        cfg.dns.allowed_clients = allowed;
        cfg.dns.disallowed_clients = disallowed;
        cfg.dns.blocked_hosts = blocked_hosts;
    }

    s.save_config().map_err(ApiError::internal)
}

/// `GET /control/blocked_services/all`
pub async fn services_all() -> Json<&'static sift_filter::services::Catalogue> {
    Json(sift_filter::services::catalogue())
}

/// `GET /control/blocked_services/services`
///
/// The legacy endpoint: just the identifiers.
pub async fn services_ids() -> Json<Vec<String>> {
    Json(sift_filter::services::ids())
}

/// `GET /control/blocked_services/list`
pub async fn services_list(State(s): State<Shared>) -> Json<Vec<String>> {
    Json(s.config.read().filtering.blocked_services.ids.clone())
}

/// `POST /control/blocked_services/set`
pub async fn services_set(State(s): State<Shared>, Json(ids): Json<Vec<String>>) -> ApiResult<()> {
    s.config.write().filtering.blocked_services.ids = ids.clone();
    s.filters.write().set_blocked_services(&ids);

    s.save_config().map_err(ApiError::internal)?;
    s.reloader.reload_filters(&s.filters.read());

    Ok(())
}

/// `GET /control/blocked_services/get`
pub async fn services_get(State(s): State<Shared>) -> Json<serde_json::Value> {
    let cfg = s.config.read();
    let bs = &cfg.filtering.blocked_services;

    Json(json!({
        "schedule": { "time_zone": bs.schedule.time_zone },
        "ids": bs.ids,
    }))
}

/// The `/control/blocked_services/update` request.
#[derive(Deserialize)]
pub struct ServicesUpdateReq {
    /// The blocked service identifiers.
    #[serde(default)]
    pub ids: Vec<String>,
    /// When the block applies.
    #[serde(default)]
    pub schedule: Option<serde_json::Value>,
}

/// `PUT /control/blocked_services/update`
pub async fn services_update(
    State(s): State<Shared>,
    Json(req): Json<ServicesUpdateReq>,
) -> ApiResult<()> {
    {
        let mut cfg = s.config.write();
        s.filters.write().set_blocked_services(&req.ids);
        cfg.filtering.blocked_services.ids = req.ids;
        if let Some(tz) = req
            .schedule
            .as_ref()
            .and_then(|v| v.get("time_zone"))
            .and_then(|v| v.as_str())
        {
            cfg.filtering.blocked_services.schedule.time_zone = tz.to_string();
        }
    }

    s.save_config().map_err(ApiError::internal)?;
    s.reloader.reload_filters(&s.filters.read());

    Ok(())
}

/// Describes the configured certificate, if any.
fn tls_report(s: &Shared) -> (sift_dns::tls::Status, sift_config::model::TlsConfig) {
    let t = s.config.read().tls.clone();
    let src = sift_dns::tls::Source {
        certificate_chain: t.certificate_chain.clone(),
        private_key: t.private_key.clone(),
        certificate_path: t.certificate_path.clone(),
        private_key_path: t.private_key_path.clone(),
    };

    let status = if src.is_empty() {
        sift_dns::tls::Status::default()
    } else {
        sift_dns::tls::inspect(&src)
    };

    (status, t)
}

/// Renders the certificate report the way `/control/tls/status` does.
fn tls_json(
    st: &sift_dns::tls::Status,
    t: &sift_config::model::TlsConfig,
    plain_dns: bool,
) -> serde_json::Value {
    let zero = sift_core::gotime::GO_ZERO_TIME;

    let mut out = json!({
        "not_before": if st.not_before.is_empty() { zero.to_string() } else { st.not_before.clone() },
        "not_after": if st.not_after.is_empty() { zero.to_string() } else { st.not_after.clone() },
        "dns_names": if st.dns_names.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::to_value(&st.dns_names).unwrap_or(serde_json::Value::Null)
        },
        "valid_cert": st.valid_cert,
        "valid_chain": st.valid_chain,
        "valid_key": st.valid_key,
        "valid_pair": st.valid_pair,
        "enabled": t.enabled,
        "force_https": t.force_https,
        // port_dnscrypt is always sent; the other three are omitempty.
        "port_dnscrypt": t.port_dnscrypt,
        "dnscrypt_config_file": t.dnscrypt_config_file,
        "certificate_chain": t.certificate_chain,
        "private_key": t.private_key,
        "certificate_path": t.certificate_path,
        "private_key_path": t.private_key_path,
        "private_key_saved": !t.private_key.is_empty() || !t.private_key_path.is_empty(),
        "serve_plain_dns": plain_dns,
    });

    let Some(m) = out.as_object_mut() else {
        return out;
    };

    // Upstream marks these `omitempty`, so an unset one is absent rather than
    // an empty string or a zero.
    if !t.server_name.is_empty() {
        m.insert("server_name".into(), json!(t.server_name));
    }
    for (k, v) in [
        ("port_https", t.port_https),
        ("port_dns_over_tls", t.port_dns_over_tls),
        ("port_dns_over_quic", t.port_dns_over_quic),
    ] {
        if v != 0 {
            m.insert(k.into(), json!(v));
        }
    }
    for (k, v) in [
        ("key_type", &st.key_type),
        ("subject", &st.subject),
        ("issuer", &st.issuer),
        ("warning_validation", &st.warning_validation),
    ] {
        if !v.is_empty() {
            m.insert(k.into(), json!(v));
        }
    }

    out
}

/// `GET /control/tls/status`
pub async fn tls_status(State(s): State<Shared>) -> Json<serde_json::Value> {
    let (st, t) = tls_report(&s);
    let plain = s.config.read().dns.serve_plain_dns;

    Json(tls_json(&st, &t, plain))
}

/// The encryption settings the interface sends.
#[derive(Deserialize, Clone, Default)]
pub struct TlsSettings {
    /// Whether encryption is on.
    #[serde(default)]
    pub enabled: bool,
    /// The hostname the certificate is for.
    #[serde(default)]
    pub server_name: String,
    /// Whether plain HTTP redirects to HTTPS.
    #[serde(default)]
    pub force_https: bool,
    /// The HTTPS port.
    #[serde(default)]
    pub port_https: u16,
    /// The DNS-over-TLS port.
    #[serde(default)]
    pub port_dns_over_tls: u16,
    /// The DNS-over-QUIC port.
    #[serde(default)]
    pub port_dns_over_quic: u16,
    /// The PEM-encoded certificate chain.
    #[serde(default)]
    pub certificate_chain: String,
    /// The PEM-encoded private key.
    #[serde(default)]
    pub private_key: String,
    /// A path to the certificate chain.
    #[serde(default)]
    pub certificate_path: String,
    /// A path to the private key.
    #[serde(default)]
    pub private_key_path: String,
    /// Whether plain DNS is still served.
    #[serde(default = "default_true_bool")]
    pub serve_plain_dns: bool,
}

/// The default for `serve_plain_dns`, which is on unless turned off.
fn default_true_bool() -> bool {
    true
}

/// Inspects a proposed certificate without storing it.
fn inspect_settings(req: &TlsSettings) -> sift_dns::tls::Status {
    let src = sift_dns::tls::Source {
        certificate_chain: req.certificate_chain.clone(),
        private_key: req.private_key.clone(),
        certificate_path: req.certificate_path.clone(),
        private_key_path: req.private_key_path.clone(),
    };

    if src.is_empty() {
        sift_dns::tls::Status::default()
    } else {
        sift_dns::tls::inspect(&src)
    }
}

/// Copies the proposed settings into a config block.
fn settings_to_config(req: &TlsSettings, t: &mut sift_config::model::TlsConfig) {
    t.enabled = req.enabled;
    t.server_name = req.server_name.clone();
    t.force_https = req.force_https;
    t.port_https = req.port_https;
    t.port_dns_over_tls = req.port_dns_over_tls;
    t.port_dns_over_quic = req.port_dns_over_quic;
    t.certificate_chain = req.certificate_chain.clone();
    t.private_key = req.private_key.clone();
    t.certificate_path = req.certificate_path.clone();
    t.private_key_path = req.private_key_path.clone();
}

/// `POST /control/tls/validate`
///
/// Reports on a certificate the user is still editing without storing it.
pub async fn tls_validate(
    State(s): State<Shared>,
    Json(req): Json<TlsSettings>,
) -> Json<serde_json::Value> {
    let _ = &s;
    let st = inspect_settings(&req);

    let mut t = sift_config::model::TlsConfig::default();
    settings_to_config(&req, &mut t);

    Json(tls_json(&st, &t, req.serve_plain_dns))
}

/// `POST /control/tls/configure`
///
/// Stores the settings, refusing a certificate that cannot be served: saving
/// one would leave the listeners unable to start on the next restart.
pub async fn tls_configure(
    State(s): State<Shared>,
    Json(req): Json<TlsSettings>,
) -> ApiResult<Json<serde_json::Value>> {
    let st = inspect_settings(&req);

    let configured = !req.certificate_chain.is_empty()
        || !req.certificate_path.is_empty()
        || !req.private_key.is_empty()
        || !req.private_key_path.is_empty();

    if req.enabled && !st.valid_pair {
        let why = if st.warning_validation.is_empty() {
            "a certificate and a matching private key are required".to_string()
        } else {
            st.warning_validation.clone()
        };

        return Err(ApiError::bad_request(format!(
            "encryption not enabled: {why}"
        )));
    }

    if req.enabled && req.port_https == 0 && req.port_dns_over_tls == 0 {
        return Err(ApiError::bad_request(
            "encryption not enabled: no port is set for HTTPS or DNS-over-TLS",
        ));
    }

    if configured && !st.valid_cert {
        return Err(ApiError::bad_request(format!(
            "invalid certificate: {}",
            st.warning_validation
        )));
    }

    {
        let mut cfg = s.config.write();
        settings_to_config(&req, &mut cfg.tls);
        cfg.dns.serve_plain_dns = req.serve_plain_dns;
    }

    s.save_config().map_err(ApiError::internal)?;

    let t = s.config.read().tls.clone();

    Ok(Json(tls_json(&st, &t, req.serve_plain_dns)))
}

/// `GET /control/dhcp/status`
///
/// This build has no DHCP server, so the status is always disabled and empty
/// regardless of what the configuration file holds.  Echoing a stored
/// `enabled: true` would tell the web interface a server is running when
/// nothing is serving leases.
///
/// The shape still matches upstream's `DhcpStatus`, so the interface renders
/// its DHCP page normally and shows the feature as off.
pub async fn dhcp_status() -> Json<serde_json::Value> {
    Json(json!({
        "interface_name": "",
        "v4": {
            "gateway_ip": "",
            "subnet_mask": "",
            "range_start": "",
            "range_end": "",
            "lease_duration": 0,
        },
        "v6": {
            "range_start": "",
            "lease_duration": 0,
        },
        "leases": [],
        "static_leases": [],
        "enabled": false,
    }))
}

/// `GET /control/dhcp/interfaces`
///
/// Always empty: with no DHCP server there is no interface to offer.
pub async fn dhcp_interfaces() -> Json<serde_json::Value> {
    Json(json!({}))
}

/// `GET /control/i18n/current_language`
pub async fn current_language(State(s): State<Shared>) -> String {
    s.config.read().language.clone()
}

/// `POST /control/i18n/change_language`
pub async fn change_language(State(s): State<Shared>, body: String) -> ApiResult<()> {
    let lang = body.trim().trim_matches('"').to_string();
    s.config.write().language = lang;

    s.save_config().map_err(ApiError::internal)
}

/// `GET /control/profile`
///
/// The name is the one the gate signed the request in as.  Working it out
/// again here meant a second bcrypt for every request carrying Basic
/// credentials, run while this held the config lock and then took it a
/// second time inside -- which a writer queued between the two would have
/// turned into a deadlock.
pub async fn profile(
    State(s): State<Shared>,
    user: Option<Extension<auth::SignedIn>>,
) -> Json<serde_json::Value> {
    let cfg = s.config.read();
    let name = user
        .map(|Extension(auth::SignedIn(name))| name)
        .unwrap_or_else(|| {
            cfg.users
                .first()
                .map(|u| u.name.clone())
                .unwrap_or_default()
        });

    Json(json!({
        "name": name,
        "language": cfg.language,
        "theme": cfg.theme,
    }))
}

/// The `/control/profile/update` request.
#[derive(Deserialize)]
pub struct ProfileUpdateReq {
    /// The UI language.
    #[serde(default)]
    pub language: Option<String>,
    /// The UI theme.
    #[serde(default)]
    pub theme: Option<String>,
}

/// `PUT /control/profile/update`
pub async fn profile_update(
    State(s): State<Shared>,
    Json(req): Json<ProfileUpdateReq>,
) -> ApiResult<()> {
    {
        let mut cfg = s.config.write();
        if let Some(l) = req.language {
            cfg.language = l;
        }
        if let Some(t) = req.theme {
            cfg.theme = match t.as_str() {
                "dark" => sift_config::model::Theme::Dark,
                "light" => sift_config::model::Theme::Light,
                _ => sift_config::model::Theme::Auto,
            };
        }
    }

    s.save_config().map_err(ApiError::internal)
}

/// Returns the name of the user whose session cookie the request carries.
///
/// Only the cookie: Basic credentials mean a password check, which is the
/// gate's to make, under the throttle -- see `routes::authenticate`.
pub fn session_user(s: &Shared, headers: &HeaderMap) -> Option<String> {
    let c = headers.get(header::COOKIE)?.to_str().ok()?;
    let tok = auth::token_from_cookies(c)?;

    s.sessions.get(tok).map(|sess| sess.user)
}

/// The stored hash of a user's password, if there is such a user.
///
/// A copy, so the check that follows runs without the config lock held: a
/// bcrypt takes long enough that holding a read lock through it stalls every
/// writer behind a stranger's guess.
pub fn stored_hash(s: &Shared, name: &str) -> Option<String> {
    s.config
        .read()
        .users
        .iter()
        .find(|u| u.name == name)
        .map(|u| u.password.clone())
}

/// The `/control/login` request.
/// Every field defaults: Go's `encoding/json` leaves a field the caller
/// omitted at its zero value rather than failing, so a partial body that
/// upstream answers 200 must not become a 422 here.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct LoginReq {
    /// The user name.
    pub name: String,
    /// The password.
    pub password: String,
}

/// `POST /control/login`
///
/// The throttle is consulted before the password is checked, which is the
/// order upstream's `handleLogin` uses: a blocked client is turned away
/// without its guess ever being compared, so a block costs the same whether
/// the guess was right or wrong.  Unlike upstream, an attempt from the
/// internet is counted before the check rather than after, and handed back
/// if it was right -- see [`auth::LoginLimiter::check`] -- so guesses sent
/// all at once cannot all slip under the threshold together.  A source the
/// connection guard spares is checked and counted as upstream does it; see
/// [`auth::Lane`].
pub async fn login(
    State(s): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginReq>,
) -> Response {
    let client = peer.ip().to_string();
    let hash = stored_hash(&s, &req.name);
    let lane = crate::routes::lane(&s, &client);
    let key = crate::routes::throttle_key(&s, &client);

    match s.login_limiter.check(&key, lane, req.password, hash).await {
        Verdict::Accepted => {}
        Verdict::Blocked(left) => return auth::too_many_attempts(left),
        Verdict::Busy => return auth::verifiers_busy(),
        Verdict::Rejected => {
            // 403, not the 401 this once answered: upstream's `handleLogin`
            // hands `newCookie`'s error to `writeErrorWithIP` with
            // `StatusForbidden`.
            return (StatusCode::FORBIDDEN, "invalid username or password").into_response();
        }
    }

    let ttl = Duration::from_secs(s.config.read().http.session_ttl.as_secs().max(1) as u64);
    let token = s.sessions.create(&req.name, ttl);

    let mut headers = HeaderMap::new();
    if let Ok(v) = auth::session_cookie(&token, ttl).parse() {
        headers.insert(header::SET_COOKIE, v);
    }

    (StatusCode::OK, headers).into_response()
}

/// `GET /control/logout`
pub async fn logout(State(s): State<Shared>, headers: HeaderMap) -> Response {
    if let Some(c) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok())
        && let Some(tok) = auth::token_from_cookies(c)
    {
        s.sessions.remove(tok);
    }

    let mut out = HeaderMap::new();
    if let Ok(v) = auth::clear_cookie().parse() {
        out.insert(header::SET_COOKIE, v);
    }
    if let Ok(v) = "/login.html".parse() {
        out.insert(header::LOCATION, v);
    }

    (StatusCode::FOUND, out).into_response()
}

/// `GET /control/install/get_addresses`
/// The DNS port the wizard suggests, which upstream hard-codes.
const DEFAULT_PORT_DNS: u16 = 53;

/// The admin port the wizard suggests when the environment says nothing.
const DEFAULT_PORT_HTTP: u16 = 80;

/// The environment variable upstream lets a deployment override it with.
const WEB_PORT_ENV: &str = "ADGUARD_HOME_DEFAULT_WEB_PORT";

/// The admin port the setup wizard should offer.
///
/// This is a *suggestion* for the finished install, not the port the wizard is
/// being served on: upstream answers 80 here while listening on 3000, so the
/// finished server ends up on 80 unless the operator says otherwise.  Echoing
/// the live port instead — which is what this did — quietly moved every fresh
/// install to 3000.  A container that sets `ADGUARD_HOME_DEFAULT_WEB_PORT`
/// gets that instead, as it would under the Go build.
fn suggested_web_port() -> u16 {
    parse_web_port(std::env::var(WEB_PORT_ENV).ok().as_deref())
}

/// Applies upstream's rule to an override, so the rule can be tested without
/// writing to the process environment.
///
/// Anything that is not a port in 1..=65535 is a warning and the default, as
/// `suggestedWebPort` does.
fn parse_web_port(raw: Option<&str>) -> u16 {
    let Some(raw) = raw else {
        return DEFAULT_PORT_HTTP;
    };

    match raw.parse::<u16>() {
        Ok(p) if p != 0 => p,
        _ => {
            tracing::warn!(
                env = WEB_PORT_ENV,
                val = %raw,
                "invalid web port; using default"
            );

            DEFAULT_PORT_HTTP
        }
    }
}

pub async fn install_addresses() -> Json<serde_json::Value> {
    Json(json!({
        "web_port": suggested_web_port(),
        "dns_port": DEFAULT_PORT_DNS,
        "interfaces": crate::netiface::all(),
        "version": sift_core::VERSION,
    }))
}

/// The `/control/install/check_config` request.
#[derive(Deserialize)]
pub struct CheckConfigReq {
    /// The proposed web interface binding.
    #[serde(default)]
    pub web: Option<PortCheck>,
    /// The proposed DNS binding.
    #[serde(default)]
    pub dns: Option<PortCheck>,
    /// Whether to set the system resolver.
    #[serde(default)]
    pub set_static_ip: bool,
}

/// A proposed address and port.
#[derive(Deserialize, Default)]
pub struct PortCheck {
    /// The address to bind.
    #[serde(default)]
    pub ip: Option<String>,
    /// The port to bind.
    #[serde(default)]
    pub port: Option<u16>,
    /// Whether the port is being changed.
    #[serde(default)]
    pub autofix: bool,
}

/// `POST /control/install/check_config`
pub async fn install_check(Json(_req): Json<CheckConfigReq>) -> Json<serde_json::Value> {
    Json(json!({
        "web": { "status": "" },
        "dns": { "status": "" },
        "static_ip": { "static": "no", "ip": "", "error": "" },
    }))
}

/// The `/control/install/configure` request.
/// Every field defaults: Go's `encoding/json` leaves a field the caller
/// omitted at its zero value rather than failing, so a partial body that
/// upstream answers 200 must not become a 422 here.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct InstallReq {
    /// The web interface binding.
    pub web: PortCheck,
    /// The DNS binding.
    pub dns: PortCheck,
    /// The administrator's name.
    pub username: String,
    /// The administrator's password.
    pub password: String,
}

/// `POST /control/install/configure`
pub async fn install_configure(
    State(s): State<Shared>,
    Json(req): Json<InstallReq>,
) -> ApiResult<()> {
    if req.username.trim().is_empty() || req.password.is_empty() {
        return Err(ApiError::bad_request(
            "a username and password are required",
        ));
    }
    if !s.needs_install() {
        return Err(ApiError::forbidden(
            "this installation is already configured",
        ));
    }

    let hash = auth::hash_password(&req.password)
        .map_err(|e| ApiError::internal(format!("hashing the password: {e}")))?;

    {
        let mut cfg = s.config.write();
        cfg.users = vec![sift_config::model::WebUser {
            name: req.username,
            password: hash,
        }];

        if let Some(p) = req.dns.port {
            cfg.dns.port = p;
        }
        if let Some(ip) = req.dns.ip.as_deref().and_then(|i| i.parse().ok()) {
            cfg.dns.bind_hosts = vec![ip];
        }
        if let (Some(ip), Some(port)) = (
            req.web
                .ip
                .as_deref()
                .and_then(|i| i.parse::<std::net::IpAddr>().ok()),
            req.web.port,
        ) {
            cfg.http.address = sift_config::types::AddrPort(std::net::SocketAddr::new(ip, port));
        }
    }

    s.save_config().map_err(ApiError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wizard_suggests_the_port_the_go_build_suggests() {
        // Verified against adguard/adguardhome:v0.107.79 on a fresh install:
        //   {"version":"v0.107.79","web_port":80,"dns_port":53}
        // These are suggestions for the finished install, not the ports the
        // wizard is being served on.  Echoing the live ports instead put every
        // fresh install's admin interface on 3000.
        assert_eq!(DEFAULT_PORT_DNS, 53);
        assert_eq!(parse_web_port(None), 80, "no override means 80");
        assert_eq!(
            parse_web_port(Some("8080")),
            8080,
            "a container may override it"
        );

        for bad in ["0", "", "not a port", "70000", "-1"] {
            assert_eq!(
                parse_web_port(Some(bad)),
                80,
                "{bad:?} is not a port; upstream warns and falls back"
            );
        }
    }

    #[tokio::test]
    async fn dhcp_status_is_always_disabled_and_empty() {
        // Whatever the config says, this build serves no leases, so the status
        // must not claim a server is running.
        let Json(v) = dhcp_status().await;

        assert_eq!(v["enabled"], serde_json::json!(false));
        assert_eq!(v["interface_name"], serde_json::json!(""));
        assert_eq!(v["leases"], serde_json::json!([]));
        assert_eq!(v["static_leases"], serde_json::json!([]));
        assert_eq!(v["v4"]["range_start"], serde_json::json!(""));
        assert_eq!(v["v6"]["range_start"], serde_json::json!(""));
    }

    #[tokio::test]
    async fn dhcp_status_keeps_the_shape_the_interface_expects() {
        // The web interface reads these keys even when the feature is off.
        let Json(v) = dhcp_status().await;

        for key in [
            "enabled",
            "interface_name",
            "v4",
            "v6",
            "leases",
            "static_leases",
        ] {
            assert!(v.get(key).is_some(), "missing {key}");
        }
        for key in [
            "gateway_ip",
            "subnet_mask",
            "range_start",
            "range_end",
            "lease_duration",
        ] {
            assert!(v["v4"].get(key).is_some(), "missing v4.{key}");
        }
        for key in ["range_start", "lease_duration"] {
            assert!(v["v6"].get(key).is_some(), "missing v6.{key}");
        }
    }

    #[tokio::test]
    async fn dhcp_interfaces_is_empty() {
        let Json(v) = dhcp_interfaces().await;
        assert_eq!(v, serde_json::json!({}));
    }

    #[test]
    fn query_parameters_are_read_and_decoded() {
        assert_eq!(
            query_param("ip0=192.0.2.5&ip1=192.0.2.6", "ip1").as_deref(),
            Some("192.0.2.6")
        );
        assert_eq!(query_param("ip0=a%3Ab", "ip0").as_deref(), Some("a:b"));
        assert_eq!(query_param("ip0=a+b", "ip0").as_deref(), Some("a b"));
        assert_eq!(query_param("ip0=x", "ip1"), None);
    }

    #[test]
    fn whois_fields_are_always_an_object() {
        assert_eq!(whois_json(&[]), serde_json::json!({}));
        assert_eq!(
            whois_json(&[("city".into(), "Ashburn".into())]),
            serde_json::json!({ "city": "Ashburn" })
        );
    }

    #[test]
    fn a_bad_access_entry_is_refused_rather_than_stored() {
        // Storing one meant writing it to the config file and then dropping
        // it when the lists were built, so an allowlist could quietly become
        // empty -- which admits everybody.
        let ok = |v: &[&str]| {
            validate_access_clients("allowed clients", &to_strings(v)).map_err(|e| e.message)
        };

        ok(&["10.0.0.1", "172.17.0.0/16", "mi12t", "2001:db8::/32"])
            .expect("every documented form must be accepted");

        let e = ok(&["10.0.0.1", "not a client"]).expect_err("must be refused");
        assert!(e.contains("index 1"), "{e}");
        assert!(e.contains("bad ip, cidr, or clientid"), "{e}");

        let e = ok(&["mi12t", "mi12t"]).expect_err("duplicates must be refused");
        assert!(e.contains("duplicated values"), "{e}");
    }

    #[test]
    fn both_access_lists_may_hold_entries() {
        // Upstream refuses only an entry appearing in *both* -- the
        // disallowed list is ignored while the allowed one is set, which is
        // what the interface tells the user. Refusing the pair outright, as
        // this did, rejects a configuration the Go build accepts.
        let allowed = to_strings(&["10.0.0.1"]);
        let disallowed = to_strings(&["10.0.0.2"]);
        assert!(allowed.iter().all(|a| !disallowed.contains(a)));

        assert_eq!(first_duplicate(&to_strings(&["a", "b", "a"])), Some("a"));
        assert_eq!(first_duplicate(&to_strings(&["a", "b"])), None);
    }

    /// Owned strings for the list helpers, which take `&[String]`.
    fn to_strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn the_supported_tag_list_matches_the_ui() {
        // These are exactly what /control/clients reports upstream.
        assert_eq!(SUPPORTED_TAGS.len(), 21);
        assert!(SUPPORTED_TAGS.contains(&"device_phone"));
        assert!(SUPPORTED_TAGS.contains(&"os_windows"));
        assert!(SUPPORTED_TAGS.contains(&"user_child"));
        assert!(
            SUPPORTED_TAGS.windows(2).all(|w| w[0] < w[1]),
            "kept sorted"
        );
    }
}
