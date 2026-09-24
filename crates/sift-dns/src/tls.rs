//! Server-side TLS: loading a certificate and key, and reporting on them.
//!
//! The report feeds `/control/tls/status` and `/control/tls/validate`, which
//! the web interface uses to tell the user whether their certificate is
//! usable, so the checks here have to be the ones a user would expect: does
//! the chain parse, does the key parse, do they belong together, and what
//! names and dates does the certificate carry.
//!
//! Two more things are about what a stranger's handshake costs:
//!
//! - **`tls.strict_sni_check`** refuses a DNS-over-TLS or DNS-over-QUIC
//!   handshake whose server name the certificate does not cover, before
//!   anything is signed -- see [`any_name_matches`] for exactly which names
//!   pass, copied from upstream.  HTTPS and HTTP/3 never apply it, because
//!   upstream's web server does not.
//! - **Session resumption is stateless**, on every configuration built here.
//!   A reconnecting client carries its own resumption state in a ticket
//!   rather than holding one of 256 slots in a cache that every scanner's
//!   handshake also writes to, so a scan cannot push real clients back onto
//!   full handshakes.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Where a certificate and key come from.
///
/// Upstream accepts either the PEM inline in the config or a path to a file,
/// and rejects a config that sets both for the same item.
#[derive(Clone, Debug, Default)]
pub struct Source {
    /// The PEM-encoded certificate chain.
    pub certificate_chain: String,
    /// The PEM-encoded private key.
    pub private_key: String,
    /// A path to read the certificate chain from.
    pub certificate_path: String,
    /// A path to read the private key from.
    pub private_key_path: String,
}

impl Source {
    /// Reports whether anything at all was configured.
    pub fn is_empty(&self) -> bool {
        self.certificate_chain.is_empty()
            && self.certificate_path.is_empty()
            && self.private_key.is_empty()
            && self.private_key_path.is_empty()
    }

    /// Reports whether any part of the pair is read from a file.
    ///
    /// Only a file can change underneath a running server: PEM held inline in
    /// the config is replaced through `/control/tls/configure`, which installs
    /// it itself.  This is what decides whether there is anything to watch.
    pub fn reads_files(&self) -> bool {
        !self.certificate_path.is_empty() || !self.private_key_path.is_empty()
    }

    /// Reads the certificate PEM, from the config or from disk.
    fn cert_pem(&self) -> Result<String, Error> {
        match (
            self.certificate_chain.is_empty(),
            self.certificate_path.is_empty(),
        ) {
            (false, false) => Err(Error::Conflict(
                "set either certificate_chain or certificate_path, not both",
            )),
            (false, true) => Ok(self.certificate_chain.clone()),
            (true, false) => std::fs::read_to_string(&self.certificate_path)
                .map_err(|e| Error::Read(self.certificate_path.clone(), e.to_string())),
            (true, true) => Err(Error::Missing("no certificate configured")),
        }
    }

    /// Reads the private key PEM, from the config or from disk.
    fn key_pem(&self) -> Result<String, Error> {
        match (
            self.private_key.is_empty(),
            self.private_key_path.is_empty(),
        ) {
            (false, false) => Err(Error::Conflict(
                "set either private_key or private_key_path, not both",
            )),
            (false, true) => Ok(self.private_key.clone()),
            (true, false) => std::fs::read_to_string(&self.private_key_path)
                .map_err(|e| Error::Read(self.private_key_path.clone(), e.to_string())),
            (true, true) => Err(Error::Missing("no private key configured")),
        }
    }
}

/// Why a certificate or key could not be used.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Both the inline and the path form were given for one item.
    #[error("{0}")]
    Conflict(&'static str),

    /// Neither form was given.
    #[error("{0}")]
    Missing(&'static str),

    /// A file could not be read.
    #[error("reading {0}: {1}")]
    Read(String, String),

    /// The PEM held no usable item.
    #[error("{0}")]
    Parse(String),

    /// The key does not match the certificate.
    #[error("the private key does not match the certificate")]
    Mismatch,

    /// rustls refused the pair.
    #[error("tls: {0}")]
    Rustls(String),
}

/// What is known about a configured certificate.
///
/// Mirrors the fields `/control/tls/status` reports.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// Whether the chain parsed.
    pub valid_cert: bool,
    /// Whether the chain is complete and self-consistent.
    pub valid_chain: bool,
    /// Whether the key parsed.
    pub valid_key: bool,
    /// Whether the key belongs to the certificate.
    pub valid_pair: bool,
    /// The names the certificate covers.
    ///
    /// DNS names only, as upstream's `dns_names` field is: the IP addresses a
    /// certificate may also carry are reported by [`Status::has_ip_addresses`]
    /// instead, because the API's field is compared against Go's.
    pub dns_names: Vec<String>,
    /// Whether the certificate names any IP address.
    ///
    /// Discovery of Designated Resolvers only advertises DNS-over-TLS when it
    /// does: a client that found this resolver by address has no hostname to
    /// validate the certificate against.
    pub has_ip_addresses: bool,
    /// When the certificate becomes valid, in Go's zero-time-aware format.
    pub not_before: String,
    /// When the certificate expires.
    pub not_after: String,
    /// The key's algorithm, as upstream words it.
    pub key_type: String,
    /// The certificate's subject.
    pub subject: String,
    /// The certificate's issuer.
    pub issuer: String,
    /// Why the certificate is unusable, if it is.
    pub warning_validation: String,
}

/// A loaded, ready-to-serve certificate.
pub struct Loaded {
    /// The rustls configuration for DNS-over-TLS.
    pub dot: Arc<ServerConfig>,
    /// The rustls configuration for HTTPS and DNS-over-HTTPS, which differs
    /// only in the protocols it advertises.
    pub https: Arc<ServerConfig>,
    /// The rustls configuration for HTTP/3, which QUIC carries and which
    /// therefore needs its own ALPN identifier.
    pub h3: Arc<ServerConfig>,
    /// The rustls configuration for DNS-over-QUIC.
    ///
    /// Separate because QUIC requires TLS 1.3 and its own ALPN identifier.
    pub doq: Arc<ServerConfig>,
    /// What to report about the certificate.
    pub status: Status,
}

/// Parses a certificate chain from PEM.
fn parse_chain(pem: &str) -> Result<Vec<CertificateDer<'static>>, Error> {
    let mut r = std::io::BufReader::new(pem.as_bytes());
    let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut r)
        .collect::<Result<_, _>>()
        .map_err(|e| Error::Parse(format!("parsing the certificate chain: {e}")))?;

    if chain.is_empty() {
        return Err(Error::Parse(
            "the certificate chain holds no certificate".into(),
        ));
    }

    Ok(chain)
}

/// Parses a private key from PEM, accepting the forms rustls supports.
fn parse_key(pem: &str) -> Result<PrivateKeyDer<'static>, Error> {
    let mut r = std::io::BufReader::new(pem.as_bytes());

    rustls_pemfile::private_key(&mut r)
        .map_err(|e| Error::Parse(format!("parsing the private key: {e}")))?
        .ok_or_else(|| Error::Parse("the private key holds no key".into()))
}

/// Describes a certificate without building a server configuration.
///
/// This is what `/control/tls/validate` needs: an answer about a certificate
/// the user is still editing, which may well be unusable.
pub fn inspect(src: &Source) -> Status {
    let mut st = Status::default();

    let cert_pem = match src.cert_pem() {
        Ok(p) => p,
        Err(e) => {
            st.warning_validation = e.to_string();

            return st;
        }
    };

    let chain = match parse_chain(&cert_pem) {
        Ok(c) => c,
        Err(e) => {
            st.warning_validation = e.to_string();

            return st;
        }
    };

    st.valid_cert = true;
    // A chain is usable when every certificate in it parsed; rustls performs
    // the ordering and trust checks when it builds the configuration.
    st.valid_chain = chain.len() > 1;
    describe_leaf(&chain[0], &mut st);

    let key_pem = match src.key_pem() {
        Ok(p) => p,
        Err(e) => {
            st.warning_validation = e.to_string();

            return st;
        }
    };

    let key = match parse_key(&key_pem) {
        Ok(k) => k,
        Err(e) => {
            st.warning_validation = e.to_string();

            return st;
        }
    };

    st.valid_key = true;

    // The pair is proven by asking rustls to build a configuration from it:
    // that is the same check the server itself performs.
    match build(chain.clone(), key) {
        Ok(_) => st.valid_pair = true,
        Err(e) => {
            st.warning_validation = e.to_string();

            return st;
        }
    }

    // A usable pair can still be one no client will accept -- self-signed, or
    // missing its intermediates.  Upstream serves it anyway and says so, which
    // is the only way the operator finds out before their clients do.
    if let Err(why) = verify_chain(&chain, &st.dns_names) {
        st.warning_validation = why;
    }

    st
}

/// Checks the chain against the trusted roots, as a client would.
///
/// Returns why it failed, or `Ok` when it verifies.
fn verify_chain(chain: &[CertificateDer<'static>], names: &[String]) -> Result<(), String> {
    use rustls::client::verify_server_cert_signed_by_trust_anchor;
    use rustls::server::ParsedCertificate;

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let parsed = ParsedCertificate::try_from(&chain[0])
        .map_err(|e| format!("validating certificate pair: {e}"))?;

    let intermediates = &chain[1..];
    let now = rustls_pki_types::UnixTime::now();

    verify_server_cert_signed_by_trust_anchor(
        &parsed,
        &roots,
        intermediates,
        now,
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .all,
    )
    .map_err(|e| format!("validating certificate pair: certificate does not verify: {e}"))?;

    let _ = names;

    Ok(())
}

/// Fills in the fields taken from the leaf certificate.
///
/// Returns when the certificate expires, in seconds since the Unix epoch, for
/// the callers that have to act on it rather than report it.
fn describe_leaf(leaf: &CertificateDer<'_>, st: &mut Status) -> Option<i64> {
    use x509_parser::prelude::*;

    let Ok((_, cert)) = X509Certificate::from_der(leaf.as_ref()) else {
        st.warning_validation = "the certificate could not be decoded".into();

        return None;
    };

    let not_after = cert.validity().not_after.timestamp();

    st.key_type = public_key_name(&cert);
    st.subject = cert.subject().to_string();
    st.issuer = cert.issuer().to_string();
    st.not_before = format_time(cert.validity().not_before.timestamp());
    st.not_after = format_time(not_after);

    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(n) => st.dns_names.push((*n).to_string()),
                GeneralName::IPAddress(_) => st.has_ip_addresses = true,
                _ => {}
            }
        }
    }

    // A certificate with no SAN falls back to its common name, as clients did
    // before SANs were required.
    if st.dns_names.is_empty() {
        for cn in cert.subject().iter_common_name() {
            if let Ok(s) = cn.as_str() {
                st.dns_names.push(s.to_string());
            }
        }
    }

    Some(not_after)
}

/// Names the certificate's public key algorithm.
///
/// Upstream reports the algorithm -- `RSA`, `ECDSA` -- not the PEM container
/// the private key arrived in, which may be PKCS#8 for either.
fn public_key_name(cert: &x509_parser::certificate::X509Certificate<'_>) -> String {
    use x509_parser::public_key::PublicKey;

    match cert.public_key().parsed() {
        Ok(PublicKey::RSA(_)) => "RSA".to_string(),
        Ok(PublicKey::EC(_)) => "ECDSA".to_string(),
        Ok(PublicKey::DSA(_)) => "DSA".to_string(),
        _ => "unknown".to_string(),
    }
}

/// Formats a certificate timestamp the way Go's JSON encoder would.
fn format_time(unix: i64) -> String {
    jiff::Timestamp::from_second(unix)
        .map(sift_core::gotime::format_utc)
        .unwrap_or_else(|_| sift_core::gotime::GO_ZERO_TIME.to_string())
}

/// The names a strict server-name check accepts for a certificate.
///
/// Upstream's `replaceGetCertificate` takes the leaf's `DNSNames` -- the
/// subject alternative names of DNS type, IP addresses not among them -- and
/// only when there are none, the subject's common name.  Go keeps the *last*
/// common name the subject carries, so that is the one taken here.  A
/// certificate with neither yields one empty name, which matches nothing: in
/// strict mode such a certificate refuses every handshake, as upstream's does.
fn sni_names(leaf: &CertificateDer<'_>) -> Vec<String> {
    use x509_parser::prelude::*;

    let Ok((_, cert)) = X509Certificate::from_der(leaf.as_ref()) else {
        return Vec::new();
    };

    let mut names = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(n) = name {
                names.push((*n).to_string());
            }
        }
    }

    if names.is_empty() {
        let cn = cert
            .subject()
            .iter_common_name()
            .filter_map(|cn| cn.as_str().ok())
            .last()
            .unwrap_or_default();
        names.push(cn.to_string());
    }

    names
}

/// Reports whether the server name a client sent is one the certificate
/// covers, exactly as upstream's `anyNameMatches` decides it.
///
/// ```go
/// if !netutil.IsValidHostname(sni) && !netutil.IsValidIPString(sni) { return false }
/// if _, ok = slices.BinarySearch(dnsNames, sni); ok { return true }
/// for _, dn := range dnsNames { if matchesDomainWildcard(sni, dn) { return true } }
/// ```
///
/// which comes to this:
///
/// - **No server name is refused.**  Go reports a missing one as the empty
///   string, which is not a valid hostname.  rustls also reports an IP
///   address sent as a server name as no server name at all, so that is
///   refused too -- upstream would accept one only if the certificate listed
///   the address as a *DNS* name, which no issuer does.
/// - **An exact match passes**, compared byte for byte.  rustls hands over the
///   name already lowercased, and upstream compares case-sensitively against
///   the certificate as issued, so a certificate name with a capital letter
///   in it matches nothing here -- as it matches nothing a client sending a
///   lowercase name asks upstream for.
/// - **A wildcard matches any depth.**  `*.example.com` is only the suffix
///   `.example.com` to upstream, so `a.b.example.com` passes, and
///   `example.com` itself does not.
/// - **Anything that is not a valid hostname is refused** before it is
///   compared, which includes a name with an underscore or a trailing dot.
pub fn any_name_matches(names: &[String], sni: Option<&str>) -> bool {
    let Some(sni) = sni else {
        return false;
    };

    if !is_valid_hostname(sni) {
        return false;
    }

    names.iter().any(|n| n == sni)
        || names
            .iter()
            .any(|n| n.starts_with("*.") && sni.ends_with(&n[1..]))
}

/// Upstream's `netutil.IsValidHostname`, for the ASCII names rustls hands
/// over: at most 253 bytes, labels of letters, digits and inner hyphens of at
/// most 63 bytes each, and a last label that is not all digits.
fn is_valid_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }

    let mut labels = name.split('.').peekable();
    while let Some(label) = labels.next() {
        let last = labels.peek().is_none();
        let bytes = label.as_bytes();
        let outer = |b: u8| b.is_ascii_alphanumeric();

        let valid = match bytes {
            [] => false,
            [only] => outer(*only),
            [first, inner @ .., end] => {
                bytes.len() <= 63
                    && outer(*first)
                    && outer(*end)
                    && inner.iter().all(|&b| outer(b) || b == b'-')
            }
        };
        if !valid || (last && bytes.iter().all(u8::is_ascii_digit)) {
            return false;
        }
    }

    true
}

/// A certificate that can be replaced while the listeners keep running.
///
/// rustls takes the certificate when a `ServerConfig` is built, so a listener
/// started with one keeps it for life.  Handing it a resolver instead means a
/// certificate replaced through `/control/tls/configure` -- or rewritten on
/// disk by whatever renews it -- takes effect on the next handshake rather
/// than at the next restart.
///
/// It also carries `tls.strict_sni_check`, which the DNS-over-TLS and
/// DNS-over-QUIC configurations built by [`reloadable`] consult on every
/// handshake, so that saving the setting reaches running listeners the way a
/// new certificate does.
#[derive(Debug, Default)]
pub struct Reloadable {
    /// The certificate currently being served.
    current: parking_lot::RwLock<Option<Slot>>,
    /// Whether DNS-over-TLS and DNS-over-QUIC refuse a server name the
    /// certificate does not cover.
    strict_sni: AtomicBool,
}

/// What a [`Reloadable`] is serving, and what it was built from.
///
/// One lock holds all of it: a fingerprint that disagreed with the
/// certificate beside it would send a renewal check the wrong way, and names
/// that belonged to another certificate would let a strict check pass or
/// fail on the wrong one.
#[derive(Debug)]
struct Slot {
    /// What rustls hands to a handshake.
    key: Arc<rustls::sign::CertifiedKey>,
    /// The names a strict server-name check accepts; see [`sni_names`].
    names: Vec<String>,
    /// A digest of the PEM this was read from.
    fingerprint: [u8; 32],
    /// When the leaf expires, in seconds since the Unix epoch, when the
    /// certificate could be decoded far enough to say.
    not_after: Option<i64>,
}

impl Reloadable {
    /// An empty slot, serving nothing until a certificate is installed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs a certificate and key, replacing whatever was there.
    fn set(
        &self,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        fingerprint: [u8; 32],
        not_after: Option<i64>,
    ) -> Result<(), Error> {
        let signing = rustls::crypto::ring::sign::any_supported_type(&key)
            .map_err(|e| Error::Rustls(format!("using the private key: {e}")))?;
        let names = sni_names(&chain[0]);

        *self.current.write() = Some(Slot {
            key: Arc::new(rustls::sign::CertifiedKey::new(chain, signing)),
            names,
            fingerprint,
            not_after,
        });

        Ok(())
    }

    /// Switches the strict server-name check on or off.
    ///
    /// This is `tls.strict_sni_check`.  It applies to DNS-over-TLS and
    /// DNS-over-QUIC from their next handshake, and never to HTTPS or HTTP/3.
    pub fn set_strict_sni(&self, on: bool) {
        self.strict_sni.store(on, Ordering::Relaxed);
    }

    /// Reports whether the strict server-name check is on.
    pub fn strict_sni(&self) -> bool {
        self.strict_sni.load(Ordering::Relaxed)
    }

    /// Reports whether a certificate is installed.
    pub fn is_loaded(&self) -> bool {
        self.current.read().is_some()
    }

    /// When the certificate being served expires, in seconds since the Unix
    /// epoch.
    ///
    /// `None` when nothing is installed, or when the certificate did not
    /// decode far enough to carry a date.
    pub fn expires_at(&self) -> Option<i64> {
        self.current.read().as_ref()?.not_after
    }

    /// The digest of the PEM the served certificate was read from.
    fn fingerprint(&self) -> Option<[u8; 32]> {
        Some(self.current.read().as_ref()?.fingerprint)
    }
}

impl rustls::server::ResolvesServerCert for Reloadable {
    fn resolve(
        &self,
        _hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.current.read().as_ref()?.key.clone())
    }
}

/// The certificate resolver for DNS-over-TLS and DNS-over-QUIC, which applies
/// `tls.strict_sni_check` when it is on.
///
/// Upstream wraps the certificate callback of exactly these two listeners in
/// `replaceGetCertificate`; its web server, which carries HTTPS and
/// DNS-over-HTTPS, is built without it.  Refusing here refuses before
/// anything is signed, which is the whole cost of a handshake: rustls answers
/// the ClientHello with an alert, and the listener counts the failed
/// handshake against the source as it counts any other.
#[derive(Debug)]
struct StrictSni(Arc<Reloadable>);

impl rustls::server::ResolvesServerCert for StrictSni {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let current = self.0.current.read();
        let slot = current.as_ref()?;

        if self.0.strict_sni() && !any_name_matches(&slot.names, hello.server_name()) {
            // Upstream warns here, once per handshake.  That is a line per
            // connection for anyone dialling the port by address, which is
            // what the rustls filter in `main.rs` exists to keep out of the
            // log, so it is a debug line here.
            tracing::debug!(
                server_name = hello.server_name().unwrap_or_default(),
                "unknown sni in client hello"
            );

            return None;
        }

        Some(slot.key.clone())
    }
}

/// Makes session resumption stateless, for every listener alike.
///
/// rustls resumes from a 256-entry cache by default, and every handshake that
/// completes writes to it -- a scanner's as much as a client's -- so a scan
/// of a hundred-odd connections is enough to push every real client back
/// onto a full handshake.  A ticket carries the state with the client
/// instead, sealed under a key only this process holds and rotates every six
/// hours, so there is nothing here for a scan to evict.
///
/// One ticket per handshake rather than rustls' two.  A client that resumes
/// is given a fresh one each time, so a client reconnecting in turn always
/// has one in hand; the second would only serve a client opening connections
/// in parallel, which a DNS client and an HTTP/2 browser do not, and it would
/// double what each scanner's handshake costs to send.
///
/// Each configuration gets its own ticket key, so a ticket issued for one
/// protocol resumes nothing on another.  The key lives with the
/// configuration, which is built once for the life of the process: a
/// certificate installed later reaches the listeners through the resolver,
/// not by rebuilding them, so tickets issued before a renewal still resume
/// after it.  Across a restart they do not, and a client simply makes one
/// full handshake.
///
/// Early data stays off: `max_early_data_size` is left at rustls' zero, since
/// a replayed query is a replayed query, and quinn keeps it that way.
fn resume_statelessly(c: &mut ServerConfig) {
    match rustls::crypto::ring::Ticketer::new() {
        Ok(t) => {
            c.ticketer = t;
            c.send_tls13_tickets = 1;
        }
        // Only a failure to gather randomness, which leaves the default
        // cache in place rather than a listener that cannot start.
        Err(e) => tracing::warn!(error = %e, "tls session tickets are unavailable"),
    }
}

/// Digests the PEM a certificate and key were read from.
///
/// Comparing the bytes is what distinguishes a renewal from a file that has
/// merely been read again: a renewal script rewrites both files on a schedule
/// whether or not the contents moved, and rebuilding the signing key for a
/// file that did not change would churn the listeners for nothing.
fn fingerprint(cert_pem: &str, key_pem: &str) -> [u8; 32] {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(cert_pem.as_bytes());
    // The two are hashed with a separator, so moving bytes from the end of one
    // to the start of the other cannot go unnoticed.
    ctx.update(&[0]);
    ctx.update(key_pem.as_bytes());

    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());

    out
}

/// Builds the four server configurations around one reloadable certificate.
///
/// Each listener advertises its own protocol, but they share the certificate,
/// so replacing it reaches all of them at once.  DNS-over-TLS and
/// DNS-over-QUIC resolve it through [`StrictSni`], so `tls.strict_sni_check`
/// reaches them too; HTTPS and HTTP/3 resolve it directly.
pub fn reloadable(resolver: Arc<Reloadable>) -> Loaded {
    let make = |alpn: Vec<Vec<u8>>, strict: bool| {
        let builder = ServerConfig::builder().with_no_client_auth();
        let mut c = if strict {
            builder.with_cert_resolver(Arc::new(StrictSni(resolver.clone())))
        } else {
            builder.with_cert_resolver(resolver.clone())
        };
        c.alpn_protocols = alpn;
        resume_statelessly(&mut c);

        Arc::new(c)
    };

    Loaded {
        dot: make(vec![b"dot".to_vec()], true),
        https: make(vec![b"h2".to_vec(), b"http/1.1".to_vec()], false),
        h3: make(vec![b"h3".to_vec()], false),
        doq: make(vec![b"doq".to_vec()], true),
        status: Status::default(),
    }
}

/// Parses a source and installs it into a reloadable slot.
pub fn install(src: &Source, into: &Reloadable) -> Result<Status, Error> {
    let cert_pem = src.cert_pem()?;
    let key_pem = src.key_pem()?;

    install_pem(&cert_pem, &key_pem, fingerprint(&cert_pem, &key_pem), into)
}

/// Reinstalls the certificate, but only when the source has changed.
///
/// A certificate is renewed by something else -- certbot, acme.sh, a mounted
/// secret -- which rewrites the files underneath a running server and has no
/// way to tell it.  Nothing in the config changes when that happens, so
/// comparing what the files now hold against what is being served is the only
/// thing standing between a renewal and an expired certificate served until
/// the next restart.
///
/// Returns the new status when a replacement was installed, and `None` when
/// the source holds what is already being served.
pub fn refresh(src: &Source, into: &Reloadable) -> Result<Option<Status>, Error> {
    let cert_pem = src.cert_pem()?;
    let key_pem = src.key_pem()?;

    let fp = fingerprint(&cert_pem, &key_pem);
    if into.fingerprint() == Some(fp) {
        return Ok(None);
    }

    install_pem(&cert_pem, &key_pem, fp, into).map(Some)
}

/// Installs PEM that has already been read.
fn install_pem(
    cert_pem: &str,
    key_pem: &str,
    fingerprint: [u8; 32],
    into: &Reloadable,
) -> Result<Status, Error> {
    let chain = parse_chain(cert_pem)?;
    let key = parse_key(key_pem)?;

    let mut status = Status {
        valid_cert: true,
        valid_key: true,
        ..Default::default()
    };
    status.valid_chain = chain.len() > 1;
    let not_after = describe_leaf(&chain[0], &mut status);

    // Building a configuration first is what catches a key that does not
    // match the certificate: the resolver would accept the pair and fail at
    // handshake time instead.  It is also what keeps a renewal caught halfway
    // through -- the new certificate beside the old key -- from replacing a
    // working pair: nothing is installed until this has passed.
    build(chain.clone(), key.clone_key())?;
    into.set(chain, key, fingerprint, not_after)?;
    status.valid_pair = true;

    Ok(status)
}

/// Builds a rustls server configuration from a chain and key.
fn build(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, Error> {
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| {
            // rustls reports a mismatched pair as a generic error; the user
            // needs to be told which of the two problems they have.
            let text = e.to_string();
            if text.contains("key") && text.contains("match") {
                Error::Mismatch
            } else {
                Error::Rustls(text)
            }
        })
}

/// Loads a certificate and key, producing configurations for each protocol.
pub fn load(src: &Source) -> Result<Loaded, Error> {
    let chain = parse_chain(&src.cert_pem()?)?;
    let key = parse_key(&src.key_pem()?)?;

    let mut status = Status {
        valid_cert: true,
        valid_key: true,
        ..Default::default()
    };
    status.valid_chain = chain.len() > 1;
    describe_leaf(&chain[0], &mut status);

    // rustls consumes the key, so build each configuration from a clone.
    let mut dot = build(chain.clone(), key.clone_key())?;
    // DNS-over-TLS advertises itself so a client can be sure what it reached.
    dot.alpn_protocols = vec![b"dot".to_vec()];

    let mut https = build(chain.clone(), key.clone_key())?;
    https.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let mut h3 = build(chain.clone(), key.clone_key())?;
    h3.alpn_protocols = vec![b"h3".to_vec()];

    // RFC 9250 names the protocol `doq`; earlier drafts used other tokens,
    // and clients that still send them are simply not served.
    let mut doq = build(chain, key)?;
    doq.alpn_protocols = vec![b"doq".to_vec()];

    for c in [&mut dot, &mut https, &mut h3, &mut doq] {
        resume_statelessly(c);
    }

    status.valid_pair = true;

    Ok(Loaded {
        dot: Arc::new(dot),
        https: Arc::new(https),
        h3: Arc::new(h3),
        doq: Arc::new(doq),
        status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generates a self-signed certificate for the given names.
    fn self_signed(names: &[&str]) -> (String, String) {
        let c = rcgen::generate_simple_self_signed(
            names.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
        )
        .expect("generating a certificate");

        (c.cert.pem(), c.signing_key.serialize_pem())
    }

    fn inline(cert: &str, key: &str) -> Source {
        Source {
            certificate_chain: cert.to_string(),
            private_key: key.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn loads_a_self_signed_pair() {
        let (cert, key) = self_signed(&["dns.example.com"]);
        let loaded = load(&inline(&cert, &key)).expect("a matching pair must load");

        assert!(loaded.status.valid_cert);
        assert!(loaded.status.valid_key);
        assert!(loaded.status.valid_pair);
        assert_eq!(loaded.status.dns_names, ["dns.example.com"]);
        assert!(loaded.status.warning_validation.is_empty());
    }

    #[test]
    fn advertises_the_right_protocols_per_listener() {
        let (cert, key) = self_signed(&["dns.example.com"]);
        let loaded = load(&inline(&cert, &key)).unwrap();

        assert_eq!(loaded.dot.alpn_protocols, vec![b"dot".to_vec()]);
        assert_eq!(
            loaded.https.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(loaded.doq.alpn_protocols, vec![b"doq".to_vec()]);
        assert_eq!(loaded.h3.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[test]
    fn reports_every_name_the_certificate_covers() {
        let (cert, key) = self_signed(&["a.example.com", "b.example.com"]);
        let st = inspect(&inline(&cert, &key));

        assert_eq!(st.dns_names, ["a.example.com", "b.example.com"]);
    }

    #[test]
    fn reports_validity_dates() {
        let (cert, key) = self_signed(&["dns.example.com"]);
        let st = inspect(&inline(&cert, &key));

        // Formatted the way Go's encoder would, so the interface can parse it.
        assert!(st.not_before.ends_with('Z'), "got {}", st.not_before);
        assert!(st.not_after.ends_with('Z'), "got {}", st.not_after);
        assert!(st.not_before < st.not_after);
    }

    #[test]
    fn reports_the_key_algorithm_not_the_pem_container() {
        // rcgen emits a PKCS#8 file holding an EC key; upstream reports the
        // algorithm, so reporting "PKCS#8" would be wrong.
        let (cert, key) = self_signed(&["dns.example.com"]);
        let st = inspect(&inline(&cert, &key));

        assert!(
            matches!(st.key_type.as_str(), "RSA" | "ECDSA" | "DSA"),
            "expected an algorithm name, got {:?}",
            st.key_type
        );
    }

    #[test]
    fn a_self_signed_certificate_is_served_but_flagged() {
        // Upstream serves it and warns, which is how the operator finds out
        // before their clients do.
        let (cert, key) = self_signed(&["dns.example.com"]);
        let st = inspect(&inline(&cert, &key));

        assert!(st.valid_pair, "the pair is usable");
        assert!(
            st.warning_validation.contains("does not verify"),
            "a self-signed certificate should be flagged, got {:?}",
            st.warning_validation
        );
    }

    #[test]
    fn a_mismatched_key_is_rejected() {
        let (cert, _) = self_signed(&["a.example.com"]);
        let (_, other_key) = self_signed(&["b.example.com"]);

        let st = inspect(&inline(&cert, &other_key));
        assert!(st.valid_cert, "the certificate itself is fine");
        assert!(st.valid_key, "the key itself is fine");
        assert!(!st.valid_pair, "but they do not belong together");
        assert!(!st.warning_validation.is_empty());

        assert!(load(&inline(&cert, &other_key)).is_err());
    }

    #[test]
    fn garbage_is_reported_rather_than_panicking() {
        let st = inspect(&inline("not a certificate", "not a key"));
        assert!(!st.valid_cert);
        assert!(!st.valid_key);
        assert!(!st.valid_pair);
        assert!(st.warning_validation.contains("certificate"));
    }

    #[test]
    fn a_key_without_a_certificate_is_reported() {
        let (_, key) = self_signed(&["a.example.com"]);
        let st = inspect(&Source {
            private_key: key,
            ..Default::default()
        });

        assert!(!st.valid_cert);
        assert!(st.warning_validation.contains("no certificate"));
    }

    #[test]
    fn setting_both_the_inline_and_the_path_form_is_refused() {
        let (cert, key) = self_signed(&["a.example.com"]);
        let src = Source {
            certificate_chain: cert,
            certificate_path: "/etc/ssl/cert.pem".into(),
            private_key: key,
            ..Default::default()
        };

        let st = inspect(&src);
        assert!(
            st.warning_validation.contains("not both"),
            "got {}",
            st.warning_validation
        );
    }

    #[test]
    fn loads_from_files() {
        let (cert, key) = self_signed(&["dns.example.com"]);
        let dir = std::env::temp_dir().join(format!("sift-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cp = dir.join("cert.pem");
        let kp = dir.join("key.pem");
        std::fs::write(&cp, &cert).unwrap();
        std::fs::write(&kp, &key).unwrap();

        let src = Source {
            certificate_path: cp.to_string_lossy().into_owned(),
            private_key_path: kp.to_string_lossy().into_owned(),
            ..Default::default()
        };

        let loaded = load(&src).expect("a pair on disk must load");
        assert!(loaded.status.valid_pair);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_file_is_reported_with_its_path() {
        let src = Source {
            certificate_path: "/nonexistent/cert.pem".into(),
            private_key_path: "/nonexistent/key.pem".into(),
            ..Default::default()
        };

        let st = inspect(&src);
        assert!(st.warning_validation.contains("/nonexistent/cert.pem"));
    }

    #[test]
    fn an_unconfigured_source_is_empty() {
        assert!(Source::default().is_empty());
        assert!(
            !Source {
                private_key: "x".into(),
                ..Default::default()
            }
            .is_empty()
        );
    }

    #[test]
    fn a_reloadable_certificate_can_be_replaced_while_running() {
        // A certificate installed through the API has to reach the running
        // listeners; otherwise it only takes effect at the next restart.
        let slot = Arc::new(Reloadable::new());
        assert!(!slot.is_loaded());

        let (cert, key) = self_signed(&["first.example"]);
        let status = install(&inline(&cert, &key), &slot).expect("the pair should install");
        assert!(status.valid_pair);
        assert!(slot.is_loaded());

        let first = served(&slot);

        let (cert2, key2) = self_signed(&["second.example"]);
        install(&inline(&cert2, &key2), &slot).expect("the second pair should install");

        assert_ne!(
            first,
            served(&slot),
            "the served certificate should have changed"
        );
    }

    /// The leaf certificate a slot would hand to a handshake.
    fn served(slot: &Reloadable) -> Vec<u8> {
        let guard = slot.current.read();
        let s = guard.as_ref().expect("a certificate should be resolvable");

        s.key.cert[0].as_ref().to_vec()
    }

    /// A temporary directory holding a certificate and key on disk.
    struct OnDisk {
        dir: std::path::PathBuf,
        src: Source,
    }

    impl OnDisk {
        fn new(names: &[&str]) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "sift-tls-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::create_dir_all(&dir).unwrap();

            let src = Source {
                certificate_path: dir.join("cert.pem").to_string_lossy().into_owned(),
                private_key_path: dir.join("key.pem").to_string_lossy().into_owned(),
                ..Default::default()
            };
            let me = Self { dir, src };
            me.write(names);

            me
        }

        /// Replaces both files, as a renewal would.
        fn write(&self, names: &[&str]) {
            let (cert, key) = self_signed(names);
            std::fs::write(self.dir.join("cert.pem"), cert).unwrap();
            std::fs::write(self.dir.join("key.pem"), key).unwrap();
        }
    }

    impl Drop for OnDisk {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    #[test]
    fn a_renewal_on_disk_is_picked_up_without_a_restart() {
        // The whole point: certbot rewrites the files and tells nobody.
        let files = OnDisk::new(&["renewed.example"]);
        let slot = Reloadable::new();

        let first = refresh(&files.src, &slot)
            .expect("the pair on disk should load")
            .expect("nothing was installed yet, so this is a change");
        assert!(first.valid_pair);
        let before = served(&slot);

        // Reading the same files again must not churn the listeners.
        assert!(
            refresh(&files.src, &slot).unwrap().is_none(),
            "unchanged files are not a renewal"
        );
        assert_eq!(before, served(&slot), "and nothing was replaced");

        files.write(&["renewed.example"]);
        assert!(
            refresh(&files.src, &slot)
                .expect("the renewed pair should load")
                .is_some(),
            "a rewritten certificate is a renewal even under the same name"
        );
        assert_ne!(before, served(&slot), "the new one is being served");
    }

    #[test]
    fn a_certificate_installed_through_the_api_is_not_reloaded_again() {
        // `install` records what it installed, so the periodic check that
        // follows it sees no change and leaves the listeners alone.
        let files = OnDisk::new(&["api.example"]);
        let slot = Reloadable::new();

        install(&files.src, &slot).expect("the pair should install");
        assert!(refresh(&files.src, &slot).unwrap().is_none());
    }

    #[test]
    fn a_half_written_renewal_leaves_the_running_certificate_alone() {
        // A renewal that writes the certificate before the key is briefly a
        // mismatched pair.  Serving nothing for that moment would be worse
        // than serving the certificate that still works.
        let files = OnDisk::new(&["half.example"]);
        let slot = Reloadable::new();
        refresh(&files.src, &slot).unwrap().unwrap();
        let before = served(&slot);

        let (cert, _) = self_signed(&["half.example"]);
        std::fs::write(files.dir.join("cert.pem"), cert).unwrap();

        assert!(
            refresh(&files.src, &slot).is_err(),
            "the pair does not match"
        );
        assert_eq!(before, served(&slot), "so the old one is still served");

        // And the next check, once the key lands, installs the pair.
        files.write(&["half.example"]);
        assert!(refresh(&files.src, &slot).unwrap().is_some());
        assert_ne!(before, served(&slot));
    }

    #[test]
    fn a_certificate_that_vanishes_leaves_the_running_one_alone() {
        // Some renewal tools unlink before they write.
        let files = OnDisk::new(&["gone.example"]);
        let slot = Reloadable::new();
        refresh(&files.src, &slot).unwrap().unwrap();
        let before = served(&slot);

        std::fs::remove_file(files.dir.join("cert.pem")).unwrap();
        assert!(refresh(&files.src, &slot).is_err());
        assert_eq!(before, served(&slot));
    }

    #[test]
    fn the_expiry_of_the_served_certificate_is_readable() {
        // This is what the periodic check warns from: a certificate running
        // out of time that nothing has replaced.
        let slot = Reloadable::new();
        assert_eq!(slot.expires_at(), None, "nothing is installed");

        let (cert, key) = self_signed(&["expiry.example"]);
        install(&inline(&cert, &key), &slot).unwrap();

        let at = slot
            .expires_at()
            .expect("an installed certificate has a date");
        assert!(
            at > jiff::Timestamp::now().as_second(),
            "a fresh certificate has not expired"
        );
    }

    #[test]
    fn only_a_source_that_reads_files_is_worth_watching() {
        let (cert, key) = self_signed(&["inline.example"]);
        assert!(
            !inline(&cert, &key).reads_files(),
            "inline PEM only changes through the API"
        );
        assert!(OnDisk::new(&["file.example"]).src.reads_files());
        assert!(
            Source {
                certificate_path: "/etc/ssl/cert.pem".into(),
                private_key: key,
                ..Default::default()
            }
            .reads_files(),
            "one of the two on disk is enough"
        );
    }

    #[test]
    fn a_mismatched_pair_is_refused_before_it_is_installed() {
        let slot = Reloadable::new();
        let (cert, _) = self_signed(&["a.example"]);
        let (_, key) = self_signed(&["b.example"]);

        assert!(install(&inline(&cert, &key), &slot).is_err());
        assert!(!slot.is_loaded(), "nothing should have been installed");
    }

    #[test]
    fn the_reloadable_configurations_advertise_the_right_protocols() {
        let slot = Arc::new(Reloadable::new());
        let loaded = reloadable(slot);

        assert_eq!(loaded.dot.alpn_protocols, vec![b"dot".to_vec()]);
        assert_eq!(
            loaded.https.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(loaded.doq.alpn_protocols, vec![b"doq".to_vec()]);
        assert_eq!(loaded.h3.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[test]
    fn ip_addresses_are_reported_separately_from_dns_names() {
        // The API's `dns_names` is compared against Go's, which carries DNS
        // names only; DDR needs to know about IP names as well.
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()));
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();

        let st = inspect(&inline(&cert.pem(), &key.serialize_pem()));
        assert_eq!(st.dns_names, vec!["localhost".to_string()]);
        assert!(st.has_ip_addresses);
    }

    #[test]
    fn a_certificate_without_ip_names_says_so() {
        let (c, k) = self_signed(&["localhost"]);
        assert!(!inspect(&inline(&c, &k)).has_ip_addresses);
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn a_strict_check_accepts_what_upstreams_any_name_matches_accepts() {
        // Each case is a line of upstream's `anyNameMatches`, and the table
        // in its `config_internal_test.go` besides.
        let cert = names(&["dns.example.com", "*.wild.example.com"]);
        let yes = |sni: &str| any_name_matches(&cert, Some(sni));

        assert!(yes("dns.example.com"), "an exact name");
        assert!(yes("a.wild.example.com"), "one label under a wildcard");
        assert!(
            yes("a.b.wild.example.com"),
            "a wildcard is a suffix to upstream, so any depth passes"
        );

        assert!(
            !yes("wild.example.com"),
            "the wildcard does not cover its apex"
        );
        assert!(!yes("example.com"));
        assert!(!yes("other.example.net"));
        assert!(!yes("xdns.example.com"), "a suffix is not a name");
        assert!(!any_name_matches(&cert, None), "no server name at all");

        // Not valid hostnames, so refused before they are compared.
        assert!(!yes("dns.example.com."), "a trailing dot");
        assert!(!yes("under_score.wild.example.com"));
        assert!(!yes("-a.wild.example.com"));
        assert!(
            !any_name_matches(&names(&["*.123"]), Some("x.123")),
            "an all-numeric last label"
        );
    }

    #[test]
    fn a_strict_check_compares_the_certificates_names_as_issued() {
        // rustls lowercases what the client sent; upstream compares against
        // the certificate byte for byte, so a capital in the certificate
        // matches no lowercase name there, and none here.
        assert!(!any_name_matches(
            &names(&["DNS.example.com"]),
            Some("dns.example.com")
        ));
        assert!(any_name_matches(
            &names(&["dns.example.com"]),
            Some("dns.example.com")
        ));
    }

    #[test]
    fn hostname_validity_is_upstreams() {
        for good in [
            "a",
            "a.b",
            "xn--80ak6aa92e.com",
            "1.example",
            "a-b.c",
            &"a".repeat(63),
        ] {
            assert!(is_valid_hostname(good), "{good:?}");
        }
        for bad in [
            "",
            ".",
            "a..b",
            "a.",
            "-a",
            "a-",
            "a_b",
            "1.2.3.4",
            &"a".repeat(64),
            &format!("{}com", "a.".repeat(126)),
        ] {
            assert!(!is_valid_hostname(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_certificate_without_dns_names_is_known_by_its_common_name() {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "first.example");
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress("192.0.2.1".parse().unwrap()));
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();

        // An IP address is not a DNS name to Go, so the common name stands in.
        assert_eq!(sni_names(cert.der()), ["first.example"]);

        let (c, _) = self_signed(&["a.example", "b.example"]);
        let der = parse_chain(&c).unwrap();
        assert_eq!(sni_names(&der[0]), ["a.example", "b.example"]);
    }

    /// A client that trusts anything, so the tests can offer server names
    /// the certificate does not cover and see what the *server* does.
    #[derive(Debug)]
    struct TrustAnything;

    impl rustls::client::danger::ServerCertVerifier for TrustAnything {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &rustls_pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls_pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    /// A client for `alpn` that trusts anything and sends `sni`, or no
    /// server name at all.
    fn client(alpn: &[u8], sni: Option<&str>) -> (Arc<rustls::ClientConfig>, ServerNameOwned) {
        let mut c = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(TrustAnything))
            .with_no_client_auth();
        c.alpn_protocols = vec![alpn.to_vec()];
        c.enable_sni = sni.is_some();

        let name = ServerNameOwned::try_from(sni.unwrap_or("unsent.invalid").to_string()).unwrap();

        (Arc::new(c), name)
    }

    type ServerNameOwned = rustls_pki_types::ServerName<'static>;

    /// Moves everything `from` has to send into `to`, returning `to`'s
    /// verdict on it.
    fn deliver(
        from: &mut impl std::ops::DerefMut<Target = rustls::ConnectionCommon<impl Sized>>,
        to: &mut impl std::ops::DerefMut<Target = rustls::ConnectionCommon<impl Sized>>,
    ) -> Result<(), rustls::Error> {
        let mut wire = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut wire).unwrap();
        }

        let mut rest = &wire[..];
        while !rest.is_empty() {
            to.read_tls(&mut rest).unwrap();
            to.process_new_packets()?;
        }

        Ok(())
    }

    /// Runs a whole handshake in memory, and the tickets after it.
    fn handshake(
        server: &Arc<ServerConfig>,
        (client, name): &(Arc<rustls::ClientConfig>, ServerNameOwned),
    ) -> Result<rustls::ClientConnection, rustls::Error> {
        let mut c = rustls::ClientConnection::new(client.clone(), name.clone()).unwrap();
        let mut s = rustls::ServerConnection::new(server.clone()).unwrap();

        for _ in 0..8 {
            deliver(&mut c, &mut s)?;
            deliver(&mut s, &mut c)?;
        }
        assert!(
            !c.is_handshaking() && !s.is_handshaking(),
            "stuck mid-handshake"
        );

        Ok(c)
    }

    /// Four configurations around one reloadable certificate for `names`.
    fn listening(names: &[&str], strict: bool) -> Loaded {
        let (cert, key) = self_signed(names);
        let slot = Arc::new(Reloadable::new());
        install(&inline(&cert, &key), &slot).unwrap();
        slot.set_strict_sni(strict);

        reloadable(slot)
    }

    #[test]
    fn strict_sni_refuses_a_name_the_certificate_does_not_cover_on_dot_and_doq() {
        let tls = listening(&["dns.example.com"], true);

        for (cfg, alpn) in [(&tls.dot, &b"dot"[..]), (&tls.doq, &b"doq"[..])] {
            assert!(handshake(cfg, &client(alpn, Some("dns.example.com"))).is_ok());
            assert!(
                handshake(cfg, &client(alpn, Some("other.example.com"))).is_err(),
                "a name the certificate does not cover"
            );
            assert!(
                handshake(cfg, &client(alpn, None)).is_err(),
                "no server name is refused too"
            );
        }
    }

    #[test]
    fn strict_sni_never_reaches_https_or_http3() {
        // Upstream's web server is built with a plain certificate list.
        let tls = listening(&["dns.example.com"], true);

        for (cfg, alpn) in [(&tls.https, &b"h2"[..]), (&tls.h3, &b"h3"[..])] {
            assert!(handshake(cfg, &client(alpn, Some("other.example.com"))).is_ok());
            assert!(handshake(cfg, &client(alpn, None)).is_ok());
        }
    }

    #[test]
    fn without_strict_sni_any_name_is_served() {
        let tls = listening(&["dns.example.com"], false);

        assert!(handshake(&tls.dot, &client(b"dot", Some("other.example.com"))).is_ok());
        assert!(handshake(&tls.dot, &client(b"dot", None)).is_ok());
    }

    #[test]
    fn strict_sni_can_be_switched_on_a_running_listener() {
        let (cert, key) = self_signed(&["dns.example.com"]);
        let slot = Arc::new(Reloadable::new());
        install(&inline(&cert, &key), &slot).unwrap();
        let tls = reloadable(slot.clone());
        let stranger = client(b"dot", Some("other.example.com"));

        assert!(handshake(&tls.dot, &stranger).is_ok());
        slot.set_strict_sni(true);
        assert!(handshake(&tls.dot, &stranger).is_err());
    }

    #[test]
    fn a_clientid_below_a_wildcard_certificate_passes_strict_sni() {
        // How ClientIDs are meant to be used over DoT: a certificate for the
        // server's name and everything below it, and a label per device.
        let tls = listening(&["dns.example.com", "*.dns.example.com"], true);

        assert!(
            handshake(
                &tls.dot,
                &client(b"dot", Some("kids-tablet.dns.example.com"))
            )
            .is_ok()
        );
        assert!(handshake(&tls.dot, &client(b"dot", Some("dns.example.com"))).is_ok());
    }

    #[test]
    fn strict_sni_refuses_an_address_sent_as_a_server_name() {
        // What a scanner dialling the port by address sends.  rustls reads an
        // IP literal as no server name, and a strict check refuses that
        // before anything is signed; without it the handshake goes ahead.
        //
        // rustls will not send an address as a server name, so a name of the
        // same length is sent and rewritten on the way.
        let first_flight = |strict: bool| {
            let tls = listening(&["dns.example.com"], strict);
            let (cfg, name) = client(b"dot", Some("abc.xyz"));
            let mut c = rustls::ClientConnection::new(cfg, name).unwrap();
            let mut s = rustls::ServerConnection::new(tls.dot.clone()).unwrap();

            let mut hello = Vec::new();
            while c.wants_write() {
                c.write_tls(&mut hello).unwrap();
            }
            let at = hello
                .windows(7)
                .position(|w| w == b"abc.xyz")
                .expect("the server name is in the hello");
            hello[at..at + 7].copy_from_slice(b"1.2.3.4");

            s.read_tls(&mut &hello[..]).unwrap();
            s.process_new_packets().map(|_| ())
        };

        assert!(first_flight(true).is_err(), "refused at the ClientHello");
        assert!(first_flight(false).is_ok(), "served without the check");
    }

    #[test]
    fn a_reinstalled_certificate_brings_its_own_names() {
        let slot = Arc::new(Reloadable::new());
        slot.set_strict_sni(true);
        let tls = reloadable(slot.clone());

        let (cert, key) = self_signed(&["first.example"]);
        install(&inline(&cert, &key), &slot).unwrap();
        assert!(handshake(&tls.dot, &client(b"dot", Some("first.example"))).is_ok());

        let (cert, key) = self_signed(&["second.example"]);
        install(&inline(&cert, &key), &slot).unwrap();
        assert!(handshake(&tls.dot, &client(b"dot", Some("first.example"))).is_err());
        assert!(handshake(&tls.dot, &client(b"dot", Some("second.example"))).is_ok());
    }

    #[test]
    fn every_configuration_resumes_from_a_ticket_and_never_early() {
        let reloaded = listening(&["dns.example.com"], false);
        let (cert, key) = self_signed(&["dns.example.com"]);
        let loaded = load(&inline(&cert, &key)).unwrap();

        for tls in [&reloaded, &loaded] {
            for cfg in [&tls.dot, &tls.https, &tls.h3, &tls.doq] {
                assert!(cfg.ticketer.enabled(), "stateless resumption");
                assert_eq!(cfg.send_tls13_tickets, 1);
                assert_eq!(cfg.max_early_data_size, 0, "no 0-RTT");
            }
        }
    }

    #[test]
    fn a_client_that_reconnects_resumes_rather_than_handshaking_again() {
        use rustls::HandshakeKind;

        let tls = listening(&["dns.example.com"], true);
        let dot = client(b"dot", Some("dns.example.com"));

        let first = handshake(&tls.dot, &dot).unwrap();
        assert_eq!(first.handshake_kind(), Some(HandshakeKind::Full));

        // The same client config holds the ticket the first handshake left.
        let again = handshake(&tls.dot, &dot).unwrap();
        assert_eq!(
            again.handshake_kind(),
            Some(HandshakeKind::Resumed),
            "resumed, and through the strict check"
        );
    }

    #[test]
    fn a_scan_of_handshakes_does_not_push_a_client_out_of_resumption() {
        // The point of tickets.  rustls' default cache holds 256 sessions
        // and forgets the oldest, so this many strangers completing a
        // handshake in between used to cost the client its resumption.
        use rustls::HandshakeKind;

        let tls = listening(&["dns.example.com"], false);
        let regular = client(b"dot", Some("dns.example.com"));
        handshake(&tls.dot, &regular).unwrap();

        for _ in 0..300 {
            handshake(&tls.dot, &client(b"dot", Some("dns.example.com"))).unwrap();
        }

        let back = handshake(&tls.dot, &regular).unwrap();
        assert_eq!(back.handshake_kind(), Some(HandshakeKind::Resumed));
    }

    #[test]
    fn a_ticket_for_one_protocol_resumes_nothing_on_another() {
        use rustls::HandshakeKind;

        let tls = listening(&["dns.example.com"], false);
        let (cfg, name) = client(b"dot", Some("dns.example.com"));
        handshake(&tls.dot, &(cfg.clone(), name.clone())).unwrap();

        // The ticket is in `cfg`'s store; offer it to the DoQ configuration,
        // whose ticket key is its own.
        let mut other = (*cfg).clone();
        other.alpn_protocols = vec![b"doq".to_vec()];
        let crossed = handshake(&tls.doq, &(Arc::new(other), name)).unwrap();
        assert_eq!(crossed.handshake_kind(), Some(HandshakeKind::Full));
    }
}
