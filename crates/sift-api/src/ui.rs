//! Serving the embedded web interface.
//!
//! Text assets are stored **brotli-compressed**, which keeps ~1.3 MB of
//! JavaScript and CSS down to ~0.4 MB in the binary.  A client that accepts `br`
//! gets the stored bytes untouched; anything else is decompressed on the way
//! out.  `scripts/brotli.mjs` does the compressing, at the end of
//! `scripts/build-frontend.sh`.
//!
//! Brotli is what browsers reach for over HTTPS; over plain HTTP most of them
//! still advertise only gzip, and those clients are served the decompressed
//! bytes.  That would be expensive per request, which is why the caching below
//! matters: a client pays for an asset once per build, not once per page load.
//!
//! # Memory
//!
//! No response copies an asset.  The stored bytes are `'static` and served as
//! they are, and each asset is decompressed **at most once** for the life of
//! the process, the first time a client without brotli asks for it, into a
//! buffer every later response shares.  Decompressing per request made the
//! public login script (60 KB stored, 226 KB plain) a lever: one HTTP/2
//! connection opening 200 streams without brotli, and never granting a byte
//! of flow-control window, pinned 45 MB for a few kilobytes sent and no
//! session.  Those 200 responses are now 200 reference counts on one buffer.
//!
//! What that costs is the plain form of whatever has been asked for, once:
//! 1.38 MB if every asset of the current build is, and about 245 KB for
//! everything a signed-out visitor can reach -- the login page, its script
//! and stylesheet, and the icons.
//!
//! # Caching
//!
//! The build names every script and stylesheet after a hash of its contents
//! and writes it under `static/`, so such a file can never change meaning: it
//! is served `immutable` with a year's `max-age` and is never asked about
//! again.  Everything else — the three HTML shells, the icons — is served
//! `no-cache`, so the client asks every time and gets a 304 when nothing
//! changed.  `ETag` makes that cheap:
//! it is the stored file's SHA-256, which rust-embed computes at build time,
//! and `If-None-Match` is answered without touching the body.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{LazyLock, OnceLock};

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use rust_embed::RustEmbed;

/// The built web interface.
#[derive(RustEmbed)]
#[folder = "../../web/build"]
struct Assets;

/// The extension the compressed form is stored under.
const STORED_EXT: &str = "br";

/// The `Content-Encoding` the stored form carries.
const STORED_ENCODING: &str = "br";

/// Caching for a content-addressed asset: a year, and never revalidated.
///
/// The name holds a hash of the contents, so a change produces a different
/// URL and this one stays correct forever.
const IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// Caching for an asset whose name says nothing about its contents.
///
/// `no-cache` does not mean "do not store"; it means "store it, but ask before
/// reusing it".  The ask is answered with a 304 whenever the build has not
/// moved, so this costs a round trip rather than a download.
const REVALIDATE: &str = "no-cache";

/// Where the build puts its content-addressed output, and only that.
const HASHED_DIR: &str = "static/";

/// Serves an asset by request path.
///
/// An unknown path falls back to `index.html` so the single-page app can
/// handle its own routing, which is what upstream's file server does.
pub fn serve(path: &str, headers: &HeaderMap) -> Response {
    let clean = path.trim_start_matches('/');
    let candidate = if clean.is_empty() {
        "index.html"
    } else {
        clean
    };

    if let Some(r) = lookup(candidate, headers) {
        return r;
    }

    // Only fall back for paths that look like navigation, not for a missing
    // asset: answering a missing script with HTML hides real problems.
    if candidate.contains('.') {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    lookup("index.html", headers)
        .unwrap_or_else(|| (StatusCode::NOT_FOUND, "not found").into_response())
}

/// Looks an asset up, preferring the stored compressed form.
fn lookup(name: &str, headers: &HeaderMap) -> Option<Response> {
    let mime = mime_for(name);
    let caching = if is_content_addressed(name) {
        IMMUTABLE
    } else {
        REVALIDATE
    };

    // Stored compressed.
    if let Some(f) = Assets::get(&format!("{name}.{STORED_EXT}")) {
        let hash = f.metadata.sha256_hash();

        if accepts_brotli(headers) {
            let etag = etag(&hash, STORED_ENCODING);
            if matches_etag(headers, &etag) {
                return Some(not_modified(&etag, caching));
            }

            return Some(
                (
                    [
                        (header::CONTENT_TYPE, mime),
                        (header::CONTENT_ENCODING, STORED_ENCODING),
                        (header::VARY, "Accept-Encoding"),
                        (header::CACHE_CONTROL, caching),
                        (header::ETAG, etag.as_str()),
                    ],
                    Body::from(shared(f.data)),
                )
                    .into_response(),
            );
        }

        // A representation is identified by its own bytes, so the
        // decompressed form cannot share the compressed form's validator.
        let etag = etag(&hash, "identity");
        if matches_etag(headers, &etag) {
            return Some(not_modified(&etag, caching));
        }

        let plain = plain(name, &hash, &f.data)?;

        return Some(
            (
                [
                    (header::CONTENT_TYPE, mime),
                    (header::VARY, "Accept-Encoding"),
                    (header::CACHE_CONTROL, caching),
                    (header::ETAG, etag.as_str()),
                ],
                Body::from(plain),
            )
                .into_response(),
        );
    }

    // Stored as-is.
    let f = Assets::get(name)?;
    let etag = etag(&f.metadata.sha256_hash(), "identity");
    if matches_etag(headers, &etag) {
        return Some(not_modified(&etag, caching));
    }

    Some(
        (
            [
                (header::CONTENT_TYPE, mime),
                (header::CACHE_CONTROL, caching),
                (header::ETAG, etag.as_str()),
            ],
            Body::from(shared(f.data)),
        )
            .into_response(),
    )
}

/// The stored bytes of an asset, as a body that does not copy them.
///
/// A release build embeds every asset, so this is a `'static` slice and the
/// body only points at it.  A debug build reads the file afresh on each
/// lookup, which is rust-embed's development convenience, and the owned bytes
/// it hands back are moved rather than copied.
fn shared(data: Cow<'static, [u8]>) -> Bytes {
    match data {
        Cow::Borrowed(b) => Bytes::from_static(b),
        Cow::Owned(v) => Bytes::from(v),
    }
}

/// An asset's plain form, as it was when it was decompressed.
struct Plain {
    /// The stored file's hash, which says which build these bytes are of.
    hash: [u8; 32],
    /// The decompressed bytes, or `None` if the stored ones did not
    /// decompress -- remembered too, so a broken asset is not retried on
    /// every request.
    bytes: Option<Bytes>,
}

/// One slot per compressed asset, each filled the first time it is needed.
///
/// Built from the build's own list of files, so it holds exactly the assets
/// there are: a request for anything else never reaches it, and nothing a
/// client sends can add a slot.
static PLAIN: LazyLock<HashMap<String, OnceLock<Plain>>> = LazyLock::new(|| {
    Assets::iter()
        .filter_map(|p| {
            p.strip_suffix(STORED_EXT)
                .and_then(|n| n.strip_suffix('.'))
                .map(|name| (name.to_string(), OnceLock::new()))
        })
        .collect()
});

/// The decompressed form of a stored asset, decompressed at most once.
///
/// Every response after the first shares the same buffer, so a client that
/// cannot take brotli costs a reference count rather than a copy.  The hash
/// check only matters to a debug build, which reads the files from disk and
/// so can see a rebuilt interface under a running server: bytes cached from
/// the old build are never served under the new build's validator.
fn plain(name: &str, hash: &[u8; 32], stored: &[u8]) -> Option<Bytes> {
    let Some(slot) = PLAIN.get(name) else {
        return decompress(stored).map(Bytes::from);
    };

    let cached = slot.get_or_init(|| Plain {
        hash: *hash,
        bytes: decompress(stored).map(Bytes::from),
    });
    if cached.hash != *hash {
        return decompress(stored).map(Bytes::from);
    }

    cached.bytes.clone()
}

/// Reports whether the client will take brotli.
fn accepts_brotli(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',').any(|part| {
                let mut it = part.split(';');
                let coding = it.next().unwrap_or("").trim();
                // `br;q=0` is a refusal, not an offer.
                let refused = it.any(|p| p.trim().replace(' ', "") == "q=0");

                coding.eq_ignore_ascii_case(STORED_ENCODING) && !refused
            })
        })
}

/// The validator for one representation of an asset.
///
/// Half of the SHA-256 is plenty to tell two builds apart and keeps the header
/// short.  The suffix separates the encodings, which are different
/// representations of the same resource and must not share a validator.
fn etag(hash: &[u8; 32], encoding: &str) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(2 + 32 + 1 + encoding.len());
    out.push('"');
    for b in &hash[..16] {
        let _ = write!(out, "{b:02x}");
    }
    out.push('-');
    out.push_str(encoding);
    out.push('"');

    out
}

/// Reports whether `If-None-Match` covers this validator.
fn matches_etag(headers: &HeaderMap, etag: &str) -> bool {
    let Some(v) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };

    v.split(',').any(|candidate| {
        let candidate = candidate.trim();
        // The weak prefix is stripped: comparison here is weak, which is what
        // a conditional GET asks for.
        candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
    })
}

/// A 304, which carries the validator and the caching but no body.
///
/// `Content-Length` is left to hyper, which writes zero.  RFC 9110 makes the
/// header optional here and a meaningful value would have to be the length of
/// the representation the client already holds — which for the decompressed
/// form means decompressing it, the one thing a 304 exists to avoid.
fn not_modified(etag: &str, caching: &str) -> Response {
    (
        StatusCode::NOT_MODIFIED,
        [
            (header::CACHE_CONTROL, caching),
            (header::ETAG, etag),
            (header::VARY, "Accept-Encoding"),
        ],
    )
        .into_response()
}

/// Reports whether a name holds a hash of the file's own contents.
///
/// `web/client/vite.config.ts` writes every hashed bundle under `static/` and
/// nothing else there, so this is a fact about the build's layout rather than
/// a guess about the name.  It used to sniff for a long run of hex, which was
/// right for the bundler of the day and would have quietly cached the wrong
/// thing for a year the first time someone shortened the hash, or added an
/// asset whose name happened to read like a digest.  Vite's hash is base64url
/// and would not have matched it at all.
///
/// Such a file can be cached forever, because changing it changes its name.
fn is_content_addressed(name: &str) -> bool {
    name.starts_with(HASHED_DIR)
}

/// Decompresses a stored asset.
fn decompress(data: &[u8]) -> Option<Vec<u8>> {
    let mut input = data;
    let mut out = Vec::new();
    brotli_decompressor::BrotliDecompress(&mut input, &mut out).ok()?;

    Some(out)
}

/// The media type for an asset name.
fn mime_for(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// The logical names of every embedded asset, without the storage extension.
///
/// `routes.rs` checks its gates against the real build rather than against
/// names someone typed into a test.
#[cfg(test)]
pub(crate) fn names() -> impl Iterator<Item = String> {
    Assets::iter().map(|p| p.trim_end_matches(".br").to_string())
}

/// Reports whether the web interface was embedded in this build.
pub fn is_embedded() -> bool {
    Assets::get("index.html.br").is_some() || Assets::get("index.html").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn brotli_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::ACCEPT_ENCODING,
            "gzip, deflate, br".parse().unwrap(),
        );

        h
    }

    /// The request a browser makes over plain HTTP: no brotli on offer.
    fn gzip_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "gzip, deflate".parse().unwrap());

        h
    }

    fn revalidating(etag: &str, accepts_br: bool) -> HeaderMap {
        let mut h = if accepts_br {
            brotli_headers()
        } else {
            gzip_headers()
        };
        h.insert(header::IF_NONE_MATCH, etag.parse().unwrap());

        h
    }

    fn header_of(r: &Response, name: header::HeaderName) -> String {
        r.headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default()
    }

    /// The hashed dashboard script this build emitted.
    fn hashed_script() -> String {
        Assets::iter()
            .map(|p| p.to_string())
            .find(|p| p.starts_with("static/main.") && p.ends_with(".js.br"))
            .expect("a hashed main bundle is embedded")
            .trim_end_matches(".br")
            .to_string()
    }

    #[test]
    fn the_interface_is_embedded() {
        assert!(
            is_embedded(),
            "the built web interface should be compiled in"
        );
    }

    #[test]
    fn the_root_serves_the_app_shell() {
        let r = serve("/", &brotli_headers());
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            header_of(&r, header::CONTENT_TYPE),
            "text/html; charset=utf-8"
        );
        assert_eq!(header_of(&r, header::CONTENT_ENCODING), "br");
    }

    #[test]
    fn a_client_without_brotli_gets_plain_bytes() {
        let r = serve("/", &gzip_headers());
        assert_eq!(r.status(), StatusCode::OK);
        assert!(r.headers().get(header::CONTENT_ENCODING).is_none());
    }

    #[test]
    fn a_refusal_of_brotli_is_honoured() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "br;q=0, gzip".parse().unwrap());

        assert!(!accepts_brotli(&h));
        assert!(accepts_brotli(&brotli_headers()));
        assert!(!accepts_brotli(&gzip_headers()));
        assert!(!accepts_brotli(&HeaderMap::new()));
    }

    #[test]
    fn the_login_and_install_pages_are_present() {
        for p in ["/login.html", "/install.html"] {
            assert_eq!(
                serve(p, &brotli_headers()).status(),
                StatusCode::OK,
                "missing {p}"
            );
        }
    }

    #[test]
    fn unknown_routes_fall_back_to_the_app_shell() {
        // The UI routes client-side, so a bare path must return index.html.
        let r = serve("/dashboard", &brotli_headers());
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            header_of(&r, header::CONTENT_TYPE),
            "text/html; charset=utf-8"
        );
    }

    #[test]
    fn a_missing_asset_is_a_404_not_the_app_shell() {
        let r = serve("/nope.js", &brotli_headers());
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn media_types_cover_the_shipped_assets() {
        assert_eq!(mime_for("a.js"), "text/javascript; charset=utf-8");
        assert_eq!(mime_for("a.css"), "text/css; charset=utf-8");
        assert_eq!(mime_for("a.png"), "image/png");
        assert_eq!(mime_for("a.svg"), "image/svg+xml");
        assert_eq!(mime_for("a.unknown"), "application/octet-stream");
    }

    #[test]
    fn binary_assets_are_served_uncompressed() {
        let r = serve("/assets/favicon.png", &brotli_headers());
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(header_of(&r, header::CONTENT_TYPE), "image/png");
        assert!(r.headers().get(header::CONTENT_ENCODING).is_none());
    }

    #[test]
    fn a_hashed_name_is_recognised_and_a_plain_one_is_not() {
        assert!(is_content_addressed("static/main.78c7dceaaf136317fba1.js"));
        assert!(is_content_addressed("static/main.a9dac25216f825dc1ebe.css"));
        assert!(is_content_addressed(
            "static/install.7c9221729fcc590e9f22.js.LICENSE.txt"
        ));

        assert!(!is_content_addressed("index.html"));
        assert!(!is_content_addressed("login.html"));
        assert!(!is_content_addressed("assets/favicon.png"));
        assert!(!is_content_addressed("assets/safari-pinned-tab.svg"));
        // Named like a digest but not built as one: outside static/, so it
        // revalidates rather than sticking for a year.
        assert!(!is_content_addressed("assets/78c7dceaaf136317fba1.png"));
    }

    #[test]
    fn everything_the_build_emitted_is_classified_the_way_it_was_built() {
        // The layout the caching rests on, asserted rather than assumed.  A
        // build that stops putting bundles under static/, or starts putting
        // something else there, fails here rather than in a browser weeks
        // later holding a year-old file.
        let mut hashed = 0;
        for p in Assets::iter() {
            let name = p.trim_end_matches(".br").to_string();
            if is_content_addressed(&name) {
                hashed += 1;
                continue;
            }

            assert!(
                matches!(name.as_str(), "index.html" | "login.html" | "install.html")
                    || name.starts_with("assets/"),
                "{name} is served no-cache; is that deliberate?"
            );
        }

        assert!(hashed >= 3, "the three bundles should be content-addressed");
    }

    #[test]
    fn a_hashed_asset_is_cached_forever_and_the_shell_is_not() {
        let r = serve(&format!("/{}", hashed_script()), &brotli_headers());
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(header_of(&r, header::CACHE_CONTROL), IMMUTABLE);

        let r = serve("/", &brotli_headers());
        assert_eq!(header_of(&r, header::CACHE_CONTROL), REVALIDATE);
    }

    #[test]
    fn a_matching_validator_is_answered_with_304() {
        for accepts_br in [true, false] {
            let first = serve("/", &brotli_or_gzip(accepts_br));
            assert_eq!(first.status(), StatusCode::OK);
            let tag = header_of(&first, header::ETAG);
            assert!(!tag.is_empty(), "every response carries a validator");

            let again = serve("/", &revalidating(&tag, accepts_br));
            assert_eq!(again.status(), StatusCode::NOT_MODIFIED);
            assert_eq!(header_of(&again, header::ETAG), tag);
            assert_eq!(header_of(&again, header::CACHE_CONTROL), REVALIDATE);
        }
    }

    fn brotli_or_gzip(accepts_br: bool) -> HeaderMap {
        if accepts_br {
            brotli_headers()
        } else {
            gzip_headers()
        }
    }

    #[test]
    fn the_two_encodings_do_not_share_a_validator() {
        // Otherwise a cache holding the compressed form would serve it to a
        // client that asked for the plain one, or the reverse.
        let compressed = header_of(&serve("/", &brotli_headers()), header::ETAG);
        let plain = header_of(&serve("/", &gzip_headers()), header::ETAG);

        assert_ne!(compressed, plain);
        assert!(compressed.ends_with("-br\""), "{compressed}");
        assert!(plain.ends_with("-identity\""), "{plain}");
    }

    #[test]
    fn a_stale_validator_gets_the_body() {
        let r = serve("/", &revalidating("\"0000-br\"", true));
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[test]
    fn a_wildcard_validator_matches() {
        let r = serve("/", &revalidating("*", true));
        assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
    }

    #[test]
    fn a_weak_validator_matches_its_strong_form() {
        let tag = header_of(&serve("/", &brotli_headers()), header::ETAG);
        let r = serve("/", &revalidating(&format!("W/{tag}"), true));
        assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
    }

    #[test]
    fn an_uncompressed_asset_revalidates_too() {
        let first = serve("/assets/favicon.png", &brotli_headers());
        let tag = header_of(&first, header::ETAG);
        assert!(!tag.is_empty());

        let again = serve("/assets/favicon.png", &revalidating(&tag, true));
        assert_eq!(again.status(), StatusCode::NOT_MODIFIED);
    }

    /// The login bundle this build emitted: public, and the largest thing a
    /// signed-out visitor can ask for.
    fn login_script() -> String {
        Assets::iter()
            .map(|p| p.to_string())
            .find(|p| p.starts_with("static/login.") && p.ends_with(".js.br"))
            .expect("a hashed login bundle is embedded")
            .trim_end_matches(".br")
            .to_string()
    }

    async fn body_of(r: Response) -> Bytes {
        axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .expect("an asset body is in memory")
    }

    #[tokio::test]
    async fn a_client_without_brotli_shares_one_decompressed_copy() {
        // Decompressing per request was a lever: 200 streams asking for the
        // public login script without brotli, on a connection that never
        // grants flow-control window, pinned 45 MB for a few kilobytes sent.
        // Two responses pointing at the same buffer is the proof that the
        // second one cost a reference count rather than a decompression.
        let path = format!("/{}", login_script());

        let first = serve(&path, &gzip_headers());
        let second = serve(&path, &gzip_headers());
        assert_eq!(first.status(), StatusCode::OK);
        assert!(first.headers().get(header::CONTENT_ENCODING).is_none());

        let tag = header_of(&first, header::ETAG);
        assert!(tag.ends_with("-identity\""), "{tag}");
        assert_eq!(header_of(&second, header::ETAG), tag);
        assert_eq!(header_of(&first, header::CACHE_CONTROL), IMMUTABLE);

        let a = body_of(first).await;
        let b = body_of(second).await;
        assert_eq!(a.as_ptr(), b.as_ptr(), "both responses share one buffer");

        let stored = Assets::get(&format!("{}.br", login_script())).unwrap();
        assert_eq!(
            a,
            decompress(&stored.data).unwrap(),
            "and it is the plain form of the stored bytes"
        );

        // The compressed representation keeps its own validator and is the
        // stored bytes themselves, untouched.
        let br = serve(&path, &brotli_headers());
        let br_tag = header_of(&br, header::ETAG);
        assert!(br_tag.ends_with("-br\""), "{br_tag}");
        assert_ne!(br_tag, tag);
        let body = body_of(br).await;
        assert_eq!(body, stored.data.as_ref());

        // Where the bytes are embedded -- every build but a debug one, which
        // reads them from disk -- the body is the embedded bytes themselves.
        if let Cow::Borrowed(embedded) = stored.data {
            assert_eq!(body.as_ptr(), embedded.as_ptr(), "not a copy");
        }
    }

    #[test]
    fn only_assets_the_build_emitted_have_a_slot_to_fill() {
        // The cache is sized by the build, not by what clients ask for: a
        // slot per compressed asset, made before any request arrives.
        let compressed = Assets::iter().filter(|p| p.ends_with(".br")).count();
        assert_eq!(PLAIN.len(), compressed);
        assert!(PLAIN.contains_key("index.html"));
        assert!(!PLAIN.contains_key("index.html.br"));
        assert!(!PLAIN.contains_key("assets/favicon.png"), "stored plain");
    }

    #[test]
    fn the_stored_bytes_really_are_brotli() {
        let stored = Assets::get("index.html.br").expect("index.html.br is embedded");
        let plain = decompress(&stored.data).expect("it decompresses");

        assert!(
            String::from_utf8_lossy(&plain).contains("<title>"),
            "the decompressed shell should be the HTML document"
        );
    }
}
