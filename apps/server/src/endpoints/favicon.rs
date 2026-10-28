use actix_session::Session;
use actix_web::{HttpResponse, get, http::StatusCode, web};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::error_response;
use crate::session_auth::session_vault_id;

const LOG: logger::ServerLogger = logger::Logger::create(logger::ServerContext::Favicon);

// Same-origin favicon proxy: `GET /api/favicon?u=<absolute icon URL>`.
//
// Why a proxy exists at all: the app is served with
// `Cross-Origin-Embedder-Policy: require-corp` (mandatory for sqlite-wasm
// OPFS / SharedArrayBuffer), which makes the browser refuse cross-origin
// `<img>` loads unless the host opts in via CORP — and favicon hosts don't.
// Fetching through this endpoint makes icons same-origin, so the homepage can
// render them. The extension popup needs no proxy (extension pages carry no
// COEP), but it may use it all the same.
//
// Privacy notes:
//  - Session-protected like every other /api route: the icon URLs name sites
//    in the caller's vault, so no anonymous fetching.
//  - Upstream sees only this server's IP/user-agent, never the vault owner.
//  - Responses inherit the /api `Cache-Control: no-store` scope header on
//    purpose: a *browser* disk cache of icons would be a plaintext list of
//    vault sites. The client keeps its own TTL-bounded icon cache (per vault,
//    cleared on sign-out) instead — see `apps/client/src/lib/favicon/`.
//  - The in-process `FaviconCache` below is the reason a warm icon costs no
//    DNS lookup and no upstream round-trip. It is memory only: nothing about
//    the caller's vault survives a restart on this server.
//
// SSRF notes: the URL comes from the caller's own vault (self-attack only),
// but the guards below hold regardless — absolute http(s) only, no
// credentials in URL, literal and DNS-resolved IPs must be public (no
// loopback/private/link-local), bounded redirects/size/timeout, image bytes
// only. The `<link rel="icon">` discovery fallback re-applies the same guards
// to the page it reads and to the icon it names. Residual TOCTOU (DNS changing
// between check and connect) is accepted and documented: a hostile favicon
// host is already inside your vault.

#[derive(Deserialize)]
pub struct FaviconQuery {
    pub u: String,
}

const MAX_URL_LEN: usize = 2048;
const MAX_ICON_BYTES: usize = 256 * 1024;
/// How much of a page we read when looking for its declared icon. The `<link>`
/// tags live in `<head>`, i.e. the first few KiB — a cap on the *prefix* keeps
/// the fallback cheap without rejecting real homepages (GitHub's HTML is
/// ~580 KiB, Tailwind's ~880 KiB) the way a whole-document cap would.
const MAX_HTML_PREFIX_BYTES: usize = 256 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_REDIRECTS: usize = 3;
const UPSTREAM_USER_AGENT: &str = "Voult/1.0 (favicon)";

// Cache bounds. The hit TTL is deliberately much longer than the miss TTL: a
// real icon rarely changes, while a 404 can be a transient misconfiguration.
const CACHE_MAX_ENTRIES: usize = 512;
const CACHE_MAX_BYTES: usize = 8 * 1024 * 1024;
const CACHE_HIT_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const CACHE_MISS_TTL: Duration = Duration::from_secs(30 * 60);

/// One upstream client for the whole process.
///
/// Building a `reqwest::Client` per request (the previous shape) meant no
/// connection reuse at all: every single icon paid a fresh DNS resolve, TCP
/// handshake and TLS negotiation to the favicon host. `reqwest::Client` is
/// internally an `Arc` around a pooled connection map, so sharing one is both
/// safe and the entire point.
///
/// Redirects are followed **manually** in `fetch_icon` (hence `Policy::none`):
/// reqwest's built-in policy would happily follow a `302` to `http://127.0.0.1`
/// or a private range, which is exactly the blind spot the public-IP check
/// exists to close. Each hop is re-validated on the way.
pub fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|e| {
            // Only a broken TLS backend lands here; keep serving rather than
            // refusing to boot. Icons then fail closed (502) per request.
            LOG.error(
                format_args!("favicon http client init failed ({e}); using reqwest defaults"),
                logger::Metadata::new(),
            );
            reqwest::Client::new()
        })
}

// --- In-process cache ------------------------------------------------------

enum CacheEntry {
    Icon {
        content_type: String,
        body: Vec<u8>,
    },
    Failed {
        status: StatusCode,
        code: &'static str,
        message: &'static str,
    },
}

struct Cached {
    entry: CacheEntry,
    stored_at: Instant,
    /// Accounting weight for eviction. Misses count as 0 (they are bounded by
    /// the entry cap alone).
    bytes: usize,
}

impl Cached {
    fn ttl(&self) -> Duration {
        match self.entry {
            CacheEntry::Icon { .. } => CACHE_HIT_TTL,
            CacheEntry::Failed { .. } => CACHE_MISS_TTL,
        }
    }
}

/// What a cache lookup produced. `Failed` is a *negative* entry: the upstream
/// answer was "there is no icon here", which must not cost another round-trip
/// on the next render.
pub enum CacheHit {
    Icon(Vec<u8>, String),
    Failed(StatusCode, &'static str, &'static str),
}

#[derive(Default)]
struct CacheState {
    entries: HashMap<String, Cached>,
    total_bytes: usize,
}

impl CacheState {
    fn insert(&mut self, key: &str, entry: CacheEntry, bytes: usize, now: Instant) {
        if let Some(old) = self.entries.remove(key) {
            self.total_bytes = self.total_bytes.saturating_sub(old.bytes);
        }
        self.total_bytes += bytes;
        self.entries.insert(
            key.to_string(),
            Cached {
                entry,
                stored_at: now,
                bytes,
            },
        );
        self.evict(now);
    }

    /// Drop expired entries, then the oldest until both bounds hold. Runs under
    /// the same lock as the insert, so it never sees a torn state.
    fn evict(&mut self, now: Instant) {
        self.entries
            .retain(|_, c| now.duration_since(c.stored_at) < c.ttl());
        self.total_bytes = self.entries.values().map(|c| c.bytes).sum();
        while self.entries.len() > CACHE_MAX_ENTRIES || self.total_bytes > CACHE_MAX_BYTES {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, c)| c.stored_at)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            if let Some(removed) = self.entries.remove(&oldest) {
                self.total_bytes = self.total_bytes.saturating_sub(removed.bytes);
            }
        }
    }
}

/// Process-lifetime icon cache, built **once** outside the `HttpServer::new`
/// closure (that closure runs per worker, so building it inside would give each
/// worker its own copy — see `recovery::ChallengeThrottle` for the same trap).
///
/// In-memory by design: a disk cache here would be a plaintext list of the
/// caller's vault sites sitting on the server, which the trust boundary forbids.
#[derive(Default)]
pub struct FaviconCache {
    state: Mutex<CacheState>,
}

impl FaviconCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn lookup(&self, key: &str) -> Option<CacheHit> {
        self.lookup_at(key, Instant::now())
    }

    /// `now` is a parameter so expiry is testable without sleeping.
    fn lookup_at(&self, key: &str, now: Instant) -> Option<CacheHit> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match state.entries.get(key) {
            Some(cached) if now.duration_since(cached.stored_at) < cached.ttl() => {
                Some(match &cached.entry {
                    CacheEntry::Icon { content_type, body } => {
                        CacheHit::Icon(body.clone(), content_type.clone())
                    }
                    CacheEntry::Failed {
                        status,
                        code,
                        message,
                    } => CacheHit::Failed(*status, code, message),
                })
            }
            Some(_) => {
                // Expired: drop it now so the refetch is not shadowed.
                if let Some(old) = state.entries.remove(key) {
                    state.total_bytes = state.total_bytes.saturating_sub(old.bytes);
                }
                None
            }
            None => None,
        }
    }

    fn store_icon(&self, key: &str, body: &[u8], content_type: &str) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.insert(
            key,
            CacheEntry::Icon {
                content_type: content_type.to_string(),
                body: body.to_vec(),
            },
            body.len(),
            Instant::now(),
        );
    }

    fn store_miss(&self, key: &str, status: StatusCode, code: &'static str, message: &'static str) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.insert(
            key,
            CacheEntry::Failed {
                status,
                code,
                message,
            },
            0,
            Instant::now(),
        );
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.state.lock().unwrap().entries.len()
    }
}

// --- Validation helpers ----------------------------------------------------

fn invalid_url_response() -> HttpResponse {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid icon url",
        "INVALID_FAVICON_URL",
    )
}

fn fetch_failed_response() -> HttpResponse {
    error_response(
        StatusCode::BAD_GATEWAY,
        "could not fetch icon",
        "FAVICON_FETCH_FAILED",
    )
}

/// Syntactic validation only — no network. Kept separate from the public-IP
/// check so a cache hit can answer without touching DNS.
fn validate_icon_url(raw: &str) -> Result<reqwest::Url, HttpResponse> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_URL_LEN {
        return Err(invalid_url_response());
    }
    let url = reqwest::Url::parse(trimmed).map_err(|_| invalid_url_response())?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "icon url must be http(s)",
            "INVALID_FAVICON_URL",
        ));
    }
    if url.username() != "" || url.password().is_some() || url.host_str().is_none() {
        return Err(invalid_url_response());
    }
    Ok(url)
}

/// True for IPs that must never be fetched: loopback, private, link-local,
/// multicast, unspecified, documentation, benchmarking, and IPv6 unique-local.
fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                // Carrier-grade NAT 100.64.0.0/10.
                || (o[0] == 100 && (o[1] & 0b1100_0000) == 0b0100_0000)
                // Benchmarking 198.18.0.0/15.
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19)))
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                // Unique-local fc00::/7.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Link-local fe80::/10.
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // Documentation 2001:db8::/32.
                || (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8))
        }
    }
}

/// Literal IPs are checked without DNS; hostnames are resolved and *every*
/// answer must be public (blocks DNS-rebinding to loopback/private).
async fn ensure_public_host(url: &reqwest::Url) -> Result<(), HttpResponse> {
    let Some(host) = url.host_str() else {
        return Err(invalid_url_response());
    };
    let host = host.to_string();
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !is_public_ip(&ip) {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "icon host not allowed",
                "FAVICON_HOST_DENIED",
            ));
        }
        return Ok(());
    }
    let port = url.port_or_known_default().unwrap_or(443);
    match tokio::net::lookup_host((host.as_str(), port)).await {
        Ok(addrs) => {
            let mut saw_public = false;
            for addr in addrs {
                if !is_public_ip(&addr.ip()) {
                    return Err(error_response(
                        StatusCode::BAD_REQUEST,
                        "icon host not allowed",
                        "FAVICON_HOST_DENIED",
                    ));
                }
                saw_public = true;
            }
            if saw_public {
                Ok(())
            } else {
                Err(error_response(
                    StatusCode::BAD_GATEWAY,
                    "icon host did not resolve",
                    "FAVICON_FETCH_FAILED",
                ))
            }
        }
        Err(_) => Err(error_response(
            StatusCode::BAD_GATEWAY,
            "icon host did not resolve",
            "FAVICON_FETCH_FAILED",
        )),
    }
}

/// Minimal magic-byte sniff for common icon formats (upstream Content-Type is
/// usually right, but a missing/wrong header shouldn't 502 a valid icon).
fn sniff_image_kind(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() >= 8 && &bytes[..8] == b"\x89PNG\r\n\x1a\n" {
        return Some("image/png");
    }
    if bytes.len() >= 3 && &bytes[..3] == b"\xff\xd8\xff" {
        return Some("image/jpeg");
    }
    if bytes.len() >= 6 && (&bytes[..6] == b"GIF87a" || &bytes[..6] == b"GIF89a") {
        return Some("image/gif");
    }
    if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    if bytes.len() >= 4 && &bytes[..4] == b"\x00\x00\x01\x00" {
        return Some("image/x-icon");
    }
    if bytes.len() >= 2 && &bytes[..2] == b"BM" {
        return Some("image/bmp");
    }
    // SVG: optional XML prolog / whitespace / comments before `<svg`.
    let head = bytes
        .get(..bytes.len().min(512))
        .and_then(|b| std::str::from_utf8(b).ok())
        .unwrap_or("")
        .trim_start();
    let head = head
        .strip_prefix("<?xml")
        .and_then(|rest| rest.split_once("?>").map(|(_, tail)| tail.trim_start()))
        .unwrap_or(head);
    if head.starts_with("<svg") {
        return Some("image/svg+xml");
    }
    None
}

// --- Upstream fetching -----------------------------------------------------

struct Icon {
    bytes: Vec<u8>,
    content_type: String,
}

/// A failed upstream answer, kept as data so it can be negative-cached and
/// replayed byte-for-byte on the next request.
struct FetchFailure {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

fn fetch_failure(status: StatusCode, code: &'static str, message: &'static str) -> FetchFailure {
    FetchFailure {
        status,
        code,
        message,
    }
}

/// Fetches an icon, following up to `MAX_REDIRECTS` redirects **by hand** so
/// every hop is checked against the public-IP guard. The first URL was already
/// validated by the caller, so its DNS lookup is not repeated.
async fn fetch_icon(client: &reqwest::Client, url: &reqwest::Url) -> Result<Icon, FetchFailure> {
    let mut current = url.clone();
    let mut hops = 0usize;
    loop {
        if hops > 0 && ensure_public_host(&current).await.is_err() {
            LOG.log(
                format_args!("favicon redirect rejected: non-public host"),
                logger::Metadata::new(),
            );
            return Err(fetch_failure(
                StatusCode::BAD_GATEWAY,
                "FAVICON_FETCH_FAILED",
                "icon host not allowed",
            ));
        }

        let upstream = client
            .get(current.clone())
            .header(reqwest::header::USER_AGENT, UPSTREAM_USER_AGENT)
            .send()
            .await
            .map_err(|e| {
                LOG.log(
                    format_args!("favicon fetch failed: {e}"),
                    logger::Metadata::new(),
                );
                fetch_failure(
                    StatusCode::BAD_GATEWAY,
                    "FAVICON_FETCH_FAILED",
                    "could not fetch icon",
                )
            })?;

        if upstream.status().is_redirection() {
            if hops == MAX_REDIRECTS {
                return Err(fetch_failure(
                    StatusCode::BAD_GATEWAY,
                    "FAVICON_FETCH_FAILED",
                    "too many redirects",
                ));
            }
            let Some(location) = upstream
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
            else {
                return Err(fetch_failure(
                    StatusCode::BAD_GATEWAY,
                    "FAVICON_FETCH_FAILED",
                    "redirect without a location",
                ));
            };
            let next = current.join(location).map_err(|_| {
                fetch_failure(
                    StatusCode::BAD_GATEWAY,
                    "FAVICON_FETCH_FAILED",
                    "invalid redirect",
                )
            })?;
            if next.scheme() != "https" && next.scheme() != "http" {
                return Err(fetch_failure(
                    StatusCode::BAD_GATEWAY,
                    "FAVICON_FETCH_FAILED",
                    "invalid redirect",
                ));
            }
            if next.username() != "" || next.password().is_some() || next.host_str().is_none() {
                return Err(fetch_failure(
                    StatusCode::BAD_GATEWAY,
                    "FAVICON_FETCH_FAILED",
                    "invalid redirect",
                ));
            }
            current = next;
            hops += 1;
            continue;
        }

        if !upstream.status().is_success() {
            return Err(fetch_failure(
                StatusCode::BAD_GATEWAY,
                "FAVICON_FETCH_FAILED",
                "icon host returned an error",
            ));
        }
        if let Some(len) = upstream.content_length()
            && len > MAX_ICON_BYTES as u64
        {
            return Err(fetch_failure(
                StatusCode::BAD_GATEWAY,
                "FAVICON_TOO_LARGE",
                "icon too large",
            ));
        }
        let declared = upstream
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(';').next().unwrap_or("").trim().to_lowercase());
        let bytes = upstream.bytes().await.map_err(|e| {
            LOG.log(
                format_args!("favicon read failed: {e}"),
                logger::Metadata::new(),
            );
            fetch_failure(
                StatusCode::BAD_GATEWAY,
                "FAVICON_FETCH_FAILED",
                "could not read icon",
            )
        })?;
        if bytes.is_empty() {
            return Err(fetch_failure(
                StatusCode::BAD_GATEWAY,
                "FAVICON_FETCH_FAILED",
                "could not read icon",
            ));
        }
        if bytes.len() > MAX_ICON_BYTES {
            return Err(fetch_failure(
                StatusCode::BAD_GATEWAY,
                "FAVICON_TOO_LARGE",
                "icon too large",
            ));
        }
        // Trust a declared image/* type; otherwise sniff. Anything else is not
        // proxied (an HTML error page must never be served as an image).
        let content_type = match declared {
            Some(ct) if ct.starts_with("image/") => ct,
            _ => match sniff_image_kind(&bytes) {
                Some(kind) => kind.to_string(),
                None => {
                    return Err(fetch_failure(
                        StatusCode::BAD_GATEWAY,
                        "FAVICON_NOT_AN_IMAGE",
                        "not an image",
                    ));
                }
            },
        };
        return Ok(Icon {
            bytes: bytes.to_vec(),
            content_type,
        });
    }
}

/// Only a guess-shaped URL deserves discovery: `<origin>/favicon.ico` is what
/// client-side renderers synthesize when an item stores no icon
/// (`faviconForItem` in `@voult/vault-core`). A stored, specific icon URL that
/// fails is the page's own choice and is not second-guessed.
fn wants_discovery(url: &reqwest::Url) -> bool {
    url.path().to_ascii_lowercase().ends_with("favicon.ico")
}

/// Read the page at the icon URL's origin and return the icon it declares.
///
/// The page and the icon it names each pass the same public-IP guard as the
/// primary fetch. Cross-origin targets are allowed on purpose — real sites
/// host icons on CDNs — but the destination is still restricted to public IPs,
/// so this cannot be pointed at the local network.
async fn discover_declared_icon(client: &reqwest::Client, icon_url: &reqwest::Url) -> Option<Icon> {
    let mut page_url = icon_url.clone();
    page_url.set_path("/");
    page_url.set_query(None);
    page_url.set_fragment(None);
    if ensure_public_host(&page_url).await.is_err() {
        return None;
    }
    let mut response = match client
        .get(page_url.clone())
        .header(reqwest::header::USER_AGENT, UPSTREAM_USER_AGENT)
        .header(
            reqwest::header::ACCEPT,
            "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
        )
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => return None,
    };
    if !response.status().is_success() {
        return None;
    }
    let declared = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(';').next().unwrap_or("").trim().to_lowercase());
    if let Some(ct) = declared
        && !ct.starts_with("text/html")
        && !ct.starts_with("application/xhtml")
    {
        return None;
    }
    // Stream only the prefix: enough to reach the head of any real page, and a
    // hard bound on what a hostile host can make us download.
    let mut bytes: Vec<u8> = Vec::with_capacity(32 * 1024);
    while bytes.len() < MAX_HTML_PREFIX_BYTES {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let remaining = MAX_HTML_PREFIX_BYTES - bytes.len();
                bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
            }
            Ok(None) => break,
            Err(_) => return None,
        }
    }
    let html = String::from_utf8_lossy(&bytes);
    let href = find_declared_icon(&html)?;
    let resolved = page_url.join(&href).ok()?;
    if resolved.scheme() != "https" && resolved.scheme() != "http" {
        return None;
    }
    if resolved.username() != "" || resolved.password().is_some() {
        return None;
    }
    if ensure_public_host(&resolved).await.is_err() {
        return None;
    }
    fetch_icon(client, &resolved).await.ok()
}

// --- `<link rel="icon">` scanner -------------------------------------------

/// Longest href we will consider from a page. Bounded because it is attacker
/// controlled and gets resolved into a request.
const MAX_DECLARED_HREF_LEN: usize = 2048;

/// Finds the best `rel="icon"` href in an HTML document, or `None`.
///
/// Hand-written instead of pulling in an HTML parser or a regex dependency:
/// the shape we need is narrow (self-contained `<link>` tags in the document
/// head), the rules must match the extension's selection
/// (`apps/extension/src/content/favicon.ts`) so all surfaces pick the same
/// icon, and this code runs on the SSRF boundary where an auditable
/// implementation is worth more than a general one.
///
/// Assumptions, all safe-by-fallback: attributes are quoted (unquoted values
/// are still read), `&amp;` is the only entity decoded, `<base href>` is
/// ignored, and `media` variants are not matched (the server cannot know the
/// client's colour scheme). A wrong pick still yields a valid, public icon.
fn find_declared_icon(html: &str) -> Option<String> {
    // ASCII-lowercasing preserves byte offsets, so indices found in `lower` are
    // valid slices of `html`.
    let lower = html.to_ascii_lowercase();
    let mut best: Option<(u32, String)> = None;
    let mut cursor = 0usize;
    while let Some(found) = lower[cursor..].find("<link") {
        let start = cursor + found + "<link".len();
        // `<linkfoo>` is not a link tag.
        match lower[start..].chars().next() {
            Some(c) if c.is_whitespace() || c == '/' || c == '>' => {}
            Some(_) => {
                cursor = start;
                continue;
            }
            None => break,
        }
        let Some(end_offset) = lower[start..].find('>') else {
            break;
        };
        let end = start + end_offset;
        // `lower` and `html` share offsets; `end` lands on an ASCII '>'.
        let tag = &html[start..end];
        cursor = end + 1;

        let Some(href) = icon_href_in_tag(tag) else {
            continue;
        };
        let score = icon_score(tag);
        if best
            .as_ref()
            .is_none_or(|(best_score, _)| score < *best_score)
        {
            best = Some((score, href));
        }
    }
    best.map(|(_, href)| href)
}

/// Parses one `<link …>` tag and returns its href when the tag declares an
/// icon. `mask-icon` is skipped: it is a monochrome Safari pinned-tab glyph,
/// not a site icon.
fn icon_href_in_tag(tag: &str) -> Option<String> {
    let attributes = tag_attributes(tag);
    let rel = attributes
        .iter()
        .find(|(name, _)| name == "rel")
        .map(|(_, value)| value.to_ascii_lowercase())?;
    let tokens: Vec<&str> = rel.split_whitespace().collect();
    if tokens.contains(&"mask-icon") {
        return None;
    }
    let declares_icon = tokens.iter().any(|t| {
        matches!(
            *t,
            "icon" | "shortcut" | "apple-touch-icon" | "apple-touch-icon-precomposed"
        )
    });
    if !declares_icon {
        return None;
    }
    let href = attributes
        .iter()
        .find(|(name, _)| name == "href")
        .map(|(_, value)| value.trim().to_string())?;
    if href.is_empty() || href.len() > MAX_DECLARED_HREF_LEN {
        return None;
    }
    if !is_fetchable_href(&href) {
        return None;
    }
    Some(unescape_amp(&href))
}

/// Relative hrefs are fine (resolved later); an absolute one must be http(s).
/// `data:`, `javascript:`, `blob:` and friends are rejected here.
fn is_fetchable_href(href: &str) -> bool {
    let lower = href.to_ascii_lowercase();
    let Some(colon) = lower.find(':') else {
        return true; // no scheme → relative
    };
    let scheme = &lower[..colon];
    // A path segment containing ':' before any '/' is rare but legal; only
    // treat it as a scheme when it looks like one.
    if scheme.is_empty()
        || !scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return true;
    }
    scheme == "http" || scheme == "https"
}

/// Selection score for a candidate link: lower wins. Mirrors the extension's
/// preference for a raster icon closest to 32 px, then a declared-size-less
/// Apple touch icon, then anything else.
fn icon_score(tag: &str) -> u32 {
    let attributes = tag_attributes(tag);
    let rel = attributes
        .iter()
        .find(|(name, _)| name == "rel")
        .map(|(_, value)| value.to_ascii_lowercase())
        .unwrap_or_default();
    // `rel="alternate icon"` is a declared fallback; the primary icon should
    // win when both exist (GitHub declares an SVG icon plus an alternate PNG).
    let alternate_penalty = if rel.contains("alternate") { 50 } else { 0 };

    let sizes = attributes
        .iter()
        .find(|(name, _)| name == "sizes")
        .map(|(_, value)| value.to_ascii_lowercase());
    if let Some(sizes) = sizes {
        let mut best: Option<u32> = None;
        for token in sizes.split_whitespace() {
            let Some((w, h)) = token.split_once('x') else {
                continue;
            };
            let (Ok(w), Ok(h)) = (w.parse::<u32>(), h.parse::<u32>()) else {
                continue;
            };
            let side = w.max(h);
            best = Some(best.map_or(side, |current| current.max(side)));
        }
        if let Some(side) = best {
            // Explicit sizes always beat sizeless candidates: the favicon is
            // painted at ~32 px, so a 32×32 variant is the sharpest choice.
            return side.abs_diff(32) + alternate_penalty;
        }
    }
    let base = if rel.contains("apple-touch-icon") {
        100
    } else {
        200
    };
    base + alternate_penalty
}

/// Minimal `name="value"` scanner for one tag. Character-based so multibyte
/// UTF-8 in attribute values cannot split a byte boundary.
fn tag_attributes(tag: &str) -> Vec<(String, String)> {
    let chars: Vec<char> = tag.chars().collect();
    let mut out: Vec<(String, String)> = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        while i < chars.len() && (chars[i].is_whitespace() || chars[i] == '/') {
            i += 1;
        }
        let name_start = i;
        while i < chars.len() && !chars[i].is_whitespace() && chars[i] != '=' {
            i += 1;
        }
        if i == name_start {
            break;
        }
        let name: String = chars[name_start..i].iter().collect();
        let name = name.to_ascii_lowercase();
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < chars.len() && chars[i] == '=' {
            i += 1;
            while i < chars.len() && chars[i].is_whitespace() {
                i += 1;
            }
            if i < chars.len() && (chars[i] == '"' || chars[i] == '\'') {
                let quote = chars[i];
                i += 1;
                let value_start = i;
                while i < chars.len() && chars[i] != quote {
                    i += 1;
                }
                value = chars[value_start..i].iter().collect();
                if i < chars.len() {
                    i += 1; // closing quote
                }
            } else {
                let value_start = i;
                while i < chars.len() && !chars[i].is_whitespace() {
                    i += 1;
                }
                value = chars[value_start..i].iter().collect();
            }
        }
        if !name.is_empty() {
            out.push((name, value));
        }
    }
    out
}

fn unescape_amp(value: &str) -> String {
    value.replace("&amp;", "&")
}

// --- Handler ---------------------------------------------------------------

/// Wraps bytes in the response shape every icon answer uses. CORP lets the
/// split-origin dev page embed the icon under COEP; `no-store` comes from the
/// /api scope and is intentionally not overridden.
fn icon_response(bytes: Vec<u8>, content_type: String) -> HttpResponse {
    HttpResponse::Ok()
        .content_type(content_type)
        .insert_header(("Cross-Origin-Resource-Policy", "cross-origin"))
        .body(bytes)
}

#[get("/favicon")]
pub async fn favicon(
    query: web::Query<FaviconQuery>,
    session: Session,
    client: web::Data<reqwest::Client>,
    cache: web::Data<FaviconCache>,
) -> HttpResponse {
    match session_vault_id(&session) {
        Ok(Some(_)) => {}
        Ok(None) | Err(_) => return crate::error::session_required(),
    }

    // 1. Syntax only. A cache hit below answers without any DNS or network.
    let url = match validate_icon_url(&query.u) {
        Ok(url) => url,
        Err(response) => return response,
    };

    let key = url.as_str().to_string();
    if let Some(hit) = cache.lookup(&key) {
        return match hit {
            CacheHit::Icon(bytes, content_type) => icon_response(bytes, content_type),
            CacheHit::Failed(status, code, message) => error_response(status, message, code),
        };
    }

    // 2. SSRF guard. Runs only on a miss, so cached answers stay instant.
    if let Err(response) = ensure_public_host(&url).await {
        return response;
    }

    // 3. Primary fetch, then (for a guessed /favicon.ico only) discovery of the
    //    icon the page actually declares. A failure is negative-cached either
    //    way, so a dead icon costs one round-trip, not one per render.
    let icon = match fetch_icon(&client, &url).await {
        Ok(icon) => Some(icon),
        Err(failure) => {
            let discovered = if wants_discovery(&url) {
                discover_declared_icon(&client, &url).await
            } else {
                None
            };
            if discovered.is_none() {
                cache.store_miss(&key, failure.status, failure.code, failure.message);
            }
            discovered
        }
    };

    match icon {
        Some(icon) => {
            // Never log the URL: it names a site in the caller's vault.
            LOG.log(
                format_args!("favicon proxied ({} bytes)", icon.bytes.len()),
                logger::Metadata::new(),
            );
            cache.store_icon(&key, &icon.bytes, &icon.content_type);
            icon_response(icon.bytes, icon.content_type)
        }
        None => fetch_failed_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_ips_pass_and_special_ranges_fail() {
        for ok in ["8.8.8.8", "1.1.1.1", "93.184.216.34"] {
            assert!(is_public_ip(&ok.parse().unwrap()), "{ok} should be public");
        }
        for bad in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.10.20",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "100.64.0.1",
            "198.18.0.1",
            "192.0.2.1",
            "203.0.113.5",
            "::1",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "::",
            "2001:db8::1",
        ] {
            assert!(
                !is_public_ip(&bad.parse().unwrap()),
                "{bad} should be denied"
            );
        }
    }

    #[test]
    fn sniffing_recognises_common_icon_formats() {
        assert_eq!(
            sniff_image_kind(b"\x89PNG\r\n\x1a\nrest"),
            Some("image/png")
        );
        assert_eq!(sniff_image_kind(b"\xff\xd8\xff rest"), Some("image/jpeg"));
        assert_eq!(sniff_image_kind(b"GIF89a rest"), Some("image/gif"));
        let mut webp = b"RIFFxxxxWEBP".to_vec();
        webp.extend_from_slice(&[0; 4]);
        assert_eq!(sniff_image_kind(&webp), Some("image/webp"));
        assert_eq!(
            sniff_image_kind(b"\x00\x00\x01\x00 rest"),
            Some("image/x-icon")
        );
        assert_eq!(sniff_image_kind(b"\xef\xbb\xbf<svg xmlns"), None); // BOM not handled
        assert_eq!(
            sniff_image_kind(b"  <?xml version=\"1.0\"?><svg viewBox"),
            Some("image/svg+xml")
        );
        assert_eq!(
            sniff_image_kind(b"<svg viewBox=\"0 0 16 16\">"),
            Some("image/svg+xml")
        );
        assert_eq!(sniff_image_kind(b"<html><body>nope"), None);
        assert_eq!(sniff_image_kind(b""), None);
    }

    #[test]
    fn only_http_s_urls_with_hosts_parse() {
        let url = reqwest::Url::parse("https://github.com/favicon.ico").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("github.com"));
        assert!(
            reqwest::Url::parse("javascript:alert(1)")
                .unwrap()
                .host_str()
                .is_none()
        );
        assert!(
            reqwest::Url::parse("data:image/png;base64,xx")
                .unwrap()
                .host_str()
                .is_none()
        );
        assert!(reqwest::Url::parse("/favicon.ico").is_err());
    }

    #[test]
    fn validate_rejects_non_http_and_relative_and_credentials() {
        for bad in [
            "",
            "   ",
            "/favicon.ico",
            "javascript:alert(1)",
            "data:image/png;base64,xx",
            "ftp://example.com/icon.png",
            "https://user:pass@example.com/icon.png",
        ] {
            assert!(validate_icon_url(bad).is_err(), "{bad} must be rejected");
        }
        let ok = validate_icon_url(" https://example.com/favicon.ico ").unwrap();
        assert_eq!(ok.as_str(), "https://example.com/favicon.ico");
    }

    #[test]
    fn discovery_is_only_attempted_for_favicon_ico_guesses() {
        let ico = reqwest::Url::parse("https://a.test/favicon.ico").unwrap();
        assert!(wants_discovery(&ico));
        let stored = reqwest::Url::parse("https://a.test/icons/apple-touch-icon.png").unwrap();
        assert!(!wants_discovery(&stored));
    }

    #[test]
    fn finds_the_declared_icon_and_prefers_32px() {
        let html = r#"<html><head>
            <link rel="icon" href="/small.png" sizes="16x16">
            <link rel="icon" href="/best.png" sizes="32x32">
            <link rel="stylesheet" href="/site.css">
        </head></html>"#;
        assert_eq!(find_declared_icon(html).as_deref(), Some("/best.png"));
    }

    #[test]
    fn finds_icons_across_attribute_quirks() {
        // Uppercase tag + attribute, single quotes.
        assert_eq!(
            find_declared_icon("<LINK REL='shortcut icon' HREF='/f.ico'>").as_deref(),
            Some("/f.ico")
        );
        // Unquoted value.
        assert_eq!(
            find_declared_icon("<link rel=icon href=/raw.ico>").as_deref(),
            Some("/raw.ico"),
        );
        // Entity-escaped query string.
        assert_eq!(
            find_declared_icon("<link rel=\"icon\" href=\"/i?x=1&amp;y=2\">").as_deref(),
            Some("/i?x=1&y=2")
        );
        // Apple touch icon when nothing is sized.
        assert_eq!(
            find_declared_icon(
                "<link rel=\"apple-touch-icon\" href=\"/touch.png\"><link rel=\"icon\" href=\"/plain.png\">"
            )
            .as_deref(),
            Some("/touch.png")
        );
        // Absolute CDN href.
        assert_eq!(
            find_declared_icon("<link rel=\"icon\" href=\"https://cdn.test/i.png\">").as_deref(),
            Some("https://cdn.test/i.png")
        );
    }

    #[test]
    fn rejects_unusable_candidates() {
        // mask-icon is a Safari pinned-tab glyph, not a site icon.
        assert_eq!(
            find_declared_icon("<link rel=\"mask-icon\" href=\"/m.svg\">"),
            None
        );
        // data: URIs are never fetched.
        assert_eq!(
            find_declared_icon("<link rel=\"icon\" href=\"data:image/png;base64,xx\">"),
            None
        );
        // No link at all / unrelated rels.
        assert_eq!(find_declared_icon("<html><body>hi</body></html>"), None);
        assert_eq!(
            find_declared_icon("<link rel=\"stylesheet\" href=\"/a.css\">"),
            None
        );
        // `<linkfoo>` is not a tag.
        assert_eq!(
            find_declared_icon("<linkfoo rel=\"icon\" href=\"/a.ico\">"),
            None
        );
        // Truncated tag.
        assert_eq!(
            find_declared_icon("<link rel=\"icon\" href=\"/a.ico\""),
            None
        );
        // Empty href.
        assert_eq!(find_declared_icon("<link rel=\"icon\" href=\"\">"), None);
    }

    #[test]
    fn primary_icon_beats_an_alternate_fallback() {
        let html = r#"<link rel="alternate icon" href="/alt.png">
            <link rel="icon" type="image/svg+xml" href="/primary.svg">"#;
        assert_eq!(find_declared_icon(html).as_deref(), Some("/primary.svg"));
    }

    #[test]
    fn icon_href_handles_utf8_values_without_panicking() {
        assert_eq!(
            find_declared_icon("<link rel=\"icon\" href=\"/ïcône-ü.png\">").as_deref(),
            Some("/ïcône-ü.png")
        );
    }

    #[test]
    fn cache_serves_hits_and_expires_them() {
        let cache = FaviconCache::new();
        let key = "https://a.test/favicon.ico";
        cache.store_icon(key, b"png-bytes", "image/png");
        match cache.lookup(key) {
            Some(CacheHit::Icon(bytes, content_type)) => {
                assert_eq!(bytes, b"png-bytes");
                assert_eq!(content_type, "image/png");
            }
            _ => panic!("expected a cached icon"),
        }

        let later = Instant::now() + CACHE_HIT_TTL + Duration::from_secs(1);
        assert!(cache.lookup_at(key, later).is_none());
        // The expired entry was dropped, not just shadowed.
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn negative_entries_are_replayed_then_expire() {
        let cache = FaviconCache::new();
        let key = "https://a.test/favicon.ico";
        cache.store_miss(
            key,
            StatusCode::BAD_GATEWAY,
            "FAVICON_FETCH_FAILED",
            "could not fetch icon",
        );
        match cache.lookup(key) {
            Some(CacheHit::Failed(status, code, _)) => {
                assert_eq!(status, StatusCode::BAD_GATEWAY);
                assert_eq!(code, "FAVICON_FETCH_FAILED");
            }
            _ => panic!("expected a negative entry"),
        }
        // Misses expire far sooner than hits.
        let later = Instant::now() + CACHE_MISS_TTL + Duration::from_secs(1);
        assert!(cache.lookup_at(key, later).is_none());
    }

    #[test]
    fn cache_evicts_oldest_beyond_the_entry_cap() {
        let cache = FaviconCache::new();
        for i in 0..(CACHE_MAX_ENTRIES + 8) {
            cache.store_icon(&format!("https://a.test/{i}.ico"), b"x", "image/png");
        }
        assert!(cache.len() <= CACHE_MAX_ENTRIES);
    }

    #[test]
    fn cache_evicts_to_stay_under_the_byte_cap() {
        let cache = FaviconCache::new();
        let body = vec![0u8; 1024 * 1024];
        for i in 0..(CACHE_MAX_BYTES / body.len() + 2) {
            cache.store_icon(&format!("https://a.test/{i}.ico"), &body, "image/png");
        }
        let state = cache.state.lock().unwrap();
        assert!(state.total_bytes <= CACHE_MAX_BYTES);
    }

    // Wiring test: proves the route is reachable with the two shared `web::Data`
    // values installed (`reqwest::Client` + `FaviconCache`). A mismatch there is
    // invisible at compile time and only shows up as a 500 on first request.
    #[actix_web::test]
    async fn unauthenticated_requests_are_rejected_with_the_shared_state_installed() {
        use actix_session::{SessionMiddleware, storage::CookieSessionStore};
        use actix_web::{App, cookie::Key, test};

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(build_http_client()))
                .app_data(web::Data::new(FaviconCache::new()))
                .wrap(SessionMiddleware::new(
                    CookieSessionStore::default(),
                    Key::generate(),
                ))
                .service(favicon),
        )
        .await;

        let request = test::TestRequest::get()
            .uri("/favicon?u=https%3A%2F%2Fexample.com%2Ffavicon.ico")
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "the proxy must never fetch anonymously"
        );
    }
}
