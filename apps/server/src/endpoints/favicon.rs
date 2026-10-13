use actix_session::Session;
use actix_web::{HttpResponse, get, http::StatusCode, web};
use serde::Deserialize;
use std::net::IpAddr;

use crate::error::error_response;
use crate::session_auth::session_vault_id;

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
//    purpose: a disk cache of icons would be a plaintext list of vault sites.
//    Icons are tiny; refetching per page load is the trade-off.
//
// SSRF notes: the URL comes from the caller's own vault (self-attack only),
// but the guards below hold regardless — absolute http(s) only, no
// credentials in URL, literal and DNS-resolved IPs must be public (no
// loopback/private/link-local), bounded redirects/size/timeout, image bytes
// only. Residual TOCTOU (DNS changing between check and connect) is accepted
// and documented: a hostile favicon host is already inside your vault.

#[derive(Deserialize)]
pub struct FaviconQuery {
    pub u: String,
}

const MAX_URL_LEN: usize = 2048;
const MAX_ICON_BYTES: usize = 256 * 1024;
const FETCH_TIMEOUT_SECS: u64 = 8;
const MAX_REDIRECTS: usize = 3;

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

#[get("/favicon")]
pub async fn favicon(query: web::Query<FaviconQuery>, session: Session) -> HttpResponse {
    match session_vault_id(&session) {
        Ok(Some(_)) => {}
        Ok(None) | Err(_) => return crate::error::session_required(),
    }

    let raw = query.u.trim();
    if raw.is_empty() || raw.len() > MAX_URL_LEN {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid icon url",
            "INVALID_FAVICON_URL",
        );
    }
    let url = match reqwest::Url::parse(raw) {
        Ok(u) => u,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid icon url",
                "INVALID_FAVICON_URL",
            );
        }
    };
    if url.scheme() != "https" && url.scheme() != "http" {
        return error_response(
            StatusCode::BAD_REQUEST,
            "icon url must be http(s)",
            "INVALID_FAVICON_URL",
        );
    }
    if url.username() != "" || url.password().is_some() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid icon url",
            "INVALID_FAVICON_URL",
        );
    }
    let host = match url.host_str() {
        Some(h) => h.to_string(),
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid icon url",
                "INVALID_FAVICON_URL",
            );
        }
    };
    // Literal IPs are checked without DNS; hostnames are resolved and every
    // answer must be public (blocks DNS-rebinding to loopback/private).
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !is_public_ip(&ip) {
            return error_response(
                StatusCode::BAD_REQUEST,
                "icon host not allowed",
                "FAVICON_HOST_DENIED",
            );
        }
    } else {
        let port = url.port_or_known_default().unwrap_or(443);
        match tokio::net::lookup_host((host.as_str(), port)).await {
            Ok(addrs) => {
                let mut saw_public = false;
                for addr in addrs {
                    if !is_public_ip(&addr.ip()) {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "icon host not allowed",
                            "FAVICON_HOST_DENIED",
                        );
                    }
                    saw_public = true;
                }
                if !saw_public {
                    return error_response(
                        StatusCode::BAD_GATEWAY,
                        "icon host did not resolve",
                        "FAVICON_FETCH_FAILED",
                    );
                }
            }
            Err(_) => {
                return error_response(
                    StatusCode::BAD_GATEWAY,
                    "icon host did not resolve",
                    "FAVICON_FETCH_FAILED",
                );
            }
        }
    }

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(FETCH_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            log::warn!("favicon client build failed: {e}");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "icon fetch unavailable",
                "FAVICON_FETCH_FAILED",
            );
        }
    };
    let upstream = match client
        .get(url)
        .header(reqwest::header::USER_AGENT, "Voult/1.0 (favicon)")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            log::info!("favicon fetch failed: {e}");
            return error_response(
                StatusCode::BAD_GATEWAY,
                "could not fetch icon",
                "FAVICON_FETCH_FAILED",
            );
        }
    };
    if !upstream.status().is_success() {
        return error_response(
            StatusCode::BAD_GATEWAY,
            "icon host returned an error",
            "FAVICON_FETCH_FAILED",
        );
    }
    if let Some(len) = upstream.content_length() {
        if len > MAX_ICON_BYTES as u64 {
            return error_response(
                StatusCode::BAD_GATEWAY,
                "icon too large",
                "FAVICON_TOO_LARGE",
            );
        }
    }
    let declared = upstream
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(';').next().unwrap_or("").trim().to_lowercase());
    let bytes = match upstream.bytes().await {
        Ok(b) => b,
        Err(e) => {
            log::info!("favicon read failed: {e}");
            return error_response(
                StatusCode::BAD_GATEWAY,
                "could not read icon",
                "FAVICON_FETCH_FAILED",
            );
        }
    };
    if bytes.len() > MAX_ICON_BYTES || bytes.is_empty() {
        return error_response(
            StatusCode::BAD_GATEWAY,
            "icon too large",
            "FAVICON_TOO_LARGE",
        );
    }
    // Trust a declared image/* type; otherwise sniff. Anything else is not
    // proxied (an HTML error page must never be served as an image).
    let content_type = match declared {
        Some(ct) if ct.starts_with("image/") => ct,
        _ => match sniff_image_kind(&bytes) {
            Some(kind) => kind.to_string(),
            None => {
                return error_response(
                    StatusCode::BAD_GATEWAY,
                    "not an image",
                    "FAVICON_NOT_AN_IMAGE",
                );
            }
        },
    };

    // Never log the URL: it names a site in the caller's vault.
    log::info!("favicon proxied ({} bytes)", bytes.len());
    HttpResponse::Ok()
        .content_type(content_type)
        // Lets the split-origin dev page (:8081 ← :8080) embed the icon under
        // COEP; same-origin production doesn't need it but is unaffected.
        .insert_header(("Cross-Origin-Resource-Policy", "cross-origin"))
        .body(bytes)
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
}
