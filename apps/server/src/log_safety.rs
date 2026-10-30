//! Helpers for values that are safe to put in a log line.
//!
//! The logger escapes control characters but knows nothing about field
//! semantics. These helpers are the small, shared vocabulary for the two
//! recurring cases: an identifier that needs correlation without being copied
//! in full, and a configuration URL that must not carry a password or query.
//!
//! See `plans/p0-log-redaction.md`.

/// First 8 characters of an identifier, for logs.
///
/// Enough to correlate the lines of one request or vault, while keeping the
/// full value (a stable vault UUID, a provider file id, an opaque revision) out
/// of a file that is copied into backups and support bundles. Never use this
/// for authorization: it is a display label, not an identity.
///
/// `char_indices` rather than byte slicing so a non-ASCII provider value cannot
/// panic on a char boundary.
pub fn short_id(id: &str) -> &str {
    match id.char_indices().nth(8) {
        Some((index, _)) => &id[..index],
        None => id,
    }
}

/// A database URL with its query/fragment and password removed.
///
/// The startup line is genuinely useful ("which database am I on?"), but the
/// raw value can contain `?mode=rwc` or, if a non-SQLite URL is ever used,
/// credentials. Keep the scheme/host/path; drop everything that could be a
/// secret. An unparseable value is replaced wholesale rather than echoed.
///
/// `Url`'s `Display` percent-encodes spaces in a path; that is cosmetic and
/// still recognisable.
pub fn database_url_for_log(raw: &str) -> String {
    match reqwest::Url::parse(raw) {
        Ok(mut url) => {
            let _ = url.set_password(None);
            url.set_query(None);
            url.set_fragment(None);
            url.to_string()
        }
        Err(_) => "<invalid database url>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_id_keeps_eight_characters() {
        assert_eq!(short_id("3f2504e0-4f89-41d3-9a0c-0305e82c3302"), "3f2504e0");
        assert_eq!(short_id("abc"), "abc");
        assert_eq!(short_id(""), "");
    }

    #[test]
    fn short_id_respects_char_boundaries() {
        // Four two-byte characters: a byte slice at 8 would panic or split.
        assert_eq!(short_id("éééééééééé"), "éééééééé");
    }

    #[test]
    fn database_url_drops_the_query_and_fragment() {
        assert_eq!(
            database_url_for_log("sqlite:///tmp/voult.db?mode=rwc"),
            "sqlite:///tmp/voult.db"
        );
        assert_eq!(
            database_url_for_log("sqlite:///tmp/voult.db?mode=rwc#frag"),
            "sqlite:///tmp/voult.db"
        );
    }

    #[test]
    fn database_url_drops_a_password() {
        assert_eq!(
            database_url_for_log("postgres://user:secret@host/db?sslmode=require"),
            "postgres://user@host/db"
        );
    }

    #[test]
    fn database_url_never_echoes_an_unparseable_value() {
        assert_eq!(
            database_url_for_log("not a url with secret"),
            "<invalid database url>"
        );
    }
}
