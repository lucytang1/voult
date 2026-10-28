//! Readable formatting for Actix Web's default request logger.
//!
//! The default `Logger` middleware emits one space-separated line:
//!
//! ```text
//! ::1 "GET /api/get_vault HTTP/1.1" 200 1501 "http://localhost:8081/" "Mozilla/5.0 …" 0.000534
//! ```
//!
//! We turn the request target and status into the message and move the
//! connection/request details into metadata. Long values such as the
//! user-agent stay at the end so the request itself is easy to scan.

use super::FormattedEvent;
use crate::{MetaValue, Metadata};

/// Parse Actix's default request-log line.
///
/// Returns `None` for custom logger formats or malformed lines, in which case
/// the caller keeps the original text.
pub(crate) fn parse(message: &str) -> Option<FormattedEvent> {
    let mut cursor = Cursor::new(message);

    let remote = cursor.token()?;
    let request = cursor.quoted()?;
    let status = cursor.token()?;
    let size = cursor.token()?;
    let referer = cursor.quoted()?;
    let user_agent = cursor.quoted()?;
    let elapsed_seconds = cursor.token()?;

    cursor.skip_whitespace();
    if cursor.index != cursor.input.len() {
        return None;
    }

    let (method, path, _protocol) = split_request(&request)?;
    let message = format!("{method} {path} {status}");

    let mut metadata = Metadata::new();

    if remote != "-" && !remote.is_empty() {
        metadata.insert("remote", remote);
    }
    if size != "-" && !size.is_empty() {
        match size.parse::<u64>() {
            Ok(bytes) => {
                metadata.insert("size", MetaValue::from(bytes));
            }
            Err(_) => {
                metadata.insert("size", size);
            }
        }
    }
    metadata.insert("duration", format_duration(elapsed_seconds));
    if referer != "-" && !referer.is_empty() {
        metadata.insert("referer", referer);
    }
    if user_agent != "-" && !user_agent.is_empty() {
        metadata.insert("user_agent", user_agent);
    }

    Some(FormattedEvent { message, metadata })
}

/// Split the quoted request line into method, target, and protocol.
fn split_request(request: &str) -> Option<(&str, &str, &str)> {
    let mut parts = request.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    let protocol = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    Some((method, path, protocol))
}

/// Turn Actix's fractional seconds into a compact human-readable duration.
fn format_duration(raw: &str) -> String {
    match raw.parse::<f64>() {
        Ok(seconds) if seconds >= 1.0 => format!("{seconds:.3}s"),
        Ok(seconds) => format!("{:.3}ms", seconds * 1000.0),
        Err(_) => raw.to_string(),
    }
}

struct Cursor<'a> {
    input: &'a str,
    index: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, index: 0 }
    }

    fn skip_whitespace(&mut self) {
        while self.index < self.input.len() {
            let ch = self.input[self.index..]
                .chars()
                .next()
                .expect("index is a char boundary");
            if !ch.is_whitespace() {
                break;
            }
            self.index += ch.len_utf8();
        }
    }

    fn token(&mut self) -> Option<&'a str> {
        self.skip_whitespace();
        let start = self.index;
        while self.index < self.input.len() {
            let ch = self.input[self.index..]
                .chars()
                .next()
                .expect("index is a char boundary");
            if ch.is_whitespace() {
                break;
            }
            self.index += ch.len_utf8();
        }
        if self.index == start {
            None
        } else {
            Some(&self.input[start..self.index])
        }
    }

    /// Actix's default logger does not escape quoted values, so read until the
    /// next double quote. If a user-agent itself contains a quote the line is
    /// ambiguous; callers fall back to the raw line when parsing fails.
    fn quoted(&mut self) -> Option<String> {
        self.skip_whitespace();
        if !self.input[self.index..].starts_with('"') {
            return None;
        }
        self.index += 1;

        let start = self.index;
        while self.index < self.input.len() {
            let ch = self.input[self.index..]
                .chars()
                .next()
                .expect("index is a char boundary");
            if ch == '"' {
                let value = self.input[start..self.index].to_string();
                self.index += 1;
                return Some(value);
            }
            self.index += ch.len_utf8();
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_the_default_actix_line() {
        let input = r#"::1 "GET /api/get_vault HTTP/1.1" 200 1501 "http://localhost:8081/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36" 0.000534"#;

        let event = parse(input).expect("default Actix logger line");
        assert_eq!(event.message, "GET /api/get_vault 200");

        let fields: Vec<_> = event.metadata.iter().collect();
        assert_eq!(
            fields.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
            ["remote", "size", "duration", "referer", "user_agent"]
        );
        assert!(matches!(
            fields[1].1,
            MetaValue::Json(serde_json::Value::Number(value)) if value.as_u64() == Some(1501)
        ));
        assert!(matches!(
            fields[2].1,
            MetaValue::Json(serde_json::Value::String(value)) if value == "0.534ms"
        ));
        assert!(matches!(
            fields[3].1,
            MetaValue::Json(serde_json::Value::String(value)) if value == "http://localhost:8081/"
        ));
        assert!(matches!(
            fields[4].1,
            MetaValue::Json(serde_json::Value::String(value)) if value.starts_with("Mozilla/5.0")
        ));
    }

    #[test]
    fn omits_placeholder_metadata() {
        let input = r#"127.0.0.1 "GET / HTTP/1.1" 404 - "-" "-" 0.0012"#;
        let event = parse(input).expect("placeholder metadata");
        assert_eq!(event.message, "GET / 404");
        let keys: Vec<_> = event.metadata.iter().map(|(key, _)| key).collect();
        assert_eq!(keys, ["remote", "duration"]);
    }

    #[test]
    fn formats_seconds_for_long_requests() {
        let input = r#"127.0.0.1 "GET /slow HTTP/1.1" 200 10 "-" "curl/8.0" 2.5000"#;
        let event = parse(input).expect("long request");
        let duration = event
            .metadata
            .iter()
            .find(|(key, _)| *key == "duration")
            .map(|(_, value)| value)
            .expect("duration");
        assert!(matches!(
            duration,
            MetaValue::Json(serde_json::Value::String(value)) if value == "2.500s"
        ));
    }

    #[test]
    fn rejects_custom_or_malformed_lines() {
        assert!(parse("plain text").is_none());
        assert!(parse(r#"::1 "GET / HTTP/1.1" 200"#).is_none());
        assert!(parse(r#"::1 "GET / HTTP/1.1" 200 10 "-" "ua" 0.1 extra"#).is_none());
    }
}
