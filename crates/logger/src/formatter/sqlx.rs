//! Readable formatting for `sqlx::query` records.
//!
//! SQLx emits its query timing events through `tracing`; the `log` compatibility
//! layer renders the structured fields as one escaped `key=value` string. That
//! is accurate but unpleasant to read:
//!
//! ```text
//! summary="SELECT \"vault\".\"id\"…" db.statement="\n\nSELECT ...\n" rows_affected=0 ...
//! ```
//!
//! For the `sqlx::query` target we parse the fields, unescape the SQL summary,
//! and re-emit the useful counters as normal metadata. The full `db.statement`
//! is intentionally omitted: the summary is the readable message, and the full
//! statement duplicates it with escaped newlines.

use super::FormattedEvent;
use crate::{MetaValue, Metadata};

/// Parse a SQLx query log message. Returns `None` when the message is not the
/// expected structured shape, in which case the caller keeps the original text.
pub(crate) fn parse(message: &str) -> Option<FormattedEvent> {
    let fields = parse_fields(message)?;

    let field = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };

    let summary = field("summary").unwrap_or_default();
    let statement = field("db.statement").unwrap_or_default();
    let selected = if summary.trim().is_empty() {
        statement
    } else {
        summary
    };
    let message = normalize_sql(selected);
    if message.is_empty() {
        return None;
    }

    let mut metadata = Metadata::new();
    if let Some(value) = field("rows_affected") {
        insert_number_or_text(&mut metadata, "rows_affected", value);
    }
    if let Some(value) = field("rows_returned") {
        insert_number_or_text(&mut metadata, "rows_returned", value);
    }
    if let Some(value) = field("elapsed") {
        metadata.insert("elapsed", value);
    } else if let Some(value) = field("elapsed_secs") {
        metadata.insert("elapsed_secs", value);
    }
    if let Some(value) = field("slow_threshold") {
        metadata.insert("slow_threshold", value);
    }

    Some(FormattedEvent { message, metadata })
}

fn insert_number_or_text(metadata: &mut Metadata, key: &'static str, value: &str) {
    match value.parse::<u64>() {
        Ok(number) => {
            metadata.insert(key, MetaValue::from(number));
        }
        Err(_) => {
            metadata.insert(key, value);
        }
    }
}

/// Parse `key=value` pairs where values may be quoted, escaped strings.
///
/// A trailing non-`key=value` token (for example SQLx's slow-statement message)
/// ends the field list; everything before it is kept.
fn parse_fields(input: &str) -> Option<Vec<(String, String)>> {
    let mut fields = Vec::new();
    let mut index = 0;
    let len = input.len();

    while index < len {
        while index < len {
            let ch = input[index..].chars().next()?;
            if !ch.is_whitespace() {
                break;
            }
            index += ch.len_utf8();
        }
        if index >= len {
            break;
        }

        let key_start = index;
        while index < len {
            let ch = input[index..].chars().next()?;
            if ch == '=' || ch.is_whitespace() {
                break;
            }
            index += ch.len_utf8();
        }

        if index >= len || !input[index..].starts_with('=') {
            // Trailing message rather than a field. Keep what we have.
            break;
        }

        let key = input[key_start..index].to_string();
        index += 1;

        if input[index..].starts_with('"') {
            let (value, next) = parse_quoted(input, index)?;
            fields.push((key, value));
            index = next;
        } else {
            let value_start = index;
            while index < len {
                let ch = input[index..].chars().next()?;
                if ch.is_whitespace() {
                    break;
                }
                index += ch.len_utf8();
            }
            fields.push((key, input[value_start..index].to_string()));
        }
    }

    if fields.is_empty() {
        None
    } else {
        Some(fields)
    }
}

/// Parse a Rust-debug-style quoted string, including `\"`, `\\`, and common
/// control escapes. Returns the unescaped value and the byte index after the
/// closing quote.
fn parse_quoted(input: &str, start: usize) -> Option<(String, usize)> {
    let mut value = String::new();
    let mut chars = input[start + 1..].char_indices().peekable();

    while let Some((offset, ch)) = chars.next() {
        match ch {
            '"' => return Some((value, start + 1 + offset + 1)),
            '\\' => {
                let (_, escaped) = chars.next()?;
                match escaped {
                    '"' => value.push('"'),
                    '\\' => value.push('\\'),
                    'n' => value.push('\n'),
                    'r' => value.push('\r'),
                    't' => value.push('\t'),
                    '0' => value.push('\0'),
                    'u' => {
                        // Rust debug escaping uses \u{...} for control chars.
                        if chars.peek().map(|(_, ch)| *ch) == Some('{') {
                            chars.next();
                        }
                        let mut hex = String::new();
                        for (_, ch) in chars.by_ref() {
                            if ch == '}' {
                                break;
                            }
                            hex.push(ch);
                        }
                        if let Some(ch) =
                            u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
                        {
                            value.push(ch);
                        }
                    }
                    other => value.push(other),
                }
            }
            _ => value.push(ch),
        }
    }

    None
}

/// Collapse SQL newlines and repeated whitespace into one readable line.
fn normalize_sql(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut pending_space = false;

    for ch in value.trim().chars() {
        if ch.is_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space && !out.is_empty() {
            out.push(' ');
        }
        pending_space = false;
        out.push(ch);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_sqlx_query_shape() {
        let input = r#"summary="SELECT \"cloud_binding\".\"vault_id\", \"cloud_binding\".\"provider_kind\"" db.statement="\n\nSELECT \"cloud_binding\".\"vault_id\", \"cloud_binding\".\"provider_kind\" FROM \"cloud_binding\"\n" rows_affected=0 rows_returned=1 elapsed=718.25µs elapsed_secs=0.00071825"#;

        let query = parse(input).expect("structured SQLx query");
        assert_eq!(
            query.message,
            r#"SELECT "cloud_binding"."vault_id", "cloud_binding"."provider_kind""#
        );

        let metadata: Vec<_> = query
            .metadata
            .iter()
            .map(|(key, value)| (key, value))
            .collect();
        assert_eq!(metadata.len(), 3);
        assert!(matches!(
            metadata[0].1,
            MetaValue::Json(serde_json::Value::Number(value)) if value.as_u64() == Some(0)
        ));
        assert!(matches!(
            metadata[1].1,
            MetaValue::Json(serde_json::Value::Number(value)) if value.as_u64() == Some(1)
        ));
        assert!(matches!(metadata[2].1, MetaValue::Json(_)));
    }

    #[test]
    fn falls_back_to_statement_when_summary_is_missing() {
        let input =
            r#"db.statement="\n\nSELECT 1\n" rows_affected=0 rows_returned=0 elapsed=1.20ms"#;
        let query = parse(input).expect("statement fallback");
        assert_eq!(query.message, "SELECT 1");
    }

    #[test]
    fn keeps_slow_threshold() {
        let input = r#"summary="SELECT 1" db.statement="" rows_affected=0 rows_returned=1 elapsed=1.20ms elapsed_secs=0.0012 slow_threshold=Some(1s)"#;
        let query = parse(input).expect("slow query");
        let keys: Vec<_> = query.metadata.iter().map(|(key, _)| key).collect();
        assert_eq!(
            keys,
            [
                "rows_affected",
                "rows_returned",
                "elapsed",
                "slow_threshold"
            ]
        );
    }

    #[test]
    fn rejects_unstructured_messages() {
        assert!(parse("plain message without fields").is_none());
        assert!(parse("").is_none());
    }
}
