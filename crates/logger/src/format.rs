//! Log-line rendering and stderr output.

use std::io::{self, IsTerminal, Write as _};

use crate::{Level, MetaValue, Metadata};

/// Render one line and write it to stderr.
///
/// The line is fully built before stderr is locked, so metadata formatting can
/// never hold the output lock. Write errors are ignored: logging must not panic
/// or change program behaviour.
pub(crate) fn write_line(
    level: Level,
    context: &str,
    message: &str,
    metadata: &Metadata,
    color: bool,
) {
    let timestamp = utc_timestamp();
    let line = render_line(level, &timestamp, context, message, metadata, color);
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{line}");
}

/// ISO 8601 UTC, e.g. `2026-10-28T04:05:23+00:00`.
fn utc_timestamp() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S+00:00")
        .to_string()
}

/// True when the output is a terminal that supports colour and the user has
/// not opted out through `NO_COLOR` or a dumb terminal.
pub(crate) fn color_enabled() -> bool {
    if !io::stderr().is_terminal() {
        return false;
    }
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if let Some(term) = std::env::var_os("TERM") {
        if term.to_string_lossy().eq_ignore_ascii_case("dumb") {
            return false;
        }
    }
    true
}

/// Pure line renderer, kept separate from stderr for unit tests.
pub(crate) fn render_line(
    level: Level,
    timestamp: &str,
    context: &str,
    message: &str,
    metadata: &Metadata,
    color: bool,
) -> String {
    let mut line = String::with_capacity(64 + message.len());

    // The prefix is one visually distinct block: timestamp, level, and
    // context. Colour applies to this whole block; the message and metadata
    // stay plain so they read as payload rather than part of the header.
    let mut prefix = String::with_capacity(48);
    prefix.push_str(timestamp);
    prefix.push(' ');
    prefix.push_str(&format!("{:<5}", level.label()));
    prefix.push(' ');
    if !context.is_empty() {
        prefix.push('(');
        prefix.push_str(context);
        prefix.push_str(") ");
    }

    if color {
        line.push_str(level_color(level));
        line.push_str(&prefix);
        line.push_str("\x1b[0m");
    } else {
        line.push_str(&prefix);
    }
    push_escaped_message(&mut line, message);

    // Metadata is rendered as an indented object block so the message and each
    // field are visually distinct. The whole block stays uncoloured.
    let mut entries = metadata.iter().peekable();
    if entries.peek().is_some() {
        line.push_str(" {\n");
        let mut first = true;
        for (key, value) in entries {
            if !first {
                line.push_str(",\n");
            }
            first = false;
            line.push_str("  ");
            line.push_str(key);
            line.push_str(": ");
            render_value(&mut line, value);
        }
        line.push_str("\n}");
    }

    line
}

fn level_color(level: Level) -> &'static str {
    match level {
        Level::Debug => "\x1b[35m", // magenta
        Level::Log => "\x1b[32m",   // green
        Level::Warn => "\x1b[33m",  // yellow
        Level::Error => "\x1b[31m", // red
    }
}

fn render_value(out: &mut String, value: &MetaValue) {
    match value {
        MetaValue::Json(serde_json::Value::String(value)) => push_single_quoted(out, value),
        MetaValue::Json(value) => match serde_json::to_string(value) {
            Ok(rendered) => out.push_str(&rendered),
            Err(_) => out.push_str("'<invalid-json>'"),
        },
        MetaValue::Error(value) | MetaValue::Unknown(value) => {
            push_single_quoted(out, value);
        }
    }
}

/// Escape control characters in a log message.
///
/// Messages are the one free-form part of a log line: they can contain a
/// provider error, a URL, or another third-party string. Without this, a
/// `\n` inside such a value forges a second log line (and a fake timestamp /
/// level). Metadata already escapes its values; the message must do the same.
/// Non-control characters, including non-ASCII text, pass through unchanged.
fn push_escaped_message(out: &mut String, message: &str) {
    for ch in message.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.extend(ch.escape_default()),
            ch => out.push(ch),
        }
    }
}

/// Text metadata is always single-quoted so strings and numbers are visually
/// distinct. Single quotes and control characters are escaped.
fn push_single_quoted(out: &mut String, value: &str) {
    out.push('\'');
    for ch in value.chars() {
        match ch {
            '\'' => out.push_str("\\'"),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out.push('\'');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Metadata;

    fn line(metadata: Metadata, color: bool) -> String {
        render_line(
            Level::Warn,
            "2026-10-27T18:08:01+00:00",
            "config",
            "something happened",
            &metadata,
            color,
        )
    }

    #[test]
    fn renders_timestamp_level_context_and_message() {
        let rendered = line(Metadata::new(), false);
        assert_eq!(
            rendered,
            "2026-10-27T18:08:01+00:00 WARN  (config) something happened"
        );
    }

    #[test]
    fn timestamp_is_iso_8601_utc() {
        let timestamp = utc_timestamp();
        assert!(timestamp.ends_with("+00:00"));
        assert!(timestamp.contains('T'));
    }

    #[test]
    fn renders_string_and_json_metadata() {
        let metadata = crate::metadata! {
            "provider" => "google_drive",
            "status" => 409,
            "retryable" => false,
            "note" => "needs a retry",
        };

        let rendered = line(metadata, false);
        assert!(rendered.ends_with(
            "{\n  provider: 'google_drive',\n  status: 409,\n  retryable: false,\n  note: 'needs a retry'\n}"
        ));
    }

    #[test]
    fn renders_error_and_unknown_metadata() {
        let metadata = crate::metadata! {
            "cause" => MetaValue::error("connection refused"),
            "raw" => MetaValue::unknown(&Some(7)),
        };

        let rendered = line(metadata, false);
        assert!(rendered.ends_with("{\n  cause: 'connection refused',\n  raw: 'Some(7)'\n}"));
    }

    #[test]
    fn escapes_single_quoted_values() {
        let metadata = crate::metadata! {
            "path" => "a 'b'\\c\nd",
        };

        let rendered = line(metadata, false);
        assert!(rendered.ends_with(
            r#"{
  path: 'a \'b\'\\c\nd'
}"#
        ));
    }

    #[test]
    fn colour_wraps_only_the_prefix() {
        let plain = line(Metadata::new(), false);
        let colored = line(Metadata::new(), true);

        assert!(colored.contains(
            "\x1b[33m2026-10-27T18:08:01+00:00 WARN  (config) \x1b[0msomething happened"
        ));
        assert!(!plain.contains('\x1b'));
        assert_eq!(
            colored.replace("\x1b[33m", "").replace("\x1b[0m", ""),
            plain
        );
    }

    #[test]
    fn escapes_control_characters_in_the_message() {
        let rendered = render_line(
            Level::Warn,
            "2026-10-27T18:08:01+00:00",
            "cloud",
            "provider said a\n2026-10-27T18:08:01+00:00 ERROR (config) forged",
            &Metadata::new(),
            false,
        );

        // The newline is escaped, so the forged "line" stays part of one line.
        assert!(!rendered.contains('\n'));
        assert!(rendered.contains("a\\n2026-10-27T18:08:01+00:00"));
    }

    #[test]
    fn keeps_non_ascii_message_text() {
        let rendered = render_line(
            Level::Warn,
            "2026-10-27T18:08:01+00:00",
            "cloud",
            "café — naïve",
            &Metadata::new(),
            false,
        );
        assert!(rendered.ends_with("café — naïve"));
    }
}
