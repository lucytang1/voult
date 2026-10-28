//! `log` facade integration.
//!
//! Actix, SeaORM/SQLx, and other dependencies emit through the `log` crate.
//! Installing this bridge lets those records use the same filter, formatter,
//! and stderr sink as first-party calls. There can only be one global `log`
//! backend, so [`install`] is guarded by `Once` and tolerates an already
//! installed backend.

use std::sync::Once;

use crate::{Level, LevelFilter, Metadata, enabled, format};

struct LogBackend;

impl log::Log for LogBackend {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        enabled(map_level(metadata.level()))
    }

    fn log(&self, record: &log::Record<'_>) {
        let level = map_level(record.level());
        if !enabled(level) {
            return;
        }

        // External records have no first-party context, so use the `log`
        // target (module path) as the context. This is the one place where a
        // context is derived rather than hardcoded by the call site.
        let message = record.args().to_string();

        // Some dependencies put structured or space-separated payloads in
        // `record.args()`. Target-specific formatters turn those into a normal
        // message + metadata pair; unrecognised records pass through unchanged.
        if let Some(event) = crate::formatter::format(record.target(), &message) {
            format::write_line(
                level,
                record.target(),
                &event.message,
                &event.metadata,
                format::color_enabled(),
            );
            return;
        }

        format::write_line(
            level,
            record.target(),
            &message,
            &Metadata::new(),
            format::color_enabled(),
        );
    }

    fn flush(&self) {}
}

fn map_level(level: log::Level) -> Level {
    match level {
        log::Level::Error => Level::Error,
        log::Level::Warn => Level::Warn,
        log::Level::Info => Level::Log,
        log::Level::Debug | log::Level::Trace => Level::Debug,
    }
}

static INSTALL: Once = Once::new();

/// Install the global `log` backend at most once.
pub(crate) fn install(filter: LevelFilter) {
    INSTALL.call_once(|| match log::set_boxed_logger(Box::new(LogBackend)) {
        Ok(()) => log::set_max_level(filter.to_log_level_filter()),
        Err(_) => {
            // A library or test harness installed another backend first. Our
            // own Logger methods still work; only facade records go elsewhere.
            eprintln!(
                "[logger] a global log backend was already installed; \
                 `log` records will continue to use it"
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_log_facade_levels() {
        assert_eq!(map_level(log::Level::Error), Level::Error);
        assert_eq!(map_level(log::Level::Warn), Level::Warn);
        assert_eq!(map_level(log::Level::Info), Level::Log);
        assert_eq!(map_level(log::Level::Debug), Level::Debug);
        assert_eq!(map_level(log::Level::Trace), Level::Debug);
    }
}
