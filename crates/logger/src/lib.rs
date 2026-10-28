//! Small shared logger for the Voult server and launcher.
//! [`init`] also installs this crate as the global `log` backend, so records
//! from Actix, SeaORM/SQLx, and other dependencies use the same filter,
//! formatter, and stderr sink. There can only be one global backend; a
//! pre-existing backend is reported and left in place.
//!
//! ```ignore
//! use logger::{logger, LauncherContext, Logger, Metadata};
//!
//! // Default instance, context "logger".
//! logger.log("Starting server", Metadata::new());
//!
//! // Typed app context.
//! let process = Logger::create(LauncherContext::Process);
//! process.error(&err, Metadata::new());
//! ```
//!
//! See `README.md` for the `VOULT_LOG_LEVEL` filter, metadata arms, and output
//! format.

#![forbid(unsafe_code)]

mod backend;
mod context;
mod format;
mod formatter;
mod level;
mod metadata;

use std::{fmt, sync::OnceLock};

pub use context::{
    DefaultContext, LauncherContext, LauncherLogger, LogContext, ServerContext, ServerLogger,
};
pub use level::{Level, LevelFilter, ParseLevelError};
pub use metadata::{MetaValue, Metadata};

/// Environment variable controlling the minimum printed level. Values: `debug`, `log`, `warn`, `error` (case-insensitive)
pub const ENV_LOG_LEVEL: &str = "VOULT_LOG_LEVEL";

static FILTER: OnceLock<LevelFilter> = OnceLock::new();

/// Initialise the global filter from `VOULT_LOG_LEVEL` and install the `log`
/// backend.
///
/// Idempotent: a second call returns the first result and does not re-read the
/// environment. Call this after dotenv loading and before the first log call if
/// the environment value should apply.
pub fn init() -> LevelFilter {
    let filter = *FILTER.get_or_init(LevelFilter::from_env);
    backend::install(filter);
    filter
}

/// Whether the global filter permits `level`.
///
/// Before [`init`], this uses the default `log` filter. This is public so
/// callers can avoid expensive message construction; the `Logger` methods also
/// use it internally before formatting.
pub fn enabled(level: Level) -> bool {
    FILTER
        .get()
        .copied()
        .unwrap_or(LevelFilter::DEFAULT)
        .allows(level)
}

/// A logger bound to one typed, hardcoded context.
///
/// `Logger` is cheap to copy: it carries only the context enum. The level
/// filter is global, so every instance follows the same `VOULT_LOG_LEVEL`.
#[derive(Debug, Clone, Copy)]
pub struct Logger<C: LogContext> {
    context: C,
}

impl<C: LogContext> Logger<C> {
    /// Create a logger from a typed context, e.g. [`ServerContext::Auth`] or
    /// [`LauncherContext::Process`].
    pub const fn create(context: C) -> Self {
        Self { context }
    }

    /// Development detail.
    pub fn debug(&self, message: impl fmt::Display, metadata: Metadata) {
        self.write(Level::Debug, message, metadata);
    }

    /// Production breadcrumb.
    pub fn log(&self, message: impl fmt::Display, metadata: Metadata) {
        self.write(Level::Log, message, metadata);
    }

    /// A recoverable problem worth attention.
    pub fn warn(&self, message: impl fmt::Display, metadata: Metadata) {
        self.write(Level::Warn, message, metadata);
    }

    /// A failure. Accepts a string or any error type, since both implement
    /// [`fmt::Display`].
    pub fn error(&self, error: impl fmt::Display, metadata: Metadata) {
        self.write(Level::Error, error, metadata);
    }

    fn write(&self, level: Level, message: impl fmt::Display, metadata: Metadata) {
        if !enabled(level) {
            return;
        }

        // Format only after the filter check. `format_args!` callers therefore
        // pay no allocation when the level is disabled.
        let message = message.to_string();
        format::write_line(
            level,
            self.context.label(),
            &message,
            &metadata,
            format::color_enabled(),
        );
    }
}

impl Default for Logger<DefaultContext> {
    fn default() -> Self {
        Self::create(DefaultContext::Default)
    }
}

/// Default logger instance, equivalent to
/// `Logger::create(DefaultContext::Default)`.
///
/// The lowercase name matches the Bluesky-style call site (`logger.log(...)`).
#[allow(non_upper_case_globals)]
pub static logger: Logger<DefaultContext> = Logger::create(DefaultContext::Default);
