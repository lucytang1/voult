//! Log levels and the environment-driven minimum-level filter.

use std::{env, fmt, str::FromStr};

use crate::ENV_LOG_LEVEL;

/// The four levels exposed by this logger.
///
/// `Log` is the production breadcrumb level (roughly `info` in the `log`
/// crate); `Debug` is for development-only detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug,
    Log,
    Warn,
    Error,
}

impl Level {
    /// Fixed-width uppercase label used in a rendered log line.
    pub fn label(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Log => "LOG",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// The minimum level that will be printed.
///
/// Ordering is `Debug < Log < Warn < Error`, so a filter allows its own level
/// and every level above it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LevelFilter(Level);

impl LevelFilter {
    pub const DEBUG: Self = Self(Level::Debug);
    pub const LOG: Self = Self(Level::Log);
    pub const WARN: Self = Self(Level::Warn);
    pub const ERROR: Self = Self(Level::Error);

    /// Default when `VOULT_LOG_LEVEL` is unset: production breadcrumbs only.
    pub const DEFAULT: Self = Self::LOG;

    /// Parse one of `debug`, `log`, `warn`, `error` (case-insensitive).
    ///
    /// `info` is accepted as an alias for `log` to make the common Rust habit
    /// work without introducing a fifth level. An empty value means the
    /// default; `from_env` warns separately when the variable was explicitly
    /// set to an empty string.
    pub fn parse(raw: &str) -> Result<Self, ParseLevelError> {
        let value = raw.trim();
        if value.is_empty() {
            return Ok(Self::DEFAULT);
        }

        match value.to_ascii_lowercase().as_str() {
            "debug" => Ok(Self::DEBUG),
            "log" | "info" => Ok(Self::LOG),
            "warn" => Ok(Self::WARN),
            "error" => Ok(Self::ERROR),
            _ => Err(ParseLevelError {
                value: value.to_string(),
            }),
        }
    }

    /// Read `VOULT_LOG_LEVEL`, warning once and falling back to `log` on an
    /// invalid value. An empty value is treated as a configuration mistake
    /// worth surfacing, but never fatal.
    pub fn from_env() -> Self {
        match env::var(ENV_LOG_LEVEL) {
            Ok(raw) => {
                if raw.trim().is_empty() {
                    eprintln!("[logger] {ENV_LOG_LEVEL} is empty; using 'log'");
                    return Self::DEFAULT;
                }

                match Self::parse(&raw) {
                    Ok(filter) => filter,
                    Err(error) => {
                        eprintln!("[logger] invalid {ENV_LOG_LEVEL} value {error}; using 'log'");
                        Self::DEFAULT
                    }
                }
            }
            Err(_) => Self::DEFAULT,
        }
    }

    /// Whether this filter permits `level`.
    pub fn allows(self, level: Level) -> bool {
        level >= self.0
    }

    /// Map to the `log` facade's max-level setting.
    ///
    /// `Debug` maps to `Trace` so dependency `trace!` records reach our
    /// backend, where they are rendered as `DEBUG`.
    pub(crate) fn to_log_level_filter(self) -> log::LevelFilter {
        match self.0 {
            Level::Debug => log::LevelFilter::Trace,
            Level::Log => log::LevelFilter::Info,
            Level::Warn => log::LevelFilter::Warn,
            Level::Error => log::LevelFilter::Error,
        }
    }
}

impl fmt::Display for LevelFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            Level::Debug => "debug",
            Level::Log => "log",
            Level::Warn => "warn",
            Level::Error => "error",
        })
    }
}

impl FromStr for LevelFilter {
    type Err = ParseLevelError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::parse(raw)
    }
}

/// Error returned when a level string is not one of the four accepted values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseLevelError {
    value: String,
}

impl fmt::Display for ParseLevelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "'{}' (expected debug, log, warn, or error)", self.value)
    }
}

impl std::error::Error for ParseLevelError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_level_and_alias() {
        assert_eq!(LevelFilter::parse("debug"), Ok(LevelFilter::DEBUG));
        assert_eq!(LevelFilter::parse("log"), Ok(LevelFilter::LOG));
        assert_eq!(LevelFilter::parse("info"), Ok(LevelFilter::LOG));
        assert_eq!(LevelFilter::parse("warn"), Ok(LevelFilter::WARN));
        assert_eq!(LevelFilter::parse("error"), Ok(LevelFilter::ERROR));
    }

    #[test]
    fn parsing_is_case_insensitive_and_trims() {
        assert_eq!(LevelFilter::parse("  WARN  "), Ok(LevelFilter::WARN));
        assert_eq!(LevelFilter::parse("Info"), Ok(LevelFilter::LOG));
    }

    #[test]
    fn empty_means_default() {
        assert_eq!(LevelFilter::parse(""), Ok(LevelFilter::DEFAULT));
        assert_eq!(LevelFilter::parse("   "), Ok(LevelFilter::DEFAULT));
    }

    #[test]
    fn rejects_unknown_levels() {
        assert!(LevelFilter::parse("trace").is_err());
        assert!(LevelFilter::parse("verbose").is_err());
    }

    #[test]
    fn filter_matrix() {
        let cases = [
            (LevelFilter::DEBUG, [true, true, true, true]),
            (LevelFilter::LOG, [false, true, true, true]),
            (LevelFilter::WARN, [false, false, true, true]),
            (LevelFilter::ERROR, [false, false, false, true]),
        ];

        for (filter, expected) in cases {
            for (index, level) in [Level::Debug, Level::Log, Level::Warn, Level::Error]
                .into_iter()
                .enumerate()
            {
                assert!(
                    filter.allows(level) == expected[index],
                    "filter {filter} / level {level}"
                );
            }
        }
    }

    #[test]
    fn filters_render_lowercase() {
        assert_eq!(LevelFilter::DEBUG.to_string(), "debug");
        assert_eq!(LevelFilter::LOG.to_string(), "log");
        assert_eq!(LevelFilter::WARN.to_string(), "warn");
        assert_eq!(LevelFilter::ERROR.to_string(), "error");
    }

    #[test]
    fn levels_render_uppercase() {
        assert_eq!(Level::Debug.to_string(), "DEBUG");
        assert_eq!(Level::Log.to_string(), "LOG");
        assert_eq!(Level::Warn.to_string(), "WARN");
        assert_eq!(Level::Error.to_string(), "ERROR");
    }

    #[test]
    fn parses_through_from_str() {
        assert_eq!("warn".parse::<LevelFilter>(), Ok(LevelFilter::WARN));
        assert!("trace".parse::<LevelFilter>().is_err());
    }

    #[test]
    fn maps_to_log_facade_max_levels() {
        assert_eq!(
            LevelFilter::DEBUG.to_log_level_filter(),
            log::LevelFilter::Trace
        );
        assert_eq!(
            LevelFilter::LOG.to_log_level_filter(),
            log::LevelFilter::Info
        );
        assert_eq!(
            LevelFilter::WARN.to_log_level_filter(),
            log::LevelFilter::Warn
        );
        assert_eq!(
            LevelFilter::ERROR.to_log_level_filter(),
            log::LevelFilter::Error
        );
    }
}
