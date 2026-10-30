//! Hardcoded, typed log contexts.
//!
//! There are two app-facing context types:
//!
//! - [`ServerContext`] for `apps/server` (including the migration crate)
//! - [`LauncherContext`] for the macOS launcher
//!
//! [`DefaultContext`] backs the crate-level `logger` instance. Context values
//! are enums rather than strings so a typo is a compile error and every log
//! site uses one of a known set of labels.

use crate::Logger;

/// A hardcoded context label carried by a [`Logger`].
pub trait LogContext: Copy {
    /// Fixed lowercase label rendered in the `(context)` slot.
    fn label(self) -> &'static str;
}

/// Context for the default `logger` instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultContext {
    Default,
}

impl LogContext for DefaultContext {
    fn label(self) -> &'static str {
        "logger"
    }
}

/// Every context used by the server process.
///
/// `Migration` lives here so the separate migration crate can use the same
/// type without depending on the server binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerContext {
    /// Process lifecycle, startup, shutdown.
    Server,
    /// Environment, database, static-site, and session-key configuration.
    Config,
    /// Login, registration verifiers, crypto params, password rotation.
    Auth,
    /// Vault read/update and the lock epoch.
    Vault,
    /// Vault chooser / multi-vault endpoints.
    Vaults,
    /// New-vault registration.
    Register,
    /// Manual lock signalling.
    Lock,
    /// Extension pairing codes.
    Pair,
    /// Session status.
    Session,
    /// Recovery challenge/unlock/rewrap/regenerate.
    Recovery,
    /// Favicon proxy and cache.
    Favicon,
    /// Cloud provider bindings, OAuth, tokens, and mirroring.
    Cloud,
    /// Query-free HTTP access log (method, route pattern, status).
    Request,
    /// Database migrations.
    Migration,
}

impl LogContext for ServerContext {
    fn label(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Config => "config",
            Self::Auth => "auth",
            Self::Vault => "vault",
            Self::Vaults => "vaults",
            Self::Register => "register",
            Self::Lock => "lock",
            Self::Pair => "pair",
            Self::Session => "session",
            Self::Recovery => "recovery",
            Self::Favicon => "favicon",
            Self::Cloud => "cloud",
            Self::Request => "request",
            Self::Migration => "migration",
        }
    }
}

/// Every context used by the launcher process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LauncherContext {
    /// App lifecycle and browser opening.
    Launcher,
    /// Launcher environment configuration.
    Config,
    /// Server child process control: spawn, stop, health, crash detection.
    Process,
    /// Tray menu and icon.
    Tray,
}

impl LogContext for LauncherContext {
    fn label(self) -> &'static str {
        match self {
            Self::Launcher => "launcher",
            Self::Config => "config",
            Self::Process => "process",
            Self::Tray => "tray",
        }
    }
}

/// Logger type used by the server and migration crates.
pub type ServerLogger = Logger<ServerContext>;

/// Logger type used by the launcher.
pub type LauncherLogger = Logger<LauncherContext>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_labels_are_fixed() {
        let cases = [
            (ServerContext::Server, "server"),
            (ServerContext::Config, "config"),
            (ServerContext::Auth, "auth"),
            (ServerContext::Vault, "vault"),
            (ServerContext::Vaults, "vaults"),
            (ServerContext::Register, "register"),
            (ServerContext::Lock, "lock"),
            (ServerContext::Pair, "pair"),
            (ServerContext::Session, "session"),
            (ServerContext::Recovery, "recovery"),
            (ServerContext::Favicon, "favicon"),
            (ServerContext::Cloud, "cloud"),
            (ServerContext::Migration, "migration"),
        ];

        for (context, expected) in cases {
            assert_eq!(context.label(), expected);
        }
    }

    #[test]
    fn launcher_labels_are_fixed() {
        let cases = [
            (LauncherContext::Launcher, "launcher"),
            (LauncherContext::Config, "config"),
            (LauncherContext::Process, "process"),
            (LauncherContext::Tray, "tray"),
        ];

        for (context, expected) in cases {
            assert_eq!(context.label(), expected);
        }
    }
}
