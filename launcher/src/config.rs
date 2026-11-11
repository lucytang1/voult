/*!
 * Launcher env config — single source of truth.
 *
 * | Var | Required | Values | Default | Notes |
 * |-----|----------|--------|---------|-------|
 * | `VOULT_ENV` | Optional | `development` / `production` | `production` | Controls dev vs prod branching (auto-start, CWD). Panics on any other value. |
 * | `VOULT_LOG_LEVEL` | Optional | `debug` / `log` / `warn` / `error` (`info` aliases `log`) | `log` | Read by `crates/logger`; filters launcher root-level logging. |
 *
 * Dev: `VOULT_ENV=development` (set in `apps/server/.env`) => launcher
 * does NOT auto-start server and does NOT auto-open browser, so you can run
 * `cargo run` in `apps/server` and `launcher` independently.
 *
 * Production (or unset): auto-start + auto-open enabled, prod DB.
 */

use std::{env, path::PathBuf};

pub const ENV_VOULT_ENV: &str = "VOULT_ENV";

/// Launcher config logging context.
const CONFIG_LOG: logger::LauncherLogger = logger::Logger::create(logger::LauncherContext::Config);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Development,
    Production,
}

impl Environment {
    /// Strict — only `development` / `production` (case-insensitive). Panics otherwise.
    pub fn from_env() -> Self {
        match env::var(ENV_VOULT_ENV) {
            Ok(raw) => match raw.trim().to_lowercase().as_str() {
                "development" => Self::Development,
                "production" => Self::Production,
                "" => {
                    CONFIG_LOG.warn(
                        format_args!("{ENV_VOULT_ENV} is empty, defaulting to production"),
                        logger::metadata! { "env_var" => ENV_VOULT_ENV },
                    );
                    Self::Production
                }
                other => {
                    panic!("{ENV_VOULT_ENV} must be 'development' or 'production', got '{other}'")
                }
            },
            Err(_) => Self::Production,
        }
    }

    pub fn is_dev(self) -> bool {
        self == Self::Development
    }
}

/// Platform data directory, deliberately identical to the server's
/// `apps/server/src/config.rs::voult_data_dir()`:
/// - macOS: `~/Library/Application Support/Voult`
/// - Linux: `$XDG_DATA_HOME/Voult` or `~/.local/share/Voult`
///
/// The launcher and server must agree, or a per-install `.env` would be read by
/// only one of the two processes.
fn voult_data_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join("Library/Application Support"))?;

    #[cfg(not(target_os = "macos"))]
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share"))
        })?;

    Some(base.join("Voult"))
}

/// Load `.env` files so `VOULT_ENV` / `VOULT_LOG_LEVEL` are visible even when
/// launcher CWD != repo root. Priority (shell wins, `from_path` does not
/// override):
/// 1. CWD `.env`
/// 2. `apps/server/.env` (authoritative dev file)
/// 3. repo root `.env`
/// 4. per-install `.env` (see [`voult_data_dir`])
pub fn load_dotenv() {
    let _ = dotenvy::dotenv();
    let launcher_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(root) = launcher_dir.parent() {
        let server_env = root.join("apps/server/.env");
        if server_env.exists() {
            let _ = dotenvy::from_path(&server_env);
        }
        let root_env = root.join(".env");
        if root_env.exists() {
            let _ = dotenvy::from_path(&root_env);
        }
    }

    // A bundled launcher has no useful CWD or repo root. The server already
    // reads this per-install file, so the launcher reads it too; otherwise
    // VOULT_LOG_LEVEL would work for only one of the two processes.
    if let Some(dir) = voult_data_dir() {
        let user_env = dir.join(".env");
        if user_env.exists() {
            let _ = dotenvy::from_path(&user_env);
        }
    }
}
