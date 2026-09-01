/*!
 * Launcher env config — single source of truth.
 *
 * | Var | Required | Values | Default | Notes |
 * |-----|----------|--------|---------|-------|
 * | `VOULT_ENV` | Optional | `development` / `production` | `production` | Controls dev vs prod branching (auto-start, CWD). Panics on any other value. |
 *
 * Dev: `VOULT_ENV=development` (set in `apps/server/.env`) => launcher
 * does NOT auto-start server and does NOT auto-open browser, so you can run
 * `cargo run` in `apps/server` and `launcher` independently.
 *
 * Production (or unset): auto-start + auto-open enabled, prod DB.
 */

use std::{env, path::PathBuf};

pub const ENV_VOULT_ENV: &str = "VOULT_ENV";

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
                    eprintln!("[launcher] {ENV_VOULT_ENV} is empty, defaulting to production");
                    Self::Production
                }
                other => panic!("{ENV_VOULT_ENV} must be 'development' or 'production', got '{other}'"),
            },
            Err(_) => Self::Production,
        }
    }

    pub fn is_dev(self) -> bool {
        self == Self::Development
    }
}

/// Load `.env` files so `VOULT_ENV` is visible even when launcher CWD != repo root.
/// Priority (shell wins, `from_path` does not override):
/// 1. CWD `.env`
/// 2. `apps/server/.env` (authoritative dev file)
/// 3. repo root `.env`
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
}
