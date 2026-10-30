/*!
 * Centralized env config — single source of truth for env var names, allowed
 * values, and mandatory/optional semantics.
 *
 * Design goals (per cleanup request):
 * - One canonical key per concept (`VOULT_ENV`), one set of concrete values.
 * - No multi-key fallback (`VOULT_ENV` only) and no verbose inline checks in `main.rs`.
 * - All validation panics on invalid concrete values so misconfig fails fast.
 *
 * # Env vars
 *
 * | Var | Required | Allowed values | Default | Notes |
 * |-----|----------|----------------|---------|-------|
 * | `VOULT_ENV` | Optional | `development` / `production` | `production` | Controls dev vs prod branching (DB path, etc.). Case-insensitive. Panics on any other value. |
 * | `VOULT_LOG_LEVEL` | Optional | `debug` / `log` / `warn` / `error` (`info` aliases `log`) | `log` | Read by `crates/logger`, not by this module. Controls all server and launcher logging, including `log`-facade records from Actix, SeaORM/SQLx, and other dependencies. `RUST_LOG` is ignored. |
 * | `DATABASE_URL` | Optional | valid `sqlite://` URL | dev: `sqlite://voult.db?mode=rwc` (normalized to absolute), prod: `~/Library/Application Support/Voult/voult.db` | Panics if set but empty. |
 * | `SESSION_COOKIE_KEY` | Optional | `>=64` chars | per-install `session.key` (0600) | Panics if set but <64. |
 * | `STATIC_DIR` | Optional | path | bundle probe / `../client/dist` | — |
 * | `CORS_ORIGINS` | Optional | comma-separated | `http://localhost:8081,http://127.0.0.1:8081` | — |
 * | `TRUSTED_PROXY_IPS` | Optional | comma-separated exact IPs | empty | Peers allowed to set `X-Forwarded-For`. Ignored from any other peer. Panics on an invalid IP. |
 * | `SESSION_COOKIE_SECURE` / `SAME_SITE` / `TTL_SECONDS` | Optional | — | `false` / `lax` / `604800` | — |
 * | Cloud provider keys | Optional | provider-specific | — | See `cloud::provider::CloudProvider::env_keys`; unconfigured providers are omitted from `/cloud/providers`. |
 */

use std::{
    env, fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

pub const ENV_VOULT_ENV: &str = "VOULT_ENV";
pub const ENV_DATABASE_URL: &str = "DATABASE_URL";
pub const ENV_SESSION_COOKIE_KEY: &str = "SESSION_COOKIE_KEY";
pub const ENV_STATIC_DIR: &str = "STATIC_DIR";
pub const ENV_CORS_ORIGINS: &str = "CORS_ORIGINS";
/// Exact peer addresses allowed to set `X-Forwarded-For`. Empty by default:
/// forwarded headers from any other peer are client-controlled and ignored.
pub const ENV_TRUSTED_PROXY_IPS: &str = "TRUSTED_PROXY_IPS";

/// Config logging context.
const CONFIG_LOG: logger::ServerLogger = logger::Logger::create(logger::ServerContext::Config);

// Strict environment — only two concrete values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Development,
    Production,
}

impl Environment {
    // Reads `VOULT_ENV` from the environment. Panics on invalid value.
    pub fn from_env() -> Self {
        match env::var(ENV_VOULT_ENV) {
            Ok(raw) => {
                let v = raw.trim().to_lowercase();
                match v.as_str() {
                    "development" => Self::Development,
                    "production" => Self::Production,
                    "" => {
                        CONFIG_LOG.warn(
                            format_args!("{ENV_VOULT_ENV} is empty, defaulting to production"),
                            logger::metadata! { "env_var" => ENV_VOULT_ENV },
                        );
                        Self::Production
                    }
                    other => panic!(
                        "{ENV_VOULT_ENV} must be 'development' or 'production', got '{other}'"
                    ),
                }
            }
            Err(_) => Self::Production,
        }
    }

    pub fn is_dev(self) -> bool {
        self == Self::Development
    }
    pub fn is_prod(self) -> bool {
        self == Self::Production
    }
}

// ---------------------------------------------------------------------------
// dotenv loading — call once at startup before reading any config
// ---------------------------------------------------------------------------

/// Load all `.env` sources in priority order without overriding shell env.
/// 1. `CARGO_MANIFEST_DIR/.env` (dev manifest, ensures VOULT_ENV/DATABASE_URL
///    visible when launcher spawns binary with CWD != server)
/// 2. CWD `.env` (`dotenvy::dotenv`)
/// 3. Bundled `Resources/.env` + user `~/Library/Application Support/Voult/.env`
pub fn load_dotenv() {
    // 1. Manifest pre-load: only when not explicitly production via shell,
    //    so `VOULT_ENV=production` on a dev machine doesn't leak dev DB URL.
    let explicit_prod = env::var(ENV_VOULT_ENV)
        .map(|v| v.trim().eq_ignore_ascii_case("production"))
        .unwrap_or(false);

    if !explicit_prod {
        let manifest_env = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".env");
        if manifest_env.exists() {
            match dotenvy::from_path(&manifest_env) {
                Ok(_) => eprintln!(
                    "[voult] Pre-loaded manifest env from {}",
                    manifest_env.display()
                ),
                Err(e) => eprintln!(
                    "[voult] Failed to pre-load manifest env {}: {}",
                    manifest_env.display(),
                    e
                ),
            }
        }
    } else {
        eprintln!("[voult] Explicit production env detected, skipping manifest pre-load");
    }

    // 2. CWD
    let _ = dotenvy::dotenv();

    // 3. Bundled + user
    load_bundled_env();
}

fn load_bundled_env() {
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            for rel in [
                "../Resources/.env",
                "../../Resources/.env",
                "Resources/.env",
            ] {
                let p = dir.join(rel);
                if p.exists() {
                    let _ = dotenvy::from_path(&p);
                    eprintln!("[voult] Loaded bundled env from {}", p.display());
                    break;
                }
            }
            for rel in ["../Resources/cloud.env", "../../Resources/cloud.env"] {
                let p = dir.join(rel);
                if p.exists() {
                    let _ = dotenvy::from_path(&p);
                    eprintln!("[voult] Loaded bundled cloud env from {}", p.display());
                    break;
                }
            }
        }
    }
    let data_dir = voult_data_dir();
    let user_env = data_dir.join(".env");
    if user_env.exists() {
        let _ = dotenvy::from_path(&user_env);
        eprintln!("[voult] Loaded user env from {}", user_env.display());
    }
}

// ---------------------------------------------------------------------------
// DATABASE_URL resolution — clean, non-verbose
// ---------------------------------------------------------------------------

pub fn voult_data_dir() -> PathBuf {
    if let Some(dir) = dirs::data_dir() {
        dir.join("Voult")
    } else {
        PathBuf::from("voult_data")
    }
}

fn is_relative_sqlite_url(url: &str) -> bool {
    // Relative iff `sqlite://` + not `sqlite:///` + not :memory: + path is relative
    if !url.starts_with("sqlite://") || url.starts_with("sqlite:///") || url.contains(":memory:") {
        return false;
    }
    let without = &url["sqlite://".len()..];
    let path_part = without.split_once('?').map(|(p, _)| p).unwrap_or(without);
    !path_part.is_empty() && Path::new(path_part).is_relative()
}

fn normalize_dev_database_url(url: &str) -> String {
    let without = &url["sqlite://".len()..];
    let (path_part, query) = match without.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (without, None),
    };
    let abs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path_part);
    match query {
        Some(q) => format!("sqlite://{}?{}", abs.display(), q),
        None => format!("sqlite://{}", abs.display()),
    }
}

/// Resolve `DATABASE_URL` with strict validation and dev normalization.
/// Panics if `DATABASE_URL` is set but empty. In dev, relative sqlite URLs
/// are normalized to absolute; in prod, dev's `voult.db` relative URL is
/// ignored so dev .env doesn't leak into prod when `VOULT_ENV=production`.
pub fn database_url(env: Environment) -> String {
    if let Ok(raw) = env::var(ENV_DATABASE_URL) {
        let trimmed = raw.trim().to_string();
        if trimmed.is_empty() {
            panic!("{ENV_DATABASE_URL} is set but empty — must be a valid sqlite URL or unset");
        }

        if env.is_dev() && is_relative_sqlite_url(&trimmed) {
            let normalized = normalize_dev_database_url(&trimmed);
            CONFIG_LOG.log(
                format_args!("Normalized relative {ENV_DATABASE_URL} to {normalized}"),
                logger::Metadata::new(),
            );
            return normalized;
        }

        if env.is_prod() && is_relative_sqlite_url(&trimmed) {
            // `apps/server/.env` dev value shouldn't leak into explicit prod run
            let without = &trimmed["sqlite://".len()..];
            let path_part = without.split_once('?').map(|(p, _)| p).unwrap_or(without);
            if path_part == "voult.db" {
                CONFIG_LOG.warn(
                    format_args!(
                        "Ignoring dev {ENV_DATABASE_URL} '{trimmed}' in production, using prod DB at Application Support"
                    ),
                    logger::metadata! { "env_var" => ENV_DATABASE_URL },
                );
                // fall through to prod default
            } else {
                return trimmed;
            }
        } else {
            return trimmed;
        }
    }

    // Fallback: per-install prod DB
    let data_dir = voult_data_dir();
    if let Err(e) = fs::create_dir_all(&data_dir) {
        CONFIG_LOG.warn(
            format_args!(
                "Could not create Voult data directory {}: {}",
                data_dir.display(),
                e
            ),
            logger::Metadata::new(),
        );
    } else {
        CONFIG_LOG.log(
            format_args!("Using Voult data directory: {}", data_dir.display()),
            logger::Metadata::new(),
        );
    }
    let db_path = data_dir.join("voult.db");
    format!("sqlite://{}?mode=rwc", db_path.display())
}

// ---------------------------------------------------------------------------
// helpers for other env vars (used in main.rs)
// ---------------------------------------------------------------------------

/// Returns `Some(trimmed)` if set and non-empty, else `None`.
pub fn optional_env(key: &str) -> Option<String> {
    env::var(key).ok().and_then(|v| {
        let t = v.trim().to_string();
        if t.is_empty() { None } else { Some(t) }
    })
}

/// Returns trimmed value or panics with concrete message if missing/empty.
#[allow(dead_code)]
pub fn require_env(key: &str) -> String {
    optional_env(key).unwrap_or_else(|| panic!("Required env var {key} is not set"))
}

/// Parses `TRUSTED_PROXY_IPS` into exact peer addresses.
///
/// The list is compared against the **socket peer** only. A forwarded header is
/// honoured when — and only when — the connection came from one of these
/// addresses; for any other peer `X-Forwarded-For` is attacker-controlled and
/// ignored. Invalid entries panic on purpose: silently dropping one would
/// either weaken a limit or hide a typo in a security control.
pub fn trusted_proxies() -> Vec<IpAddr> {
    let Some(raw) = optional_env(ENV_TRUSTED_PROXY_IPS) else {
        return Vec::new();
    };
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            entry.parse::<IpAddr>().unwrap_or_else(|_| {
                panic!("{ENV_TRUSTED_PROXY_IPS} contains an invalid IP address: '{entry}'")
            })
        })
        .collect()
}
