mod cloud;
mod datetime_codec;
mod db;
mod endpoints;
mod entity;
mod error;
mod id_codec;
mod security_headers;
mod session_auth;
mod static_site;

use actix_cors::Cors;
use actix_session::SessionMiddleware;
use actix_session::config::PersistentSession;
use actix_session::storage::CookieSessionStore;
use actix_web::cookie::time::Duration;
use actix_web::cookie::{Key, SameSite};
use actix_web::middleware;
use actix_web::middleware::DefaultHeaders;
use actix_web::{App, HttpServer, web};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use migration::{Migrator, MigratorTrait};
use rand::RngCore;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use endpoints::{
    auth, cloud_endpoints, favicon, get_crypto_params, get_vault, lock, logout, pair, recovery,
    register, session_status, update_vault, update_vault_password, vaults,
};
use static_site::static_site;

mod config;
use config::Environment;
use logger::{Logger, ServerContext, ServerLogger};

/// Process-level logging contexts.
const SERVER_LOG: ServerLogger = Logger::create(ServerContext::Server);
const CONFIG_LOG: ServerLogger = Logger::create(ServerContext::Config);

fn voult_data_dir() -> PathBuf {
    config::voult_data_dir()
}

/// Resolve STATIC_DIR: env override wins, otherwise probe bundle-adjacent
/// locations (for Voult.app) then dev fallback.
fn resolve_static_dir() -> String {
    if let Some(dir) = config::optional_env(config::ENV_STATIC_DIR) {
        return dir;
    }

    // Candidate 1: relative to current exe (covers Voult.app/Contents/MacOS/voult-server → ../Resources/dist)
    if let Ok(exe) = env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            let candidates = [
                exe_dir.join("../Resources/dist"),
                exe_dir.join("../../Resources/dist"),
                exe_dir.join("Resources/dist"),
            ];
            for cand in &candidates {
                if cand.join("index.html").exists() {
                    CONFIG_LOG.log(
                        format_args!("Using bundled static site at {}", cand.display()),
                        logger::Metadata::new(),
                    );
                    return cand.to_string_lossy().to_string();
                }
            }
        }
    }

    // Candidate 2: CWD-relative dev fallback
    let fallback = "../client/dist".to_string();
    fallback
}

/// Resolve session cookie key: env wins, otherwise per-install file at
/// `~/Library/Application Support/Voult/session.key` (generated once, 0600).
fn resolve_session_cookie_key() -> String {
    if let Some(key) = config::optional_env(config::ENV_SESSION_COOKIE_KEY) {
        if key.len() >= 64 {
            return key;
        }
        // Concrete validation: throw is handled by panic in caller if <64, but here
        // we treat too-short as misconfig and fall back with warn (strict would panic)
        CONFIG_LOG.warn(
            format_args!(
                "{} from env is <64 chars (got {}), ignoring and using per-install key",
                config::ENV_SESSION_COOKIE_KEY,
                key.len()
            ),
            logger::metadata! {
                "env_var" => config::ENV_SESSION_COOKIE_KEY,
                "length" => key.len(),
            },
        );
    }

    let data_dir = voult_data_dir();
    let key_path = data_dir.join("session.key");

    // Try to read existing key
    if let Ok(existing) = fs::read_to_string(&key_path) {
        let trimmed = existing.trim().to_string();
        if trimmed.len() >= 64 {
            CONFIG_LOG.log(
                format_args!("Using per-install session key at {}", key_path.display()),
                logger::Metadata::new(),
            );
            return trimmed;
        }
        CONFIG_LOG.warn(
            format_args!(
                "Existing session key at {} is too short, regenerating",
                key_path.display()
            ),
            logger::Metadata::new(),
        );
    }

    // Generate a new 64-byte random key, base64-encoded (88 chars)
    let mut bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut bytes);
    let key = BASE64_STANDARD.encode(bytes);

    if let Err(e) = fs::create_dir_all(&data_dir) {
        CONFIG_LOG.warn(
            format_args!("Could not create data dir for session key: {}", e),
            logger::Metadata::new(),
        );
    } else {
        match fs::write(&key_path, format!("{key}\n")) {
            Ok(()) => {
                // Restrict to owner only (0600) on unix
                let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
                CONFIG_LOG.log(
                    format_args!(
                        "Generated new per-install session key at {}",
                        key_path.display()
                    ),
                    logger::Metadata::new(),
                );
            }
            Err(e) => {
                CONFIG_LOG.warn(
                    format_args!(
                        "Could not persist session key to {}: {}",
                        key_path.display(),
                        e
                    ),
                    logger::Metadata::new(),
                );
            }
        }
    }
    key
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    config::load_dotenv();
    // Installs the shared logger as the global `log` backend, so every server
    // module, Actix request log, SeaORM/SQLx record, and migration warning uses
    // the same VOULT_LOG_LEVEL filter and output format.
    let log_filter = logger::init();

    let env = Environment::from_env();
    SERVER_LOG.log(
        format_args!(
            "VOULT_LOG_LEVEL={} VOULT_ENV={} (is_dev: {})",
            log_filter,
            env::var(config::ENV_VOULT_ENV)
                .unwrap_or_else(|_| "(unset, defaulting to production)".to_string()),
            env.is_dev()
        ),
        logger::metadata! { "dev" => env.is_dev() },
    );

    let database_url = config::database_url(env);
    CONFIG_LOG.log(
        format_args!("DATABASE_URL resolved to {}", database_url),
        logger::Metadata::new(),
    );

    // Session cookie signing/encryption secret. Must be at least 64 bytes for
    // the cookie-session backend. Never share or commit it.
    let session_cookie_key = resolve_session_cookie_key();
    if session_cookie_key.len() < 64 {
        panic!("SESSION_COOKIE_KEY must be at least 64 characters long");
    }
    let secret_key = Key::from(session_cookie_key.as_bytes());

    // Persistent (non-browser) sessions with a configurable idle TTL.
    // Default: 7-day idle expiry.
    let cookie_secure = env::var("SESSION_COOKIE_SECURE")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    let cookie_same_site = match env::var("SESSION_COOKIE_SAME_SITE")
        .unwrap_or_else(|_| "lax".to_string())
        .to_lowercase()
        .as_str()
    {
        "strict" => SameSite::Strict,
        "none" => SameSite::None,
        _ => SameSite::Lax,
    };
    let session_ttl_seconds = env::var("SESSION_TTL_SECONDS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(7 * 24 * 60 * 60);

    let db = db::establish_connection(&database_url).await;

    Migrator::up(&db, None)
        .await
        .expect("Failed to run database migrations");

    let db_data = web::Data::new(db);
    cloud::mirror::start_sweeper(db_data.get_ref().clone());

    // Clear recovery challenges orphaned by a crash or a restart. They carry a
    // hard TTL and are swept on every insert too, so this is tidiness rather
    // than correctness — but it means a restart never resurrects rows that can
    // no longer be honoured.
    recovery::prune_expired_challenges(db_data.get_ref()).await;

    // Credentialed requests (cookies) require explicit origins — never pair
    // `allow_any_origin()` with cookies.
    let cors_origins: Vec<String> = config::optional_env(config::ENV_CORS_ORIGINS)
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_else(|| {
            vec![
                "http://localhost:8081".to_string(),
                "http://127.0.0.1:8081".to_string(),
            ]
        });

    // Static site (the exported Expo web client) served at the root. The API
    // lives under /api. Override the location with STATIC_DIR.
    let static_dir = resolve_static_dir();
    if !Path::new(&static_dir).join("index.html").exists() {
        CONFIG_LOG.warn(
            format_args!(
                "Static site not found at {} (run `npm run build:web` in apps/client); only the API will be served",
                static_dir
            ),
            logger::metadata! { "static_dir" => static_dir.as_str() },
        );
    }

    // Built ONCE, outside the `HttpServer::new` closure. That closure runs once
    // per worker, so constructing the throttle inside it would hand every worker
    // its own budget and let a single client spend 10x the intended allowance.
    // `web::Data` is an Arc, so cloning it into each worker shares one instance.
    let recovery_throttle = web::Data::new(recovery::ChallengeThrottle::default());

    // Same reason for both favicon halves: one shared upstream HTTP client keeps
    // connection pooling (the previous per-request client paid a fresh DNS +
    // TCP + TLS handshake for every icon), and one shared icon cache means an
    // icon fetched by any worker is warm for all of them.
    let favicon_client = web::Data::new(favicon::build_http_client());
    let favicon_cache = web::Data::new(favicon::FaviconCache::new());

    // A deployment declaration, not a sniffed request property. HSTS and
    // upgrade-insecure-requests are only meaningful when the browser-facing
    // origin is HTTPS; the shipped server binds loopback HTTP.
    let https = config::https_enabled();

    SERVER_LOG.log(
        format_args!("web security headers: https={https} hsts={https}"),
        logger::metadata! { "https" => https },
    );
    SERVER_LOG.log(
        "Starting server at http://localhost:8080",
        logger::Metadata::new(),
    );
    HttpServer::new(move || {
        let mut cors = Cors::default()
            .supports_credentials()
            .allow_any_method()
            .allow_any_header();
        for origin in &cors_origins {
            cors = cors.allowed_origin(origin);
        }

        let session_middleware =
            SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                .cookie_name("voult_session".to_string())
                .cookie_secure(cookie_secure)
                .cookie_http_only(true)
                .cookie_same_site(cookie_same_site)
                .session_lifecycle(
                    PersistentSession::default()
                        .session_ttl(Duration::seconds(session_ttl_seconds)),
                )
                .build();

        App::new()
            .app_data(db_data.clone())
            .app_data(recovery_throttle.clone())
            .app_data(favicon_client.clone())
            .app_data(favicon_cache.clone())
            .wrap(middleware::Logger::default())
            .wrap(session_middleware)
            .wrap(cors)
            // Registered last, so it is the outermost middleware: responses
            // short-circuited by CORS (preflight) and middleware-generated
            // errors still receive the policy. The previous COOP/COEP-only
            // DefaultHeaders was registered first (innermost).
            .wrap(security_headers::default_headers(https))
            .service(
                web::scope("/api")
                    // Vault/session/ciphertext responses must never sit in a
                    // cache (browser, proxy, or the extension's fetch cache).
                    .wrap(DefaultHeaders::new().add(("Cache-Control", "no-store")))
                    // Body-level failures (missing required field, malformed
                    // JSON, oversized body) answer with the same
                    // {"error_msg","code"} envelope the handlers use.
                    .app_data(endpoints::json_config())
                    .service(register::register)
                    .service(auth::auth)
                    .service(favicon::favicon)
                    .service(get_vault::get_vault)
                    .service(get_crypto_params::get_crypto_params)
                    .service(update_vault::update_vault)
                    .service(session_status::get_session)
                    .service(logout::logout)
                    .service(lock::lock)
                    .service(pair::pair_start)
                    .service(pair::pair_consume)
                    // Vault recovery (case 3). All three are unauthenticated by
                    // design — the recovering user has a paper recovery key and
                    // no session. Only `rewrap` writes, and it establishes the
                    // session itself.
                    .service(recovery::recovery_challenge)
                    .service(recovery::recovery_unlock)
                    .service(recovery::recovery_rewrap)
                    // Rotation is session-required: it is a deliberate change to a
                    // live vault made from inside the app, not a stranded user.
                    .service(recovery::recovery_regenerate)
                    .service(update_vault_password::update_vault_password)
                    .service(vaults::create_vault)
                    .service(vaults::list_vaults)
                    .service(cloud_endpoints::cloud_providers)
                    .service(cloud_endpoints::cloud_credentials)
                    .service(cloud_endpoints::cloud_auth_start)
                    .service(cloud_endpoints::cloud_oauth_callback)
                    .service(cloud_endpoints::cloud_status)
                    .service(cloud_endpoints::cloud_disconnect)
                    .service(cloud_endpoints::cloud_get_pending)
                    .service(cloud_endpoints::cloud_get_binding)
                    .service(cloud_endpoints::cloud_list_bindings)
                    .service(cloud_endpoints::cloud_list_vaults)
                    .service(cloud_endpoints::cloud_create_vault)
                    .service(cloud_endpoints::cloud_read_vault)
                    .service(cloud_endpoints::cloud_replace_vault)
                    .service(cloud_endpoints::cloud_mirror_vault)
                    .service(cloud_endpoints::cloud_upsert_binding)
                    .service(cloud_endpoints::cloud_link_pending)
                    .service(cloud_endpoints::cloud_list_vaults_pending)
                    .service(cloud_endpoints::cloud_read_vault_pending)
                    .service(cloud_endpoints::cloud_delete_vault),
            )
            .service(static_site(&static_dir))
    })
    .bind(("localhost", 8080))?
    .run()
    .await
}
