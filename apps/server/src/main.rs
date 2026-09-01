mod datetime_codec;
mod db;
mod endpoints;
mod entity;
mod error;
mod google;
mod id_codec;
mod session_auth;
mod static_site;

use actix_cors::Cors;
use actix_session::SessionMiddleware;
use actix_session::config::PersistentSession;
use actix_session::storage::CookieSessionStore;
use actix_web::cookie::time::Duration;
use actix_web::cookie::{Key, SameSite};
use actix_web::middleware::DefaultHeaders;
use actix_web::middleware::Logger;
use actix_web::{App, HttpServer, web};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use env_logger::Env;
use migration::{Migrator, MigratorTrait};
use rand::RngCore;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use endpoints::{
    auth, get_crypto_params, get_vault, google_endpoints, register, session_status,
    update_vault, update_vault_password, vaults,
};
use static_site::static_site;

mod config;
use config::Environment;

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
                    log::info!("Using bundled static site at {}", cand.display());
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
        log::warn!(
            "{} from env is <64 chars (got {}), ignoring and using per-install key",
            config::ENV_SESSION_COOKIE_KEY,
            key.len()
        );
    }

    let data_dir = voult_data_dir();
    let key_path = data_dir.join("session.key");

    // Try to read existing key
    if let Ok(existing) = fs::read_to_string(&key_path) {
        let trimmed = existing.trim().to_string();
        if trimmed.len() >= 64 {
            log::info!("Using per-install session key at {}", key_path.display());
            return trimmed;
        }
        log::warn!("Existing session key at {} is too short, regenerating", key_path.display());
    }

    // Generate a new 64-byte random key, base64-encoded (88 chars)
    let mut bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut bytes);
    let key = BASE64_STANDARD.encode(bytes);

    if let Err(e) = fs::create_dir_all(&data_dir) {
        log::warn!("Could not create data dir for session key: {}", e);
    } else {
        match fs::write(&key_path, format!("{key}\n")) {
            Ok(()) => {
                // Restrict to owner only (0600) on unix
                let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
                log::info!("Generated new per-install session key at {}", key_path.display());
            }
            Err(e) => {
                log::warn!("Could not persist session key to {}: {}", key_path.display(), e);
            }
        }
    }
    key
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    config::load_dotenv();
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    let env = Environment::from_env();
    log::info!(
        "VOULT_ENV={} (is_dev: {})",
        env::var(config::ENV_VOULT_ENV).unwrap_or_else(|_| "(unset, defaulting to production)".to_string()),
        env.is_dev()
    );

    let database_url = config::database_url(env);
    log::info!("DATABASE_URL resolved to {}", database_url);

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
        log::warn!(
            "Static site not found at {} (run `npm run build:web` in apps/client); only the API will be served",
            static_dir
        );
    }

    log::info!("Starting server at http://localhost:8080");
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
            // Required by sqlite-wasm OPFS (SharedArrayBuffer). Mirrors the
            // client's public/_headers.
            .wrap(
                DefaultHeaders::new()
                    .add(("Cross-Origin-Opener-Policy", "same-origin"))
                    .add(("Cross-Origin-Embedder-Policy", "require-corp")),
            )
            .wrap(Logger::default())
            .wrap(session_middleware)
            .wrap(cors)
            .service(
                web::scope("/api")
                    .service(register::register)
                    .service(auth::auth)
                    .service(get_vault::get_vault)
                    .service(get_crypto_params::get_crypto_params)
                    .service(update_vault::update_vault)
                    .service(session_status::get_session)
                    .service(update_vault_password::update_vault_password)
                    .service(vaults::create_vault)
                    .service(vaults::list_vaults)
                    .service(google_endpoints::google_auth_start)
                    .service(google_endpoints::google_oauth_callback)
                    .service(google_endpoints::google_oauth_callback_legacy)
                    .service(google_endpoints::google_status)
                    .service(google_endpoints::google_disconnect)
                    .service(google_endpoints::google_get_pending)
                    .service(google_endpoints::google_get_binding)
                    .service(google_endpoints::google_list_bindings)
                    .service(google_endpoints::google_list_vaults)
                    .service(google_endpoints::google_create_vault)
                    .service(google_endpoints::google_read_vault)
                    .service(google_endpoints::google_replace_vault)
                    .service(google_endpoints::google_upsert_binding)
                    .service(google_endpoints::google_link_pending)
                    .service(google_endpoints::google_list_vaults_pending)
                    .service(google_endpoints::google_read_vault_pending)
                    .service(google_endpoints::google_delete_vault),
            )
            .service(static_site(&static_dir))
    })
    .bind(("localhost", 8080))?
    .run()
    .await
}
