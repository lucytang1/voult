mod datetime_codec;
mod db;
mod endpoints;
mod entity;
mod error;
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
use dotenvy::dotenv;
use env_logger::Env;
use migration::{Migrator, MigratorTrait};
use std::env;
use std::path::Path;

use endpoints::{
    auth, get_crypto_params, get_vault, logout, register, session_status, update_vault,
};
use static_site::static_site;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env file");

    // Session cookie signing/encryption secret. Must be at least 64 bytes for
    // the cookie-session backend. Never share or commit it.
    let session_cookie_key = env::var("SESSION_COOKIE_KEY")
        .expect("SESSION_COOKIE_KEY must be set in .env file (at least 64 characters)");
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
    let cors_origins: Vec<String> = env::var("CORS_ORIGINS")
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_else(|_| {
            vec![
                "http://localhost:8081".to_string(),
                "http://127.0.0.1:8081".to_string(),
            ]
        });

    // Static site (the exported Expo web client) served at the root. The API
    // lives under /api. Override the location with STATIC_DIR.
    let static_dir = env::var("STATIC_DIR").unwrap_or_else(|_| "../client/dist".to_string());
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
                    .service(logout::logout),
            )
            .service(static_site(&static_dir))
    })
    .bind(("localhost", 8080))?
    .run()
    .await
}
