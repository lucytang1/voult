use actix_session::Session;
use actix_web::{HttpResponse, http::StatusCode, post, web};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::DbPool;
use crate::endpoints::validate;
use crate::entity::vault::{self, Entity as VaultEntity};
use crate::error::error_response;
use crate::id_codec::uuid_from_db;
use crate::session_auth::establish_vault_session;

const LOG: logger::ServerLogger = logger::Logger::create(logger::ServerContext::Auth);

#[derive(Deserialize)]
pub struct AuthRequest {
    // Client-generated, stable vault identity embedded in the encrypted vault.
    pub vault_id: String,
    // Verifier derived from the master password client-side. Authentication
    // credential only — never the password or any key.
    pub vault_verifier: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub vault_id: Uuid,
    pub salt: String,
    pub iterations: i32,
    pub crypto_version: i32,
    // Encrypted envelope holding the vault key, wrapped by the master password.
    // Returned so the client can unwrap the vault key locally after unlock.
    pub vault_key_wrap: Option<String>,
    pub vault_key_wrap_iv: Option<String>,
}

#[post("/auth")]
pub async fn auth(
    pool: web::Data<DbPool>,
    session: Session,
    payload: web::Json<AuthRequest>,
) -> HttpResponse {
    let request = payload.into_inner();

    // The verifier is a 256-bit MAC. Enforcing the shape here makes that a
    // property of the protocol rather than a convention the client is trusted
    // to follow: a short verifier would be a guessable credential.
    let vault_uuid = match validate::require_uuid("vault_id", &request.vault_id) {
        Ok(id) => id,
        Err(e) => return e.response(),
    };
    if let Err(e) = validate::require_b64_exact(
        "vault_verifier",
        &request.vault_verifier,
        validate::VERIFIER_LEN,
    ) {
        return e.response();
    }
    let presented_verifier = request.vault_verifier.trim();

    let vault = match VaultEntity::find()
        .filter(vault::Column::Id.eq(vault_uuid.to_string()))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(vault)) => vault,
        Ok(None) => {
            // Do not distinguish "no such vault" from "bad verifier" to avoid
            // enumerating vault existence. Return the same generic error.
            return error_response(
                StatusCode::UNAUTHORIZED,
                "invalid vault_id or vault_verifier",
                "AUTH_FAILED",
            );
        }
        Err(e) => {
            LOG.error(
                format_args!("failed to fetch vault: {:?}", e),
                logger::Metadata::new(),
            );
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to fetch vault",
                "DB_ERROR",
            );
        }
    };

    if vault.vault_verifier != presented_verifier {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "invalid vault_id or vault_verifier",
            "AUTH_FAILED",
        );
    }

    // Rotate/purge any existing session before establishing the authenticated
    // one, then store only the authenticated vault ID in the session cookie.
    if let Err(e) = establish_vault_session(&session, &vault.id) {
        LOG.error(
            format_args!("failed to establish session: {:?}", e),
            logger::Metadata::new(),
        );
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to establish session",
            "SESSION_ERROR",
        );
    }

    let response = AuthResponse {
        vault_id: match uuid_from_db(&vault.id) {
            Ok(id) => id,
            Err(e) => {
                LOG.error(
                    format_args!("invalid UUID in vault.id: {:?}", e),
                    logger::Metadata::new(),
                );
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "invalid vault id in database",
                    "DATA_INTEGRITY_ERROR",
                );
            }
        },
        salt: vault.salt,
        iterations: vault.iterations,
        crypto_version: vault.crypto_version,
        vault_key_wrap: vault.vault_key_wrap,
        vault_key_wrap_iv: vault.vault_key_wrap_iv,
    };

    HttpResponse::Ok().json(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DbPool;
    use crate::endpoints::register;
    use actix_web::App;
    use actix_web::cookie::Key;
    use actix_web::test;
    use migration::MigratorTrait;
    use sea_orm::Database;
    use serde_json::json;

    const VAULT_ID: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
    const OTHER_VAULT_ID: &str = "00000000-0000-4000-8000-000000000000";

    async fn test_pool() -> DbPool {
        let pool = Database::connect("sqlite::memory:").await.expect("connect");
        migration::Migrator::up(&pool, None).await.expect("migrate");
        pool
    }

    fn b64_of(len: usize, fill: u8) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(vec![fill; len])
    }

    macro_rules! test_app {
        ($pool:expr) => {
            test::init_service(
                App::new()
                    .app_data(web::Data::new($pool.clone()))
                    .app_data(crate::endpoints::json_config())
                    .wrap(
                        actix_session::SessionMiddleware::builder(
                            actix_session::storage::CookieSessionStore::default(),
                            Key::from(
                                b"test-key-for-session-middleware-must-be-at-least-64-bytes-long!!",
                            ),
                        )
                        .cookie_name("voult_session".to_string())
                        .build(),
                    )
                    .service(register::register)
                    .service(super::auth),
            )
            .await
        };
    }

    /// Seeds a complete v2 vault through the real registration endpoint.
    macro_rules! seed_vault {
        ($app:expr) => {{
            let resp = test::call_service(
                &$app,
                test::TestRequest::post()
                    .uri("/register")
                    .set_json(json!({
                        "vault_id": VAULT_ID,
                        "vault_verifier": b64_of(32, 0xA4),
                        "salt": b64_of(16, 0xA3),
                        "iterations": 60000,
                        "vaultiv": b64_of(12, 0xA2),
                        "vault": b64_of(64, 0xA1),
                        "crypto_version": 2,
                        "vault_key_wrap": b64_of(48, 0xA5),
                        "vault_key_wrap_iv": b64_of(12, 0xA6),
                        "recovery_verifier": b64_of(32, 0xB1),
                        "recovery_salt": b64_of(16, 0xB2),
                        "recovery_wrap": b64_of(48, 0xB3),
                        "recovery_wrap_iv": b64_of(12, 0xB4),
                    }))
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED);
        }};
    }

    fn auth_body(vault_id: &str, verifier: String) -> serde_json::Value {
        json!({ "vault_id": vault_id, "vault_verifier": verifier })
    }

    /// A malformed verifier is a request-shape failure, not an authentication
    /// attempt: 400, no session, and no comparison against the stored row.
    #[actix_web::test]
    async fn auth_rejects_malformed_credentials() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        seed_vault!(app);

        let cases = [
            ("short verifier", auth_body(VAULT_ID, "AAAA".to_string())),
            (
                "non-base64 verifier",
                auth_body(VAULT_ID, "not base64!!".to_string()),
            ),
            (
                "uppercase vault id",
                auth_body(&VAULT_ID.to_uppercase(), b64_of(32, 0xA4)),
            ),
            (
                "unhyphenated vault id",
                auth_body(&VAULT_ID.replace('-', ""), b64_of(32, 0xA4)),
            ),
        ];

        for (name, body) in cases {
            let resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/auth")
                    .set_json(body)
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{name}");
            assert!(
                !resp
                    .response()
                    .cookies()
                    .any(|c| c.name() == "voult_session"),
                "{name} must not establish a session"
            );
            let body: serde_json::Value = test::read_body_json(resp).await;
            assert_eq!(body["code"], "INVALID_INPUT", "{name}");
        }
    }

    /// The only two authentication outcomes for a well-formed credential are
    /// "session" and one indistinguishable failure. Shape validation must not
    /// create a third, informative one.
    #[actix_web::test]
    async fn auth_failures_are_indistinguishable() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        seed_vault!(app);

        let mut bodies = Vec::new();
        for case in [
            // Unknown vault, well-formed verifier.
            auth_body(OTHER_VAULT_ID, b64_of(32, 0xA4)),
            // Known vault, well-formed wrong verifier.
            auth_body(VAULT_ID, b64_of(32, 0xEE)),
        ] {
            let resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/auth")
                    .set_json(case)
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            bodies.push(test::read_body(resp).await);
        }
        assert_eq!(
            bodies[0], bodies[1],
            "unknown vault and wrong verifier must be indistinguishable"
        );
        let parsed: serde_json::Value = serde_json::from_slice(&bodies[0]).unwrap();
        assert_eq!(parsed["code"], "AUTH_FAILED");
    }
}
