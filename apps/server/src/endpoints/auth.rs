use actix_session::Session;
use actix_web::{HttpResponse, http::StatusCode, post, web};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::credentials;
use crate::db::DbPool;
use crate::entity::vault::{self, Entity as VaultEntity};
use crate::id_codec::uuid_from_db;
use crate::session_auth::establish_vault_session;

const LOG: logger::ServerLogger = logger::Logger::create(logger::ServerContext::Auth);

#[derive(Deserialize)]
pub struct AuthRequest {
    // Client-generated, stable vault identity embedded in the encrypted vault.
    pub vault_id: String,
    // The verifier derived from the master password client-side. This is the
    // HMAC *preimage* of the server's stored credential — it is never persisted
    // (`crate::credentials` stores only a keyed hash). Still a bearer value in
    // transit; never log it, and never add a path that accepts the stored hash.
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

#[derive(Serialize)]
struct ErrorResponse {
    error_msg: String,
    code: &'static str,
}

fn error_response(status: StatusCode, error_msg: &str, code: &'static str) -> HttpResponse {
    HttpResponse::build(status).json(ErrorResponse {
        error_msg: error_msg.to_string(),
        code,
    })
}

#[post("/auth")]
pub async fn auth(
    pool: web::Data<DbPool>,
    session: Session,
    payload: web::Json<AuthRequest>,
) -> HttpResponse {
    let request = payload.into_inner();
    if request.vault_id.trim().is_empty() || !credentials::acceptable(&request.vault_verifier) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "vault_id and vault_verifier are required",
            "INVALID_INPUT",
        );
    }

    // A malformed vault ID is an invalid request, not an auth failure.
    let vault_uuid = match Uuid::parse_str(&request.vault_id) {
        Ok(u) => u,
        Err(_) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid vault_id", "INVALID_INPUT");
        }
    };

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

    // Constant-time check against the stored keyed hash. The presented value is
    // the HMAC preimage; the stored hash is never accepted as input.
    if !credentials::accepts(
        &vault.verifier_salt,
        &vault.verifier_hash,
        &request.vault_verifier,
    ) {
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
    use crate::endpoints::{register, session_status};
    use actix_web::App;
    use actix_web::cookie::{Cookie, Key};
    use actix_web::test;
    use base64::Engine as _;
    use migration::MigratorTrait;
    use sea_orm::{ActiveModelTrait, Database, EntityTrait, Set};
    use serde_json::json;

    const VAULT_ID: &str = "9b2f5c1e-7a44-4d2b-9f3a-2c6e8b1d0a55";
    /// A realistic credential: 32 bytes of base64, which is what the client
    /// derives. The exact value does not matter — only that it is the same
    /// string on every login, because it is a deterministic HMAC.
    const VERIFIER: &str = "ZDU0YzJmMWEtYmU3ZC00YzE5LThmMjMtYTBjNmU4YjFkMDU1";

    async fn test_pool() -> DbPool {
        let pool = Database::connect("sqlite::memory:").await.expect("connect");
        migration::Migrator::up(&pool, None).await.expect("migrate");
        pool
    }

    fn register_body(verifier: &str) -> serde_json::Value {
        json!({
            "vault_id": VAULT_ID,
            "vault_verifier": verifier,
            "salt": "c2FsdC1zYWx0LTE2Ynkx",
            "iterations": 60000,
            "vaultiv": "aXYtMTJieXRlcyE=",
            "vault": "Y2lwaGVydGV4dA==",
            "crypto_version": 2,
            "vault_key_wrap": "d3JhcA==",
            "vault_key_wrap_iv": "d2l2",
            "recovery_verifier": "cmVjb3ZlcnktdmVyaWZpZXI=",
            "recovery_salt": "cmVjb3Zlcnktc2FsdA==",
            "recovery_wrap": "cmVjb3Zlcnktd3JhcA==",
            "recovery_wrap_iv": "cmVjdml2",
        })
    }

    /// Registers the vault and returns the app plus the session cookie the
    /// registration itself established (registration logs the caller in).
    macro_rules! registered_app {
        ($pool:expr) => {{
            let app = test::init_service(
                App::new()
                    .app_data(web::Data::new($pool.clone()))
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
                    .service(super::auth)
                    .service(session_status::get_session),
            )
            .await;

            let resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/register")
                    .set_json(register_body(VERIFIER))
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED, "register must succeed");
            let cookie: Cookie<'static> = resp
                .response()
                .cookies()
                .find(|c| c.name() == "voult_session")
                .expect("register must set the session cookie")
                .clone()
                .into_owned();
            (app, cookie)
        }};
    }

    /// The credential the client holds is a bearer value in transit. What must
    /// never happen is the *stored* value becoming presentable again.
    #[actix_web::test]
    async fn auth_accepts_the_verifier_and_establishes_a_session() {
        let pool = test_pool().await;
        let (app, _registration_cookie) = registered_app!(&pool);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/auth")
                .set_json(json!({"vault_id": VAULT_ID, "vault_verifier": VERIFIER}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // The response is the unlock material, and the cookie is the session.
        let cookie: Cookie<'static> = resp
            .response()
            .cookies()
            .find(|c| c.name() == "voult_session")
            .expect("a successful auth must set the session cookie")
            .clone()
            .into_owned();
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["vault_id"], VAULT_ID);
        assert_eq!(body["vault_key_wrap"], "d3JhcA==");

        let session = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/session")
                .cookie(cookie)
                .to_request(),
        )
        .await;
        assert_eq!(session.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn auth_rejects_a_wrong_verifier_without_releasing_key_material() {
        let pool = test_pool().await;
        let (app, _) = registered_app!(&pool);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/auth")
                .set_json(json!({"vault_id": VAULT_ID, "vault_verifier": format!("{VERIFIER}x")}))
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(
            resp.response()
                .cookies()
                .all(|c| c.name() != "voult_session"),
            "a failed auth must not establish or rotate a session"
        );
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["code"], "AUTH_FAILED");
        assert!(
            body.get("vault_key_wrap").is_none(),
            "a failed auth must not leak the vault-key envelope"
        );
    }

    /// Pass-the-hash regression. The stored hash is the at-rest form of the
    /// credential; if presenting it ever authenticated, the whole change would
    /// be pointless (a dumped row would be replayable again).
    #[actix_web::test]
    async fn auth_rejects_the_stored_hash() {
        let pool = test_pool().await;
        let (app, _) = registered_app!(&pool);

        let row = VaultEntity::find()
            .filter(vault::Column::Id.eq(VAULT_ID))
            .one(&pool)
            .await
            .expect("query")
            .expect("row");
        assert!(credentials::accepts(
            &row.verifier_salt,
            &row.verifier_hash,
            VERIFIER
        ));

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/auth")
                .set_json(json!({"vault_id": VAULT_ID, "vault_verifier": row.verifier_hash}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// The point of the P0 item: the row must not contain anything that can be
    /// presented to `/auth`.
    #[actix_web::test]
    async fn registration_never_stores_the_presented_verifier() {
        let pool = test_pool().await;
        let _ = registered_app!(&pool);

        let row = VaultEntity::find()
            .filter(vault::Column::Id.eq(VAULT_ID))
            .one(&pool)
            .await
            .expect("query")
            .expect("row");

        // Shape: a 16-byte salt and a 32-byte hash, both base64.
        assert_eq!(
            crate::credentials::VERIFIER_SALT_LEN,
            base64::engine::general_purpose::STANDARD
                .decode(&row.verifier_salt)
                .expect("salt is base64")
                .len()
        );
        assert_eq!(
            crate::credentials::VERIFIER_HASH_LEN,
            base64::engine::general_purpose::STANDARD
                .decode(&row.verifier_hash)
                .expect("hash is base64")
                .len()
        );

        assert_ne!(row.verifier_hash, VERIFIER);
        assert_ne!(row.verifier_salt, VERIFIER);
        assert!(!row.verifier_hash.contains(VERIFIER));
        assert!(!row.verifier_salt.contains(VERIFIER));
    }

    /// A row below migration 8 has an empty credential pair. It must look like
    /// a wrong password (401 AUTH_FAILED), never a 500 and never a distinct
    /// code — otherwise a migrated install becomes a distinguishable oracle.
    #[actix_web::test]
    async fn auth_fails_closed_on_a_row_with_no_credential() {
        let pool = test_pool().await;
        let (app, _) = registered_app!(&pool);

        let row = VaultEntity::find()
            .filter(vault::Column::Id.eq(VAULT_ID))
            .one(&pool)
            .await
            .expect("query")
            .expect("row");
        let mut am: vault::ActiveModel = row.into();
        am.verifier_salt = Set(String::new());
        am.verifier_hash = Set(String::new());
        am.update(&pool).await.expect("clear credential");

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/auth")
                .set_json(json!({"vault_id": VAULT_ID, "vault_verifier": VERIFIER}))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["code"], "AUTH_FAILED");
    }
}
