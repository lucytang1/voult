use actix_session::Session;
use actix_web::{HttpResponse, http::StatusCode, post, web};
use sea_orm::{ActiveModelTrait, Set, TransactionTrait};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::DbPool;
use crate::entity::vault::ActiveModel as VaultActiveModel;
use crate::id_codec::uuid_to_db;
use crate::session_auth::establish_vault_session;

const LOG: logger::ServerLogger = logger::Logger::create(logger::ServerContext::Register);

#[derive(Deserialize)]
pub struct RegisterRequest {
    // Client-generated, stable vault identity embedded in the encrypted vault.
    pub vault_id: String,
    // Verifier derived from the master password client-side. Authentication
    // credential only — never the password or any key.
    pub vault_verifier: String,
    pub salt: String,
    pub iterations: i32,
    pub vaultiv: String,
    pub vault: String,
    #[serde(default)]
    pub crypto_version: Option<i32>,
    // Encrypted envelope holding the vault key, wrapped by the master password.
    // Required: without it the vault can never be unlocked.
    pub vault_key_wrap: String,
    pub vault_key_wrap_iv: String,
    // --- Recovery (case 3) ------------------------------------------------
    // Required. Recovery is a property every vault has from the moment it is
    // created — there is no enable step and no "recoverable later" state, so a
    // registration that arrives without these is rejected outright rather than
    // stored as a vault that can never be recovered.
    //
    // recovery_verifier = HMAC-SHA256(K_rec, "recovery-verify-v1"): the server's
    // second authentication path, which it can validate without holding the
    // secret or K_rec.
    pub recovery_verifier: String,
    // 16-byte HKDF salt (base64) for K_rec, served pre-auth by
    // GET /get_crypto_params so a recovering client can derive K_rec.
    pub recovery_salt: String,
    // AES-GCM envelope holding vaultKeyRaw under K_rec (Rule R1: raw key, not a
    // password-derived key). Must be unwrapped with AAD
    // utf8("voult-env|v2|<vault_id>|recovery").
    pub recovery_wrap: String,
    pub recovery_wrap_iv: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub vault_id: Uuid,
    pub vault: String,
    pub iterations: i32,
    pub vaultiv: String,
    pub salt: String,
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

#[post("/register")]
pub async fn register(
    pool: web::Data<DbPool>,
    session: Session,
    payload: web::Json<RegisterRequest>,
) -> HttpResponse {
    let request = payload.into_inner();

    // Validate the credentials BEFORE the transaction so a rejected request
    // never opens one, and never reaches a vault insert. Anything missing here
    // is a client bug, not a partial success.
    if request.vault_id.trim().is_empty()
        || request.vault_verifier.trim().is_empty()
        || request.salt.trim().is_empty()
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            "vault_id, vault_verifier and salt are required",
            "INVALID_INPUT",
        );
    }
    if request.vault_key_wrap.trim().is_empty() || request.vault_key_wrap_iv.trim().is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "vault_key_wrap and vault_key_wrap_iv are required",
            "INVALID_INPUT",
        );
    }
    // Recovery is mandatory: paired or not at all, so a half-written recovery
    // envelope can never be stored alongside a live vault.
    if request.recovery_verifier.trim().is_empty()
        || request.recovery_salt.trim().is_empty()
        || request.recovery_wrap.trim().is_empty()
        || request.recovery_wrap_iv.trim().is_empty()
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            "recovery_verifier, recovery_salt, recovery_wrap and recovery_wrap_iv are required",
            "INVALID_INPUT",
        );
    }

    // The vault ID must be a well-formed UUID the client generated.
    let vault_uuid = match Uuid::parse_str(&request.vault_id) {
        Ok(u) => u,
        Err(_) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid vault_id", "INVALID_INPUT");
        }
    };

    let crypto_version = request.crypto_version.unwrap_or(1);

    let tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            LOG.error(
                format_args!("failed to create transaction: {:?}", e),
                logger::Metadata::new(),
            );
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to create vault",
                "DB_ERROR",
            );
        }
    };

    let new_vault = VaultActiveModel {
        id: Set(uuid_to_db(vault_uuid)),
        vault: Set(request.vault),
        salt: Set(request.salt),
        iterations: Set(request.iterations),
        vaultiv: Set(request.vaultiv),
        vault_verifier: Set(request.vault_verifier),
        version: Set(1),
        crypto_version: Set(crypto_version),
        vault_key_wrap: Set(Some(request.vault_key_wrap)),
        vault_key_wrap_iv: Set(Some(request.vault_key_wrap_iv)),
        // Written together with the password envelope in this one insert, so a
        // vault can never exist with one and not the other. `credential_version`
        // is deliberately left NotSet: it takes the column default of 0 and no
        // vault is ever created with a non-zero one.
        recovery_verifier: Set(Some(request.recovery_verifier)),
        recovery_salt: Set(Some(request.recovery_salt)),
        recovery_wrap: Set(Some(request.recovery_wrap)),
        recovery_wrap_iv: Set(Some(request.recovery_wrap_iv)),
        recovery_created_at: Set(Some(chrono::Utc::now())),
        ..Default::default()
    };

    let inserted_vault = match new_vault.insert(&tx).await {
        Ok(inserted) => inserted,
        Err(e) => {
            // A duplicate vault_id (unique primary key) is a client conflict,
            // not a server error. SeaORM surfaces sqlite UNIQUE as Query or Exec
            // depending on driver version – check both and fall back to string.
            let err_str = format!("{e:?}");
            let is_unique = err_str.contains("UNIQUE constraint failed")
                || err_str.contains("unique constraint")
                || err_str.contains("1555");
            if matches!(e, sea_orm::DbErr::Exec(_) | sea_orm::DbErr::Query(_)) && is_unique {
                LOG.warn(
                    format_args!("vault registration conflict: {:?}", e),
                    logger::Metadata::new(),
                );
                let _ = tx.rollback().await;
                return error_response(
                    StatusCode::CONFLICT,
                    "vault already exists",
                    "VAULT_EXISTS",
                );
            }
            // Also treat any Exec/Query with unique substring as conflict even if above missed
            if is_unique {
                LOG.warn(
                    format_args!("vault registration conflict (unique): {:?}", e),
                    logger::Metadata::new(),
                );
                let _ = tx.rollback().await;
                return error_response(
                    StatusCode::CONFLICT,
                    "vault already exists",
                    "VAULT_EXISTS",
                );
            }
            LOG.error(
                format_args!("failed to create vault: {:?}", e),
                logger::Metadata::new(),
            );
            let _ = tx.rollback().await;
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to create vault",
                "DB_ERROR",
            );
        }
    };

    if let Err(e) = tx.commit().await {
        LOG.error(
            format_args!("failed to commit transaction: {:?}", e),
            logger::Metadata::new(),
        );
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to create vault",
            "DB_ERROR",
        );
    }

    // Establish a vault-scoped session for the newly created vault.
    if let Err(e) = establish_vault_session(&session, &inserted_vault.id) {
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

    let vault_id = match Uuid::parse_str(&inserted_vault.id) {
        Ok(id) => id,
        Err(e) => {
            LOG.error(
                format_args!("invalid UUID in inserted vault.id: {:?}", e),
                logger::Metadata::new(),
            );
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid vault id in database",
                "DATA_INTEGRITY_ERROR",
            );
        }
    };

    let response = RegisterResponse {
        vault_id,
        vault: inserted_vault.vault,
        salt: inserted_vault.salt,
        iterations: inserted_vault.iterations,
        vaultiv: inserted_vault.vaultiv,
        vault_key_wrap: inserted_vault.vault_key_wrap,
        vault_key_wrap_iv: inserted_vault.vault_key_wrap_iv,
    };

    HttpResponse::Created().json(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DbPool;
    use crate::endpoints::get_crypto_params;
    use crate::entity::vault::{self, Entity as VaultEntity};
    use actix_web::App;
    use actix_web::cookie::Key;
    use actix_web::test;
    use migration::MigratorTrait;
    use sea_orm::{ColumnTrait, Database, EntityTrait, QueryFilter};

    const VAULT_ID: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

    async fn test_pool() -> DbPool {
        let pool = Database::connect("sqlite::memory:").await.expect("connect");
        migration::Migrator::up(&pool, None).await.expect("migrate");
        pool
    }

    /// Builds the app with the session middleware so the handler sees a session.
    macro_rules! test_app {
        ($pool:expr) => {
            test::init_service(
                App::new()
                    .app_data(web::Data::new($pool.clone()))
                    .app_data(crate::endpoints::json_config())
                    .wrap(
                        actix_session::SessionMiddleware::builder(
                            actix_session::storage::CookieSessionStore::default(),
                            // Cookie-session keys must be at least 64 bytes.
                            Key::from(
                                b"test-key-for-session-middleware-must-be-at-least-64-bytes-long!!",
                            ),
                        )
                        .cookie_name("voult_session".to_string())
                        .build(),
                    )
                    .service(register)
                    .service(get_crypto_params::get_crypto_params),
            )
            .await
        };
    }

    /// A complete, valid registration body.
    fn valid_body() -> serde_json::Value {
        serde_json::json!({
            "vault_id": VAULT_ID,
            "vault_verifier": "dmVyaWZpZXI=",
            "salt": "c2FsdA==",
            "iterations": 60000,
            "vaultiv": "aXY=",
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

    async fn find_vault(pool: &DbPool) -> Option<vault::Model> {
        VaultEntity::find()
            .filter(vault::Column::Id.eq(VAULT_ID))
            .one(pool)
            .await
            .expect("query")
    }

    /// M2: a complete registration populates every recovery column, stamps
    /// recovery_created_at, and starts at credential_version 0.
    #[actix_web::test]
    async fn registration_persists_recovery_material() {
        let pool = test_pool().await;
        let app = test_app!(&pool);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/register")
                .set_json(valid_body())
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let v = find_vault(&pool).await.expect("vault row exists");

        assert_eq!(
            v.recovery_verifier.as_deref(),
            Some("cmVjb3ZlcnktdmVyaWZpZXI=")
        );
        assert_eq!(v.recovery_salt.as_deref(), Some("cmVjb3Zlcnktc2FsdA=="));
        assert_eq!(v.recovery_wrap.as_deref(), Some("cmVjb3Zlcnktd3JhcA=="));
        assert_eq!(v.recovery_wrap_iv.as_deref(), Some("cmVjdml2"));
        assert!(
            v.recovery_created_at.is_some(),
            "recovery_created_at must be stamped at registration"
        );
        assert_eq!(v.credential_version, 0);

        // The password envelope is untouched by the recovery additions.
        assert_eq!(v.vault_key_wrap.as_deref(), Some("d3JhcA=="));
        assert_eq!(v.vault_key_wrap_iv.as_deref(), Some("d2l2"));
    }

    /// M2: a fresh vault reports has_recovery and hands back the salt a
    /// recovering client needs to derive K_rec, without a session.
    #[actix_web::test]
    async fn crypto_params_expose_recovery_salt_and_flag() {
        let pool = test_pool().await;
        let app = test_app!(&pool);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/register")
                .set_json(valid_body())
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!("/get_crypto_params?vault_id={VAULT_ID}"))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;

        assert_eq!(body["has_recovery"], true);
        assert_eq!(body["recovery_salt"], "cmVjb3Zlcnktc2FsdA==");
        // The envelope and verifier must NOT be exposed pre-auth.
        assert!(body.get("recovery_wrap").is_none());
        assert!(body.get("recovery_verifier").is_none());
    }

    /// M2: registration without recovery material is rejected, and no vault row
    /// is created. Each recovery field is dropped in turn — recovery is
    /// all-or-nothing, so no partial set is accepted either.
    #[actix_web::test]
    async fn registration_without_recovery_is_rejected() {
        for missing in [
            "recovery_verifier",
            "recovery_salt",
            "recovery_wrap",
            "recovery_wrap_iv",
            // The password envelope was already required; keep it honest too.
            "vault_key_wrap",
            "vault_key_wrap_iv",
        ] {
            let pool = test_pool().await;
            let app = test_app!(&pool);

            let mut body = valid_body();
            body.as_object_mut().expect("object").remove(missing);

            let resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/register")
                    .set_json(body)
                    .to_request(),
            )
            .await;
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "missing {missing} must be rejected"
            );
            let body: serde_json::Value = test::read_body_json(resp).await;
            assert_eq!(body["code"], "INVALID_INPUT");

            assert!(
                find_vault(&pool).await.is_none(),
                "missing {missing} must not create a vault row"
            );
        }
    }

    /// An empty-string recovery field is not a substitute for a missing one —
    /// serde's "required" check only fires on absence.
    #[actix_web::test]
    async fn registration_with_blank_recovery_is_rejected() {
        let pool = test_pool().await;
        let app = test_app!(&pool);

        let mut body = valid_body();
        body["recovery_wrap"] = serde_json::Value::String("   ".to_string());

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/register")
                .set_json(body)
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(find_vault(&pool).await.is_none());
    }

    /// A duplicate vault_id still conflicts, and the conflict must not disturb
    /// the recovery material already stored on the original row.
    #[actix_web::test]
    async fn duplicate_registration_conflicts_without_touching_recovery() {
        let pool = test_pool().await;
        let app = test_app!(&pool);

        let first = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/register")
                .set_json(valid_body())
                .to_request(),
        )
        .await;
        assert_eq!(first.status(), StatusCode::CREATED);

        let mut second = valid_body();
        second["recovery_verifier"] = serde_json::Value::String("dGFtcGVyZWQ=".to_string());
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/register")
                .set_json(second)
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        let v = find_vault(&pool).await.expect("original row survives");
        assert_eq!(
            v.recovery_verifier.as_deref(),
            Some("cmVjb3ZlcnktdmVyaWZpZXI="),
            "the losing registration must not overwrite recovery"
        );
        assert_eq!(v.credential_version, 0);
    }
}
