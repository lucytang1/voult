use crate::db::DbPool;
use crate::endpoints::validate;
use crate::entity::vault::{self, Entity as VaultEntity};
use crate::error::error_response;
use crate::session_auth::session_vault_id;
use actix_session::Session;
use actix_web::{HttpResponse, http::StatusCode, post, web};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;

const LOG: logger::ServerLogger = logger::Logger::create(logger::ServerContext::Auth);

#[derive(Deserialize)]
pub struct UpdatePasswordRequest {
    pub new_vault_verifier: String,
    /// Must be absent. Accepting a new salt without a matching new password
    /// envelope is how a vault becomes permanently unopenable: the next unlock
    /// derives the wrapping key from the new salt and cannot unwrap the old
    /// envelope. The atomic rewrap (P1 "Complete password-change protocol
    /// atomically") will accept these together with the envelope and a
    /// `credential_version` CAS; until then the only safe rotation is the
    /// verifier alone.
    pub new_salt: Option<String>,
    /// Must be absent, for the same reason as `new_salt`.
    pub new_iterations: Option<i32>,
}

/// Rotates the password verifier in place.
///
/// This is deliberately **not** a password change: the KDF parameters and the
/// password-wrapped vault-key envelope are untouched. A real password change
/// rewraps the vault key and must therefore be one atomic write with the new
/// envelope — owned by the P1 password-change item, not this endpoint.
#[post("/vault/password")]
pub async fn update_vault_password(
    pool: web::Data<DbPool>,
    session: Session,
    body: web::Json<UpdatePasswordRequest>,
) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => return crate::error::session_required(),
    };

    let request = body.into_inner();
    if let Err(e) = validate::require_b64_exact(
        "new_vault_verifier",
        &request.new_vault_verifier,
        validate::VERIFIER_LEN,
    ) {
        return e.response();
    }
    if request.new_salt.is_some() || request.new_iterations.is_some() {
        LOG.warn(
            format_args!("password change refused: KDF parameters require the atomic rewrap flow"),
            logger::Metadata::new(),
        );
        return error_response(
            StatusCode::CONFLICT,
            "changing salt or iterations requires the atomic rewrap flow with a new vault-key envelope",
            "PASSWORD_CHANGE_REQUIRES_REWRAP",
        );
    }

    let vault = match VaultEntity::find()
        .filter(vault::Column::Id.eq(&vault_id))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            return error_response(StatusCode::NOT_FOUND, "vault not found", "VAULT_NOT_FOUND");
        }
        Err(e) => {
            LOG.error(format_args!("{:?}", e), logger::Metadata::new());
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "db error", "DB_ERROR");
        }
    };

    let mut am: vault::ActiveModel = vault.into();
    am.vault_verifier = Set(request.new_vault_verifier.trim().to_string());
    match VaultEntity::update(am).exec(pool.get_ref()).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"updated": true})),
        Err(e) => {
            LOG.error(format_args!("{:?}", e), logger::Metadata::new());
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "db error", "DB_ERROR")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DbPool;
    use crate::endpoints::register;
    use crate::entity::vault::Entity as VaultEntity;
    use actix_web::App;
    use actix_web::cookie::{Cookie, Key};
    use actix_web::test;
    use migration::MigratorTrait;
    use sea_orm::Database;
    use serde_json::json;

    const VAULT_ID: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

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
                    .service(super::update_vault_password),
            )
            .await
        };
    }

    /// Registers a vault and returns the session cookie.
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
            let cookie: Cookie<'static> = resp
                .response()
                .cookies()
                .find(|c| c.name() == "voult_session")
                .expect("register must set the session cookie")
                .clone()
                .into_owned();
            cookie
        }};
    }

    fn post(body: serde_json::Value, cookie: &Cookie<'static>) -> test::TestRequest {
        test::TestRequest::post()
            .uri("/vault/password")
            .cookie(cookie.clone())
            .set_json(body)
    }

    async fn load(pool: &DbPool) -> vault::Model {
        VaultEntity::find_by_id(VAULT_ID)
            .one(pool)
            .await
            .unwrap()
            .unwrap()
    }

    /// The endpoint cannot change the KDF parameters: without a matching new
    /// password envelope that would leave the vault unopenable by any password.
    #[actix_web::test]
    async fn password_rotation_refuses_kdf_changes() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        let cookie = seed_vault!(app);
        let before = load(&pool).await;

        for (name, body) in [
            (
                "new_salt",
                json!({
                    "new_vault_verifier": b64_of(32, 0xC2),
                    "new_salt": b64_of(16, 0xC1),
                }),
            ),
            (
                "new_iterations",
                json!({
                    "new_vault_verifier": b64_of(32, 0xC2),
                    "new_iterations": 120_000,
                }),
            ),
        ] {
            let resp = test::call_service(&app, post(body, &cookie).to_request()).await;
            assert_eq!(resp.status(), StatusCode::CONFLICT, "{name}");
            let body: serde_json::Value = test::read_body_json(resp).await;
            assert_eq!(body["code"], "PASSWORD_CHANGE_REQUIRES_REWRAP", "{name}");
            assert_eq!(load(&pool).await, before, "{name} mutated the vault");
        }
    }

    /// A verifier-only rotation is safe and remains supported; only the
    /// verifier column may move.
    #[actix_web::test]
    async fn password_rotation_accepts_a_verifier_only_change() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        let cookie = seed_vault!(app);
        let before = load(&pool).await;

        let short = test::call_service(
            &app,
            post(json!({"new_vault_verifier": "AAAA"}), &cookie).to_request(),
        )
        .await;
        assert_eq!(short.status(), StatusCode::BAD_REQUEST);
        assert_eq!(load(&pool).await, before, "a bad verifier must not write");

        let new_verifier = b64_of(32, 0xEE);
        let resp = test::call_service(
            &app,
            post(json!({"new_vault_verifier": new_verifier}), &cookie).to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let after = load(&pool).await;
        assert_eq!(after.vault_verifier, new_verifier);
        assert_eq!(after.salt, before.salt);
        assert_eq!(after.iterations, before.iterations);
        assert_eq!(after.vault_key_wrap, before.vault_key_wrap);
        assert_eq!(after.vault_key_wrap_iv, before.vault_key_wrap_iv);
    }
}
