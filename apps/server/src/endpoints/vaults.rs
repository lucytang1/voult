use crate::db::DbPool;
use crate::endpoints::validate::{self, VaultMaterial};
use crate::entity::vault::{self, Entity as VaultEntity};
use crate::id_codec::uuid_to_db;
use crate::session_auth::session_vault_id;
use actix_session::Session;
use actix_web::{HttpResponse, get, http::StatusCode, post, web};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const LOG: logger::ServerLogger = logger::Logger::create(logger::ServerContext::Vaults);

#[derive(Deserialize)]
pub struct CreateVaultRequest {
    pub vault_id: Option<String>,
    pub vault: String,
    pub vaultiv: String,
    pub salt: String,
    pub iterations: i32,
    // Required and only ever `SUPPORTED_CRYPTO_VERSION`. The default used to be
    // 2 here and 1 in /register; neither default is allowed now.
    pub crypto_version: i32,
    pub vault_key_wrap: String,
    pub vault_key_wrap_iv: String,
    // Required: an omitted verifier used to be written as "", which made the
    // vault permanently unauthenticatable (`/auth` refuses a blank verifier).
    pub vault_verifier: String,
    // --- Recovery (case 3) ------------------------------------------------
    // Required, exactly as on POST /register. This endpoint writes a complete
    // vault row, so leaving these optional would open a second way to create a
    // vault that can never be recovered — the exact state recovery exists to
    // prevent. Currently unreferenced by the client (see §M2), but the route is
    // live and session-authenticated, so the invariant is enforced here rather
    // than relying on nobody calling it.
    pub recovery_verifier: String,
    pub recovery_salt: String,
    pub recovery_wrap: String,
    pub recovery_wrap_iv: String,
}
#[derive(Serialize)]
pub struct CreateVaultResponse {
    pub vault_id: Uuid,
    pub vault: String,
    pub vaultiv: String,
    pub salt: String,
    pub iterations: i32,
    pub version: i32,
    pub crypto_version: i32,
}
fn err(s: StatusCode, m: &str, c: &str) -> HttpResponse {
    HttpResponse::build(s).json(serde_json::json!({"error_msg": m, "code": c}))
}

#[post("/vaults")]
pub async fn create_vault(
    pool: web::Data<DbPool>,
    session: Session,
    payload: web::Json<CreateVaultRequest>,
) -> HttpResponse {
    let vault_id_sess = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return err(
                StatusCode::UNAUTHORIZED,
                "session required",
                "SESSION_REQUIRED",
            );
        }
    };
    let req = payload.into_inner();

    // Shape first: a rejected body must not even be the reason for a DB read.
    // The session check stays above it so a session-less caller still gets the
    // 401 its client teardown expects.
    if let Err(e) = validate::validate_vault_material(&VaultMaterial {
        vault_verifier: &req.vault_verifier,
        salt: &req.salt,
        iterations: req.iterations,
        vault_iv: &req.vaultiv,
        vault: &req.vault,
        crypto_version: req.crypto_version,
        vault_key_wrap: &req.vault_key_wrap,
        vault_key_wrap_iv: &req.vault_key_wrap_iv,
        recovery_verifier: &req.recovery_verifier,
        recovery_salt: &req.recovery_salt,
        recovery_wrap: &req.recovery_wrap,
        recovery_wrap_iv: &req.recovery_wrap_iv,
    }) {
        return e.response();
    }

    let vault_uuid = match &req.vault_id {
        Some(raw) => match validate::require_uuid("vault_id", raw) {
            Ok(id) if id.to_string() == vault_id_sess => id,
            Ok(_) => {
                return err(
                    StatusCode::FORBIDDEN,
                    "vault_id does not match session",
                    "VAULT_MISMATCH",
                );
            }
            Err(e) => return e.response(),
        },
        None => match validate::canonical_uuid(&vault_id_sess) {
            Some(id) => id,
            None => {
                return err(
                    StatusCode::UNAUTHORIZED,
                    "invalid session",
                    "SESSION_REQUIRED",
                );
            }
        },
    };

    // vault already exists for this session -> conflict
    if VaultEntity::find()
        .filter(vault::Column::Id.eq(&vault_id_sess))
        .one(pool.get_ref())
        .await
        .map(|o| o.is_some())
        .unwrap_or(false)
    {
        return err(StatusCode::CONFLICT, "vault already exists", "VAULT_EXISTS");
    }

    let am = vault::ActiveModel {
        id: Set(uuid_to_db(vault_uuid)),
        vault: Set(req.vault),
        salt: Set(req.salt),
        iterations: Set(req.iterations),
        vaultiv: Set(req.vaultiv),
        vault_verifier: Set(req.vault_verifier),
        version: Set(1),
        crypto_version: Set(req.crypto_version),
        vault_key_wrap: Set(Some(req.vault_key_wrap)),
        vault_key_wrap_iv: Set(Some(req.vault_key_wrap_iv)),
        recovery_verifier: Set(Some(req.recovery_verifier)),
        recovery_salt: Set(Some(req.recovery_salt)),
        recovery_wrap: Set(Some(req.recovery_wrap)),
        recovery_wrap_iv: Set(Some(req.recovery_wrap_iv)),
        recovery_created_at: Set(Some(chrono::Utc::now())),
        ..Default::default()
    };
    let inserted = match am.insert(pool.get_ref()).await {
        Ok(v) => v,
        Err(e) => {
            let s = format!("{e:?}");
            if s.contains("UNIQUE constraint failed")
                || s.contains("unique constraint")
                || s.contains("1555")
            {
                LOG.warn(
                    format_args!("vault create conflict: {:?}", e),
                    logger::Metadata::new(),
                );
                return err(StatusCode::CONFLICT, "vault already exists", "VAULT_EXISTS");
            }
            LOG.error(
                format_args!("failed to create vault: {:?}", e),
                logger::Metadata::new(),
            );
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to create vault",
                "DB_ERROR",
            );
        }
    };
    let vid = Uuid::parse_str(&inserted.id).unwrap_or(vault_uuid);
    HttpResponse::Created().json(CreateVaultResponse {
        vault_id: vid,
        vault: inserted.vault,
        vaultiv: inserted.vaultiv,
        salt: inserted.salt,
        iterations: inserted.iterations,
        version: inserted.version,
        crypto_version: inserted.crypto_version,
    })
}

#[get("/vaults")]
pub async fn list_vaults(pool: web::Data<DbPool>, session: Session) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return err(
                StatusCode::UNAUTHORIZED,
                "session required",
                "SESSION_REQUIRED",
            );
        }
    };
    let v = match VaultEntity::find()
        .filter(vault::Column::Id.eq(&vault_id))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(v)) => v,
        Ok(None) => return err(StatusCode::NOT_FOUND, "vault not found", "VAULT_NOT_FOUND"),
        Err(e) => {
            LOG.error(format_args!("{:?}", e), logger::Metadata::new());
            return err(StatusCode::INTERNAL_SERVER_ERROR, "db error", "DB_ERROR");
        }
    };
    HttpResponse::Ok().json(serde_json::json!({"vaults": [{"vault_id": v.id, "version": v.version, "crypto_version": v.crypto_version, "created_at": v.created_at.to_rfc3339()}]}))
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
    use sea_orm::{Database, EntityTrait};
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
                    .service(super::create_vault),
            )
            .await
        };
    }

    fn valid_body() -> serde_json::Value {
        json!({
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
        })
    }

    /// Registers a vault (to mint a session), then deletes the row so `/vaults`
    /// can be reached. The cookie is client-side state, so it stays valid —
    /// which is the only way this otherwise-unreachable route can be tested.
    macro_rules! session_without_vault {
        ($app:expr, $pool:expr) => {{
            let resp = test::call_service(
                &$app,
                test::TestRequest::post()
                    .uri("/register")
                    .set_json(valid_body())
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED);
            let cookie: Cookie<'static> = resp
                .response()
                .cookies()
                .find(|c| c.name() == "voult_session")
                .expect("session cookie")
                .clone()
                .into_owned();
            VaultEntity::delete_by_id(VAULT_ID)
                .exec($pool)
                .await
                .expect("delete vault");
            cookie
        }};
    }

    /// `vault_verifier` used to be optional and defaulted to `""`, writing a
    /// vault that could never authenticate again. It is now required and shaped.
    #[actix_web::test]
    async fn create_vault_requires_a_shaped_verifier() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        let cookie = session_without_vault!(app, &pool);

        for (name, body) in [
            ("missing verifier", {
                let mut b = valid_body();
                b.as_object_mut().unwrap().remove("vault_verifier");
                b
            }),
            ("empty verifier", {
                let mut b = valid_body();
                b["vault_verifier"] = serde_json::json!("");
                b
            }),
            ("short verifier", {
                let mut b = valid_body();
                b["vault_verifier"] = serde_json::json!(b64_of(16, 0xA4));
                b
            }),
            ("crypto_version 1", {
                let mut b = valid_body();
                b["crypto_version"] = serde_json::json!(1);
                b
            }),
        ] {
            let resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/vaults")
                    .cookie(cookie.clone())
                    .set_json(body)
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{name}");
            assert!(
                VaultEntity::find_by_id(VAULT_ID)
                    .one(&pool)
                    .await
                    .unwrap()
                    .is_none(),
                "{name} must not create a row"
            );
        }
    }

    /// A complete body still works, and the verifier is stored exactly once.
    #[actix_web::test]
    async fn create_vault_stores_the_complete_row() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        let cookie = session_without_vault!(app, &pool);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/vaults")
                .cookie(cookie)
                .set_json(valid_body())
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let stored = VaultEntity::find_by_id(VAULT_ID)
            .one(&pool)
            .await
            .unwrap()
            .expect("row exists");
        assert_eq!(stored.vault_verifier, b64_of(32, 0xA4));
        assert_eq!(stored.crypto_version, 2);
        assert_eq!(stored.iterations, 60_000);
    }
}
