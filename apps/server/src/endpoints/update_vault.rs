use actix_session::Session;
use actix_web::{HttpResponse, http::StatusCode, post, web};
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, ExprTrait, QueryFilter};
use serde::{Deserialize, Serialize};

use crate::entity::vault::{self, Entity as Vault};
use crate::rate_limit::{RateLimiter, Subject, VaultWrite};
use crate::session_auth::session_vault_id;

use crate::db::DbPool;

const LOG: logger::ServerLogger = logger::Logger::create(logger::ServerContext::Vault);

#[derive(Deserialize)]
struct UpdateVaultRequest {
    pub vault: String,
    pub vaultiv: String,
    pub version: u32,
    #[serde(default)]
    pub crypto_version: Option<i32>,
    #[serde(default)]
    pub vault_key_wrap: Option<String>,
    #[serde(default)]
    pub vault_key_wrap_iv: Option<String>,
}

#[derive(Serialize)]
pub struct UpdateVaultResponse {
    pub vault: String,
    pub vaultiv: String,
    pub iterations: u32,
    pub version: u32,
    pub crypto_version: i32,
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

#[post("/update_vault")]
pub async fn update_vault(
    pool: web::Data<DbPool>,
    limiter: web::Data<RateLimiter>,
    session: Session,
    payload: web::Json<UpdateVaultRequest>,
) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        Ok(None) | Err(_) => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "session required",
                "SESSION_REQUIRED",
            );
        }
    };

    // Keyed on the SESSION's vault, never on anything in the body: a stolen
    // cookie for one vault must not be able to spend another vault's budget.
    // 60/min is generous for sync (which coalesces) and for a human edit pace,
    // while bounding disk writes and the post-commit provider mirror.
    if let Err(rejected) = limiter
        .charge::<VaultWrite>(&Subject::Vault(&vault_id))
        .await
    {
        return rejected.into_response();
    }

    let request = payload.into_inner();

    let vault = match Vault::find()
        .filter(vault::Column::Id.eq(&vault_id))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(vault)) => vault,
        Ok(None) => {
            return error_response(StatusCode::NOT_FOUND, "vault not found", "VAULT_NOT_FOUND");
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

    let new_vault = request.vault;
    let new_vaultiv = request.vaultiv;
    let new_crypto_version = request.crypto_version.unwrap_or(vault.crypto_version);
    let new_vault_key_wrap = request.vault_key_wrap.or(vault.vault_key_wrap.clone());
    let new_vault_key_wrap_iv = request
        .vault_key_wrap_iv
        .or(vault.vault_key_wrap_iv.clone());

    // Atomic compare-and-swap: only write when the vault is still at the
    // version the client pushed against. rows_affected == 0 means a
    // concurrent push from another device already won — return 409.
    let update_result = Vault::update_many()
        .col_expr(vault::Column::Vault, Expr::value(new_vault.clone()))
        .col_expr(vault::Column::Vaultiv, Expr::value(new_vaultiv.clone()))
        .col_expr(
            vault::Column::CryptoVersion,
            Expr::value(new_crypto_version),
        )
        .col_expr(
            vault::Column::VaultKeyWrap,
            Expr::value(new_vault_key_wrap.clone()),
        )
        .col_expr(
            vault::Column::VaultKeyWrapIv,
            Expr::value(new_vault_key_wrap_iv.clone()),
        )
        .col_expr(
            vault::Column::Version,
            Expr::col(vault::Column::Version).add(1),
        )
        .filter(vault::Column::Id.eq(&vault_id))
        .filter(vault::Column::Version.eq(request.version as i32))
        .exec(pool.get_ref())
        .await;

    match update_result {
        Ok(result) if result.rows_affected > 0 => {}
        Ok(_) => {
            return error_response(
                StatusCode::CONFLICT,
                "vault version mismatch",
                "VERSION_CONFLICT",
            );
        }
        Err(e) => {
            LOG.error(
                format_args!("failed to update vault: {:?}", e),
                logger::Metadata::new(),
            );
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to update vault",
                "DB_ERROR",
            );
        }
    }

    // The CAS guarantees the stored version was request.version, so it is now +1.
    let new_version = request.version + 1;

    // Disaster-recovery mirroring, strictly AFTER the commit.
    //
    // The server is the write authority; Drive holds an encrypted copy that is
    // re-written out of band. `mark_pending` is one indexed read plus a single
    // status update for bound vaults and a pure no-op for local-only ones, so
    // it cannot meaningfully delay the response. The Drive write itself is
    // spawned detached and is never awaited here: a Google outage must not turn
    // an accepted vault write into a 5xx or a slow response.
    let mirror_pool = pool.get_ref().clone();
    let mirror_vault_id = vault_id.clone();
    crate::cloud::mirror::mark_pending(&mirror_pool, &mirror_vault_id).await;
    crate::cloud::mirror::spawn_after_commit(mirror_pool, mirror_vault_id);

    HttpResponse::Ok().json(UpdateVaultResponse {
        vault: new_vault,
        vaultiv: new_vaultiv,
        iterations: vault.iterations as u32,
        version: new_version,
        crypto_version: new_crypto_version,
        vault_key_wrap: new_vault_key_wrap,
        vault_key_wrap_iv: new_vault_key_wrap_iv,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DbPool;
    use crate::endpoints::register;
    use crate::entity::vault::Entity as VaultEntity;
    use crate::rate_limit::Budget;
    use actix_web::App;
    use actix_web::cookie::{Cookie, Key};
    use actix_web::test;
    use migration::MigratorTrait;
    use sea_orm::{ActiveModelTrait, Database, EntityTrait, Set};
    use serde_json::json;

    const VAULT_ID: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

    async fn test_pool() -> DbPool {
        let pool = Database::connect("sqlite::memory:").await.expect("connect");
        migration::Migrator::up(&pool, None).await.expect("migrate");
        pool
    }

    /// Advances an existing vault to `version` without going through register,
    /// so a test can start from a known non-initial version. Register itself
    /// creates the vault at version 1 and establishes the session.
    async fn set_vault_version(pool: &DbPool, version: i32) {
        use sea_orm::{ColumnTrait, QueryFilter};
        let _ = vault::Entity::update_many()
            .col_expr(vault::Column::Version, Expr::value(version))
            .filter(vault::Column::Id.eq(VAULT_ID))
            .exec(pool)
            .await
            .expect("set version");
    }

    async fn seed_binding(pool: &DbPool, file_id: Option<&str>) {
        let am = crate::entity::cloud_binding::ActiveModel {
            vault_id: Set(VAULT_ID.to_string()),
            provider_kind: Set(crate::cloud::provider::ProviderKind::GoogleDrive
                .as_str()
                .to_string()),
            remote_file_id: Set(file_id.map(|s| s.to_string())),
            sync_status: Set("idle".to_string()),
            ..Default::default()
        };
        am.insert(pool).await.expect("insert binding");
    }

    /// Builds the app with the session middleware so the handler sees a session.
    macro_rules! test_app {
        ($pool:expr) => {
            test::init_service(
                App::new()
                    .app_data(web::Data::new($pool.clone()))
                    // Registration is wired in to establish the session; keep
                    // its budgets effectively unbounded — these tests are not
                    // about rate limiting.
                    .app_data(web::Data::new(crate::rate_limit::RateLimiter::permissive(
                        $pool.clone(),
                    )))
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
                    .service(register::register)
                    .service(super::update_vault),
            )
            .await
        };
    }

    /// Registers the vault and returns `(app, session_cookie)`.
    ///
    /// `call_service` does not propagate cookies between calls, so the session
    /// cookie is captured from the register response and replayed on the vault
    /// write — that cookie is the only thing authorizing it.
    macro_rules! authenticated_app {
        ($pool:expr) => {{
            let app = test_app!($pool);
            let req = test::TestRequest::post()
                .uri("/register")
                .set_json(json!({
                    "vault_id": VAULT_ID,
                    "vault_verifier": "dmVyaWZpZXI=",
                    "salt": "c2FsdA==",
                    "iterations": 60000,
                    "vaultiv": "aXY=",
                    "vault": "Y2lwaGVydGV4dA==",
                    "crypto_version": 2,
                    "vault_key_wrap": "d3JhcA==",
                    "vault_key_wrap_iv": "d2l2",
                    // Recovery is mandatory at registration. These tests cover
                    // vault writes and mirroring, not recovery, so opaque
                    // stand-in values are enough to get a valid row.
                    "recovery_verifier": "cmVjb3ZlcnktdmVyaWZpZXI=",
                    "recovery_salt": "cmVjb3Zlcnktc2FsdA==",
                    "recovery_wrap": "cmVjb3Zlcnktd3JhcA==",
                    "recovery_wrap_iv": "cmVjdml2",
                }))
                .to_request();
            let resp = test::call_service(&app, req).await;
            assert!(
                resp.status().is_success(),
                "register must succeed to seed the session"
            );
            // Owned copy: the response body is borrowed from `resp`, so the
            // cookie is cloned out before `resp` is dropped.
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

    /// Built as a `TestRequest` so each test converts it with `.to_request()`
    /// at the call site — avoids naming the concrete request type here.
    fn write_request(version: u32, cookie: &Cookie<'static>) -> test::TestRequest {
        test::TestRequest::post()
            .uri("/update_vault")
            .cookie(cookie.clone())
            .set_json(json!({
                "vault": "bmV3LWNpcGhlcnRleHQ=",
                "vaultiv": "bmV3aXY=",
                "version": version,
            }))
    }

    /// The core guarantee: a vault write commits and returns normally even when
    /// the vault has a Drive binding and the mirror cannot possibly succeed
    /// (no Google token, and no reachable provider). Mirroring is out of band.
    #[actix_web::test]
    async fn vault_write_succeeds_even_when_the_mirror_cannot_run() {
        let pool = test_pool().await;
        let (app, cookie) = authenticated_app!(&pool);
        set_vault_version(&pool, 3).await;
        seed_binding(&pool, Some("drive-file-1")).await;

        let resp = test::call_service(&app, write_request(3, &cookie).to_request()).await;

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a Drive outage must never fail or slow an accepted vault write"
        );
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["version"], 4, "CAS must still advance the version");

        // And the write is genuinely durable.
        let stored = VaultEntity::find_by_id(VAULT_ID)
            .one(&pool)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.version, 4);
        assert_eq!(stored.vault, "bmV3LWNpcGhlcnRleHQ=");
    }

    /// A stale base version must still lose the CAS before any mirroring
    /// happens — the mirror must never paper over a conflict.
    #[actix_web::test]
    async fn stale_version_still_conflicts_without_mirroring() {
        let pool = test_pool().await;
        let (app, cookie) = authenticated_app!(&pool);
        set_vault_version(&pool, 3).await;
        seed_binding(&pool, Some("drive-file-1")).await;

        let resp = test::call_service(&app, write_request(1, &cookie).to_request()).await;

        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["code"], "VERSION_CONFLICT");
        assert_eq!(
            VaultEntity::find_by_id(VAULT_ID)
                .one(&pool)
                .await
                .unwrap()
                .unwrap()
                .version,
            3,
            "a rejected write must leave the stored version untouched"
        );
    }

    /// A local-only vault (no Drive binding) takes the fast path: the write
    /// succeeds and no binding row is conjured.
    #[actix_web::test]
    async fn local_only_vault_write_needs_no_binding() {
        let pool = test_pool().await;
        let (app, cookie) = authenticated_app!(&pool);
        set_vault_version(&pool, 3).await;

        let resp = test::call_service(&app, write_request(3, &cookie).to_request()).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            crate::entity::cloud_binding::Entity::find()
                .all(&pool)
                .await
                .unwrap()
                .len(),
            0,
            "a local-only vault must not gain a Drive binding from a vault write"
        );
    }

    /// Mirroring runs after the response is built. With a binding but no Google
    /// token the mirror cannot reach Drive, so it must record `auth_required`
    /// rather than erroring — and must leave the watermark unmoved so Settings
    /// reports the backup as stale instead of silently claiming success.
    #[actix_web::test]
    async fn mirror_after_commit_records_failure_without_touching_the_vault() {
        let pool = test_pool().await;
        let (app, cookie) = authenticated_app!(&pool);
        set_vault_version(&pool, 3).await;
        seed_binding(&pool, Some("drive-file-1")).await;

        let resp = test::call_service(&app, write_request(3, &cookie).to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Drive the same code path the detached task would run, deterministically.
        crate::cloud::mirror::mirror_now(&pool, VAULT_ID).await;

        let binding = crate::entity::cloud_binding::Entity::find_by_id(VAULT_ID)
            .one(&pool)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            binding.mirrored_vault_version, None,
            "a failed mirror must not advance the backup watermark"
        );
        assert_ne!(
            binding.sync_status, "idle",
            "a failed mirror must not report the backup as current"
        );
        assert_eq!(
            VaultEntity::find_by_id(VAULT_ID)
                .one(&pool)
                .await
                .unwrap()
                .unwrap()
                .version,
            4,
            "the vault write stands regardless of mirror outcome"
        );
    }

    /// Builds the same app as `test_app!` but with an explicit limiter, so a
    /// test can spend a small write budget.
    macro_rules! app_with_limiter {
        ($pool:expr, $limiter:expr) => {
            test::init_service(
                App::new()
                    .app_data(web::Data::new($pool.clone()))
                    .app_data(web::Data::new($limiter))
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
                    .service(super::update_vault),
            )
            .await
        };
    }

    fn write_limiter(pool: &DbPool, max: u32) -> RateLimiter {
        RateLimiter::for_tests(
            pool.clone(),
            &[
                ("VaultWrite", Budget::new(max, 60)),
                ("RegisterIp", Budget::new(1_000, 60)),
                ("RegisterGlobal", Budget::new(1_000, 60)),
            ],
        )
    }

    /// Vault writes are the disk-fill / mirror-amplification vector once a
    /// session exists. The budget is per session vault.
    #[actix_web::test]
    async fn writes_are_limited_per_session_vault() {
        let pool = test_pool().await;
        let (app, cookie) = {
            // Register through a permissive app, then hand the cookie to a
            // budgeted app: registration itself is not what this test measures.
            let permissive = test_app!(&pool);
            let resp = test::call_service(
                &permissive,
                test::TestRequest::post()
                    .uri("/register")
                    .set_json(json!({
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
                    }))
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
            let budgeted = app_with_limiter!(&pool, write_limiter(&pool, 2));
            (budgeted, cookie)
        };

        let first = test::call_service(&app, write_request(1, &cookie).to_request()).await;
        assert_eq!(first.status(), StatusCode::OK);
        let second = test::call_service(&app, write_request(2, &cookie).to_request()).await;
        assert_eq!(second.status(), StatusCode::OK);

        let third = test::call_service(&app, write_request(3, &cookie).to_request()).await;
        assert_eq!(third.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(third.headers().get("retry-after").is_some());
        let body: serde_json::Value = test::read_body_json(third).await;
        assert_eq!(body["code"], "RATE_LIMITED");

        // The refused write must not have landed.
        let stored = VaultEntity::find_by_id(VAULT_ID)
            .one(&pool)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.version, 3);
    }

    /// Locking is a safety action and reads are not amplification: neither is
    /// rate-limited, even when the write budget is exhausted.
    #[actix_web::test]
    async fn exhausted_write_budget_still_allows_lock_and_reads() {
        let pool = test_pool().await;
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .app_data(web::Data::new(write_limiter(&pool, 1)))
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
                .service(super::update_vault)
                .service(crate::endpoints::lock::lock)
                .service(crate::endpoints::get_vault::get_vault),
        )
        .await;

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/register")
                .set_json(json!({
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
                }))
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

        let ok = test::call_service(&app, write_request(1, &cookie).to_request()).await;
        assert_eq!(ok.status(), StatusCode::OK);
        let refused = test::call_service(&app, write_request(2, &cookie).to_request()).await;
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);

        let lock = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/lock")
                .cookie(cookie.clone())
                .to_request(),
        )
        .await;
        assert_eq!(lock.status(), StatusCode::OK);

        let read = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/get_vault")
                .cookie(cookie)
                .to_request(),
        )
        .await;
        assert_eq!(read.status(), StatusCode::OK);
    }

    /// `/vault/password` writes the same vault row under the same identity, so
    /// it shares the `VaultWrite` budget instead of handing a stolen cookie a
    /// second allowance by switching endpoints.
    #[actix_web::test]
    async fn password_change_shares_the_write_budget() {
        let pool = test_pool().await;

        // Register through a permissive app; the budgeted app below serves the
        // two write endpoints.
        let permissive = test_app!(&pool);
        let resp = test::call_service(
            &permissive,
            test::TestRequest::post()
                .uri("/register")
                .set_json(json!({
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
                }))
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

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .app_data(web::Data::new(write_limiter(&pool, 1)))
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
                .service(super::update_vault)
                .service(crate::endpoints::update_vault_password::update_vault_password),
        )
        .await;

        let changed = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/vault/password")
                .cookie(cookie.clone())
                .set_json(json!({ "new_vault_verifier": "bmV3LXZlcmlmaWVy" }))
                .to_request(),
        )
        .await;
        assert_eq!(changed.status(), StatusCode::OK);

        let write = test::call_service(&app, write_request(1, &cookie).to_request()).await;
        assert_eq!(
            write.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "the password change already spent the shared write budget"
        );

        let stored = VaultEntity::find_by_id(VAULT_ID)
            .one(&pool)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.vault_verifier, "bmV3LXZlcmlmaWVy");
    }
}
