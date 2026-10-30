use actix_session::Session;
use actix_web::{HttpResponse, http::StatusCode, post, web};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::DbPool;
use crate::entity::vault::{self, Entity as VaultEntity};
use crate::id_codec::uuid_from_db;
use crate::rate_limit::{AuthIp, AuthTarget, Limited, RateLimiter, Subject};
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
    limiter: web::Data<RateLimiter>,
    // Per-IP budget. Extractors run before the handler, so a refused request
    // never reaches it (and never spends a vault budget). Actix polls extractor
    // futures concurrently, so a malformed body can still be answered by the
    // JSON layer with a 400 — that request does not reach the handler either.
    _limit: Limited<AuthIp>,
    session: Session,
    payload: web::Json<AuthRequest>,
) -> HttpResponse {
    let request = payload.into_inner();
    if request.vault_id.trim().is_empty() || request.vault_verifier.trim().is_empty() {
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

    // Canonical form so `ABC…` and `abc…` spend the same budget. The per-vault
    // counter is charged on the SUPPLIED id — before the lookup — so an unknown
    // vault consumes budget exactly like a known one and the 429 below cannot
    // become an existence oracle. The counter is cleared only on a successful
    // verifier (`reset` further down), so only the owner can reset it.
    let canonical_vault_id = vault_uuid.to_string();
    if let Err(rejected) = limiter
        .charge::<AuthTarget>(&Subject::Vault(&canonical_vault_id))
        .await
    {
        return rejected.into_response();
    }

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

    if vault.vault_verifier != request.vault_verifier {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "invalid vault_id or vault_verifier",
            "AUTH_FAILED",
        );
    }

    // Correct verifier: give the owner a clean budget. An attacker cannot reach
    // this line, and once the cap is already spent a correct attempt never gets
    // here either (the charge above refuses it first), so this cannot be used
    // to bypass the limit.
    limiter
        .reset::<AuthTarget>(&Subject::Vault(&canonical_vault_id))
        .await;

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
    use crate::entity::vault;
    use crate::rate_limit::{Budget, RateLimiter};
    use actix_web::App;
    use actix_web::cookie::Key;
    use actix_web::test;
    use migration::MigratorTrait;
    use sea_orm::{ActiveModelTrait, Database, Set};

    const VAULT_ID: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
    const OTHER_VAULT_ID: &str = "00000000-0000-4000-8000-000000000001";
    const VERIFIER: &str = "dmVyaWZpZXI=";

    async fn test_pool() -> DbPool {
        let pool = Database::connect("sqlite::memory:").await.expect("connect");
        migration::Migrator::up(&pool, None).await.expect("migrate");
        pool
    }

    async fn seed_vault(pool: &DbPool, vault_id: &str, verifier: &str) {
        vault::ActiveModel {
            id: Set(vault_id.to_string()),
            vault: Set("Y2lwaGVydGV4dA==".to_string()),
            salt: Set("c2FsdA==".to_string()),
            iterations: Set(60_000),
            vaultiv: Set("aXY=".to_string()),
            vault_verifier: Set(verifier.to_string()),
            version: Set(1),
            crypto_version: Set(2),
            vault_key_wrap: Set(Some("d3JhcA==".to_string())),
            vault_key_wrap_iv: Set(Some("d2l2".to_string())),
            ..Default::default()
        }
        .insert(pool)
        .await
        .expect("seed vault");
    }

    macro_rules! test_app {
        ($pool:expr, $limiter:expr) => {
            test::init_service(
                App::new()
                    .app_data(web::Data::new($pool.clone()))
                    .app_data(web::Data::new($limiter))
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
                    .service(super::auth),
            )
            .await
        };
    }

    fn auth_request(vault_id: &str, verifier: &str) -> test::TestRequest {
        test::TestRequest::post()
            .uri("/auth")
            .peer_addr("1.2.3.4:5000".parse().expect("peer"))
            .set_json(serde_json::json!({
                "vault_id": vault_id,
                "vault_verifier": verifier,
            }))
    }

    /// The per-vault budget is the only control that survives IP rotation, and
    /// it must refuse before the verifier is even compared.
    #[actix_web::test]
    async fn wrong_verifier_is_limited_per_vault() {
        let pool = test_pool().await;
        seed_vault(&pool, VAULT_ID, VERIFIER).await;
        let limiter = RateLimiter::for_tests(
            pool.clone(),
            &[
                ("AuthTarget", Budget::new(2, 60)),
                ("AuthIp", Budget::new(100, 60)),
            ],
        );
        let app = test_app!(&pool, limiter);

        for _ in 0..2 {
            let resp = test::call_service(&app, auth_request(VAULT_ID, "wrong").to_request()).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }

        let resp = test::call_service(&app, auth_request(VAULT_ID, "wrong").to_request()).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after = resp
            .headers()
            .get("retry-after")
            .expect("Retry-After header");
        assert!(!retry_after.to_str().unwrap().is_empty());
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["code"], "RATE_LIMITED");
        assert_eq!(body["error_msg"], "too many attempts, try again later");

        // A different vault has its own budget.
        let resp =
            test::call_service(&app, auth_request(OTHER_VAULT_ID, "wrong").to_request()).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Unknown and known vaults must consume budget identically, or the 429
    /// becomes an existence oracle that `/auth`'s uniform 401 avoids.
    #[actix_web::test]
    async fn unknown_vault_is_limited_identically_to_a_known_one() {
        let pool = test_pool().await;
        seed_vault(&pool, VAULT_ID, VERIFIER).await;
        let limiter = RateLimiter::for_tests(
            pool.clone(),
            &[
                ("AuthTarget", Budget::new(1, 60)),
                ("AuthIp", Budget::new(100, 60)),
            ],
        );
        let app = test_app!(&pool, limiter);

        for vault_id in [VAULT_ID, OTHER_VAULT_ID] {
            let first =
                test::call_service(&app, auth_request(vault_id, "wrong").to_request()).await;
            let second =
                test::call_service(&app, auth_request(vault_id, "wrong").to_request()).await;
            assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                second.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "known and unknown vaults must refuse at the same point"
            );
        }
    }

    /// A successful login gives the owner a fresh budget; an attacker cannot
    /// reach that branch. A correct attempt after the cap is spent is still
    /// refused, so reset-on-success is not a bypass.
    #[actix_web::test]
    async fn successful_login_clears_the_target_budget() {
        let pool = test_pool().await;
        seed_vault(&pool, VAULT_ID, VERIFIER).await;
        let limiter = RateLimiter::for_tests(
            pool.clone(),
            &[
                ("AuthTarget", Budget::new(3, 60)),
                ("AuthIp", Budget::new(100, 60)),
            ],
        );
        let app = test_app!(&pool, limiter);

        for _ in 0..2 {
            let resp = test::call_service(&app, auth_request(VAULT_ID, "wrong").to_request()).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }

        let resp = test::call_service(&app, auth_request(VAULT_ID, VERIFIER).to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Budget cleared: three more failures are accepted before the next 429.
        for _ in 0..3 {
            let resp = test::call_service(&app, auth_request(VAULT_ID, "wrong").to_request()).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
        let resp = test::call_service(&app, auth_request(VAULT_ID, "wrong").to_request()).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    /// The IP axis must use the socket peer: a rotating X-Forwarded-For must
    /// not hand out a fresh budget per request on a direct deployment.
    #[actix_web::test]
    async fn spoofed_forwarded_header_does_not_create_a_new_bucket() {
        let pool = test_pool().await;
        seed_vault(&pool, VAULT_ID, VERIFIER).await;
        let limiter = RateLimiter::for_tests(
            pool.clone(),
            &[
                ("AuthIp", Budget::new(2, 60)),
                ("AuthTarget", Budget::new(100, 60)),
            ],
        );
        let app = test_app!(&pool, limiter);

        for spoof in ["1.1.1.1", "2.2.2.2"] {
            let resp = test::call_service(
                &app,
                auth_request(VAULT_ID, "wrong")
                    .insert_header(("x-forwarded-for", spoof))
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }

        let resp = test::call_service(
            &app,
            auth_request(VAULT_ID, "wrong")
                .insert_header(("x-forwarded-for", "3.3.3.3"))
                .to_request(),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "a spoofed header must not reset the per-IP budget"
        );
    }

    /// Proves the refusal happens before the handler: once the IP budget is
    /// spent, a well-formed request for a different vault is answered with 429
    /// and never reaches the vault lookup.
    #[actix_web::test]
    async fn spent_ip_budget_refuses_before_the_handler_runs() {
        let pool = test_pool().await;
        seed_vault(&pool, VAULT_ID, VERIFIER).await;
        let limiter = RateLimiter::for_tests(
            pool.clone(),
            &[
                ("AuthIp", Budget::new(1, 60)),
                ("AuthTarget", Budget::new(100, 60)),
            ],
        );
        let app = test_app!(&pool, limiter);

        let resp = test::call_service(&app, auth_request(VAULT_ID, "wrong").to_request()).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp =
            test::call_service(&app, auth_request(OTHER_VAULT_ID, "wrong").to_request()).await;
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "the IP budget must refuse before any vault-specific work"
        );
        assert!(resp.headers().get("retry-after").is_some());
    }
}
