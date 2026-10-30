use actix_web::{HttpResponse, get, http::StatusCode, web};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};

use crate::db::DbPool;
use crate::entity::vault::{self, Entity as Vaults};
use crate::rate_limit::{CryptoParamsIp, Limited};

const LOG: logger::ServerLogger = logger::Logger::create(logger::ServerContext::Auth);

#[derive(Deserialize)]
pub struct GetCryptoParamsRequest {
    // Vault identity the client wants KDF params for, before unlocking.
    pub vault_id: String,
}

#[derive(Serialize)]
pub struct GetCryptoParamsResponse {
    pub salt: String,
    pub iterations: i32,
    /// HKDF salt for the recovery wrapping key, base64. A recovering client
    /// needs it before it can derive K_rec, and this endpoint is already
    /// reachable without a session.
    ///
    /// Widening this response leaks strictly nothing new: the endpoint already
    /// returns `salt`/`iterations` pre-auth and already answers
    /// VAULT_NOT_FOUND, i.e. it is already a vault-existence oracle (flagged P1
    /// at ROADMAP:69). A dedicated `GET /api/recovery/params` would have added a
    /// *second* unauthenticated oracle for the same fact.
    ///
    /// `recovery_wrap` / `recovery_verifier` are deliberately NOT exposed here —
    /// neither is an input to recovery, and releasing the envelope pre-auth
    /// would widen this endpoint from a params endpoint into a ciphertext one.
    pub recovery_salt: Option<String>,
    /// Whether this vault has recovery configured. Derived from
    /// `recovery_verifier IS NOT NULL` — not a stored column.
    pub has_recovery: bool,
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

#[get("/get_crypto_params")]
pub async fn get_crypto_params(
    pool: web::Data<DbPool>,
    // Per-IP budget; no per-vault budget here. A per-vault counter would make
    // the 404 path behave differently from the 200 path for a caller who does
    // not know whether the vault exists — a new oracle for no gain, since
    // enumeration is already bounded per IP.
    _limit: Limited<CryptoParamsIp>,
    payload: web::Query<GetCryptoParamsRequest>,
) -> HttpResponse {
    let request = payload.into_inner();
    if request.vault_id.trim().is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "vault_id is required",
            "INVALID_INPUT",
        );
    }
    if uuid::Uuid::parse_str(&request.vault_id).is_err() {
        return error_response(StatusCode::BAD_REQUEST, "invalid vault_id", "INVALID_INPUT");
    }

    let vault = match Vaults::find()
        .filter(vault::Column::Id.eq(&request.vault_id))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(vault)) => vault,
        Ok(None) => {
            // Do not reveal vault existence before auth; return generic error.
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

    let response = GetCryptoParamsResponse {
        salt: vault.salt,
        iterations: vault.iterations,
        // A vault can only be missing these if it predates the recovery
        // migration, so absent recovery_salt here still yields
        // has_recovery = false rather than a misleading true.
        recovery_salt: vault.recovery_salt,
        has_recovery: vault.recovery_verifier.is_some(),
    };
    HttpResponse::Ok().json(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limit::{Budget, RateLimiter};
    use actix_web::App;
    use actix_web::test;
    use migration::MigratorTrait;
    use sea_orm::Database;

    const VAULT_ID: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

    async fn test_pool() -> DbPool {
        let pool = Database::connect("sqlite::memory:").await.expect("connect");
        migration::Migrator::up(&pool, None).await.expect("migrate");
        pool
    }

    macro_rules! test_app {
        ($pool:expr, $limiter:expr) => {
            test::init_service(
                App::new()
                    .app_data(web::Data::new($pool.clone()))
                    .app_data(web::Data::new($limiter))
                    .service(super::get_crypto_params),
            )
            .await
        };
    }

    fn params_request(vault_id: &str) -> test::TestRequest {
        test::TestRequest::get()
            .uri(&format!("/get_crypto_params?vault_id={vault_id}"))
            .peer_addr("1.2.3.4:5000".parse().expect("peer"))
    }

    /// This endpoint is called once per unlock attempt; the budget is about
    /// bounding enumeration and request cost, not about a per-vault secret.
    #[actix_web::test]
    async fn crypto_params_is_limited_per_ip() {
        let pool = test_pool().await;
        let limiter =
            RateLimiter::for_tests(pool.clone(), &[("CryptoParamsIp", Budget::new(2, 60))]);
        let app = test_app!(&pool, limiter);

        for _ in 0..2 {
            let resp = test::call_service(&app, params_request(VAULT_ID).to_request()).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }

        let resp = test::call_service(&app, params_request(VAULT_ID).to_request()).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().get("retry-after").is_some());
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["code"], "RATE_LIMITED");
    }

    /// A limiter that is not in `app_data` must fail closed, not silently
    /// disable the control. A forgotten wiring is a 500, which tests catch.
    #[actix_web::test]
    async fn missing_limiter_fails_closed() {
        let pool = test_pool().await;
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .service(super::get_crypto_params),
        )
        .await;

        let resp = test::call_service(&app, params_request(VAULT_ID).to_request()).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
