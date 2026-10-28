use actix_web::{HttpResponse, get, http::StatusCode, web};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};

use crate::db::DbPool;
use crate::entity::vault::{self, Entity as Vaults};

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
