use actix_web::{HttpResponse, get, http::StatusCode, web};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};

use crate::db::DbPool;
use crate::entity::vault::{self, Entity as Vaults};

#[derive(Deserialize)]
pub struct GetCryptoParamsRequest {
    // Vault identity the client wants KDF params for, before unlocking.
    pub vault_id: String,
}

#[derive(Serialize)]
pub struct GetCryptoParamsResponse {
    pub salt: String,
    pub iterations: i32,
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
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid vault_id",
            "INVALID_INPUT",
        );
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
            log::error!("failed to fetch vault: {:?}", e);
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
    };
    HttpResponse::Ok().json(response)
}
