use actix_session::Session;
use actix_web::{HttpResponse, get, http::StatusCode, web};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Serialize;

use crate::entity::vault::{self, Entity as Vaults};
use crate::session_auth::session_vault_id;

use crate::db::DbPool;

#[derive(Serialize)]
pub struct GetVaultResponse {
    pub vault: Vault,
}

#[derive(Serialize)]
pub struct Vault {
    pub vault: String,
    pub vaultiv: String,
    pub iterations: i32,
    pub version: i32,
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

#[get("/get_vault")]
pub async fn get_vault(pool: web::Data<DbPool>, session: Session) -> HttpResponse {
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

    let vault = match Vaults::find()
        .filter(vault::Column::Id.eq(&vault_id))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(vault)) => vault,
        Ok(None) => {
            // A session referencing a missing vault is treated as no auth.
            return error_response(StatusCode::UNAUTHORIZED, "session required", "SESSION_REQUIRED");
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

    let response = GetVaultResponse {
        vault: Vault {
            vault: vault.vault,
            vaultiv: vault.vaultiv,
            iterations: vault.iterations,
            version: vault.version,
            crypto_version: vault.crypto_version,
            vault_key_wrap: vault.vault_key_wrap,
            vault_key_wrap_iv: vault.vault_key_wrap_iv,
        },
    };
    HttpResponse::Ok().json(response)
}
