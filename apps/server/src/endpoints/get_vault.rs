use serde::{Deserialize, Serialize};
use actix_web::{get, http::StatusCode, web, HttpResponse};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use crate::entity::user::{self, Entity as UserEntity};
use crate::entity::vault::{self, Entity as Vaults};
use crate::id_codec::{uuid_from_db, uuid_to_db};

use crate::db::DbPool;

#[derive(Deserialize)]
pub struct GetVaultRequest {
    pub email: String,
    pub user_key: String,
}

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
pub async fn get_vault(pool: web::Data<DbPool>, payload: web::Query<GetVaultRequest>) -> HttpResponse {
    let request = payload.into_inner();
    if request.email.trim().is_empty() || request.user_key.trim().is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "email and user_key are required",
            "INVALID_INPUT",
        );
    }

    let user = match UserEntity::find()
        .filter(user::Column::Email.eq(&request.email))
        .filter(user::Column::UserKey.eq(&request.user_key))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "user not found",
                "USER_NOT_FOUND",
            )
        }
        Err(e) => {
            log::error!("failed to fetch user: {:?}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to fetch user",
                "DB_ERROR",
            );
        }
    };

    let vault_id = match uuid_from_db(&user.vault_id) {
        Ok(id) => id,
        Err(e) => {
            log::error!("invalid UUID in user.vault_id: {:?}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid vault id in database",
                "DATA_INTEGRITY_ERROR",
            );
        }
    };

    let vault = match Vaults::find()
        .filter(vault::Column::Id.eq(uuid_to_db(vault_id)))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(vault)) => vault,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "vault not found",
                "VAULT_NOT_FOUND",
            )
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
        },
    };
    HttpResponse::Ok().json(response)
}
