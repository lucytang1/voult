use actix_web::{HttpResponse, http::StatusCode, post, web};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, Set};
use serde::{Deserialize, Serialize};

use crate::entity::user::{self, Entity as User};
use crate::entity::vault::{self, Entity as Vault};
use crate::id_codec::{uuid_from_db, uuid_to_db};

use crate::db::DbPool;

#[derive(Deserialize)]
struct UpdateVaultRequest {
    pub vault: String,
    pub vaultiv: String,
    pub version: u32,
    pub email: String,
    pub user_key: String,
}

#[derive(Serialize)]
pub struct UpdateVaultResponse {
    pub vault: String,
    pub vaultiv: String,
    pub iterations: u32,
    pub version: u32,
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
    payload: web::Json<UpdateVaultRequest>,
) -> HttpResponse {
    let request = payload.into_inner();
    //find the user by email and user key
    let user = match User::find()
        .filter(user::Column::Email.eq(&request.email))
        .filter(user::Column::UserKey.eq(&request.user_key))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => {
            return error_response(StatusCode::NOT_FOUND, "user not found", "USER_NOT_FOUND");
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

    // convert the vault_id from the database to a UUID
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

    let vault = match Vault::find()
        .filter(vault::Column::Id.eq(uuid_to_db(vault_id)))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(vault)) => vault,
        Ok(None) => {
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

    if vault.version != request.version as i32 {
        return error_response(
            StatusCode::CONFLICT,
            "vault version mismatch",
            "VERSION_CONFLICT",
        );
    }

    let current_version = vault.version;
    let mut vault_active = vault.into_active_model();
    vault_active.vault = Set(request.vault);
    vault_active.version = Set(current_version + 1);
    vault_active.vaultiv = Set(request.vaultiv);

    let updated_vault = match vault_active.update(pool.get_ref()).await {
        Ok(updated_vault) => updated_vault,
        Err(e) => {
            log::error!("failed to update vault: {:?}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to update vault",
                "DB_ERROR",
            );
        }
    };

    HttpResponse::Ok().json(UpdateVaultResponse {
        vault: updated_vault.vault,
        vaultiv: updated_vault.vaultiv,
        iterations: updated_vault.iterations as u32,
        version: updated_vault.version as u32,
    })
}
