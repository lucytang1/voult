use actix_web::{HttpResponse, http::StatusCode, post, web};
use sea_orm::{ColumnTrait, EntityTrait, ExprTrait, QueryFilter};
use sea_orm::sea_query::Expr;
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

    // Atomic compare-and-swap: only write when the vault is still at the
    // version the client pushed against. rows_affected == 0 means a
    // concurrent push from another device already won — return 409.
    let new_vault = request.vault;
    let new_vaultiv = request.vaultiv;

    let update_result = Vault::update_many()
        .col_expr(vault::Column::Vault, Expr::value(new_vault.clone()))
        .col_expr(vault::Column::Vaultiv, Expr::value(new_vaultiv.clone()))
        .col_expr(
            vault::Column::Version,
            Expr::col(vault::Column::Version).add(1),
        )
        .filter(vault::Column::Id.eq(uuid_to_db(vault_id)))
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
            log::error!("failed to update vault: {:?}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to update vault",
                "DB_ERROR",
            );
        }
    }

    // The CAS guarantees the stored version was request.version, so it is now +1.
    HttpResponse::Ok().json(UpdateVaultResponse {
        vault: new_vault,
        vaultiv: new_vaultiv,
        iterations: vault.iterations as u32,
        version: request.version + 1,
    })
}
