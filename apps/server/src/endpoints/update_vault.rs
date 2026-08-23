use actix_session::Session;
use actix_web::{HttpResponse, http::StatusCode, post, web};
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, ExprTrait, QueryFilter};
use serde::{Deserialize, Serialize};

use crate::entity::user::{self, Entity as User};
use crate::entity::vault::{self, Entity as Vault};
use crate::id_codec::{uuid_from_db, uuid_to_db};
use crate::session_auth::session_user_id;

use crate::db::DbPool;

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
    session: Session,
    payload: web::Json<UpdateVaultRequest>,
) -> HttpResponse {
    let user_id = match session_user_id(&session) {
        Ok(Some(id)) => id,
        Ok(None) | Err(_) => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "session required",
                "SESSION_REQUIRED",
            );
        }
    };

    let request = payload.into_inner();

    let user = match User::find()
        .filter(user::Column::Id.eq(&user_id))
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
        crypto_version: new_crypto_version,
        vault_key_wrap: new_vault_key_wrap,
        vault_key_wrap_iv: new_vault_key_wrap_iv,
    })
}
