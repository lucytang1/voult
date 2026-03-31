use actix_web::{http::StatusCode, post, web, HttpResponse};
use serde::{Deserialize, Serialize};
use sea_orm::{ActiveModelTrait, Set, TransactionTrait};
use uuid::Uuid;

use crate::db::DbPool;
use crate::entity::user::ActiveModel as UserActiveModel;
use crate::entity::vault::ActiveModel as VaultActiveModel;
use crate::id_codec::uuid_to_db;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub user_key: String,
    pub salt: String,
    pub iterations: i32,
    pub vaultiv: String,
    pub vault: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub user: UserResponse,
    pub vault: String,
    pub iterations: i32,
    pub vaultiv: String,
    pub salt: String,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
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

#[post("/register")]
pub async fn register(
    pool: web::Data<DbPool>,
    payload: web::Json<RegisterRequest>,
) -> HttpResponse {
    let request = payload.into_inner();
    if request.email.trim().is_empty()
        || request.user_key.trim().is_empty()
        || request.salt.trim().is_empty()
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            "email and user_key and salt are required",
            "INVALID_INPUT",
        );
    }

    let RegisterRequest {
        email,
        user_key,
        salt,
        iterations,
        vaultiv,
        vault,
    } = request;
    let user_id = Uuid::new_v4();
    let vault_id = Uuid::new_v4();

    let tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            log::error!("failed to create transaction: {:?}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to create user",
                "DB_ERROR",
            );
        }
    };

    let new_vault = VaultActiveModel {
        id: Set(uuid_to_db(vault_id)),
        vault: Set(vault),
        salt: Set(salt),
        iterations: Set(iterations),
        vaultiv: Set(vaultiv),
        version: Set(1),
        ..Default::default()
    };

    let inserted_vault = match new_vault.insert(&tx).await {
        Ok(inserted) => inserted,
        Err(e) => {
            log::error!("failed to create vault: {:?}", e);
            let _ = tx.rollback().await;
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to create user",
                "DB_ERROR",
            );
        }
    };

    let new_user = UserActiveModel {
        id: Set(uuid_to_db(user_id)),
        email: Set(email),
        user_key: Set(user_key),
        vault_id: Set(inserted_vault.id.clone()),
        ..Default::default()
    };

    let inserted_user = match new_user.insert(&tx).await {
        Ok(inserted) => inserted,
        Err(e) => {
            log::error!("failed to create user: {:?}", e);
            let _ = tx.rollback().await;
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to create user",
                "DB_ERROR",
            );
        }
    };

    if let Err(e) = tx.commit().await {
        log::error!("failed to commit transaction: {:?}", e);
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to create user",
            "DB_ERROR",
        );
    }

    let response = RegisterResponse {
        user: UserResponse {
            id: user_id,
            email: inserted_user.email,
        },
        vault: inserted_vault.vault,
        salt: inserted_vault.salt,
        iterations: inserted_vault.iterations,
        vaultiv: inserted_vault.vaultiv,
    };

    HttpResponse::Created().json(response)
}
