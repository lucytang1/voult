use actix_session::Session;
use actix_web::{HttpResponse, http::StatusCode, post, web};
use sea_orm::{ActiveModelTrait, Set, TransactionTrait};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::DbPool;
use crate::entity::user::ActiveModel as UserActiveModel;
use crate::entity::vault::ActiveModel as VaultActiveModel;
use crate::id_codec::uuid_to_db;
use crate::session_auth::establish_session;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub user_key: String,
    pub salt: String,
    pub iterations: i32,
    pub vaultiv: String,
    pub vault: String,
    #[serde(default)]
    pub crypto_version: Option<i32>,
    #[serde(default)]
    pub vault_key_wrap: Option<String>,
    #[serde(default)]
    pub vault_key_wrap_iv: Option<String>,
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
    session: Session,
    payload: web::Json<RegisterRequest>,
) -> HttpResponse {
    //request payload check
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
    //request extraction
    let RegisterRequest {
        email,
        user_key,
        salt,
        iterations,
        vaultiv,
        vault,
        crypto_version,
        vault_key_wrap,
        vault_key_wrap_iv,
    } = request;
    let user_id = Uuid::new_v4();
    let vault_id = Uuid::new_v4();
    let crypto_version = crypto_version.unwrap_or(1);

    //start transaction block
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
        crypto_version: Set(crypto_version),
        vault_key_wrap: Set(vault_key_wrap),
        vault_key_wrap_iv: Set(vault_key_wrap_iv),
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

    if let Err(e) = establish_session(&session, &inserted_user.id) {
        log::error!("failed to establish session: {:?}", e);
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to establish session",
            "SESSION_ERROR",
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
