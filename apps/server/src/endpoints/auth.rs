use actix_session::Session;
use actix_web::{HttpResponse, http::StatusCode, post, web};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::DbPool;
use crate::entity::user::{self, Entity as UserEntity};
use crate::entity::vault::{self, Entity as VaultEntity};
use crate::id_codec::uuid_from_db;
use crate::session_auth::establish_session;

#[derive(Deserialize)]
pub struct AuthRequest {
    pub email: String,
    pub user_key: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub user: UserResponse,
    pub salt: String,
    pub iterations: i32,
    pub crypto_version: i32,
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

#[post("/auth")]
pub async fn auth(
    pool: web::Data<DbPool>,
    session: Session,
    payload: web::Json<AuthRequest>,
) -> HttpResponse {
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
                StatusCode::UNAUTHORIZED,
                "invalid email or user_key",
                "AUTH_FAILED",
            );
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

    let user_id = match uuid_from_db(&user.id) {
        Ok(id) => id,
        Err(e) => {
            log::error!("invalid UUID in user.id: {:?}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid user id in database",
                "DATA_INTEGRITY_ERROR",
            );
        }
    };

    let (salt, iterations, crypto_version) = match VaultEntity::find()
        .filter(vault::Column::Id.eq(&user.vault_id))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(vault)) => (vault.salt, vault.iterations, vault.crypto_version),
        Ok(None) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "user has no vault",
                "DATA_INTEGRITY_ERROR",
            );
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

    // Rotate/purge any existing session before establishing the authenticated
    // one, then store only the authenticated user ID in the session cookie.
    if let Err(e) = establish_session(&session, &user.id) {
        log::error!("failed to establish session: {:?}", e);
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to establish session",
            "SESSION_ERROR",
        );
    }

    let response = AuthResponse {
        user: UserResponse {
            id: user_id,
            email: user.email,
        },
        salt,
        iterations,
        crypto_version,
    };

    HttpResponse::Ok().json(response)
}
