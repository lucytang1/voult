use actix_web::{HttpResponse, http::StatusCode, post, web};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::DbPool;
use crate::entity::user::{self, Entity as UserEntity};
use crate::id_codec::uuid_from_db;

#[derive(Deserialize)]
pub struct AuthRequest {
    pub email: String,
    pub user_key: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub user: UserResponse,
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
pub async fn auth(pool: web::Data<DbPool>, payload: web::Json<AuthRequest>) -> HttpResponse {
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

    let response = AuthResponse {
        user: UserResponse {
            id: match uuid_from_db(&user.id) {
                Ok(id) => id,
                Err(e) => {
                    log::error!("invalid UUID in user.id: {:?}", e);
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "invalid user id in database",
                        "DATA_INTEGRITY_ERROR",
                    );
                }
            },
            email: user.email,
        },
    };

    HttpResponse::Ok().json(response)
}
