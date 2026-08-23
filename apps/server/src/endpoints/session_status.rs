use actix_session::Session;
use actix_web::{HttpResponse, get, web};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Serialize;
use uuid::Uuid;

use crate::db::DbPool;
use crate::entity::user::{self, Entity as UserEntity};
use crate::entity::vault::{self, Entity as VaultEntity};
use crate::error::{error_response, session_required};
use crate::id_codec::uuid_from_db;
use crate::session_auth::session_user_id;

#[derive(Serialize)]
pub struct SessionResponse {
    pub authenticated: bool,
    pub user: UserResponse,
    pub crypto_version: i32,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
}

/// Validates the session cookie and returns the authenticated user and the
/// crypto version of their vault. Used by the client on reload to decide how
/// to unlock (device envelope vs. password).
#[get("/session")]
pub async fn get_session(pool: web::Data<DbPool>, session: Session) -> HttpResponse {
    let user_id = match session_user_id(&session) {
        Ok(Some(id)) => id,
        Ok(None) | Err(_) => return session_required(),
    };

    let user = match UserEntity::find()
        .filter(user::Column::Id.eq(&user_id))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return session_required(),
        Err(e) => {
            log::error!("failed to fetch user: {:?}", e);
            return error_response(
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                "failed to fetch user",
                "DB_ERROR",
            );
        }
    };

    let id = match uuid_from_db(&user.id) {
        Ok(id) => id,
        Err(e) => {
            log::error!("invalid UUID in user.id: {:?}", e);
            return error_response(
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                "invalid user id in database",
                "DATA_INTEGRITY_ERROR",
            );
        }
    };

    let crypto_version = match VaultEntity::find()
        .filter(vault::Column::Id.eq(&user.vault_id))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(vault)) => vault.crypto_version,
        Ok(None) => {
            return error_response(
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                "user has no vault",
                "DATA_INTEGRITY_ERROR",
            );
        }
        Err(e) => {
            log::error!("failed to fetch vault: {:?}", e);
            return error_response(
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                "failed to fetch vault",
                "DB_ERROR",
            );
        }
    };

    HttpResponse::Ok().json(SessionResponse {
        authenticated: true,
        user: UserResponse {
            id,
            email: user.email,
        },
        crypto_version,
    })
}
