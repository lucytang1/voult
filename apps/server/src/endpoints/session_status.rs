use actix_session::Session;
use actix_web::{HttpResponse, get, web};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Serialize;

use crate::db::DbPool;
use crate::entity::vault::{self, Entity as VaultEntity};
use crate::error::{error_response, session_required};
use crate::id_codec::uuid_from_db;
use crate::session_auth::session_vault_id;

#[derive(Serialize)]
pub struct SessionResponse {
    pub authenticated: bool,
    pub vault_id: String,
    pub crypto_version: i32,
    // Global lock signal for web ↔ extension consistency (see POST /api/lock).
    // Clients persist the last epoch they saw and wipe local keys when the
    // server reports a newer one. Monotonic, non-sensitive.
    pub lock_epoch: i32,
}

/// Validates the session cookie and returns the authenticated vault and its
/// crypto version. Used by the client on reload to decide how to unlock
/// (device envelope vs. password).
#[get("/session")]
pub async fn get_session(pool: web::Data<DbPool>, session: Session) -> HttpResponse {
    let vault_id_raw = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        Ok(None) | Err(_) => return session_required(),
    };

    // A session may reference a vault that no longer exists (e.g. deleted DB).
    // Fail closed rather than trusting the cookie alone.
    let vault = match VaultEntity::find()
        .filter(vault::Column::Id.eq(&vault_id_raw))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(vault)) => vault,
        Ok(None) => return session_required(),
        Err(e) => {
            log::error!("failed to fetch vault: {:?}", e);
            return error_response(
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                "failed to fetch vault",
                "DB_ERROR",
            );
        }
    };

    // Double-check the stored vault ID is a well-formed UUID.
    let _ = match uuid_from_db(&vault.id) {
        Ok(id) => id,
        Err(e) => {
            log::error!("invalid UUID in vault.id: {:?}", e);
            return error_response(
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                "invalid vault id in database",
                "DATA_INTEGRITY_ERROR",
            );
        }
    };

    HttpResponse::Ok().json(SessionResponse {
        authenticated: true,
        vault_id: vault.id,
        crypto_version: vault.crypto_version,
        lock_epoch: vault.lock_epoch,
    })
}
