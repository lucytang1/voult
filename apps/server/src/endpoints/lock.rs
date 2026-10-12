use actix_session::Session;
use actix_web::{HttpResponse, http::StatusCode, post, web};
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, ExprTrait, QueryFilter};
use serde::Serialize;

use crate::db::DbPool;
use crate::entity::vault::{self, Entity as Vault};
use crate::error::{error_response, session_required};
use crate::session_auth::session_vault_id;

#[derive(Serialize)]
pub struct LockResponse {
    pub lock_epoch: i32,
}

/// Global lock signal for web ↔ extension consistency. Requires a valid
/// session, then atomically bumps `vault.lock_epoch` for the session's vault.
/// Peers observe the bump via `GET /session` (check-on-use + slow fallback,
/// never a dedicated fast poller) and wipe local keys. The counter is
/// monotonic and non-sensitive — never key material or plaintext. Unlocking
/// never decrements it: unlock is per-device (each side re-unwraps locally).
#[post("/lock")]
pub async fn lock(pool: web::Data<DbPool>, session: Session) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        Ok(None) | Err(_) => return session_required(),
    };

    // Confirm the vault still exists; a session referencing a deleted vault
    // fails closed as unauthenticated.
    let current = match Vault::find()
        .filter(vault::Column::Id.eq(&vault_id))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(v)) => v,
        Ok(None) => return session_required(),
        Err(e) => {
            log::error!("failed to fetch vault for lock: {:?}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to fetch vault",
                "DB_ERROR",
            );
        }
    };

    // Atomic bump so concurrent web + extension locks both register.
    let bump = Vault::update_many()
        .col_expr(
            vault::Column::LockEpoch,
            Expr::col(vault::Column::LockEpoch).add(1),
        )
        .filter(vault::Column::Id.eq(&vault_id))
        .exec(pool.get_ref())
        .await;
    if let Err(e) = bump {
        log::error!("failed to bump lock_epoch: {:?}", e);
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to record lock",
            "DB_ERROR",
        );
    }

    HttpResponse::Ok().json(LockResponse {
        lock_epoch: current.lock_epoch.saturating_add(1),
    })
}
