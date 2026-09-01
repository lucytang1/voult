use actix_session::Session;
use actix_web::{HttpResponse, http::StatusCode, post, web};
use sea_orm::{ActiveModelTrait, Set, TransactionTrait};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::DbPool;
use crate::entity::vault::ActiveModel as VaultActiveModel;
use crate::id_codec::uuid_to_db;
use crate::session_auth::establish_vault_session;

#[derive(Deserialize)]
pub struct RegisterRequest {
    // Client-generated, stable vault identity embedded in the encrypted vault.
    pub vault_id: String,
    // Verifier derived from the master password client-side. Authentication
    // credential only — never the password or any key.
    pub vault_verifier: String,
    pub salt: String,
    pub iterations: i32,
    pub vaultiv: String,
    pub vault: String,
    #[serde(default)]
    pub crypto_version: Option<i32>,
    // Encrypted envelope holding the vault key, wrapped by the master password.
    #[serde(default)]
    pub vault_key_wrap: Option<String>,
    #[serde(default)]
    pub vault_key_wrap_iv: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub vault_id: Uuid,
    pub vault: String,
    pub iterations: i32,
    pub vaultiv: String,
    pub salt: String,
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

#[post("/register")]
pub async fn register(
    pool: web::Data<DbPool>,
    session: Session,
    payload: web::Json<RegisterRequest>,
) -> HttpResponse {
    let request = payload.into_inner();
    if request.vault_id.trim().is_empty()
        || request.vault_verifier.trim().is_empty()
        || request.salt.trim().is_empty()
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            "vault_id, vault_verifier and salt are required",
            "INVALID_INPUT",
        );
    }

    // The vault ID must be a well-formed UUID the client generated.
    let vault_uuid = match Uuid::parse_str(&request.vault_id) {
        Ok(u) => u,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid vault_id",
                "INVALID_INPUT",
            );
        }
    };

    let crypto_version = request.crypto_version.unwrap_or(1);

    let tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            log::error!("failed to create transaction: {:?}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to create vault",
                "DB_ERROR",
            );
        }
    };

    let new_vault = VaultActiveModel {
        id: Set(uuid_to_db(vault_uuid)),
        vault: Set(request.vault),
        salt: Set(request.salt),
        iterations: Set(request.iterations),
        vaultiv: Set(request.vaultiv),
        vault_verifier: Set(request.vault_verifier),
        version: Set(1),
        crypto_version: Set(crypto_version),
        vault_key_wrap: Set(request.vault_key_wrap),
        vault_key_wrap_iv: Set(request.vault_key_wrap_iv),
        ..Default::default()
    };

    let inserted_vault = match new_vault.insert(&tx).await {
        Ok(inserted) => inserted,
        Err(e) => {
            // A duplicate vault_id (unique primary key) is a client conflict,
            // not a server error. SeaORM surfaces sqlite UNIQUE as Query or Exec
            // depending on driver version – check both and fall back to string.
            let err_str = format!("{e:?}");
            let is_unique = err_str.contains("UNIQUE constraint failed")
                || err_str.contains("unique constraint")
                || err_str.contains("1555");
            if matches!(e, sea_orm::DbErr::Exec(_) | sea_orm::DbErr::Query(_)) && is_unique {
                log::warn!("vault registration conflict: {:?}", e);
                let _ = tx.rollback().await;
                return error_response(
                    StatusCode::CONFLICT,
                    "vault already exists",
                    "VAULT_EXISTS",
                );
            }
            // Also treat any Exec/Query with unique substring as conflict even if above missed
            if is_unique {
                log::warn!("vault registration conflict (unique): {:?}", e);
                let _ = tx.rollback().await;
                return error_response(
                    StatusCode::CONFLICT,
                    "vault already exists",
                    "VAULT_EXISTS",
                );
            }
            log::error!("failed to create vault: {:?}", e);
            let _ = tx.rollback().await;
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to create vault",
                "DB_ERROR",
            );
        }
    };

    if let Err(e) = tx.commit().await {
        log::error!("failed to commit transaction: {:?}", e);
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to create vault",
            "DB_ERROR",
        );
    }

    // Establish a vault-scoped session for the newly created vault.
    if let Err(e) = establish_vault_session(&session, &inserted_vault.id) {
        log::error!("failed to establish session: {:?}", e);
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to establish session",
            "SESSION_ERROR",
        );
    }

    let vault_id = match Uuid::parse_str(&inserted_vault.id) {
        Ok(id) => id,
        Err(e) => {
            log::error!("invalid UUID in inserted vault.id: {:?}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid vault id in database",
                "DATA_INTEGRITY_ERROR",
            );
        }
    };

    let response = RegisterResponse {
        vault_id,
        vault: inserted_vault.vault,
        salt: inserted_vault.salt,
        iterations: inserted_vault.iterations,
        vaultiv: inserted_vault.vaultiv,
        vault_key_wrap: inserted_vault.vault_key_wrap,
        vault_key_wrap_iv: inserted_vault.vault_key_wrap_iv,
    };

    HttpResponse::Created().json(response)
}
