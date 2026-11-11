use actix_session::Session;
use actix_web::{HttpResponse, http::StatusCode, post, web};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::DbPool;
use crate::entity::vault::{self, Entity as VaultEntity};
use crate::id_codec::uuid_from_db;
use crate::kdf::KdfParams;
use crate::session_auth::establish_vault_session;

const LOG: logger::ServerLogger = logger::Logger::create(logger::ServerContext::Auth);

#[derive(Deserialize)]
pub struct AuthRequest {
    // Client-generated, stable vault identity embedded in the encrypted vault.
    pub vault_id: String,
    // Verifier derived from the master password client-side. Authentication
    // credential only — never the password or any key.
    pub vault_verifier: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub vault_id: Uuid,
    pub salt: String,
    /// Password KDF profile. Required for the client to derive the verifier
    /// before `/auth`; returned here too so a re-auth needs one round-trip.
    pub kdf: KdfParams,
    pub crypto_version: i32,
    /// CAS counter for the password credential. The client needs it to rotate
    /// the profile; it is post-auth only.
    pub credential_version: i32,
    // Encrypted envelope holding the vault key, wrapped by the master password.
    // Returned so the client can unwrap the vault key locally after unlock.
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

#[post("/auth")]
pub async fn auth(
    pool: web::Data<DbPool>,
    session: Session,
    payload: web::Json<AuthRequest>,
) -> HttpResponse {
    let request = payload.into_inner();
    if request.vault_id.trim().is_empty() || request.vault_verifier.trim().is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "vault_id and vault_verifier are required",
            "INVALID_INPUT",
        );
    }

    // A malformed vault ID is an invalid request, not an auth failure.
    let vault_uuid = match Uuid::parse_str(&request.vault_id) {
        Ok(u) => u,
        Err(_) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid vault_id", "INVALID_INPUT");
        }
    };

    let vault = match VaultEntity::find()
        .filter(vault::Column::Id.eq(vault_uuid.to_string()))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(vault)) => vault,
        Ok(None) => {
            // Do not distinguish "no such vault" from "bad verifier" to avoid
            // enumerating vault existence. Return the same generic error.
            return error_response(
                StatusCode::UNAUTHORIZED,
                "invalid vault_id or vault_verifier",
                "AUTH_FAILED",
            );
        }
        Err(e) => {
            LOG.error(
                format_args!("failed to fetch vault: {:?}", e),
                logger::Metadata::new(),
            );
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to fetch vault",
                "DB_ERROR",
            );
        }
    };

    if vault.vault_verifier != request.vault_verifier {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "invalid vault_id or vault_verifier",
            "AUTH_FAILED",
        );
    }

    // Rotate/purge any existing session before establishing the authenticated
    // one, then store only the authenticated vault ID in the session cookie.
    if let Err(e) = establish_vault_session(&session, &vault.id) {
        LOG.error(
            format_args!("failed to establish session: {:?}", e),
            logger::Metadata::new(),
        );
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to establish session",
            "SESSION_ERROR",
        );
    }

    // A stored descriptor that does not parse is a server integrity bug; the
    // client cannot fix it and must not be told it sent a bad password.
    let kdf = match KdfParams::parse_stored(&vault.kdf) {
        Ok(kdf) => kdf,
        Err(_) => {
            LOG.error(
                format_args!("vault has an unparsable kdf column: {:?}", vault.id),
                logger::Metadata::new(),
            );
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid vault metadata",
                "DATA_INTEGRITY_ERROR",
            );
        }
    };

    let response = AuthResponse {
        vault_id: match uuid_from_db(&vault.id) {
            Ok(id) => id,
            Err(e) => {
                LOG.error(
                    format_args!("invalid UUID in vault.id: {:?}", e),
                    logger::Metadata::new(),
                );
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "invalid vault id in database",
                    "DATA_INTEGRITY_ERROR",
                );
            }
        },
        salt: vault.salt,
        kdf,
        crypto_version: vault.crypto_version,
        credential_version: vault.credential_version,
        vault_key_wrap: vault.vault_key_wrap,
        vault_key_wrap_iv: vault.vault_key_wrap_iv,
    };

    HttpResponse::Ok().json(response)
}
