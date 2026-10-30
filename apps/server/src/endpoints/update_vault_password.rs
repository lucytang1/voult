use crate::credentials;
use crate::db::DbPool;
use crate::entity::vault::{self, Entity as VaultEntity};
use crate::session_auth::session_vault_id;
use actix_session::Session;
use actix_web::{HttpResponse, post, web};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;

const LOG: logger::ServerLogger = logger::Logger::create(logger::ServerContext::Auth);

#[derive(Deserialize)]
pub struct UpdatePasswordRequest {
    pub new_vault_verifier: String,
    pub new_salt: Option<String>,
    pub new_iterations: Option<i32>,
}

#[post("/vault/password")]
pub async fn update_vault_password(
    pool: web::Data<DbPool>,
    session: Session,
    body: web::Json<UpdatePasswordRequest>,
) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized().json(
                serde_json::json!({"error_msg":"session required","code":"SESSION_REQUIRED"}),
            );
        }
    };
    // Hash the new credential before touching the row: only the salt+hash pair
    // is ever persisted.
    //
    // This endpoint still writes the credential and KDF metadata without a
    // client-side rewrap of the vault-key envelope, so a caller can strand a
    // vault (see SECURITY_AND_FEATURE_ROADMAP.md, "Complete password-change
    // protocol atomically"). That is deliberately not fixed here — this change
    // only guarantees the credential itself is never stored in plaintext.
    let Some(credential) = credentials::new_credential(&body.new_vault_verifier) else {
        return HttpResponse::BadRequest().json(
            serde_json::json!({"error_msg":"new_vault_verifier required","code":"INVALID_INPUT"}),
        );
    };
    let vault = match VaultEntity::find()
        .filter(vault::Column::Id.eq(&vault_id))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({"error_msg":"vault not found","code":"VAULT_NOT_FOUND"}));
        }
        Err(e) => {
            LOG.error(format_args!("{:?}", e), logger::Metadata::new());
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error_msg":"db error","code":"DB_ERROR"}));
        }
    };
    let mut am: vault::ActiveModel = vault.into();
    am.verifier_salt = Set(credential.salt_b64);
    am.verifier_hash = Set(credential.hash_b64);
    if let Some(s) = &body.new_salt {
        am.salt = Set(s.clone());
    }
    if let Some(it) = body.new_iterations {
        am.iterations = Set(it);
    }
    match VaultEntity::update(am).exec(pool.get_ref()).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"updated": true})),
        Err(e) => {
            LOG.error(format_args!("{:?}", e), logger::Metadata::new());
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error_msg":"db error","code":"DB_ERROR"}))
        }
    }
}
