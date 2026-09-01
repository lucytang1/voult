use actix_session::Session;
use actix_web::{HttpResponse, get, http::StatusCode, post, web};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::db::DbPool;
use crate::entity::vault::{self, Entity as VaultEntity};
use crate::id_codec::uuid_to_db;
use crate::session_auth::session_vault_id;

#[derive(Deserialize)]
pub struct CreateVaultRequest {
    pub vault_id: Option<String>, pub vault: String, pub vaultiv: String, pub salt: String, pub iterations: i32,
    #[serde(default)] pub crypto_version: Option<i32>,
    #[serde(default)] pub vault_key_wrap: Option<String>,
    #[serde(default)] pub vault_key_wrap_iv: Option<String>,
    #[serde(default)] pub vault_verifier: Option<String>,
}
#[derive(Serialize)] pub struct CreateVaultResponse { pub vault_id: Uuid, pub vault: String, pub vaultiv: String, pub salt: String, pub iterations: i32, pub version: i32, pub crypto_version: i32 }
fn err(s: StatusCode, m: &str, c: &str) -> HttpResponse { HttpResponse::build(s).json(serde_json::json!({"error_msg": m, "code": c})) }

#[post("/vaults")]
pub async fn create_vault(pool: web::Data<DbPool>, session: Session, payload: web::Json<CreateVaultRequest>) -> HttpResponse {
    let vault_id_sess = match session_vault_id(&session) { Ok(Some(id)) => id, _ => return err(StatusCode::UNAUTHORIZED, "session required", "SESSION_REQUIRED") };
    // vault already exists for this session -> conflict
    if VaultEntity::find().filter(vault::Column::Id.eq(&vault_id_sess)).one(pool.get_ref()).await.map(|o| o.is_some()).unwrap_or(false) {
        return err(StatusCode::CONFLICT, "vault already exists", "VAULT_EXISTS");
    }
    let req = payload.into_inner();
    if req.vault.trim().is_empty() || req.salt.trim().is_empty() || req.vaultiv.trim().is_empty() { return err(StatusCode::BAD_REQUEST, "vault, salt, vaultiv required", "INVALID_INPUT"); }
    let vault_uuid = match &req.vault_id {
        Some(raw) => match Uuid::parse_str(raw) {
            Ok(id) if id.to_string() == vault_id_sess => id,
            Ok(_) => return err(StatusCode::FORBIDDEN, "vault_id does not match session", "VAULT_MISMATCH"),
            Err(_) => return err(StatusCode::BAD_REQUEST, "invalid vault_id", "INVALID_INPUT"),
        },
        None => match Uuid::parse_str(&vault_id_sess) {
            Ok(id) => id,
            Err(_) => return err(StatusCode::UNAUTHORIZED, "invalid session", "SESSION_REQUIRED"),
        },
    };
    let cv = req.crypto_version.unwrap_or(2);
    let am = vault::ActiveModel { id: Set(uuid_to_db(vault_uuid)), vault: Set(req.vault), salt: Set(req.salt), iterations: Set(req.iterations), vaultiv: Set(req.vaultiv), vault_verifier: Set(req.vault_verifier.unwrap_or_default()), version: Set(1), crypto_version: Set(cv), vault_key_wrap: Set(req.vault_key_wrap), vault_key_wrap_iv: Set(req.vault_key_wrap_iv), ..Default::default() };
    let inserted = match am.insert(pool.get_ref()).await { Ok(v) => v, Err(e) => { log::error!("{:?}", e); return err(StatusCode::INTERNAL_SERVER_ERROR, "failed to create vault", "DB_ERROR"); } };
    let vid = Uuid::parse_str(&inserted.id).unwrap_or(vault_uuid);
    HttpResponse::Created().json(CreateVaultResponse { vault_id: vid, vault: inserted.vault, vaultiv: inserted.vaultiv, salt: inserted.salt, iterations: inserted.iterations, version: inserted.version, crypto_version: inserted.crypto_version })
}

#[get("/vaults")]
pub async fn list_vaults(pool: web::Data<DbPool>, session: Session) -> HttpResponse {
    let vault_id = match session_vault_id(&session) { Ok(Some(id)) => id, _ => return err(StatusCode::UNAUTHORIZED, "session required", "SESSION_REQUIRED") };
    let v = match VaultEntity::find().filter(vault::Column::Id.eq(&vault_id)).one(pool.get_ref()).await { Ok(Some(v)) => v, Ok(None) => return err(StatusCode::NOT_FOUND, "vault not found", "VAULT_NOT_FOUND"), Err(e) => { log::error!("{:?}", e); return err(StatusCode::INTERNAL_SERVER_ERROR, "db error", "DB_ERROR"); } };
    HttpResponse::Ok().json(serde_json::json!({"vaults": [{"vault_id": v.id, "version": v.version, "crypto_version": v.crypto_version, "created_at": v.created_at.to_rfc3339()}]}))
}
