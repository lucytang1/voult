use actix_session::Session;
use actix_web::{HttpResponse, get, http::StatusCode, post, web};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};

use crate::db::DbPool;
use crate::entity::cloud_binding::{self, Entity as CloudBindingEntity};
use crate::entity::google_token::{self, Entity as GoogleTokenEntity};
use crate::google::config::GoogleConfig;
use crate::google::error::{ProviderErrorKind, provider_error_response};
use crate::session_auth::session_vault_id;

// --- OAuth start / status / disconnect ---

#[derive(Serialize)]
struct AuthStartResponse {
    auth_url: String,
    state: String,
}

#[derive(Deserialize)]
pub struct AuthStartQuery {}

#[get("/google/auth/start")]
pub async fn google_auth_start(
    pool: web::Data<DbPool>,
    session: Session,
    _query: web::Query<AuthStartQuery>,
) -> HttpResponse {
    let cfg = match GoogleConfig::from_env() {
        Some(c) => c,
        None => {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error_msg":"Google OAuth not configured","code":"GOOGLE_NOT_CONFIGURED"}));
        }
    };

    // A session-bound flow stores the vault ID in OAuth state. Without a
    // session, only the short-lived pending import state is created.
    let vault_id_opt = match session_vault_id(&session) {
        Ok(Some(id)) => Some(id),
        _ => None,
    };

    let state = if let Some(ref vault_id) = vault_id_opt {
        match crate::google::oauth::generate_and_store_state(pool.get_ref(), vault_id).await {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to generate OAuth state: {}", e);
                return HttpResponse::InternalServerError().json(
                    serde_json::json!({"error_msg":"failed to create state","code":"DB_ERROR"}),
                );
            }
        }
    } else {
        // Pending flow – no local vault exists yet. The provider identity is
        // retained only as metadata after the OAuth exchange.
        match crate::google::oauth::generate_and_store_state_with_email(pool.get_ref(), None, None)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to generate pending OAuth state: {}", e);
                return HttpResponse::InternalServerError().json(
                    serde_json::json!({"error_msg":"failed to create state","code":"DB_ERROR"}),
                );
            }
        }
    };

    let auth_url = crate::google::oauth::build_auth_url(&cfg, &state);
    if let Some(ref vault_id) = vault_id_opt {
        let _ = crate::google::oauth::store_state_in_session(&session, &state);
        log::info!(
            "Generated Google OAuth state for vault {}",
            &vault_id[..8.min(vault_id.len())]
        );
    } else {
        log::info!("Generated pending Google OAuth state");
    }
    HttpResponse::Ok().json(AuthStartResponse { auth_url, state })
}

#[derive(Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

#[get("/google/oauth/callback")]
pub async fn google_oauth_callback(
    pool: web::Data<DbPool>,
    session: Session,
    query: web::Query<OAuthCallbackQuery>,
) -> HttpResponse {
    google_oauth_callback_inner(pool, session, query).await
}

#[get("/cloud/google/oauth/callback")]
pub async fn google_oauth_callback_legacy(
    pool: web::Data<DbPool>,
    session: Session,
    query: web::Query<OAuthCallbackQuery>,
) -> HttpResponse {
    google_oauth_callback_inner(pool, session, query).await
}

async fn google_oauth_callback_inner(
    pool: web::Data<DbPool>,
    session: Session,
    query: web::Query<OAuthCallbackQuery>,
) -> HttpResponse {
    let cfg = match GoogleConfig::from_env() {
        Some(c) => c,
        None => {
            return HttpResponse::InternalServerError().body("Google not configured");
        }
    };

    if let Some(err) = &query.error {
        log::warn!("Google OAuth error: {}", err);
        return HttpResponse::Found()
            .insert_header((
                "Location",
                format!(
                    "{}?google_error={}",
                    cfg.post_auth_redirect,
                    urlencoding::encode(err)
                ),
            ))
            .finish();
    }

    let code = match &query.code {
        Some(c) => c.clone(),
        None => {
            return HttpResponse::BadRequest().body("missing code");
        }
    };
    let state = match &query.state {
        Some(s) => s.clone(),
        None => return HttpResponse::BadRequest().body("missing state"),
    };

    // Try to get vault_id from session, but allow pending flow without session
    let vault_id_opt = match session_vault_id(&session) {
        Ok(Some(id)) => Some(id),
        _ => None,
    };

    if let Some(vault_id) = vault_id_opt {
        // Normal flow: state is tied to vault_id
        if let Err(e) =
            crate::google::oauth::validate_state(pool.get_ref(), &state, &vault_id).await
        {
            // Maybe it's a pending state without vault_id – try pending validation
            if let Ok(rec) =
                crate::google::oauth::validate_state_pending(pool.get_ref(), &state).await
            {
                // This is a pending state that was created without vault_id (email flow) but now we have a session
                // Treat as pending – exchange and store as pending, then link to this user after
                // For now, handle as pending exchange
                match crate::google::oauth::exchange_code_and_store_pending(
                    pool.get_ref(),
                    &state,
                    &code,
                    &cfg,
                )
                .await
                {
                    Ok((_acct_id, email)) => {
                        // Link pending to this user
                        let _ = crate::google::oauth::link_pending_to_user(
                            pool.get_ref(),
                            &state,
                            &vault_id,
                        )
                        .await;
                        log::info!(
                            "Google OAuth success (pending linked) for user {} email {}",
                            &vault_id[..8.min(vault_id.len())],
                            email
                        );
                        return HttpResponse::Found()
                            .insert_header((
                                "Location",
                                format!(
                                    "{}?google_connected=1&email={}",
                                    cfg.post_auth_redirect,
                                    urlencoding::encode(&email)
                                ),
                            ))
                            .finish();
                    }
                    Err(e) => {
                        log::error!("Pending Google OAuth exchange failed: {}", e);
                        return HttpResponse::Found()
                            .insert_header((
                                "Location",
                                format!(
                                    "{}?google_error=exchange_failed&google_error_detail={}",
                                    cfg.post_auth_redirect,
                                    urlencoding::encode(&e)
                                ),
                            ))
                            .finish();
                    }
                }
            }
            log::warn!("OAuth state validation failed: {}", e);
            return HttpResponse::Found()
                .insert_header((
                    "Location",
                    format!("{}?google_error=invalid_state", cfg.post_auth_redirect),
                ))
                .finish();
        }
        // Normal exchange with vault_id
        match crate::google::oauth::exchange_code_and_store(pool.get_ref(), &vault_id, &code, &cfg)
            .await
        {
            Ok((_acct_id, email)) => {
                log::info!(
                    "Google OAuth success for user {} email {}",
                    &vault_id[..8.min(vault_id.len())],
                    email
                );
                HttpResponse::Found()
                    .insert_header((
                        "Location",
                        format!(
                            "{}?google_connected=1&email={}",
                            cfg.post_auth_redirect,
                            urlencoding::encode(&email)
                        ),
                    ))
                    .finish()
            }
            Err(e) => {
                log::error!("Google OAuth exchange failed: {}", e);
                HttpResponse::Found()
                    .insert_header((
                        "Location",
                        format!(
                            "{}?google_error=exchange_failed&google_error_detail={}",
                            cfg.post_auth_redirect,
                            urlencoding::encode(&e)
                        ),
                    ))
                    .finish()
            }
        }
    } else {
        // No session – pending flow (unified entry for new user)
        match crate::google::oauth::validate_state_pending(pool.get_ref(), &state).await {
            Ok(pending_state) => {
                match crate::google::oauth::exchange_code_and_store_pending(
                    pool.get_ref(),
                    &state,
                    &code,
                    &cfg,
                )
                .await
                {
                    Ok((_acct_id, email)) => {
                        // Keep pending state for later linking – redirect with pending_state
                        log::info!("Google OAuth success (pending) email {}", email);
                        HttpResponse::Found()
                            .insert_header((
                                "Location",
                                format!(
                                    "{}?google_pending_state={}&email={}",
                                    cfg.post_auth_redirect,
                                    urlencoding::encode(&state),
                                    urlencoding::encode(&email)
                                ),
                            ))
                            .finish()
                    }
                    Err(e) => {
                        log::error!("Pending Google OAuth exchange failed: {}", e);
                        let email = pending_state.vault_id.as_deref().unwrap_or("");
                        HttpResponse::Found()
                            .insert_header((
                                "Location",
                                format!(
                                    "{}?google_error=exchange_failed&google_error_detail={}&email={}",
                                    cfg.post_auth_redirect,
                                    urlencoding::encode(&e),
                                    urlencoding::encode(email)
                                ),
                            ))
                            .finish()
                    }
                }
            }
            Err(e) => {
                log::warn!("Pending OAuth state validation failed: {}", e);
                HttpResponse::Found()
                    .insert_header((
                        "Location",
                        format!("{}?google_error=invalid_state", cfg.post_auth_redirect),
                    ))
                    .finish()
            }
        }
    }
}

#[derive(Serialize)]
struct GoogleStatusResponse {
    connected: bool,
    email: Option<String>,
    provider_account_id: Option<String>,
    scope: Option<String>,
}

#[get("/google/status")]
pub async fn google_status(pool: web::Data<DbPool>, session: Session) -> HttpResponse {
    // The landing page checks Google availability before a local account/session
    // exists. That is a valid disconnected state, not an authentication error.
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Ok().json(GoogleStatusResponse {
                connected: false,
                email: None,
                provider_account_id: None,
                scope: None,
            });
        }
    };

    let token = match GoogleTokenEntity::find()
        .filter(google_token::Column::VaultId.eq(&vault_id))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(t)) => t,
        Ok(None) => {
            return HttpResponse::Ok().json(GoogleStatusResponse {
                connected: false,
                email: None,
                provider_account_id: None,
                scope: None,
            });
        }
        Err(e) => {
            log::error!("failed to fetch google token: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error_msg":"db error","code":"DB_ERROR"}));
        }
    };

    HttpResponse::Ok().json(GoogleStatusResponse {
        connected: true,
        email: token.provider_email,
        provider_account_id: token.provider_account_id,
        scope: token.scope,
    })
}

#[post("/google/disconnect")]
pub async fn google_disconnect(pool: web::Data<DbPool>, session: Session) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized().json(
                serde_json::json!({"error_msg":"session required","code":"SESSION_REQUIRED"}),
            );
        }
    };

    // Delete token
    let _ = GoogleTokenEntity::delete_many()
        .filter(google_token::Column::VaultId.eq(&vault_id))
        .exec(pool.get_ref())
        .await;

    // Note: cloud_binding is preserved per spec (disconnect does not delete remote file nor local vault).
    // We optionally set sync_status to idle, but keep file_id/revision for potential reconnect.
    // For Phase 3, we just keep bindings.

    log::info!(
        "Google disconnect for user {}",
        &vault_id[..8.min(vault_id.len())]
    );
    HttpResponse::Ok().json(serde_json::json!({"disconnected": true}))
}

#[derive(Serialize)]
struct BindingResponse {
    vault_id: String,
    provider_kind: String,
    provider_account_id: Option<String>,
    drive_file_id: Option<String>,
    remote_revision: Option<String>,
    sync_status: String,
    created_at: String,
    updated_at: String,
}

#[get("/google/pending")]
pub async fn google_get_pending(
    pool: web::Data<DbPool>,
    query: web::Query<PendingVaultsQuery>,
) -> HttpResponse {
    let rec = match crate::entity::oauth_state::Entity::find_by_id(query.state.clone())
        .one(pool.get_ref())
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            // Try pending token
            match crate::entity::google_pending_token::Entity::find_by_id(query.state.clone())
                .one(pool.get_ref())
                .await
            {
                Ok(Some(p)) => {
                    return HttpResponse::Ok().json(serde_json::json!({
                        "state": p.state,
                        "local_email": p.local_email,
                        "provider_email": p.provider_email,
                        "provider_account_id": p.provider_account_id,
                        "has_token": true
                    }));
                }
                _ => {
                    return HttpResponse::NotFound().json(
                        serde_json::json!({"error_msg":"pending not found","code":"NOT_FOUND"}),
                    );
                }
            }
        }
        Err(e) => {
            log::error!("failed to fetch pending: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error_msg":"db error","code":"DB_ERROR"}));
        }
    };
    HttpResponse::Ok().json(serde_json::json!({
        "state": rec.state,
        "vault_id": rec.vault_id,
        "has_token": false
    }))
}

#[get("/google/binding")]
pub async fn google_get_binding(
    pool: web::Data<DbPool>,
    session: Session,
    query: web::Query<GoogleReadVaultQuery>,
) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized().json(
                serde_json::json!({"error_msg":"session required","code":"SESSION_REQUIRED"}),
            );
        }
    };
    if let Some(requested) = &query.vault_id {
        if requested != &vault_id {
            return HttpResponse::Forbidden().json(
                serde_json::json!({"error_msg":"vault_id does not match session","code":"VAULT_MISMATCH"}),
            );
        }
    }
    let binding = match CloudBindingEntity::find()
        .filter(cloud_binding::Column::VaultId.eq(&vault_id))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(b)) => b,
        Ok(None) => {
            return HttpResponse::NotFound().json(
                serde_json::json!({"error_msg":"binding not found","code":"BINDING_NOT_FOUND"}),
            );
        }
        Err(e) => {
            log::error!("failed to fetch binding: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error_msg":"db error","code":"DB_ERROR"}));
        }
    };
    HttpResponse::Ok().json(BindingResponse {
        vault_id: binding.vault_id,
        provider_kind: binding.provider_kind,
        provider_account_id: binding.provider_account_id,
        drive_file_id: binding.drive_file_id,
        remote_revision: binding.remote_revision,
        sync_status: binding.sync_status,
        created_at: binding.created_at.to_rfc3339(),
        updated_at: binding.updated_at.to_rfc3339(),
    })
}

#[get("/google/bindings")]
pub async fn google_list_bindings(pool: web::Data<DbPool>, session: Session) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized().json(
                serde_json::json!({"error_msg":"session required","code":"SESSION_REQUIRED"}),
            );
        }
    };
    let bindings = match CloudBindingEntity::find()
        .filter(cloud_binding::Column::VaultId.eq(&vault_id))
        .all(pool.get_ref())
        .await
    {
        Ok(b) => b,
        Err(e) => {
            log::error!("failed to list bindings: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error_msg":"db error","code":"DB_ERROR"}));
        }
    };
    let resp: Vec<BindingResponse> = bindings
        .into_iter()
        .map(|b| BindingResponse {
            vault_id: b.vault_id,
            provider_kind: b.provider_kind,
            provider_account_id: b.provider_account_id,
            drive_file_id: b.drive_file_id,
            remote_revision: b.remote_revision,
            sync_status: b.sync_status,
            created_at: b.created_at.to_rfc3339(),
            updated_at: b.updated_at.to_rfc3339(),
        })
        .collect();
    HttpResponse::Ok().json(serde_json::json!({"bindings": resp}))
}

// --- Drive vault transport ---

#[derive(Serialize)]
struct ListVaultsResponse {
    vaults: Vec<crate::google::drive::VaultDescriptor>,
}

#[get("/google/vaults")]
pub async fn google_list_vaults(pool: web::Data<DbPool>, session: Session) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized().json(
                serde_json::json!({"error_msg":"session required","code":"SESSION_REQUIRED"}),
            );
        }
    };

    let access_token =
        match crate::google::token_store::get_valid_access_token(pool.get_ref(), &vault_id).await {
            Ok(t) => t,
            Err(code) => {
                let kind = match code.as_str() {
                    "PROVIDER_AUTH_REQUIRED" => ProviderErrorKind::AuthRequired,
                    _ => ProviderErrorKind::AuthRequired,
                };
                return provider_error_response(kind, "Google authorization required");
            }
        };

    match crate::google::drive::list_vaults(&access_token).await {
        Ok(vaults) => HttpResponse::Ok().json(ListVaultsResponse { vaults }),
        Err((kind, msg)) => provider_error_response(kind, &msg),
    }
}

#[derive(Deserialize)]
pub struct GoogleCreateVaultRequest {
    pub vault_id: String,
    pub package: String, // base64 or raw JSON string; we treat as base64 if needed, but accept raw bytes as string
}

#[derive(Serialize)]
struct GoogleCreateVaultResponse {
    file_id: String,
    remote_revision: String,
    vault_id: String,
}

#[post("/google/vaults/create")]
pub async fn google_create_vault(
    pool: web::Data<DbPool>,
    session: Session,
    body: web::Json<GoogleCreateVaultRequest>,
) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized().json(
                serde_json::json!({"error_msg":"session required","code":"SESSION_REQUIRED"}),
            );
        }
    };

    // A requested vault ID is only a consistency check; authorization comes
    // from the session and must never be selected from the request body.
    if body.vault_id != vault_id {
        return HttpResponse::Forbidden().json(
            serde_json::json!({"error_msg":"vault_id does not match session","code":"VAULT_MISMATCH"}),
        );
    }
    if uuid::Uuid::parse_str(&body.vault_id).is_err() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error_msg":"invalid vault_id","code":"INVALID_INPUT"}));
    }

    if body.package.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error_msg":"package required","code":"INVALID_INPUT"}));
    }

    // Package is expected to be base64 ciphertext JSON or raw JSON; decode base64 if possible else treat as raw
    let package_bytes =
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &body.package) {
            Ok(b) => b,
            Err(_) => body.package.as_bytes().to_vec(),
        };

    // Basic vault_id binding check: try to decode package and verify it contains same vault_id (zero-knowledge: server never decrypts, but can check that package JSON contains vault_id field if plaintext wrapper? However package is encrypted, so cannot verify. We trust client but log.)
    // For Phase 3 we just store bytes.

    let access_token =
        match crate::google::token_store::get_valid_access_token(pool.get_ref(), &vault_id).await {
            Ok(t) => t,
            Err(_) => {
                return provider_error_response(
                    ProviderErrorKind::AuthRequired,
                    "Google authorization required",
                );
            }
        };

    match crate::google::drive::create_vault(&access_token, &body.vault_id, &package_bytes).await {
        Ok((file_id, revision)) => {
            // Upsert cloud_binding
            let now = chrono::Utc::now();
            let existing = CloudBindingEntity::find()
                .filter(cloud_binding::Column::VaultId.eq(&vault_id))
                .filter(cloud_binding::Column::VaultId.eq(&body.vault_id))
                .one(pool.get_ref())
                .await
                .unwrap_or(None);

            // Fetch provider account id from token for binding
            let provider_acct = GoogleTokenEntity::find()
                .filter(google_token::Column::VaultId.eq(&vault_id))
                .one(pool.get_ref())
                .await
                .ok()
                .flatten()
                .and_then(|t| t.provider_account_id);

            if let Some(existing) = existing {
                let mut am: cloud_binding::ActiveModel = existing.into();
                am.drive_file_id = Set(Some(file_id.clone()));
                am.remote_revision = Set(Some(revision.clone()));
                am.provider_account_id = Set(provider_acct);
                am.sync_status = Set("idle".to_string());
                am.updated_at = Set(now.into());
                let _ = am.update(pool.get_ref()).await;
            } else {
                let am = cloud_binding::ActiveModel {
                    vault_id: Set(body.vault_id.clone()),
                    provider_kind: Set("google_drive".to_string()),
                    provider_account_id: Set(provider_acct),
                    drive_file_id: Set(Some(file_id.clone())),
                    remote_revision: Set(Some(revision.clone())),
                    sync_status: Set("idle".to_string()),
                    created_at: Set(now.into()),
                    updated_at: Set(now.into()),
                };
                let _ = am.insert(pool.get_ref()).await;
            }

            log::info!(
                "Created Google Drive vault {} file {}",
                &body.vault_id[..8],
                &file_id[..8.min(file_id.len())]
            );
            HttpResponse::Ok().json(GoogleCreateVaultResponse {
                file_id,
                remote_revision: revision,
                vault_id: body.vault_id.clone(),
            })
        }
        Err((kind, msg)) => provider_error_response(kind, &msg),
    }
}

#[derive(Deserialize)]
pub struct GoogleReadVaultQuery {
    pub file_id: Option<String>,
    pub vault_id: Option<String>,
}

#[get("/google/vaults/read")]
pub async fn google_read_vault(
    pool: web::Data<DbPool>,
    session: Session,
    query: web::Query<GoogleReadVaultQuery>,
) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized().json(
                serde_json::json!({"error_msg":"session required","code":"SESSION_REQUIRED"}),
            );
        }
    };

    let file_id = if let Some(fid) = &query.file_id {
        fid.clone()
    } else if let Some(vid) = &query.vault_id {
        // Lookup binding to get file_id
        let binding = CloudBindingEntity::find()
            .filter(cloud_binding::Column::VaultId.eq(&vault_id))
            .one(pool.get_ref())
            .await
            .unwrap_or(None);
        if let Some(b) = binding {
            if let Some(fid) = b.drive_file_id {
                fid
            } else {
                return provider_error_response(
                    ProviderErrorKind::VaultNotFound,
                    "vault not bound to Drive file",
                );
            }
        } else {
            // Fallback: list and find by vault_id
            let access_token =
                match crate::google::token_store::get_valid_access_token(pool.get_ref(), &vault_id)
                    .await
                {
                    Ok(t) => t,
                    Err(_) => {
                        return provider_error_response(
                            ProviderErrorKind::AuthRequired,
                            "Google authorization required",
                        );
                    }
                };
            let list = match crate::google::drive::list_vaults(&access_token).await {
                Ok(l) => l,
                Err((k, m)) => return provider_error_response(k, &m),
            };
            if let Some(found) = list.iter().find(|v| &v.vault_id == vid) {
                found.file_id.clone()
            } else {
                return provider_error_response(
                    ProviderErrorKind::VaultNotFound,
                    "vault file not found in Drive",
                );
            }
        }
    } else {
        return HttpResponse::BadRequest().json(
            serde_json::json!({"error_msg":"file_id or vault_id required","code":"INVALID_INPUT"}),
        );
    };

    let access_token =
        match crate::google::token_store::get_valid_access_token(pool.get_ref(), &vault_id).await {
            Ok(t) => t,
            Err(_) => {
                return provider_error_response(
                    ProviderErrorKind::AuthRequired,
                    "Google authorization required",
                );
            }
        };

    match crate::google::drive::read_vault(&access_token, &file_id).await {
        Ok((bytes, revision)) => {
            // Return package as base64 to avoid binary JSON issues
            let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
            HttpResponse::Ok().json(serde_json::json!({
                "package": b64,
                "remote_revision": revision,
                "file_id": file_id
            }))
        }
        Err((kind, msg)) => provider_error_response(kind, &msg),
    }
}

#[derive(Deserialize)]
pub struct GoogleReplaceVaultRequest {
    pub vault_id: Option<String>,
    pub file_id: Option<String>,
    pub package: String,
    pub if_match_revision: Option<String>,
}

#[derive(Serialize)]
struct GoogleReplaceVaultResponse {
    remote_revision: String,
    file_id: String,
}

#[post("/google/vaults/replace")]
pub async fn google_replace_vault(
    pool: web::Data<DbPool>,
    session: Session,
    body: web::Json<GoogleReplaceVaultRequest>,
) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized().json(
                serde_json::json!({"error_msg":"session required","code":"SESSION_REQUIRED"}),
            );
        }
    };

    let file_id = if let Some(fid) = &body.file_id {
        fid.clone()
    } else if let Some(vid) = &body.vault_id {
        let binding = CloudBindingEntity::find()
            .filter(cloud_binding::Column::VaultId.eq(&vault_id))
            .one(pool.get_ref())
            .await
            .unwrap_or(None);
        if let Some(b) = binding.and_then(|b| b.drive_file_id) {
            b
        } else {
            return provider_error_response(ProviderErrorKind::VaultNotFound, "vault not bound");
        }
    } else {
        return HttpResponse::BadRequest().json(
            serde_json::json!({"error_msg":"file_id or vault_id required","code":"INVALID_INPUT"}),
        );
    };

    let package_bytes =
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &body.package) {
            Ok(b) => b,
            Err(_) => body.package.as_bytes().to_vec(),
        };

    let access_token =
        match crate::google::token_store::get_valid_access_token(pool.get_ref(), &vault_id).await {
            Ok(t) => t,
            Err(_) => {
                return provider_error_response(
                    ProviderErrorKind::AuthRequired,
                    "Google authorization required",
                );
            }
        };

    match crate::google::drive::replace_vault(
        &access_token,
        &file_id,
        &package_bytes,
        body.if_match_revision.as_deref(),
    )
    .await
    {
        Ok(new_rev) => {
            // Update binding revision
            if let Some(vid) = &body.vault_id {
                let now = chrono::Utc::now();
                if let Ok(Some(existing)) = CloudBindingEntity::find()
                    .filter(cloud_binding::Column::VaultId.eq(vid))
                    .one(pool.get_ref())
                    .await
                {
                    let mut am: cloud_binding::ActiveModel = existing.into();
                    am.remote_revision = Set(Some(new_rev.clone()));
                    am.updated_at = Set(now.into());
                    let _ = am.update(pool.get_ref()).await;
                }
            }
            HttpResponse::Ok().json(GoogleReplaceVaultResponse {
                remote_revision: new_rev,
                file_id: file_id.clone(),
            })
        }
        Err((kind, msg)) => provider_error_response(kind, &msg),
    }
}

#[derive(Deserialize)]
pub struct GoogleDeleteVaultRequest {
    pub file_id: Option<String>,
    pub vault_id: Option<String>,
}

#[derive(Deserialize)]
pub struct GoogleBindingUpsertRequest {
    pub vault_id: String,
    pub drive_file_id: String,
    pub remote_revision: Option<String>,
    pub provider_kind: Option<String>,
}

#[post("/google/binding")]
pub async fn google_upsert_binding(
    pool: web::Data<DbPool>,
    session: Session,
    body: web::Json<GoogleBindingUpsertRequest>,
) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized().json(
                serde_json::json!({"error_msg":"session required","code":"SESSION_REQUIRED"}),
            );
        }
    };
    if uuid::Uuid::parse_str(&body.vault_id).is_err() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error_msg":"invalid vault_id","code":"INVALID_INPUT"}));
    }
    let now = chrono::Utc::now();
    let provider_kind = body
        .provider_kind
        .clone()
        .unwrap_or_else(|| "google_drive".to_string());
    let existing = CloudBindingEntity::find()
        .filter(cloud_binding::Column::VaultId.eq(&body.vault_id))
        .one(pool.get_ref())
        .await
        .unwrap_or(None);
    let provider_acct = GoogleTokenEntity::find()
        .filter(google_token::Column::VaultId.eq(&vault_id))
        .one(pool.get_ref())
        .await
        .ok()
        .flatten()
        .and_then(|t| t.provider_account_id);
    if let Some(existing) = existing {
        let mut am: cloud_binding::ActiveModel = existing.into();
        am.drive_file_id = Set(Some(body.drive_file_id.clone()));
        if let Some(rev) = &body.remote_revision {
            am.remote_revision = Set(Some(rev.clone()));
        }
        am.provider_account_id = Set(provider_acct);
        am.updated_at = Set(now.into());
        if let Err(e) = am.update(pool.get_ref()).await {
            log::error!("failed to update Google cloud binding: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error_msg":"failed to persist cloud binding","code":"DB_ERROR"}));
        }
    } else {
        let am = cloud_binding::ActiveModel {
            vault_id: Set(body.vault_id.clone()),
            provider_kind: Set(provider_kind),
            provider_account_id: Set(provider_acct),
            drive_file_id: Set(Some(body.drive_file_id.clone())),
            remote_revision: Set(body.remote_revision.clone()),
            sync_status: Set("idle".to_string()),
            created_at: Set(now.into()),
            updated_at: Set(now.into()),
        };
        if let Err(e) = am.insert(pool.get_ref()).await {
            log::error!("failed to insert Google cloud binding: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error_msg":"failed to persist cloud binding","code":"DB_ERROR"}));
        }
    }
    HttpResponse::Ok().json(serde_json::json!({"upserted": true, "vault_id": body.vault_id}))
}

#[derive(Deserialize)]
pub struct LinkPendingRequest {
    pub state: String,
}

#[post("/google/link-pending")]
pub async fn google_link_pending(
    pool: web::Data<DbPool>,
    session: Session,
    body: web::Json<LinkPendingRequest>,
) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized().json(
                serde_json::json!({"error_msg":"session required","code":"SESSION_REQUIRED"}),
            );
        }
    };
    match crate::google::oauth::link_pending_to_user(pool.get_ref(), &body.state, &vault_id).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"linked": true})),
        Err(e) => {
            log::error!("Failed to link pending Google token: {}", e);
            HttpResponse::BadRequest()
                .json(serde_json::json!({"error_msg": e, "code":"LINK_FAILED"}))
        }
    }
}

#[derive(Deserialize)]
pub struct PendingVaultsQuery {
    pub state: String,
}

#[get("/google/vaults/pending")]
pub async fn google_list_vaults_pending(
    pool: web::Data<DbPool>,
    query: web::Query<PendingVaultsQuery>,
) -> HttpResponse {
    // Use pending token to list Drive vaults without requiring local session
    let pending = match crate::entity::google_pending_token::Entity::find_by_id(query.state.clone())
        .one(pool.get_ref())
        .await
    {
        Ok(Some(p)) => p,
        Ok(None) => {
            return provider_error_response(
                ProviderErrorKind::AuthRequired,
                "pending Google auth not found or expired",
            );
        }
        Err(e) => {
            log::error!("failed to fetch pending token: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error_msg":"db error","code":"DB_ERROR"}));
        }
    };
    // Check expiry and refresh if needed (simplified – use stored access_token, if expired try refresh if we have refresh_token)
    let access_token = pending.access_token.clone();
    // For pending, we don't have a refresh flow tied to user, but we can still try to list
    match crate::google::drive::list_vaults(&access_token).await {
        Ok(vaults) => HttpResponse::Ok().json(serde_json::json!({"vaults": vaults})),
        Err((kind, msg)) => provider_error_response(kind, &msg),
    }
}

#[derive(Deserialize)]
pub struct PendingReadQuery {
    pub state: String,
    pub file_id: String,
}

#[get("/google/vaults/pending/read")]
pub async fn google_read_vault_pending(
    pool: web::Data<DbPool>,
    query: web::Query<PendingReadQuery>,
) -> HttpResponse {
    let pending = match crate::entity::google_pending_token::Entity::find_by_id(query.state.clone())
        .one(pool.get_ref())
        .await
    {
        Ok(Some(p)) => p,
        Ok(None) => {
            return provider_error_response(
                ProviderErrorKind::AuthRequired,
                "pending Google auth not found or expired",
            );
        }
        Err(e) => {
            log::error!("failed to fetch pending token: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error_msg":"db error","code":"DB_ERROR"}));
        }
    };
    let access_token = pending.access_token.clone();
    match crate::google::drive::read_vault(&access_token, &query.file_id).await {
        Ok((bytes, revision)) => {
            let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
            HttpResponse::Ok().json(serde_json::json!({
                "package": b64,
                "remote_revision": revision,
                "file_id": query.file_id
            }))
        }
        Err((kind, msg)) => provider_error_response(kind, &msg),
    }
}

#[post("/google/vaults/delete")]
pub async fn google_delete_vault(
    pool: web::Data<DbPool>,
    session: Session,
    body: web::Json<GoogleDeleteVaultRequest>,
) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized().json(
                serde_json::json!({"error_msg":"session required","code":"SESSION_REQUIRED"}),
            );
        }
    };

    let file_id = if let Some(fid) = &body.file_id {
        fid.clone()
    } else if let Some(vid) = &body.vault_id {
        let binding = CloudBindingEntity::find()
            .filter(cloud_binding::Column::VaultId.eq(&vault_id))
            .one(pool.get_ref())
            .await
            .unwrap_or(None);
        if let Some(b) = binding.and_then(|b| b.drive_file_id) {
            b
        } else {
            return provider_error_response(ProviderErrorKind::VaultNotFound, "vault not bound");
        }
    } else {
        return HttpResponse::BadRequest().json(
            serde_json::json!({"error_msg":"file_id or vault_id required","code":"INVALID_INPUT"}),
        );
    };

    let access_token =
        match crate::google::token_store::get_valid_access_token(pool.get_ref(), &vault_id).await {
            Ok(t) => t,
            Err(_) => {
                return provider_error_response(
                    ProviderErrorKind::AuthRequired,
                    "Google authorization required",
                );
            }
        };

    match crate::google::drive::delete_vault(&access_token, &file_id).await {
        Ok(()) => {
            // Remove binding but keep vault local per spec (disconnect does not delete local)
            if let Some(vid) = &body.vault_id {
                let _ = CloudBindingEntity::delete_many()
                    .filter(cloud_binding::Column::VaultId.eq(vid))
                    .exec(pool.get_ref())
                    .await;
            }
            HttpResponse::Ok().json(serde_json::json!({"deleted": true, "file_id": file_id}))
        }
        Err((kind, msg)) => provider_error_response(kind, &msg),
    }
}
