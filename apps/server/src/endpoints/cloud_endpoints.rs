use actix_session::Session;
use actix_web::{HttpResponse, get, post, web};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};
use serde::{Deserialize, Serialize};

use crate::cloud::error::{ProviderErrorKind, provider_error_response};
use crate::cloud::provider::{self, CloudProvider, ProviderKind};
use crate::cloud::{mirror, oauth_flow, package, token_store};
use crate::db::DbPool;
use crate::entity::cloud_binding::{self, Entity as CloudBindingEntity};
use crate::entity::cloud_pending_token;
use crate::entity::cloud_token::{self, Entity as CloudTokenEntity};
use crate::session_auth::session_vault_id;

/// Resolve the single active provider from the binding. Before first binding,
/// use the most recently connected credential; retained credentials for older
/// providers are switch-back cache and must never override an active binding.
async fn selected_provider(pool: &DbPool, vault_id: &str) -> Option<ProviderKind> {
    match CloudBindingEntity::find_by_id(vault_id.to_string())
        .one(pool)
        .await
    {
        Ok(Some(binding)) => {
            return match ProviderKind::parse(&binding.provider_kind) {
                Ok(kind) => Some(kind),
                Err(err) => {
                    log::error!("vault binding has unknown cloud provider: {}", err);
                    None
                }
            };
        }
        Ok(None) => {}
        Err(err) => {
            log::error!("failed to resolve cloud binding provider: {}", err);
            return None;
        }
    }
    match CloudTokenEntity::find()
        .filter(cloud_token::Column::VaultId.eq(vault_id))
        .order_by_desc(cloud_token::Column::UpdatedAt)
        .one(pool)
        .await
    {
        Ok(Some(token)) => match ProviderKind::parse(&token.provider_kind) {
            Ok(kind) => Some(kind),
            Err(err) => {
                log::error!("cloud token has unknown provider: {}", err);
                None
            }
        },
        Ok(None) => None,
        Err(err) => {
            log::error!("failed to resolve active cloud provider: {}", err);
            None
        }
    }
}

/// True when a vault row with this id exists.
async fn vault_exists(pool: &DbPool, vault_id: &str) -> bool {
    matches!(
        crate::entity::vault::Entity::find_by_id(vault_id.to_string())
            .one(pool)
            .await,
        Ok(Some(_))
    )
}

/// The session's vault id, but only if that vault still exists.
///
/// A cookie can outlive the vault it names — a deleted or recreated database,
/// the same case `GET /session` fails closed on. Binding a foreign-key-bearing
/// row (an `oauth_state`, a provider token) to the ghost id fails as a raw
/// `FOREIGN KEY constraint failed`, which surfaces as a 500 for what is really
/// "no session". An orphaned session is treated as no session and purged, so the
/// caller takes its pre-session path.
async fn live_session_vault_id(pool: &DbPool, session: &Session) -> Option<String> {
    match session_vault_id(session) {
        Ok(Some(id)) => {
            if vault_exists(pool, &id).await {
                Some(id)
            } else {
                log::warn!(
                    "session names vault {} which does not exist; treating as no session",
                    &id[..8.min(id.len())]
                );
                session.purge();
                None
            }
        }
        _ => None,
    }
}

#[derive(Serialize)]
struct ConfiguredProvider {
    kind: String,
    display_name: &'static str,
}

#[get("/cloud/providers")]
pub async fn cloud_providers() -> HttpResponse {
    let providers: Vec<ConfiguredProvider> = provider::configured_providers()
        .into_iter()
        .map(|kind| ConfiguredProvider {
            kind: kind.as_str().to_string(),
            display_name: kind.display_name(),
        })
        .collect();
    HttpResponse::Ok().json(serde_json::json!({"providers": providers}))
}

#[derive(Serialize)]
struct ConnectedCloudCredential {
    kind: String,
    display_name: &'static str,
    email: Option<String>,
}

/// Exposes which providers already have a saved credential for this vault so
/// switching back can reuse it without re-consent. Token values never leave the
/// server and rows without an active binding are intentionally retained.
#[get("/cloud/credentials")]
pub async fn cloud_credentials(pool: web::Data<DbPool>, session: Session) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"code":"SESSION_REQUIRED"}));
        }
    };
    let rows = match CloudTokenEntity::find()
        .filter(cloud_token::Column::VaultId.eq(&vault_id))
        .all(pool.get_ref())
        .await
    {
        Ok(rows) => rows,
        Err(err) => {
            log::error!(
                "failed to list cloud credentials for vault {}: {err}",
                &vault_id[..8.min(vault_id.len())]
            );
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"code":"DB_ERROR"}));
        }
    };
    let credentials: Vec<ConnectedCloudCredential> = rows
        .into_iter()
        .filter_map(|row| {
            let kind = ProviderKind::parse(&row.provider_kind).ok()?;
            Some(ConnectedCloudCredential {
                kind: kind.as_str().to_string(),
                display_name: kind.display_name(),
                email: row.provider_email,
            })
        })
        .collect();
    HttpResponse::Ok().json(serde_json::json!({"credentials": credentials}))
}

// --- OAuth start / status / disconnect ---

#[derive(Serialize)]
struct AuthStartResponse {
    auth_url: String,
    state: String,
}

#[derive(Deserialize)]
pub struct AuthStartQuery {
    pub provider: String,
}

#[get("/cloud/auth/start")]
pub async fn cloud_auth_start(
    pool: web::Data<DbPool>,
    session: Session,
    query: web::Query<AuthStartQuery>,
) -> HttpResponse {
    let kind = match ProviderKind::parse(&query.provider) {
        Ok(kind) => kind,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({"code":"UNKNOWN_PROVIDER"}));
        }
    };
    // The session-bound path can mint state against a known vault; otherwise the
    // pre-session import path, where the vault does not exist yet. A stale
    // cookie naming a deleted vault is treated as no session — see
    // `live_session_vault_id`.
    let vault_id_opt = live_session_vault_id(pool.get_ref(), &session).await;

    let (auth_url, state) =
        match oauth_flow::begin(pool.get_ref(), kind, vault_id_opt.as_deref()).await {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to start Google authorization: {}", e);
                return HttpResponse::InternalServerError().json(
                serde_json::json!({"error_msg":"failed to start authorization","code":"DB_ERROR"}),
            );
            }
        };

    if vault_id_opt.is_some() {
        let _ = oauth_flow::store_state_in_session(&session, &state);
    }
    log::info!(
        "Generated cloud OAuth state for vault {}",
        vault_id_opt
            .as_deref()
            .map(|v| &v[..8.min(v.len())])
            .unwrap_or("(pending)")
    );
    HttpResponse::Ok().json(AuthStartResponse { auth_url, state })
}

#[derive(Deserialize)]
pub struct OAuthCallbackQuery {
    pub provider: String,
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

#[get("/cloud/oauth/callback")]
pub async fn cloud_oauth_callback(
    pool: web::Data<DbPool>,
    session: Session,
    query: web::Query<OAuthCallbackQuery>,
) -> HttpResponse {
    cloud_oauth_callback_inner(pool, session, query).await
}

async fn cloud_oauth_callback_inner(
    pool: web::Data<DbPool>,
    session: Session,
    query: web::Query<OAuthCallbackQuery>,
) -> HttpResponse {
    let kind = match ProviderKind::parse(&query.provider) {
        Ok(kind) => kind,
        Err(_) => return HttpResponse::BadRequest().body("unknown provider"),
    };
    let Some(impl_) = provider::provider(kind) else {
        return HttpResponse::ServiceUnavailable().body("provider not configured");
    };
    let post_auth_redirect = impl_.post_auth_redirect();

    if let Some(err) = &query.error {
        log::warn!("cloud OAuth error: {}", err);
        return HttpResponse::Found()
            .insert_header((
                "Location",
                format!(
                    "{}?cloud_error={}&provider={}",
                    post_auth_redirect,
                    urlencoding::encode(err),
                    kind.as_str(),
                ),
            ))
            .finish();
    }

    let Some(code) = query.code.as_deref() else {
        return HttpResponse::BadRequest().body("missing code");
    };
    let Some(state) = query.state.as_deref() else {
        return HttpResponse::BadRequest().body("missing state");
    };

    let vault_id_opt = live_session_vault_id(pool.get_ref(), &session).await;

    let redirect_err = |detail: &str| {
        HttpResponse::Found()
            .insert_header((
                "Location",
                format!(
                    "{}?cloud_error={}&provider={}&cloud_error_detail={}",
                    post_auth_redirect,
                    urlencoding::encode("exchange_failed"),
                    kind.as_str(),
                    urlencoding::encode(detail),
                ),
            ))
            .finish()
    };

    if let Some(vault_id) = vault_id_opt {
        match oauth_flow::complete_for_vault(pool.get_ref(), kind, state, code, &vault_id).await {
            Ok((_acct, email)) => {
                log::info!(
                    "cloud OAuth success (vault-bound) for {} provider {}",
                    &vault_id[..8.min(vault_id.len())],
                    email.as_deref().unwrap_or("unknown")
                );
                HttpResponse::Found()
                    .insert_header((
                        "Location",
                        format!(
                            "{}?cloud_connected=1&provider={}&email={}",
                            post_auth_redirect,
                            kind.as_str(),
                            urlencoding::encode(email.as_deref().unwrap_or_default()),
                        ),
                    ))
                    .finish()
            }
            Err(e) => {
                // An invalid/expired state is a CSRF failure, not an exchange
                // failure, and must be reported as such.
                if e.detail().contains("state") {
                    log::warn!("cloud OAuth state validation failed: {}", e);
                    return HttpResponse::Found()
                        .insert_header((
                            "Location",
                            format!(
                                "{}?cloud_error={}&provider={}",
                                post_auth_redirect,
                                urlencoding::encode("invalid_state"),
                                kind.as_str(),
                            ),
                        ))
                        .finish();
                }
                log::warn!("cloud OAuth exchange failed: {}", e);
                redirect_err(&e.redacted_detail().to_string())
            }
        }
    } else {
        match oauth_flow::complete_pending(pool.get_ref(), kind, state, code).await {
            Ok((_acct, email)) => {
                log::info!(
                    "cloud OAuth success (pending) provider {}",
                    email.as_deref().unwrap_or("unknown")
                );
                HttpResponse::Found()
                    .insert_header((
                        "Location",
                        format!(
                            "{}?cloud_state={}&provider={}&email={}",
                            post_auth_redirect,
                            urlencoding::encode(state),
                            kind.as_str(),
                            urlencoding::encode(email.as_deref().unwrap_or_default()),
                        ),
                    ))
                    .finish()
            }
            Err(e) => {
                log::warn!("cloud OAuth exchange failed: {}", e);
                redirect_err(&e.redacted_detail().to_string())
            }
        }
    }
}

#[derive(Serialize)]
struct CloudStatusResponse {
    connected: bool,
    email: Option<String>,
    provider_account_id: Option<String>,
    scope: Option<String>,
}

#[get("/cloud/status")]
pub async fn cloud_status(pool: web::Data<DbPool>, session: Session) -> HttpResponse {
    // The landing page checks Google availability before a local account/session
    // exists. That is a valid disconnected state, not an authentication error.
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Ok().json(CloudStatusResponse {
                connected: false,
                email: None,
                provider_account_id: None,
                scope: None,
            });
        }
    };
    let Some(kind) = selected_provider(pool.get_ref(), &vault_id).await else {
        return HttpResponse::Ok().json(CloudStatusResponse {
            connected: false,
            email: None,
            provider_account_id: None,
            scope: None,
        });
    };

    let token = match CloudTokenEntity::find()
        .filter(cloud_token::Column::VaultId.eq(&vault_id))
        .filter(cloud_token::Column::ProviderKind.eq(kind.as_str()))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(t)) => t,
        Ok(None) => {
            return HttpResponse::Ok().json(CloudStatusResponse {
                connected: false,
                email: None,
                provider_account_id: None,
                scope: None,
            });
        }
        Err(e) => {
            log::error!("failed to fetch cloud token: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error_msg":"db error","code":"DB_ERROR"}));
        }
    };

    HttpResponse::Ok().json(CloudStatusResponse {
        connected: true,
        email: token.provider_email,
        provider_account_id: token.provider_account_id,
        scope: token.scope,
    })
}

#[post("/cloud/disconnect")]
pub async fn cloud_disconnect(pool: web::Data<DbPool>, session: Session) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized().json(
                serde_json::json!({"error_msg":"session required","code":"SESSION_REQUIRED"}),
            );
        }
    };
    let Some(kind) = selected_provider(pool.get_ref(), &vault_id).await else {
        return HttpResponse::Ok().json(serde_json::json!({"disconnected": true}));
    };

    // Scoped to this provider only (see token_store::delete): credentials for
    // other providers are retained so switching back needs no fresh consent.
    if let Err(e) = token_store::delete(pool.get_ref(), kind, &vault_id).await {
        log::error!("failed to delete cloud token: {}", e);
    }

    // cloud_binding is preserved: disconnecting removes the credential, not the
    // vault, and not the remote file. The mirror will report auth_required.
    log::info!(
        "cloud disconnect for user {}",
        &vault_id[..8.min(vault_id.len())]
    );
    HttpResponse::Ok().json(serde_json::json!({"disconnected": true}))
}

/// Real backup state for the Drive copy of this vault.
///
/// `sync_status` and `remote_revision` alone cannot answer "is my backup
/// current?" — the binding only knows the revision, not the vault version it
/// corresponds to. `mirrored_vault_version` vs `vault_version` does, and the
/// gap between them is exactly how many committed writes the DR copy is
/// missing.
#[derive(Serialize)]
struct BindingResponse {
    vault_id: String,
    provider_kind: String,
    provider_account_id: Option<String>,
    remote_file_id: Option<String>,
    remote_revision: Option<String>,
    sync_status: String,
    /// Current server vault version — the write authority.
    vault_version: i32,
    /// Vault version the Drive copy corresponds to; null = never mirrored.
    mirrored_vault_version: Option<i32>,
    /// Committed writes the Drive copy is missing (0 = backup current).
    versions_behind: i32,
    last_mirrored_at: Option<String>,
    last_mirror_error: Option<String>,
    created_at: String,
    updated_at: String,
}

impl BindingResponse {
    async fn from_binding(pool: &crate::db::DbPool, b: cloud_binding::Model) -> Self {
        // Read the live version so the client can compute staleness without a
        // second round trip. A missing vault row (deleted underneath us) reads
        // as version 0 rather than failing the whole binding response.
        let vault_version = crate::entity::vault::Entity::find_by_id(&b.vault_id)
            .one(pool)
            .await
            .ok()
            .flatten()
            .map(|v| v.version)
            .unwrap_or(0);
        let versions_behind = b
            .mirrored_vault_version
            .map(|mirrored| (vault_version - mirrored).max(0))
            .unwrap_or(0);
        Self {
            vault_id: b.vault_id,
            provider_kind: b.provider_kind,
            provider_account_id: b.provider_account_id,
            remote_file_id: b.remote_file_id,
            remote_revision: b.remote_revision,
            sync_status: b.sync_status,
            vault_version,
            mirrored_vault_version: b.mirrored_vault_version,
            versions_behind,
            last_mirrored_at: b.last_mirrored_at,
            last_mirror_error: b.last_mirror_error,
            created_at: b.created_at.to_rfc3339(),
            updated_at: b.updated_at.to_rfc3339(),
        }
    }
}

#[get("/cloud/pending")]
pub async fn cloud_get_pending(
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
            match cloud_pending_token::Entity::find_by_id(query.state.clone())
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

#[get("/cloud/binding")]
pub async fn cloud_get_binding(
    pool: web::Data<DbPool>,
    session: Session,
    query: web::Query<CloudReadVaultQuery>,
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
            return HttpResponse::Forbidden()
                .json(serde_json::json!({"error_msg":"vault_id does not match session","code":"VAULT_MISMATCH"}));
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
    HttpResponse::Ok().json(BindingResponse::from_binding(pool.get_ref(), binding).await)
}

#[get("/cloud/bindings")]
pub async fn cloud_list_bindings(pool: web::Data<DbPool>, session: Session) -> HttpResponse {
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
    let mut resp: Vec<BindingResponse> = Vec::with_capacity(bindings.len());
    for b in bindings {
        resp.push(BindingResponse::from_binding(pool.get_ref(), b).await);
    }
    HttpResponse::Ok().json(serde_json::json!({"bindings": resp}))
}

/// Explicit user-triggered backup ("Back up now" in Settings).
///
/// The automatic mirror is detached and fire-and-forget, so the UI has no way
/// to learn its outcome. This awaits the same CAS-gated mirror and returns the
/// real result, so the user sees success, conflict, or a specific failure
/// instead of a constant "enabled".
#[post("/cloud/vaults/mirror")]
pub async fn cloud_mirror_vault(pool: web::Data<DbPool>, session: Session) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized().json(
                serde_json::json!({"error_msg":"session required","code":"SESSION_REQUIRED"}),
            );
        }
    };

    let outcome = mirror::mirror_now(pool.get_ref(), &vault_id).await;
    match &outcome {
        mirror::MirrorOutcome::Mirrored { vault_version } => log::info!(
            "Manual Drive backup completed for vault {} at version {}",
            &vault_id[..8.min(vault_id.len())],
            vault_version
        ),
        mirror::MirrorOutcome::Conflict => log::warn!(
            "Manual Drive backup refused for vault {}: the Drive copy changed since last sync",
            &vault_id[..8.min(vault_id.len())]
        ),
        _ => {}
    }

    // Re-read the binding so the response carries the state the mirror just
    // persisted, not a value the client has to reconcile.
    let binding = CloudBindingEntity::find()
        .filter(cloud_binding::Column::VaultId.eq(&vault_id))
        .one(pool.get_ref())
        .await
        .ok()
        .flatten();

    match binding {
        Some(b) => HttpResponse::Ok().json(serde_json::json!({
            "mirror": outcome,
            "binding": BindingResponse::from_binding(pool.get_ref(), b).await,
        })),
        None => HttpResponse::Ok().json(serde_json::json!({"mirror": outcome})),
    }
}

// --- Cloud vault transport ---

#[derive(Serialize)]
struct ListVaultsResponse {
    vaults: Vec<provider::RemoteVaultFile>,
}

#[get("/cloud/vaults")]
pub async fn cloud_list_vaults(pool: web::Data<DbPool>, session: Session) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized().json(
                serde_json::json!({"error_msg":"session required","code":"SESSION_REQUIRED"}),
            );
        }
    };

    let Some(kind) = selected_provider(pool.get_ref(), &vault_id).await else {
        return provider_error_response(
            ProviderErrorKind::AuthRequired,
            "active cloud provider is not connected",
        );
    };

    let access_token =
        match token_store::get_valid_access_token(pool.get_ref(), kind, &vault_id).await {
            Ok(t) => t,
            Err(e) => return e.into_response(),
        };

    let Some(impl_) = provider::provider(kind) else {
        return provider_error_response(
            ProviderErrorKind::AuthRequired,
            "provider authorization required",
        );
    };

    match impl_.list_vault_files(&access_token).await {
        Ok(vaults) => HttpResponse::Ok().json(ListVaultsResponse { vaults }),
        Err(e) => e.into_response(),
    }
}

#[derive(Deserialize)]
pub struct CloudCreateVaultRequest {
    pub vault_id: String,
    pub package: String, // base64 or raw JSON string; we treat as base64 if needed, but accept raw bytes as string
}

#[derive(Serialize)]
struct CloudCreateVaultResponse {
    file_id: String,
    remote_revision: String,
    vault_id: String,
}

#[post("/cloud/vaults/create")]
pub async fn cloud_create_vault(
    pool: web::Data<DbPool>,
    session: Session,
    body: web::Json<CloudCreateVaultRequest>,
) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized().json(
                serde_json::json!({"error_msg":"session required","code":"SESSION_REQUIRED"}),
            );
        }
    };

    let Some(kind) = selected_provider(pool.get_ref(), &vault_id).await else {
        return provider_error_response(
            ProviderErrorKind::AuthRequired,
            "active cloud provider is not connected",
        );
    };

    // A requested vault ID is only a consistency check; authorization comes
    // from the session and must never be selected from the request body.
    if body.vault_id != vault_id {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error_msg":"vault_id does not match session","code":"VAULT_MISMATCH"}));
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

    // The package is encrypted, but its *envelope* (vault id, logical revision,
    // crypto parameters) is plaintext by design. Parsing it lets the server
    // refuse a package belonging to a different vault and lets it record
    // exactly which vault version this Drive copy holds, so the backup
    // watermark is real rather than assumed. No ciphertext is inspected.
    let header = match package::parse_header(&package_bytes, &vault_id) {
        Ok(h) => h,
        Err(code) => {
            log::warn!(
                "Rejected cloud package for vault {}: {}",
                &vault_id[..8.min(vault_id.len())],
                code
            );
            return provider_error_response(ProviderErrorKind::PackageInvalid, code);
        }
    };

    let access_token =
        match token_store::get_valid_access_token(pool.get_ref(), kind, &vault_id).await {
            Ok(t) => t,
            Err(_) => {
                return provider_error_response(
                    ProviderErrorKind::AuthRequired,
                    "provider authorization required",
                );
            }
        };

    let Some(impl_) = provider::provider(kind) else {
        return provider_error_response(
            ProviderErrorKind::AuthRequired,
            "provider authorization required",
        );
    };

    // Idempotent by vault_id: an existing file is re-adopted rather than
    // duplicated.
    let created = match impl_
        .create_vault_file(&access_token, &body.vault_id, &package_bytes)
        .await
    {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };

    // Upsert cloud_binding.
    let now = chrono::Utc::now();
    let existing = CloudBindingEntity::find()
        .filter(cloud_binding::Column::VaultId.eq(&vault_id))
        .one(pool.get_ref())
        .await
        .unwrap_or(None);

    let provider_acct = CloudTokenEntity::find()
        .filter(cloud_token::Column::VaultId.eq(&vault_id))
        .filter(cloud_token::Column::ProviderKind.eq(kind.as_str()))
        .one(pool.get_ref())
        .await
        .ok()
        .flatten()
        .and_then(|t| t.provider_account_id);

    if let Some(existing) = existing {
        let mut am: cloud_binding::ActiveModel = existing.into();
        am.remote_file_id = Set(Some(created.file_id.clone()));
        am.remote_revision = Set(Some(created.revision.clone()));
        am.provider_account_id = Set(provider_acct);
        am.sync_status = Set("idle".to_string());
        // Enrollment may adopt an existing, stale remote file. Do not claim
        // that it contains the client package's revision; the awaited mirror
        // below establishes an honest watermark by reading the server vault.
        am.mirrored_vault_version = Set(None);
        am.last_mirror_error = Set(None);
        am.updated_at = Set(now.into());
        let _ = am.update(pool.get_ref()).await;
    } else {
        let am = cloud_binding::ActiveModel {
            vault_id: Set(body.vault_id.clone()),
            provider_kind: Set(kind.as_str().to_string()),
            provider_account_id: Set(provider_acct),
            remote_file_id: Set(Some(created.file_id.clone())),
            remote_revision: Set(Some(created.revision.clone())),
            sync_status: Set("idle".to_string()),
            mirrored_vault_version: Set(None),
            last_mirrored_at: Set(Some(now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))),
            last_mirror_error: Set(None),
            created_at: Set(now.into()),
            updated_at: Set(now.into()),
        };
        let _ = am.insert(pool.get_ref()).await;
    }

    let enrollment_mirror = mirror::mirror_now(pool.get_ref(), &vault_id).await;
    log::info!(
        "Created cloud vault {} file {} at logical revision {}",
        &body.vault_id[..8],
        &created.file_id[..8.min(created.file_id.len())],
        header.logical_revision
    );
    if let mirror::MirrorOutcome::Error { code } = &enrollment_mirror {
        log::warn!(
            "Cloud enrollment mirror for vault {} did not converge: {}",
            &vault_id[..8.min(vault_id.len())],
            code
        );
    }
    HttpResponse::Ok().json(CloudCreateVaultResponse {
        file_id: created.file_id,
        remote_revision: created.revision,
        vault_id: body.vault_id.clone(),
    })
}

#[derive(Deserialize)]
pub struct CloudReadVaultQuery {
    pub file_id: Option<String>,
    pub vault_id: Option<String>,
}

#[get("/cloud/vaults/read")]
pub async fn cloud_read_vault(
    pool: web::Data<DbPool>,
    session: Session,
    query: web::Query<CloudReadVaultQuery>,
) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized().json(
                serde_json::json!({"error_msg":"session required","code":"SESSION_REQUIRED"}),
            );
        }
    };

    let Some(kind) = selected_provider(pool.get_ref(), &vault_id).await else {
        return provider_error_response(
            ProviderErrorKind::AuthRequired,
            "active cloud provider is not connected",
        );
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
            if let Some(fid) = b.remote_file_id {
                fid
            } else {
                return provider_error_response(
                    ProviderErrorKind::VaultNotFound,
                    "vault not bound to provider file",
                );
            }
        } else {
            // Fallback: list and find by vault_id
            let access_token =
                match token_store::get_valid_access_token(pool.get_ref(), kind, &vault_id).await {
                    Ok(t) => t,
                    Err(e) => return e.into_response(),
                };
            let Some(impl_) = provider::provider(kind) else {
                return provider_error_response(
                    ProviderErrorKind::AuthRequired,
                    "provider authorization required",
                );
            };
            let list = match impl_.list_vault_files(&access_token).await {
                Ok(l) => l,
                Err(e) => return e.into_response(),
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
        match token_store::get_valid_access_token(pool.get_ref(), kind, &vault_id).await {
            Ok(t) => t,
            Err(e) => return e.into_response(),
        };

    let Some(impl_) = provider::provider(kind) else {
        return provider_error_response(
            ProviderErrorKind::AuthRequired,
            "provider authorization required",
        );
    };

    match impl_.read_vault_file(&access_token, &file_id).await {
        Ok((bytes, revision)) => {
            // Return package as base64 to avoid binary JSON issues
            let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
            HttpResponse::Ok().json(serde_json::json!({
                "package": b64,
                "remote_revision": revision,
                "file_id": file_id
            }))
        }
        Err(e) => e.into_response(),
    }
}

#[derive(Deserialize)]
pub struct CloudReplaceVaultRequest {
    pub vault_id: Option<String>,
    pub file_id: Option<String>,
    pub package: String,
    pub if_match_revision: Option<String>,
}

#[derive(Serialize)]
struct CloudReplaceVaultResponse {
    remote_revision: String,
    file_id: String,
}

#[post("/cloud/vaults/replace")]
pub async fn cloud_replace_vault(
    pool: web::Data<DbPool>,
    session: Session,
    body: web::Json<CloudReplaceVaultRequest>,
) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized().json(
                serde_json::json!({"error_msg":"session required","code":"SESSION_REQUIRED"}),
            );
        }
    };

    let Some(kind) = selected_provider(pool.get_ref(), &vault_id).await else {
        return provider_error_response(
            ProviderErrorKind::AuthRequired,
            "active cloud provider is not connected",
        );
    };

    let file_id = if let Some(fid) = &body.file_id {
        fid.clone()
    } else if body.vault_id.is_some() {
        let binding = CloudBindingEntity::find()
            .filter(cloud_binding::Column::VaultId.eq(&vault_id))
            .one(pool.get_ref())
            .await
            .unwrap_or(None);
        if let Some(b) = binding.and_then(|b| b.remote_file_id) {
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

    // Envelope-level validation only (vault id + logical revision); the
    // snapshot stays opaque ciphertext.
    let header = match package::parse_header(&package_bytes, &vault_id) {
        Ok(h) => h,
        Err(code) => return provider_error_response(ProviderErrorKind::PackageInvalid, code),
    };

    let access_token =
        match token_store::get_valid_access_token(pool.get_ref(), kind, &vault_id).await {
            Ok(t) => t,
            Err(_) => {
                return provider_error_response(
                    ProviderErrorKind::AuthRequired,
                    "provider authorization required",
                );
            }
        };

    let Some(impl_) = provider::provider(kind) else {
        return provider_error_response(
            ProviderErrorKind::AuthRequired,
            "provider authorization required",
        );
    };

    match impl_
        .conditional_write(
            &access_token,
            &file_id,
            &package_bytes,
            body.if_match_revision.as_deref(),
        )
        .await
    {
        Ok(new_rev) => {
            // Update the binding revision and the backup watermark together. A
            // Drive write that updated only `remote_revision` would leave
            // Settings reporting the backup as stale when it is not.
            if CloudBindingEntity::find()
                .filter(cloud_binding::Column::VaultId.eq(&vault_id))
                .one(pool.get_ref())
                .await
                .ok()
                .flatten()
                .is_some()
            {
                mirror::mark_mirrored(
                    pool.get_ref(),
                    &vault_id,
                    header.logical_revision,
                    Some(&new_rev),
                )
                .await;
            }
            HttpResponse::Ok().json(CloudReplaceVaultResponse {
                remote_revision: new_rev,
                file_id: file_id.clone(),
            })
        }
        Err(e) => e.into_response(),
    }
}

#[derive(Deserialize)]
pub struct CloudDeleteVaultRequest {
    pub file_id: Option<String>,
    pub vault_id: Option<String>,
}

#[derive(Deserialize)]
pub struct CloudBindingUpsertRequest {
    pub vault_id: String,
    pub remote_file_id: Option<String>,
    pub remote_revision: Option<String>,
}

#[post("/cloud/binding")]
pub async fn cloud_upsert_binding(
    pool: web::Data<DbPool>,
    session: Session,
    query: web::Query<AuthStartQuery>,
    body: web::Json<CloudBindingUpsertRequest>,
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
    // Authorization comes from the session, never the body. Without this check
    // a session for vault A could rewrite the Drive binding of vault B, which
    // would redirect B's disaster-recovery copy.
    if body.vault_id != vault_id {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error_msg":"vault_id does not match session","code":"VAULT_MISMATCH"}));
    }
    let kind = match ProviderKind::parse(&query.provider) {
        Ok(kind) => kind,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({"code":"UNKNOWN_PROVIDER"}));
        }
    };
    let (remote_file_id, remote_revision, enrollment) = if let Some(file_id) =
        body.remote_file_id.as_deref()
    {
        if file_id.trim().is_empty() {
            return HttpResponse::BadRequest().json(serde_json::json!({"error_msg":"remote_file_id must not be empty","code":"INVALID_INPUT"}));
        }
        (file_id.to_string(), body.remote_revision.clone(), false)
    } else {
        // Provider switch is an explicit action. Build the package from the
        // server-authoritative ciphertext, adopt/create the target provider's
        // file, then mirror_now repairs an adopted stale copy before claiming
        // any watermark. Existing credentials for this provider are retained.
        let access_token =
            match token_store::get_valid_access_token(pool.get_ref(), kind, &vault_id).await {
                Ok(token) => token,
                Err(err) => return err.into_response(),
            };
        let Some(impl_) = provider::provider(kind) else {
            return provider_error_response(
                ProviderErrorKind::AuthRequired,
                "provider is not configured on this server",
            );
        };
        let vault = match crate::entity::vault::Entity::find_by_id(&vault_id)
            .one(pool.get_ref())
            .await
        {
            Ok(Some(vault)) => vault,
            Ok(None) => {
                return HttpResponse::NotFound()
                    .json(serde_json::json!({"code":"VAULT_NOT_FOUND"}));
            }
            Err(err) => {
                log::error!("cloud switch could not load vault: {err}");
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"code":"DB_ERROR"}));
            }
        };
        let bytes = match package::build(&vault) {
            Ok(bytes) => bytes,
            Err(code) => return provider_error_response(ProviderErrorKind::PackageInvalid, code),
        };
        let file = match impl_
            .create_vault_file(&access_token, &vault_id, &bytes)
            .await
        {
            Ok(file) => file,
            Err(err) => return err.into_response(),
        };
        (file.file_id, Some(file.revision), true)
    };
    let now = chrono::Utc::now();
    let existing = CloudBindingEntity::find()
        .filter(cloud_binding::Column::VaultId.eq(&body.vault_id))
        .one(pool.get_ref())
        .await
        .unwrap_or(None);
    let provider_acct = CloudTokenEntity::find()
        .filter(cloud_token::Column::VaultId.eq(&vault_id))
        .filter(cloud_token::Column::ProviderKind.eq(kind.as_str()))
        .one(pool.get_ref())
        .await
        .ok()
        .flatten()
        .and_then(|t| t.provider_account_id);

    // This endpoint is called right after a provider *import*: the vault was just
    // registered from that exact package, so the Drive copy already holds the
    // local vault's current version. Recording that keeps Settings from
    // reporting a fresh import as an unmirrored backup — and the next vault
    // write will advance it normally.
    let current_version = crate::entity::vault::Entity::find_by_id(&body.vault_id)
        .one(pool.get_ref())
        .await
        .ok()
        .flatten()
        .map(|v| v.version);

    if let Some(existing) = existing {
        let mut am: cloud_binding::ActiveModel = existing.into();
        am.provider_kind = Set(kind.as_str().to_string());
        am.remote_file_id = Set(Some(remote_file_id.clone()));
        if let Some(rev) = &remote_revision {
            am.remote_revision = Set(Some(rev.clone()));
        }
        am.provider_account_id = Set(provider_acct);
        if let Some(v) = current_version {
            am.mirrored_vault_version = Set(if enrollment { None } else { Some(v) });
            am.sync_status = Set(if enrollment {
                "pending".to_string()
            } else {
                "idle".to_string()
            });
            am.last_mirror_error = Set(None);
        }
        am.updated_at = Set(now.into());
        if let Err(e) = am.update(pool.get_ref()).await {
            log::error!("failed to update cloud binding: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error_msg":"failed to persist cloud binding","code":"DB_ERROR"}));
        }
    } else {
        let am = cloud_binding::ActiveModel {
            vault_id: Set(body.vault_id.clone()),
            provider_kind: Set(kind.as_str().to_string()),
            provider_account_id: Set(provider_acct),
            remote_file_id: Set(Some(remote_file_id.clone())),
            remote_revision: Set(remote_revision.clone()),
            sync_status: Set(if enrollment {
                "pending".to_string()
            } else {
                "idle".to_string()
            }),
            mirrored_vault_version: Set(if enrollment { None } else { current_version }),
            last_mirrored_at: Set((!enrollment)
                .then_some(current_version)
                .flatten()
                .map(|_| now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))),
            last_mirror_error: Set(None),
            created_at: Set(now.into()),
            updated_at: Set(now.into()),
        };
        if let Err(e) = am.insert(pool.get_ref()).await {
            log::error!("failed to insert cloud binding: {:?}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error_msg":"failed to persist cloud binding","code":"DB_ERROR"}));
        }
    }
    if enrollment {
        let _ = mirror::mirror_now(pool.get_ref(), &vault_id).await;
    }
    HttpResponse::Ok().json(serde_json::json!({"upserted": true, "vault_id": body.vault_id, "provider_kind": kind.as_str(), "remote_file_id": remote_file_id, "remote_revision": remote_revision}))
}

#[derive(Deserialize)]
pub struct LinkPendingRequest {
    pub state: String,
}

#[post("/cloud/link-pending")]
pub async fn cloud_link_pending(
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
    match oauth_flow::link_pending_to_vault(pool.get_ref(), &body.state, &vault_id).await {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({"linked": true})),
        Err(e) => HttpResponse::BadRequest()
            .json(serde_json::json!({"error_msg": e.redacted_detail(), "code":"LINK_FAILED"})),
    }
}

#[derive(Deserialize)]
pub struct PendingVaultsQuery {
    pub state: String,
}

#[get("/cloud/vaults/pending")]
pub async fn cloud_list_vaults_pending(
    pool: web::Data<DbPool>,
    query: web::Query<PendingVaultsQuery>,
) -> HttpResponse {
    // Use pending token to list cloud vaults without requiring local session
    let pending = match cloud_pending_token::Entity::find_by_id(query.state.clone())
        .one(pool.get_ref())
        .await
    {
        Ok(Some(p)) => p,
        Ok(None) => {
            return provider_error_response(
                ProviderErrorKind::AuthRequired,
                "pending cloud auth not found or expired",
            );
        }
        Err(e) => {
            log::error!("failed to fetch pending token: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error_msg":"db error","code":"DB_ERROR"}));
        }
    };
    // Simplified: use the stored access token; a pending flow has no refresh
    // cycle of its own.
    let kind = match ProviderKind::parse(&pending.provider_kind) {
        Ok(kind) => kind,
        Err(err) => {
            return provider_error_response(
                ProviderErrorKind::AuthRequired,
                &format!("pending provider is unavailable: {err}"),
            );
        }
    };
    let access_token = pending.access_token.clone();
    let Some(impl_) = provider::provider(kind) else {
        return provider_error_response(
            ProviderErrorKind::AuthRequired,
            "provider authorization required",
        );
    };
    match impl_.list_vault_files(&access_token).await {
        Ok(vaults) => HttpResponse::Ok().json(serde_json::json!({"vaults": vaults})),
        Err(e) => e.into_response(),
    }
}

#[derive(Deserialize)]
pub struct PendingReadQuery {
    pub state: String,
    pub file_id: String,
}

#[get("/cloud/vaults/pending/read")]
pub async fn cloud_read_vault_pending(
    pool: web::Data<DbPool>,
    query: web::Query<PendingReadQuery>,
) -> HttpResponse {
    let pending = match cloud_pending_token::Entity::find_by_id(query.state.clone())
        .one(pool.get_ref())
        .await
    {
        Ok(Some(p)) => p,
        Ok(None) => {
            return provider_error_response(
                ProviderErrorKind::AuthRequired,
                "pending cloud auth not found or expired",
            );
        }
        Err(e) => {
            log::error!("failed to fetch pending token: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error_msg":"db error","code":"DB_ERROR"}));
        }
    };
    let kind = match ProviderKind::parse(&pending.provider_kind) {
        Ok(kind) => kind,
        Err(err) => {
            return provider_error_response(
                ProviderErrorKind::AuthRequired,
                &format!("pending provider is unavailable: {err}"),
            );
        }
    };
    let access_token = pending.access_token.clone();
    let Some(impl_) = provider::provider(kind) else {
        return provider_error_response(
            ProviderErrorKind::AuthRequired,
            "provider authorization required",
        );
    };
    match impl_.read_vault_file(&access_token, &query.file_id).await {
        Ok((bytes, revision)) => {
            let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
            HttpResponse::Ok().json(serde_json::json!({
                "package": b64,
                "remote_revision": revision,
                "file_id": query.file_id
            }))
        }
        Err(e) => e.into_response(),
    }
}

#[post("/cloud/vaults/delete")]
pub async fn cloud_delete_vault(
    pool: web::Data<DbPool>,
    session: Session,
    body: web::Json<CloudDeleteVaultRequest>,
) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return HttpResponse::Unauthorized().json(
                serde_json::json!({"error_msg":"session required","code":"SESSION_REQUIRED"}),
            );
        }
    };

    let Some(kind) = selected_provider(pool.get_ref(), &vault_id).await else {
        return provider_error_response(
            ProviderErrorKind::AuthRequired,
            "active cloud provider is not connected",
        );
    };

    let file_id = if let Some(fid) = &body.file_id {
        fid.clone()
    } else if body.vault_id.is_some() {
        let binding = CloudBindingEntity::find()
            .filter(cloud_binding::Column::VaultId.eq(&vault_id))
            .one(pool.get_ref())
            .await
            .unwrap_or(None);
        if let Some(b) = binding.and_then(|b| b.remote_file_id) {
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
        match token_store::get_valid_access_token(pool.get_ref(), kind, &vault_id).await {
            Ok(t) => t,
            Err(e) => return e.into_response(),
        };

    let Some(impl_) = provider::provider(kind) else {
        return provider_error_response(
            ProviderErrorKind::AuthRequired,
            "provider authorization required",
        );
    };

    match impl_.delete_vault_file(&access_token, &file_id).await {
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
        Err(e) => e.into_response(),
    }
}
