use actix_session::Session;
use actix_web::{HttpResponse, get, http::StatusCode, post, web};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};
use serde::{Deserialize, Serialize};

use crate::cloud::error::{ProviderErrorKind, provider_error_response};
use crate::cloud::provider::{self, CloudProvider, ProviderKind};
use crate::cloud::{mirror, oauth_flow, package, token_store};
use crate::db::DbPool;
use crate::entity::cloud_binding::{self, Entity as CloudBindingEntity};
use crate::entity::cloud_pending_token;
use crate::entity::cloud_token::{self, Entity as CloudTokenEntity};
use crate::error::error_response;
use crate::log_safety::short_id;
use crate::session_auth::session_vault_id;

const LOG: logger::ServerLogger = logger::Logger::create(logger::ServerContext::Cloud);

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
                    LOG.error(
                        format_args!("vault binding has unknown cloud provider: {}", err),
                        logger::Metadata::new(),
                    );
                    None
                }
            };
        }
        Ok(None) => {}
        Err(err) => {
            LOG.error(
                format_args!("failed to resolve cloud binding provider: {}", err),
                logger::Metadata::new(),
            );
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
                LOG.error(
                    format_args!("cloud token has unknown provider: {}", err),
                    logger::Metadata::new(),
                );
                None
            }
        },
        Ok(None) => None,
        Err(err) => {
            LOG.error(
                format_args!("failed to resolve active cloud provider: {}", err),
                logger::Metadata::new(),
            );
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
                LOG.warn(
                    format_args!(
                        "session names vault {} which does not exist; treating as no session",
                        short_id(&id)
                    ),
                    logger::Metadata::new(),
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
            LOG.error(
                format_args!(
                    "failed to list cloud credentials for vault {}: {err}",
                    short_id(&vault_id)
                ),
                logger::Metadata::new(),
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
                LOG.error(
                    format_args!("Failed to start {kind} authorization: {}", e.code()),
                    logger::Metadata::new(),
                );
                return HttpResponse::InternalServerError().json(
                serde_json::json!({"error_msg":"failed to start authorization","code":"DB_ERROR"}),
            );
            }
        };

    // The state is validated against the database row; there is no second copy
    // in the session. (The old `store_state_in_session` write was never read and
    // duplicated a live bearer value into the cookie.)
    LOG.log(
        format_args!(
            "Generated cloud OAuth state for vault {}",
            vault_id_opt
                .as_deref()
                .map(|v| short_id(v))
                .unwrap_or("(pending)")
        ),
        logger::Metadata::new(),
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
        Err(_) => {
            // No valid provider means no landing URL to send the browser back
            // to; answer with the standard error envelope.
            return error_response(
                StatusCode::BAD_REQUEST,
                "unknown provider",
                "OAUTH_UNKNOWN_PROVIDER",
            );
        }
    };
    let Some(impl_) = provider::provider(kind) else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider not configured",
            "OAUTH_PROVIDER_UNCONFIGURED",
        );
    };
    let base = impl_.post_auth_redirect();

    // A provider denial is a normal outcome, not a body to reflect. The
    // provider's `error` string is untrusted (it can contain newlines or HTML);
    // map it to our vocabulary and log only that.
    if query.error.is_some() {
        LOG.warn(
            "cloud OAuth denied by provider",
            logger::metadata! { "provider" => kind.as_str() },
        );
        return failure_redirect(&base, "OAUTH_CANCELLED", kind);
    }

    let (Some(code), Some(state)) = (query.code.as_deref(), query.state.as_deref()) else {
        return failure_redirect(&base, "OAUTH_INVALID_REQUEST", kind);
    };

    let vault_id_opt = live_session_vault_id(pool.get_ref(), &session).await;
    let outcome = if let Some(vault_id) = &vault_id_opt {
        oauth_flow::complete_for_vault(pool.get_ref(), kind, state, code, vault_id).await
    } else {
        oauth_flow::complete_pending(pool.get_ref(), kind, state, code).await
    };

    match outcome {
        Ok(()) => {
            if let Some(vault_id) = &vault_id_opt {
                LOG.log(
                    "cloud OAuth connected",
                    logger::metadata! {
                        "provider" => kind.as_str(),
                        "vault" => short_id(vault_id),
                    },
                );
                redirect(
                    &base,
                    &[("cloud_connected", "1"), ("provider", kind.as_str())],
                )
            } else {
                LOG.log(
                    "cloud OAuth connected (pending)",
                    logger::metadata! { "provider" => kind.as_str() },
                );
                // The client needs the state to read the pending token's vault
                // list and to link it after creating the local vault. It is a
                // live bearer handle, so it is never logged (see
                // `oauth_state`); this is its only remaining exposure.
                redirect(
                    &base,
                    &[("cloud_state", state), ("provider", kind.as_str())],
                )
            }
        }
        Err(oauth_flow::CallbackError::StateRejected) => {
            // The specific reason is logged by `oauth_state` as a closed word;
            // the browser gets only the coarse code.
            failure_redirect(&base, "OAUTH_INVALID_STATE", kind)
        }
        Err(oauth_flow::CallbackError::Provider(e)) => {
            LOG.warn(
                "cloud OAuth exchange failed",
                logger::metadata! {
                    "provider" => kind.as_str(),
                    "code" => e.code(),
                },
            );
            failure_redirect(&base, "OAUTH_EXCHANGE_FAILED", kind)
        }
    }
}

/// Build a `Found` response to `base` plus query parameters.
fn redirect(base: &str, params: &[(&str, &str)]) -> HttpResponse {
    HttpResponse::Found()
        .insert_header(("Location", with_params(base, params)))
        .finish()
}

/// A fixed browser-visible failure. No detail, no email, no provider text.
fn failure_redirect(base: &str, code: &'static str, kind: ProviderKind) -> HttpResponse {
    redirect(base, &[("cloud_error", code), ("provider", kind.as_str())])
}

/// Append query parameters to a landing URL without dropping an existing query.
///
/// Values are URL-encoded. Keeping an existing `?` correct means a configured
/// landing page with its own parameters does not produce `?a=1?b=2`.
pub(crate) fn with_params(base: &str, params: &[(&str, &str)]) -> String {
    let separator = if base.contains('?') { '&' } else { '?' };
    let encoded = params
        .iter()
        .map(|(key, value)| format!("{key}={}", urlencoding::encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{base}{separator}{encoded}")
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
            LOG.error(
                format_args!("failed to fetch cloud token: {:?}", e),
                logger::Metadata::new(),
            );
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
        LOG.error(
            format_args!("failed to delete cloud token: {}", e),
            logger::Metadata::new(),
        );
    }

    // cloud_binding is preserved: disconnecting removes the credential, not the
    // vault, and not the remote file. Recording `auth_required` immediately (and
    // bumping the binding generation in the same write) means Settings shows
    // "paused — reconnect" right away instead of waiting for a mirror to fail,
    // and any upload still in flight can no longer report the copy as current.
    mirror::mark_disconnected(pool.get_ref(), &vault_id).await;
    LOG.log(
        format_args!("cloud disconnect for user {}", short_id(&vault_id)),
        logger::Metadata::new(),
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
    /// Which incarnation of this binding the numbers above describe. The client
    /// uses it to ignore a mutation response that was in flight across a switch.
    binding_generation: i32,
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
            binding_generation: b.binding_generation,
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
            LOG.error(
                format_args!("failed to fetch pending: {:?}", e),
                logger::Metadata::new(),
            );
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
            LOG.error(
                format_args!("failed to fetch binding: {:?}", e),
                logger::Metadata::new(),
            );
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
            LOG.error(
                format_args!("failed to list bindings: {:?}", e),
                logger::Metadata::new(),
            );
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
/// to learn its outcome. This awaits a *forced* pass — it verifies the live
/// provider revision (so a deleted or externally changed copy is reported rather
/// than hidden behind a current watermark) and uploads even when the recorded
/// watermark says the copy is current — and returns the real result. It still
/// refuses to overwrite a copy that moved: "Back up now" is "try again", never
/// "overwrite". A pass already running is waited for (bounded), so this never
/// races one and reports a false conflict.
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
        mirror::MirrorOutcome::Mirrored { vault_version } => LOG.log(
            format_args!(
                "Manual Drive backup completed for vault {} at version {}",
                short_id(&vault_id),
                vault_version
            ),
            logger::Metadata::new(),
        ),
        mirror::MirrorOutcome::Conflict => LOG.warn(
            format_args!(
                "Manual Drive backup refused for vault {}: the Drive copy changed since last sync",
                short_id(&vault_id)
            ),
            logger::Metadata::new(),
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
            LOG.warn(
                format_args!(
                    "Rejected cloud package for vault {}: {}",
                    short_id(&vault_id),
                    code
                ),
                logger::Metadata::new(),
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
        // This row is about to describe a new provider file. Bumping the
        // generation invalidates any pass still running against the old one.
        let next_generation = existing.binding_generation.saturating_add(1);
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
        am.binding_generation = Set(next_generation);
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
            binding_generation: Set(0),
            created_at: Set(now.into()),
            updated_at: Set(now.into()),
        };
        let _ = am.insert(pool.get_ref()).await;
    }

    let enrollment_mirror = mirror::mirror_now(pool.get_ref(), &vault_id).await;
    LOG.log(
        format_args!(
            "Created cloud vault {} file {} at logical revision {}",
            short_id(&body.vault_id),
            short_id(&created.file_id),
            header.logical_revision
        ),
        logger::Metadata::new(),
    );
    if let mirror::MirrorOutcome::Error { code } = &enrollment_mirror {
        LOG.warn(
            format_args!(
                "Cloud enrollment mirror for vault {} did not converge: {}",
                short_id(&vault_id),
                code
            ),
            logger::Metadata::new(),
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
            // Settings reporting the backup as stale when it is not. Conditional
            // on the generation the row is at now, so a switch that happened
            // while this write was in flight keeps its own state.
            if let Ok(Some(binding)) = CloudBindingEntity::find()
                .filter(cloud_binding::Column::VaultId.eq(&vault_id))
                .one(pool.get_ref())
                .await
            {
                mirror::mark_mirrored(
                    pool.get_ref(),
                    &mirror::BindingGuard::of(&binding),
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
    let mut claim = None;
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
        // file, then mirror repairs an adopted stale copy before any watermark is
        // claimed. Existing credentials for this provider are retained.
        //
        // The claim is taken BEFORE anything is created, and held across the
        // binding write and the enrollment mirror. Switching while an upload is
        // in flight therefore fails closed with no side effects — no orphan file
        // at the target provider, no half-written binding — and a vault write
        // during the switch cannot start a second pass against the half-written
        // row.
        let Some(acquired) = mirror::claim_waiting(&vault_id, mirror::SWITCH_CLAIM_WAIT).await
        else {
            LOG.log(
                format_args!(
                    "cloud switch for vault {} refused: a backup is still running",
                    short_id(&vault_id)
                ),
                logger::Metadata::new(),
            );
            return HttpResponse::Conflict().json(serde_json::json!({
                "error_msg": "a backup is still running; try again in a moment",
                "code": "BACKUP_IN_PROGRESS",
            }));
        };
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
                LOG.error(
                    format_args!("cloud switch could not load vault: {err}"),
                    logger::Metadata::new(),
                );
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
        claim = Some(acquired);
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
        // This row is about to describe a different provider file. Bumping the
        // generation invalidates any mirror pass still running against the old
        // one, so it can no longer stamp its revision or status here.
        let next_generation = existing.binding_generation.saturating_add(1);
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
        am.binding_generation = Set(next_generation);
        am.updated_at = Set(now.into());
        if let Err(e) = am.update(pool.get_ref()).await {
            LOG.error(
                format_args!("failed to update cloud binding: {:?}", e),
                logger::Metadata::new(),
            );
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
            binding_generation: Set(0),
            created_at: Set(now.into()),
            updated_at: Set(now.into()),
        };
        if let Err(e) = am.insert(pool.get_ref()).await {
            LOG.error(
                format_args!("failed to insert cloud binding: {:?}", e),
                logger::Metadata::new(),
            );
            return HttpResponse::InternalServerError().json(serde_json::json!({"error_msg":"failed to persist cloud binding","code":"DB_ERROR"}));
        }
    }
    // The switch already holds the claim, so the post-enrollment pass runs under
    // it. `mirror_now` would wait on a claim we own and time out as MIRROR_BUSY.
    if let Some(claim) = claim {
        mirror::mirror_held(pool.get_ref(), claim, mirror::MirrorMode::Auto).await;
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
            LOG.error(
                format_args!("failed to fetch pending token: {:?}", e),
                logger::Metadata::new(),
            );
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
            LOG.error(
                format_args!("failed to fetch pending token: {:?}", e),
                logger::Metadata::new(),
            );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DbPool;
    use crate::endpoints::register;
    use actix_web::cookie::{Cookie, Key};
    use actix_web::{App, test as actix_test};
    use migration::MigratorTrait;
    use sea_orm::{Database, EntityTrait};
    use serde_json::json;

    const VAULT_ID: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3302";

    async fn test_pool() -> DbPool {
        let pool = Database::connect("sqlite::memory:").await.expect("connect");
        migration::Migrator::up(&pool, None).await.expect("migrate");
        pool
    }

    /// A minimal vault row, for tests that only exercise binding bookkeeping.
    async fn seed_vault(pool: &DbPool) {
        use crate::entity::vault;
        use sea_orm::Set;

        let am = vault::ActiveModel {
            id: Set(VAULT_ID.to_string()),
            vault: Set("Y2lwaGVydGV4dA==".to_string()),
            salt: Set("c2FsdA==".to_string()),
            iterations: Set(60_000),
            vaultiv: Set("aXY=".to_string()),
            vault_verifier: Set("dmVyaWZpZXI=".to_string()),
            version: Set(1),
            crypto_version: Set(2),
            ..Default::default()
        };
        am.insert(pool).await.expect("insert vault");
    }

    /// Registers a vault and returns `(app, session cookie)`, mirroring the
    /// harness in `update_vault`'s tests: `call_service` does not carry cookies,
    /// so the cookie from `/register` has to be replayed by hand.
    macro_rules! authenticated_app {
        ($pool:expr) => {{
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new($pool.clone()))
                    .wrap(
                        actix_session::SessionMiddleware::builder(
                            actix_session::storage::CookieSessionStore::default(),
                            // Cookie-session keys must be at least 64 bytes.
                            Key::from(
                                b"test-key-for-session-middleware-must-be-at-least-64-bytes-long!!",
                            ),
                        )
                        .cookie_name("voult_session".to_string())
                        .build(),
                    )
                    .service(register::register)
                    .service(super::cloud_upsert_binding),
            )
            .await;
            let resp = actix_test::call_service(
                &app,
                actix_test::TestRequest::post()
                    .uri("/register")
                    .set_json(json!({
                        "vault_id": VAULT_ID,
                        "vault_verifier": "dmVyaWZpZXI=",
                        "salt": "c2FsdA==",
                        "iterations": 60000,
                        "vaultiv": "aXY=",
                        "vault": "Y2lwaGVydGV4dA==",
                        "crypto_version": 2,
                        "vault_key_wrap": "d3JhcA==",
                        "vault_key_wrap_iv": "d2l2",
                        "recovery_verifier": "cmVjb3ZlcnktdmVyaWZpZXI=",
                        "recovery_salt": "cmVjb3Zlcnktc2FsdA==",
                        "recovery_wrap": "cmVjb3Zlcnktd3JhcA==",
                        "recovery_wrap_iv": "cmVjdml2",
                    }))
                    .to_request(),
            )
            .await;
            assert!(resp.status().is_success(), "register must seed the session");
            let cookie: Cookie<'static> = resp
                .response()
                .cookies()
                .find(|c| c.name() == "voult_session")
                .expect("register must set the session cookie")
                .clone()
                .into_owned();
            (app, cookie)
        }};
    }

    /// A provider switch must refuse to start while a mirror holds the vault, and
    /// it must refuse *before* touching the target provider: an orphan file plus a
    /// half-written binding is exactly what the claim exists to prevent.
    #[tokio::test]
    async fn switch_is_refused_while_a_backup_is_in_flight() {
        let pool = test_pool().await;
        let (app, cookie) = authenticated_app!(pool);

        // Stand in for an upload that is still running.
        let held =
            crate::cloud::mirror::claim_waiting(VAULT_ID, std::time::Duration::from_millis(1))
                .await
                .expect("claim");

        let resp = actix_test::call_service(
            &app,
            actix_test::TestRequest::post()
                .uri("/cloud/binding?provider=dropbox")
                .cookie(cookie)
                .set_json(json!({"vault_id": VAULT_ID}))
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), 409, "a busy backup must refuse the switch");
        let body: serde_json::Value = actix_test::read_body_json(resp).await;
        assert_eq!(body["code"], "BACKUP_IN_PROGRESS");
        assert!(
            CloudBindingEntity::find()
                .all(&pool)
                .await
                .expect("query")
                .is_empty(),
            "a refused switch must not write a binding"
        );

        drop(held);
    }

    /// Disconnecting must bump the generation and say why the copy stopped
    /// moving, in one write: an upload in flight is then unable to report the
    /// backup as current afterwards.
    #[tokio::test]
    async fn disconnect_pauses_the_binding_and_invalidates_inflight_state() {
        use sea_orm::{ActiveModelTrait, Set};

        let pool = test_pool().await;
        seed_vault(&pool).await;
        let binding = cloud_binding::ActiveModel {
            vault_id: Set(VAULT_ID.to_string()),
            provider_kind: Set(ProviderKind::Dropbox.as_str().to_string()),
            remote_file_id: Set(Some("dbx-file".to_string())),
            remote_revision: Set(Some("rev-1".to_string())),
            sync_status: Set("idle".to_string()),
            mirrored_vault_version: Set(Some(1)),
            ..Default::default()
        };
        binding.insert(&pool).await.expect("seed binding");

        let before = CloudBindingEntity::find_by_id(VAULT_ID.to_string())
            .one(&pool)
            .await
            .expect("query")
            .expect("binding");

        crate::cloud::mirror::mark_disconnected(&pool, VAULT_ID).await;

        let after = CloudBindingEntity::find_by_id(VAULT_ID.to_string())
            .one(&pool)
            .await
            .expect("query")
            .expect("binding");
        assert_eq!(after.sync_status, "auth_required");
        assert_eq!(after.last_mirror_error.as_deref(), Some("DISCONNECTED"));
        assert_eq!(
            after.binding_generation,
            before.binding_generation + 1,
            "a disconnect must invalidate passes that started before it"
        );
        assert_eq!(
            after.remote_file_id.as_deref(),
            Some("dbx-file"),
            "the remote copy is preserved; only the credential is gone"
        );
        assert_eq!(after.mirrored_vault_version, Some(1));
    }

    #[test]
    fn landing_urls_keep_their_existing_query() {
        assert_eq!(
            with_params(
                "http://localhost:8080/vault",
                &[("cloud_connected", "1"), ("provider", "google_drive")]
            ),
            "http://localhost:8080/vault?cloud_connected=1&provider=google_drive"
        );
        assert_eq!(
            with_params(
                "https://app.test/vault?from=oauth",
                &[("cloud_error", "OAUTH_CANCELLED")]
            ),
            "https://app.test/vault?from=oauth&cloud_error=OAUTH_CANCELLED"
        );
    }

    #[test]
    fn redirect_values_are_url_encoded() {
        assert_eq!(
            with_params("https://app.test/vault", &[("cloud_state", "a b&c")]),
            "https://app.test/vault?cloud_state=a%20b%26c"
        );
    }

    fn location(response: &HttpResponse) -> &str {
        response
            .headers()
            .get("Location")
            .expect("redirect must carry Location")
            .to_str()
            .expect("Location is ASCII")
    }

    #[test]
    fn success_redirects_carry_no_pii() {
        let bound = redirect(
            "https://app.test/vault",
            &[("cloud_connected", "1"), ("provider", "google_drive")],
        );
        let bound = location(&bound);
        assert_eq!(
            bound,
            "https://app.test/vault?cloud_connected=1&provider=google_drive"
        );
        assert!(!bound.contains("email"));
        assert!(!bound.contains("cloud_state"));

        let pending = redirect(
            "https://app.test/vault",
            &[("cloud_state", "state-1"), ("provider", "google_drive")],
        );
        let pending = location(&pending);
        assert_eq!(
            pending,
            "https://app.test/vault?cloud_state=state-1&provider=google_drive"
        );
        assert!(!pending.contains("email"));
    }

    #[test]
    fn failure_redirects_carry_only_a_fixed_code() {
        for code in [
            "OAUTH_CANCELLED",
            "OAUTH_INVALID_REQUEST",
            "OAUTH_INVALID_STATE",
            "OAUTH_EXCHANGE_FAILED",
        ] {
            let response =
                failure_redirect("https://app.test/vault", code, ProviderKind::GoogleDrive);
            let location = location(&response);

            assert_eq!(
                location,
                format!("https://app.test/vault?cloud_error={code}&provider=google_drive")
            );
            assert!(!location.contains("email"));
            assert!(!location.contains("detail"));
            assert!(!location.contains("state="));
            assert!(!location.contains("code="));
        }
    }

    #[actix_web::test]
    async fn unknown_provider_returns_the_fixed_envelope() {
        use actix_web::cookie::Key;

        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(test_pool().await))
                .wrap(actix_session::SessionMiddleware::new(
                    actix_session::storage::CookieSessionStore::default(),
                    Key::from(b"test-key-for-session-middleware-must-be-at-least-64-bytes-long!!"),
                ))
                .service(cloud_oauth_callback),
        )
        .await;

        let resp = actix_test::call_service(
            &app,
            actix_test::TestRequest::get()
                .uri("/cloud/oauth/callback?provider=bogus")
                .to_request(),
        )
        .await;

        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = actix_test::read_body_json(resp).await;
        assert_eq!(body["code"], "OAUTH_UNKNOWN_PROVIDER");
        assert_eq!(body["error_msg"], "unknown provider");
    }
}
