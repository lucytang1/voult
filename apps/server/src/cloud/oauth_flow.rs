// Provider-neutral OAuth flow orchestration.
//
// This is the one place that sequences the whole authorization-code dance:
// mint state -> redirect to the provider -> validate state -> exchange code ->
// persist credentials. It knows nothing about any provider's endpoints or
// field names; those live behind `CloudProvider`.
//
// The route handlers in `endpoints/cloud_endpoints.rs` call into here rather
// than assembling the sequence themselves, so adding a provider cannot leave
// the callback path half-migrated.

use chrono::Utc;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};

use crate::cloud::error::{ProviderError, ProviderErrorKind};
use crate::cloud::provider::{self, CloudProvider, ProviderKind};
use crate::cloud::{oauth_state, token_store};
use crate::db::DbPool;
use crate::entity::cloud_pending_token;

const LOG: logger::ServerLogger = logger::Logger::create(logger::ServerContext::Cloud);

/// Session key holding the in-flight state, for a quick cross-check against the
/// database record.
pub const SESSION_CLOUD_OAUTH_STATE: &str = "cloud_oauth_state";

pub fn store_state_in_session(session: &actix_session::Session, state: &str) -> Result<(), String> {
    session
        .insert(SESSION_CLOUD_OAUTH_STATE, state.to_string())
        .map_err(|e| format!("session error: {:?}", e))
}

/// Build the authorization URL for `kind`, minting and persisting CSRF state
/// first.
pub async fn begin(
    pool: &DbPool,
    kind: ProviderKind,
    vault_id: Option<&str>,
) -> Result<(String, String), ProviderError> {
    let impl_ = provider::provider(kind).ok_or_else(|| {
        ProviderError::new(
            ProviderErrorKind::AuthRequired,
            format!("{kind} is not configured on this server"),
        )
    })?;

    let state = oauth_state::generate(pool, kind, vault_id)
        .await
        .map_err(|e| ProviderError::new(ProviderErrorKind::Unknown, e))?;

    Ok((impl_.authorize_url(&state), state))
}

/// Complete a session-bound callback: validate the state, exchange the code, and
/// store the credential against `vault_id`.
pub async fn complete_for_vault(
    pool: &DbPool,
    kind: ProviderKind,
    state: &str,
    code: &str,
    vault_id: &str,
) -> Result<(Option<String>, Option<String>), ProviderError> {
    oauth_state::validate(pool, kind, state, vault_id)
        .await
        .map_err(|e| ProviderError::new(ProviderErrorKind::AuthRequired, e))?;

    let set = exchange(pool, kind, code).await?;

    // Best-effort: a provider that cannot tell us the account name must not stop
    // the backup from working.
    let account = account_of(pool, kind, &set.access_token).await;

    token_store::store_token_set(
        pool,
        kind,
        vault_id,
        &set,
        account.as_ref().and_then(|a| a.account_id.clone()),
        account.as_ref().and_then(|a| a.email.clone()),
    )
    .await?;

    Ok((
        account.as_ref().and_then(|a| a.account_id.clone()),
        account.as_ref().and_then(|a| a.email.clone()),
    ))
}

/// Complete a pre-session callback: validate the state and stash the credential
/// against it, so a vault chosen later can claim it without a second consent.
pub async fn complete_pending(
    pool: &DbPool,
    kind: ProviderKind,
    state: &str,
    code: &str,
) -> Result<(Option<String>, Option<String>), ProviderError> {
    let rec = oauth_state::validate_pending(pool, kind, state)
        .await
        .map_err(|e| ProviderError::new(ProviderErrorKind::AuthRequired, e))?;

    let set = exchange(pool, kind, code).await?;
    let account = account_of(pool, kind, &set.access_token).await;

    store_pending(pool, state, &rec.provider_kind, &set, account.as_ref()).await?;
    oauth_state::consume(pool, state).await;

    Ok((
        account.as_ref().and_then(|a| a.account_id.clone()),
        account.as_ref().and_then(|a| a.email.clone()),
    ))
}

/// Move a pending credential onto a vault that now exists.
///
/// The provider comes from the *pending row*, never from the caller: a client
/// must not be able to claim that a credential minted for one provider belongs
/// to a vault's other provider slot.
pub async fn link_pending_to_vault(
    pool: &DbPool,
    state: &str,
    vault_id: &str,
) -> Result<(), ProviderError> {
    let pending = cloud_pending_token::Entity::find_by_id(state.to_string())
        .one(pool)
        .await
        .map_err(|e| ProviderError::new(ProviderErrorKind::Unknown, format!("db error: {e:?}")))?
        .ok_or_else(|| {
            ProviderError::new(ProviderErrorKind::AuthRequired, "pending token not found")
        })?;

    let kind = ProviderKind::parse(&pending.provider_kind).map_err(|e| {
        ProviderError::new(
            ProviderErrorKind::Unknown,
            format!("pending token names an unusable provider: {}", e.0),
        )
    })?;

    let set = crate::cloud::provider::TokenSet {
        access_token: pending.access_token.clone(),
        refresh_token: pending.refresh_token.clone(),
        token_type: Some(pending.token_type.clone()),
        expires_at: pending.expires_at,
        scope: pending.scope.clone(),
    };

    token_store::store_token_set(
        pool,
        kind,
        vault_id,
        &set,
        pending.provider_account_id.clone(),
        pending.provider_email.clone(),
    )
    .await?;

    cloud_pending_token::Entity::delete_by_id(state.to_string())
        .exec(pool)
        .await
        .map_err(|e| {
            ProviderError::new(
                ProviderErrorKind::Unknown,
                format!("db delete error: {e:?}"),
            )
        })?;
    Ok(())
}

async fn exchange(
    pool: &DbPool,
    kind: ProviderKind,
    code: &str,
) -> Result<crate::cloud::provider::TokenSet, ProviderError> {
    let _ = pool;
    provider::provider(kind)
        .ok_or_else(|| {
            ProviderError::new(
                ProviderErrorKind::AuthRequired,
                format!("{kind} is not configured on this server"),
            )
        })?
        .exchange_code(code)
        .await
}

async fn account_of(
    pool: &DbPool,
    kind: ProviderKind,
    access_token: &str,
) -> Option<crate::cloud::provider::ProviderAccount> {
    let _ = pool;
    let impl_ = provider::provider(kind)?;
    match impl_.account(access_token).await {
        Ok(account) => Some(account),
        Err(e) => {
            // Display-only data: a failure is not worth failing the connection
            // over, but it should be visible in the log.
            LOG.warn(
                format_args!("{kind} account lookup failed: {e}"),
                logger::Metadata::new(),
            );
            None
        }
    }
}

async fn store_pending(
    pool: &DbPool,
    state: &str,
    provider_kind: &str,
    set: &crate::cloud::provider::TokenSet,
    account: Option<&crate::cloud::provider::ProviderAccount>,
) -> Result<(), ProviderError> {
    let db = |e: sea_orm::DbErr| ProviderError::new(ProviderErrorKind::Unknown, format!("{e:?}"));

    // Upsert by deleting first; `state` is the primary key.
    cloud_pending_token::Entity::delete_by_id(state.to_string())
        .exec(pool)
        .await
        .map_err(db)?;

    cloud_pending_token::ActiveModel {
        state: Set(state.to_string()),
        provider_kind: Set(provider_kind.to_string()),
        access_token: Set(set.access_token.clone()),
        refresh_token: Set(set.refresh_token.clone()),
        token_type: Set(set
            .token_type
            .clone()
            .unwrap_or_else(|| "Bearer".to_string())),
        expires_at: Set(set.expires_at),
        scope: Set(set.scope.clone()),
        provider_account_id: Set(account.and_then(|a| a.account_id.clone())),
        provider_email: Set(account.and_then(|a| a.email.clone())),
        // Retained for the future "create a local account" path; unused today.
        local_email: Set(None),
        created_at: Set(Utc::now().into()),
    }
    .insert(pool)
    .await
    .map_err(|e| {
        ProviderError::new(
            ProviderErrorKind::Unknown,
            format!("pending insert error: {e:?}"),
        )
    })?;
    Ok(())
}
