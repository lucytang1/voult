//! Credential storage and refresh policy.
//!
//! This module owns the *policy* — "refresh when near expiry", "persist a
//! rotated refresh token before using the new access token" — and is generic
//! over [`ProviderKind`]. It contains no provider URL, scope, or field name; the
//! provider-specific parts are reached through [`CloudProvider`].

use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

use crate::cloud::error::{ProviderError, ProviderErrorKind};
use crate::cloud::provider::{self, CloudProvider, ProviderKind, StoredToken, TokenSet};
use crate::db::DbPool;
use crate::entity::cloud_token::{self, Entity as CloudTokenEntity};

/// Refresh this many seconds before actual expiry, so a token cannot expire in
/// the middle of an upload.
const EXPIRY_SKEW_SECONDS: i64 = 60;

/// Return a usable access token for `(vault_id, kind)`, refreshing when it is
/// within [`EXPIRY_SKEW_SECONDS`] of expiry.
///
/// The lookup is scoped by provider on purpose: a retained credential for a
/// different provider must never satisfy this, which is exactly why
/// `cloud_token` is keyed by `(vault_id, provider_kind)`.
pub async fn get_valid_access_token(
    pool: &DbPool,
    kind: ProviderKind,
    vault_id: &str,
) -> Result<String, ProviderError> {
    let token = load(pool, kind, vault_id).await?;
    if token.expires_at - EXPIRY_SKEW_SECONDS > Utc::now().timestamp() {
        return Ok(token.access_token);
    }

    // No refresh token means the provider would have to prompt for consent
    // again; `CloudProvider::refresh` reports that as AuthRequired, so there is
    // nothing to pre-check here.
    let impl_ = provider::provider(kind).ok_or_else(|| {
        ProviderError::new(
            ProviderErrorKind::AuthRequired,
            format!("{kind} is not configured on this server"),
        )
    })?;

    let refreshed = impl_
        .refresh(&StoredToken {
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            token_type: token.token_type,
            expires_at: token.expires_at,
            scope: token.scope,
        })
        .await?;

    // CONTRACT (see CloudProvider::refresh): a provider that rotates refresh
    // tokens returns the new one here. Persisting it is this module's job and
    // is deliberately a hard failure — losing a rotated refresh token is
    // permanent auth loss, and a provider's rotation policy means the old one
    // may already be dead.
    persist_refreshed(pool, kind, vault_id, &refreshed).await?;

    Ok(refreshed.access_token)
}

/// Write a token set obtained from an authorization-code exchange.
pub async fn store_token_set(
    pool: &DbPool,
    kind: ProviderKind,
    vault_id: &str,
    set: &TokenSet,
    account_id: Option<String>,
    email: Option<String>,
) -> Result<(), ProviderError> {
    let kind_str = kind.as_str();
    let existing = CloudTokenEntity::find()
        .filter(cloud_token::Column::VaultId.eq(vault_id))
        .filter(cloud_token::Column::ProviderKind.eq(kind_str))
        .one(pool)
        .await
        .map_err(|e| db_error("lookup token", e))?;

    match existing {
        Some(existing) => {
            let mut am: cloud_token::ActiveModel = existing.into();
            am.access_token = Set(set.access_token.clone());
            // `None` means "the provider did not issue a new one" (Google only
            // sends refresh tokens on first consent), so the stored value is
            // kept. It never means revoke.
            if set.refresh_token.is_some() {
                am.refresh_token = Set(set.refresh_token.clone());
            }
            am.token_type = Set(set
                .token_type
                .clone()
                .unwrap_or_else(|| "Bearer".to_string()));
            am.expires_at = Set(set.expires_at);
            am.scope = Set(set.scope.clone());
            am.provider_account_id = Set(account_id);
            am.provider_email = Set(email);
            am.updated_at = Set(Utc::now().into());
            am.update(pool)
                .await
                .map_err(|e| db_error("update token", e))?;
        }
        None => {
            let am = cloud_token::ActiveModel {
                vault_id: Set(vault_id.to_string()),
                provider_kind: Set(kind_str.to_string()),
                access_token: Set(set.access_token.clone()),
                refresh_token: Set(set.refresh_token.clone()),
                token_type: Set(set
                    .token_type
                    .clone()
                    .unwrap_or_else(|| "Bearer".to_string())),
                expires_at: Set(set.expires_at),
                scope: Set(set.scope.clone()),
                provider_account_id: Set(account_id),
                provider_email: Set(email),
                updated_at: Set(Utc::now().into()),
            };
            am.insert(pool)
                .await
                .map_err(|e| db_error("insert token", e))?;
        }
    }
    Ok(())
}

/// The stored credential for `(vault_id, kind)`, if any.
pub async fn load(
    pool: &DbPool,
    kind: ProviderKind,
    vault_id: &str,
) -> Result<cloud_token::Model, ProviderError> {
    CloudTokenEntity::find()
        .filter(cloud_token::Column::VaultId.eq(vault_id))
        .filter(cloud_token::Column::ProviderKind.eq(kind.as_str()))
        .one(pool)
        .await
        .map_err(|e| db_error("load token", e))?
        .ok_or_else(|| {
            ProviderError::new(
                ProviderErrorKind::AuthRequired,
                format!("no stored {kind} credential for this vault"),
            )
        })
}

/// Delete the credential for `(vault_id, kind)`.
///
/// Scoped to one provider on purpose: credentials for other providers are
/// retained so switching back does not require a fresh consent, so an unscoped
/// delete would silently revoke all of them.
pub async fn delete(
    pool: &DbPool,
    kind: ProviderKind,
    vault_id: &str,
) -> Result<(), ProviderError> {
    CloudTokenEntity::delete_many()
        .filter(cloud_token::Column::VaultId.eq(vault_id))
        .filter(cloud_token::Column::ProviderKind.eq(kind.as_str()))
        .exec(pool)
        .await
        .map_err(|e| db_error("delete token", e))?;
    Ok(())
}

/// Persist a refreshed token set, including rotation when the provider does it.
async fn persist_refreshed(
    pool: &DbPool,
    kind: ProviderKind,
    vault_id: &str,
    set: &TokenSet,
) -> Result<(), ProviderError> {
    let mut am: cloud_token::ActiveModel = load(pool, kind, vault_id).await?.into();
    am.access_token = Set(set.access_token.clone());
    if let Some(new_refresh) = set.refresh_token.clone() {
        am.refresh_token = Set(Some(new_refresh));
    }
    if let Some(tt) = set.token_type.clone() {
        am.token_type = Set(tt);
    }
    am.expires_at = Set(set.expires_at);
    if let Some(scope) = set.scope.clone() {
        am.scope = Set(Some(scope));
    }
    am.updated_at = Set(Utc::now().into());
    am.update(pool).await.map_err(|e| {
        // A rotating provider may already have invalidated the old refresh
        // token. Losing the atomic row update therefore requires explicit
        // re-consent rather than a generic retry with stale credentials.
        log::error!("failed to persist refreshed cloud credential: {e:?}");
        ProviderError::new(
            ProviderErrorKind::AuthRequired,
            "could not persist refreshed credential; reconnect required",
        )
    })?;
    Ok(())
}

fn db_error(what: &str, e: impl std::fmt::Debug) -> ProviderError {
    ProviderError::new(ProviderErrorKind::Unknown, format!("{what}: {e:?}"))
}
