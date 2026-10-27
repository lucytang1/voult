//! CSRF state lifecycle for the OAuth authorization-code flow.
//!
//! Provider-neutral by construction: the only provider-specific thing here is
//! the `provider_kind` column, which exists so a state minted for one provider
//! can never be redeemed at another provider's callback.
//!
//! Split out of the former provider-specific `oauth.rs` so that the state
//! machinery no longer sits inside a module that also knew Google's endpoints.

use chrono::{Duration, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

use crate::cloud::provider::ProviderKind;
use crate::db::DbPool;
use crate::entity::oauth_state::{self, Entity as OauthStateEntity};

/// How long a minted state stays redeemable. Comfortably longer than a
/// human-driven consent screen, short enough that an abandoned authorization
/// cannot be resumed much later.
const STATE_TTL_MINUTES: i64 = 10;

/// Mint a CSRF state bound to `kind` and, optionally, a vault.
pub async fn generate(
    pool: &DbPool,
    kind: ProviderKind,
    vault_id: Option<&str>,
) -> Result<String, String> {
    let state = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Opportunistic cleanup; expired rows are also ignored on read, so failure
    // here is harmless.
    let _ = oauth_state::Entity::delete_many()
        .filter(oauth_state::Column::ExpiresAt.lt(now))
        .exec(pool)
        .await;

    let am = oauth_state::ActiveModel {
        state: Set(state.clone()),
        provider_kind: Set(kind.as_str().to_string()),
        vault_id: Set(vault_id.map(|s| s.to_string())),
        created_at: Set(now.into()),
        expires_at: Set((now + Duration::minutes(STATE_TTL_MINUTES)).into()),
    };
    am.insert(pool)
        .await
        .map_err(|e| format!("db error: {:?}", e))?;
    Ok(state)
}

/// Consume a state, proving it was minted by `kind` for `vault_id`.
///
/// One-time: a successfully validated state is deleted, so a replayed callback
/// finds nothing.
pub async fn validate(
    pool: &DbPool,
    kind: ProviderKind,
    state: &str,
    vault_id: &str,
) -> Result<(), String> {
    let rec = lookup(pool, state).await?;

    // Provider binding is checked BEFORE the vault binding: the whole point of
    // storing the provider is that a callback from provider A cannot redeem a
    // state minted for provider B.
    ensure_provider(&rec, kind)?;
    ensure_vault(&rec, vault_id)?;

    consume(pool, state).await;
    Ok(())
}

/// Look up a state without consuming it, for the pre-session flow where no vault
/// exists yet. The caller consumes it after a successful code exchange.
pub async fn validate_pending(
    pool: &DbPool,
    kind: ProviderKind,
    state: &str,
) -> Result<oauth_state::Model, String> {
    let rec = lookup(pool, state).await?;
    ensure_provider(&rec, kind)?;
    // Deliberately not consumed: the exchange still has to happen.
    Ok(rec)
}

/// Delete a state after its code has been exchanged.
pub async fn consume(pool: &DbPool, state: &str) {
    let _ = OauthStateEntity::delete_by_id(state.to_string())
        .exec(pool)
        .await;
}

async fn lookup(pool: &DbPool, state: &str) -> Result<oauth_state::Model, String> {
    let rec = OauthStateEntity::find()
        .filter(oauth_state::Column::State.eq(state))
        .one(pool)
        .await
        .map_err(|e| format!("db error: {:?}", e))?
        .ok_or_else(|| "invalid state".to_string())?;

    let now: chrono::DateTime<chrono::Utc> = Utc::now().into();
    let expires: chrono::DateTime<chrono::Utc> = rec.expires_at.into();
    if now > expires {
        // Best-effort cleanup of the dead row before rejecting it.
        consume(pool, state).await;
        return Err("state expired".to_string());
    }
    Ok(rec)
}

fn ensure_provider(rec: &oauth_state::Model, kind: ProviderKind) -> Result<(), String> {
    if rec.provider_kind != kind.as_str() {
        return Err("state provider mismatch".to_string());
    }
    Ok(())
}

fn ensure_vault(rec: &oauth_state::Model, vault_id: &str) -> Result<(), String> {
    if rec.vault_id.as_deref() != Some(vault_id) {
        return Err("state user mismatch".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::oauth_state::Model;

    fn rec(kind: &str, vault: Option<&str>) -> Model {
        let now = Utc::now();
        Model {
            state: "s".to_string(),
            provider_kind: kind.to_string(),
            vault_id: vault.map(|v| v.to_string()),
            created_at: now,
            expires_at: now + Duration::minutes(5),
        }
    }

    /// A state minted for one provider must not validate for another. This is
    /// the check that makes a generic `/cloud/oauth/callback?provider=X` safe,
    /// so it is pinned with a foreign provider string rather than only the
    /// currently-known kind.
    #[test]
    fn a_state_is_bound_to_its_provider() {
        let google = rec("google_drive", Some("v1"));
        assert!(ensure_provider(&google, ProviderKind::GoogleDrive).is_ok());
        // Another provider's kind must be rejected.
        assert!(ensure_provider(&rec("dropbox", Some("v1")), ProviderKind::GoogleDrive).is_err());
    }

    #[test]
    fn a_state_is_bound_to_its_vault() {
        let bound = rec("google_drive", Some("v1"));
        assert!(ensure_vault(&bound, "v1").is_ok());
        assert!(ensure_vault(&bound, "v2").is_err());
        // A pending state has no vault yet, so it must never satisfy a
        // vault-bound validation.
        let pending = rec("google_drive", None);
        assert!(ensure_vault(&pending, "v1").is_err());
    }
}
