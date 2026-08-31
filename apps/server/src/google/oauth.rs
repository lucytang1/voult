use actix_session::Session;
use chrono::{Duration, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

use crate::db::DbPool;
use crate::entity::google_token::{self, Entity as GoogleTokenEntity};
use crate::entity::oauth_state::{self, Entity as OauthStateEntity};
use crate::google::config::GoogleConfig;

/// Exchange code for tokens, store, and fetch provider identity
pub async fn exchange_code_and_store(
    pool: &DbPool,
    vault_id: &str,
    code: &str,
    cfg: &GoogleConfig,
) -> Result<(String, String), String> {
    let client = reqwest::Client::new();
    let params = [
        ("code", code),
        ("client_id", cfg.client_id.as_str()),
        ("client_secret", cfg.client_secret.as_str()),
        ("redirect_uri", cfg.redirect_uri.as_str()),
        ("grant_type", "authorization_code"),
    ];

    let resp = client
        .post("https://oauth2.googleapis.com/token")
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("token exchange network error: {:?}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let _body = resp.text().await.unwrap_or_default();
        // Provider error bodies can contain sensitive response data; keep them
        // out of logs and out of client-visible error details.
        log::warn!("Google token exchange failed with status {}", status);
        return Err("token exchange failed".to_string());
    }

    #[derive(serde::Deserialize, Debug)]
    struct TokenResp {
        access_token: String,
        expires_in: i64,
        refresh_token: Option<String>,
        scope: Option<String>,
        token_type: Option<String>,
        // id_token: Option<String>,
    }

    let token: TokenResp = resp
        .json()
        .await
        .map_err(|e| format!("token parse error: {:?}", e))?;

    // Fetch provider identity
    let (provider_account_id, provider_email) =
        crate::google::token_store::fetch_google_userinfo(&token.access_token)
            .await
            .unwrap_or((String::new(), String::new()));

    let expires_at = Utc::now().timestamp() + token.expires_in;

    // Upsert google_token for this user
    let existing = GoogleTokenEntity::find()
        .filter(google_token::Column::VaultId.eq(vault_id))
        .one(pool)
        .await
        .map_err(|e| format!("db error: {:?}", e))?;

    if let Some(existing) = existing {
        let mut am: google_token::ActiveModel = existing.into();
        am.access_token = Set(token.access_token.clone());
        // Only overwrite refresh_token if provided (Google only sends on first consent)
        if let Some(rt) = token.refresh_token {
            am.refresh_token = Set(Some(rt));
        }
        am.expires_at = Set(expires_at);
        am.token_type = Set(token.token_type.unwrap_or_else(|| "Bearer".to_string()));
        am.scope = Set(token.scope);
        am.provider_account_id = Set(Some(provider_account_id.clone()));
        am.provider_email = Set(Some(provider_email.clone()));
        am.updated_at = Set(Utc::now().into());
        am.update(pool)
            .await
            .map_err(|e| format!("db update error: {:?}", e))?;
    } else {
        let am = google_token::ActiveModel {
            vault_id: Set(vault_id.to_string()),
            access_token: Set(token.access_token.clone()),
            refresh_token: Set(token.refresh_token),
            token_type: Set(token.token_type.unwrap_or_else(|| "Bearer".to_string())),
            expires_at: Set(expires_at),
            scope: Set(token.scope),
            provider_account_id: Set(Some(provider_account_id.clone())),
            provider_email: Set(Some(provider_email.clone())),
            updated_at: Set(Utc::now().into()),
        };
        am.insert(pool)
            .await
            .map_err(|e| format!("db insert error: {:?}", e))?;
    }

    log::info!(
        "Stored Google token for user {} provider {}",
        &vault_id[..8.min(vault_id.len())],
        if provider_email.is_empty() {
            "unknown".to_string()
        } else {
            provider_email.clone()
        }
    );

    Ok((provider_account_id, provider_email))
}

/// Generates a CSRF state token and stores it short-lived (10 min)
pub async fn generate_and_store_state(pool: &DbPool, vault_id: &str) -> Result<String, String> {
    generate_and_store_state_with_email(pool, Some(vault_id), None).await
}

pub async fn generate_and_store_state_with_email(
    pool: &DbPool,
    vault_id: Option<&str>,
    email: Option<&str>,
) -> Result<String, String> {
    let state = Uuid::new_v4().to_string();
    let now = Utc::now();
    let expires = now + Duration::minutes(10);

    // Clean up expired states (best effort)
    let _ = oauth_state::Entity::delete_many()
        .filter(oauth_state::Column::ExpiresAt.lt(now))
        .exec(pool)
        .await;

    let am = oauth_state::ActiveModel {
        state: Set(state.clone()),
        vault_id: Set(vault_id.map(|s| s.to_string())),
        created_at: Set(now.into()),
        expires_at: Set(expires.into()),
    };
    am.insert(pool)
        .await
        .map_err(|e| format!("db error: {:?}", e))?;
    Ok(state)
}

pub async fn validate_state(pool: &DbPool, state: &str, vault_id: &str) -> Result<(), String> {
    let rec = OauthStateEntity::find()
        .filter(oauth_state::Column::State.eq(state))
        .one(pool)
        .await
        .map_err(|e| format!("db error: {:?}", e))?
        .ok_or_else(|| "invalid state".to_string())?;

    if rec.vault_id.as_deref() != Some(vault_id) {
        return Err("state user mismatch".to_string());
    }

    let now: chrono::DateTime<chrono::Utc> = Utc::now().into();
    let expires: chrono::DateTime<chrono::Utc> = rec.expires_at.into();
    if now > expires {
        // Delete expired
        let _ = OauthStateEntity::delete_by_id(state.to_string())
            .exec(pool)
            .await;
        return Err("state expired".to_string());
    }

    // Consume state (one-time)
    let _ = OauthStateEntity::delete_by_id(state.to_string())
        .exec(pool)
        .await;
    Ok(())
}

pub async fn validate_state_pending(
    pool: &DbPool,
    state: &str,
) -> Result<oauth_state::Model, String> {
    let rec = OauthStateEntity::find()
        .filter(oauth_state::Column::State.eq(state))
        .one(pool)
        .await
        .map_err(|e| format!("db error: {:?}", e))?
        .ok_or_else(|| "invalid state".to_string())?;

    let now: chrono::DateTime<chrono::Utc> = Utc::now().into();
    let expires: chrono::DateTime<chrono::Utc> = rec.expires_at.into();
    if now > expires {
        let _ = OauthStateEntity::delete_by_id(state.to_string())
            .exec(pool)
            .await;
        return Err("state expired".to_string());
    }
    // Do not delete yet – caller will delete after exchange
    Ok(rec)
}

pub fn build_auth_url(cfg: &GoogleConfig, state: &str) -> String {
    // Use urlencoding for safety
    format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope={}&access_type=offline&prompt=consent&state={}&include_granted_scopes=false",
        urlencoding::encode(&cfg.client_id),
        urlencoding::encode(&cfg.redirect_uri),
        urlencoding::encode(&cfg.scope),
        urlencoding::encode(state),
    )
}

// Session key for storing pending state when DB not yet available? We store in DB, but also keep in session for quick check
pub const SESSION_GOOGLE_OAUTH_STATE: &str = "google_oauth_state";
pub fn store_state_in_session(session: &Session, state: &str) -> Result<(), String> {
    session
        .insert(SESSION_GOOGLE_OAUTH_STATE, state.to_string())
        .map_err(|e| format!("session error: {:?}", e))
}
pub fn take_state_from_session(session: &Session) -> Option<String> {
    let s: Option<String> = session.get(SESSION_GOOGLE_OAUTH_STATE).ok().flatten();
    if s.is_some() {
        session.remove(SESSION_GOOGLE_OAUTH_STATE);
    }
    s
}

/// Exchange code and store as pending (no vault_id) – for unified entry Google flow before local account exists
pub async fn exchange_code_and_store_pending(
    pool: &DbPool,
    state: &str,
    code: &str,
    cfg: &GoogleConfig,
) -> Result<(String, String), String> {
    // Validate state exists (pending)
    let rec = validate_state_pending(pool, state).await?;
    // Exchange code
    let client = reqwest::Client::new();
    let params = [
        ("code", code),
        ("client_id", cfg.client_id.as_str()),
        ("client_secret", cfg.client_secret.as_str()),
        ("redirect_uri", cfg.redirect_uri.as_str()),
        ("grant_type", "authorization_code"),
    ];
    let resp = client
        .post("https://oauth2.googleapis.com/token")
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("token exchange network error: {:?}", e))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let _body = resp.text().await.unwrap_or_default();
        log::warn!("Google token exchange failed with status {}", status);
        return Err("token exchange failed".to_string());
    }
    #[derive(serde::Deserialize, Debug)]
    struct TokenResp {
        access_token: String,
        expires_in: i64,
        refresh_token: Option<String>,
        scope: Option<String>,
        token_type: Option<String>,
    }
    let token: TokenResp = resp
        .json()
        .await
        .map_err(|e| format!("token parse error: {:?}", e))?;
    let (provider_account_id, provider_email) =
        crate::google::token_store::fetch_google_userinfo(&token.access_token)
            .await
            .unwrap_or((String::new(), String::new()));
    let expires_at = Utc::now().timestamp() + token.expires_in;

    // Store in pending table keyed by state, preserving local email from oauth_state for later user creation
    use crate::entity::google_pending_token::{self, Entity as PendingEntity};
    let local_email: Option<String> = None;
    let am = google_pending_token::ActiveModel {
        state: Set(state.to_string()),
        access_token: Set(token.access_token.clone()),
        refresh_token: Set(token.refresh_token),
        expires_at: Set(expires_at),
        provider_account_id: Set(Some(provider_account_id.clone())),
        provider_email: Set(Some(provider_email.clone())),
        local_email: Set(local_email),
        created_at: Set(Utc::now().into()),
    };
    // Upsert: delete existing if any
    let _ = PendingEntity::delete_by_id(state.to_string())
        .exec(pool)
        .await;
    am.insert(pool)
        .await
        .map_err(|e| format!("pending insert error: {:?}", e))?;

    // Consume oauth_state
    let _ = OauthStateEntity::delete_by_id(state.to_string())
        .exec(pool)
        .await;

    log::info!(
        "Stored pending Google token for state {} provider {}",
        &state[..8.min(state.len())],
        provider_email
    );
    Ok((provider_account_id, provider_email))
}

/// Link pending Google token (by state) to a newly created local user
pub async fn link_pending_to_user(
    pool: &DbPool,
    state: &str,
    vault_id: &str,
) -> Result<(), String> {
    use crate::entity::google_pending_token::{self, Entity as PendingEntity};
    let pending = PendingEntity::find_by_id(state.to_string())
        .one(pool)
        .await
        .map_err(|e| format!("db error: {:?}", e))?
        .ok_or_else(|| "pending token not found".to_string())?;

    // Upsert into google_token for this user
    let existing = GoogleTokenEntity::find()
        .filter(google_token::Column::VaultId.eq(vault_id))
        .one(pool)
        .await
        .map_err(|e| format!("db error: {:?}", e))?;
    let now = Utc::now();
    if let Some(existing) = existing {
        let mut am: google_token::ActiveModel = existing.into();
        am.access_token = Set(pending.access_token.clone());
        if pending.refresh_token.is_some() {
            am.refresh_token = Set(pending.refresh_token.clone());
        }
        am.expires_at = Set(pending.expires_at);
        am.provider_account_id = Set(pending.provider_account_id.clone());
        am.provider_email = Set(pending.provider_email.clone());
        am.updated_at = Set(now.into());
        am.update(pool)
            .await
            .map_err(|e| format!("db update error: {:?}", e))?;
    } else {
        let am = google_token::ActiveModel {
            vault_id: Set(vault_id.to_string()),
            access_token: Set(pending.access_token.clone()),
            refresh_token: Set(pending.refresh_token.clone()),
            token_type: Set("Bearer".to_string()),
            expires_at: Set(pending.expires_at),
            scope: Set(None),
            provider_account_id: Set(pending.provider_account_id.clone()),
            provider_email: Set(pending.provider_email.clone()),
            updated_at: Set(now.into()),
        };
        am.insert(pool)
            .await
            .map_err(|e| format!("db insert error: {:?}", e))?;
    }
    // Delete pending
    let _ = PendingEntity::delete_by_id(state.to_string())
        .exec(pool)
        .await;
    Ok(())
}
