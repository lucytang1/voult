use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

use crate::db::DbPool;
use crate::entity::google_token::{self, Entity as GoogleTokenEntity};

/// Retrieves a valid access token for the user, refreshing if expired.
/// Returns (access_token, provider_account_id, provider_email) or error.
pub async fn get_valid_access_token(pool: &DbPool, vault_id: &str) -> Result<String, String> {
    let token = GoogleTokenEntity::find()
        .filter(google_token::Column::VaultId.eq(vault_id))
        .one(pool)
        .await
        .map_err(|e| format!("db error: {:?}", e))?
        .ok_or_else(|| "PROVIDER_AUTH_REQUIRED".to_string())?;

    let now = Utc::now().timestamp();
    // Refresh if expiring within 60s
    if token.expires_at - 60 > now {
        return Ok(token.access_token);
    }

    // Need refresh
    let refresh = token
        .refresh_token
        .clone()
        .ok_or_else(|| "PROVIDER_AUTH_REQUIRED".to_string())?;
    refresh_access_token(pool, vault_id, &refresh).await
}

async fn refresh_access_token(
    pool: &DbPool,
    vault_id: &str,
    refresh_token: &str,
) -> Result<String, String> {
    let cfg = crate::google::config::GoogleConfig::from_env().ok_or("google not configured")?;
    let client = reqwest::Client::new();
    let params = [
        ("client_id", cfg.client_id.as_str()),
        ("client_secret", cfg.client_secret.as_str()),
        ("refresh_token", refresh_token),
        ("grant_type", "refresh_token"),
    ];
    let resp = client
        .post("https://oauth2.googleapis.com/token")
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("token refresh network error: {:?}", e))?;

    if !resp.status().is_success() {
        let _body = resp.text().await.unwrap_or_default();
        log::warn!("Google token refresh failed");
        return Err("PROVIDER_AUTH_REQUIRED".to_string());
    }

    #[derive(serde::Deserialize)]
    struct RefreshResp {
        access_token: String,
        expires_in: i64,
        token_type: Option<String>,
        scope: Option<String>,
    }

    let data: RefreshResp = resp
        .json()
        .await
        .map_err(|e| format!("refresh parse error: {:?}", e))?;
    let expires_at = Utc::now().timestamp() + data.expires_in;

    // Update DB (do not log tokens)
    let mut am: google_token::ActiveModel = GoogleTokenEntity::find()
        .filter(google_token::Column::VaultId.eq(vault_id))
        .one(pool)
        .await
        .map_err(|e| format!("db error: {:?}", e))?
        .ok_or("PROVIDER_AUTH_REQUIRED")?
        .into();

    am.access_token = Set(data.access_token.clone());
    am.expires_at = Set(expires_at);
    if let Some(t) = data.token_type {
        am.token_type = Set(t);
    }
    if let Some(s) = data.scope {
        am.scope = Set(Some(s));
    }
    am.updated_at = Set(Utc::now().into());

    am.update(pool)
        .await
        .map_err(|e| format!("db update error: {:?}", e))?;

    log::info!(
        "Refreshed Google access token for user {}",
        &vault_id[..8.min(vault_id.len())]
    );
    Ok(data.access_token)
}

/// Fetch Google userinfo to confirm account identity (email, sub)
pub async fn fetch_google_userinfo(access_token: &str) -> Result<(String, String), String> {
    let client = reqwest::Client::new();
    let resp = client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| format!("userinfo network error: {:?}", e))?;

    if !resp.status().is_success() {
        let _body = resp.text().await.unwrap_or_default();
        log::warn!("Failed to fetch Google userinfo");
        return Err("failed to fetch userinfo".to_string());
    }

    #[derive(serde::Deserialize)]
    struct Info {
        id: String,
        email: String,
    }
    let info: Info = resp
        .json()
        .await
        .map_err(|e| format!("userinfo parse error: {:?}", e))?;
    Ok((info.id, info.email))
}
