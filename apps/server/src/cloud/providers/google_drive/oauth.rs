//! Google OAuth2: authorization-code exchange, refresh, and account identity.
//!
//! Split out from the token-exchange-and-store flow it used to live in. Storing
//! credentials is provider-neutral and belongs to `cloud::token_store`; this
//! module only knows how to talk to Google's token endpoint.

use crate::cloud::error::{ProviderError, ProviderErrorKind};
use crate::cloud::provider::TokenSet;

use super::config::GoogleConfig;

const LOG: logger::ServerLogger = logger::Logger::create(logger::ServerContext::Cloud);

/// Google's token endpoint. Private to this module: no caller outside the Drive
/// implementation may reference it.
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v2/userinfo";

#[derive(serde::Deserialize, Debug)]
struct TokenResp {
    access_token: String,
    expires_in: i64,
    /// Google only sends a refresh token on first consent, so `None` here means
    /// "keep the one you have", never "revoke".
    refresh_token: Option<String>,
    scope: Option<String>,
    token_type: Option<String>,
}

fn transport_error(what: &str, e: impl std::fmt::Debug) -> ProviderError {
    ProviderError::new(
        ProviderErrorKind::RemoteUnavailable,
        format!("{what} network error: {e:?}"),
    )
}

/// Exchange an authorization code for credentials.
///
/// Provider error bodies are never returned or logged verbatim: they can carry
/// account metadata. Only the HTTP status is kept.
pub async fn exchange_code(cfg: &GoogleConfig, code: &str) -> Result<TokenSet, ProviderError> {
    let client = crate::cloud::http_client::client();
    let params = [
        ("code", code),
        ("client_id", cfg.client_id.as_str()),
        ("client_secret", cfg.client_secret.as_str()),
        ("redirect_uri", cfg.redirect_uri.as_str()),
        ("grant_type", "authorization_code"),
    ];

    let resp = client
        .post(TOKEN_URL)
        .form(&params)
        .send()
        .await
        .map_err(|e| transport_error("token exchange", e))?;

    if !resp.status().is_success() {
        LOG.warn(
            format_args!("Google token exchange failed with status {}", resp.status()),
            logger::Metadata::new(),
        );
        return Err(ProviderError::new(
            ProviderErrorKind::AuthRequired,
            format!("token exchange rejected with status {}", resp.status()),
        ));
    }

    parse_token_response(resp).await
}

/// Refresh credentials using a refresh token.
///
/// Google does NOT rotate refresh tokens, so the returned set never carries a
/// new one and the caller keeps the stored value. A provider that does rotate
/// returns its new refresh token here, and `cloud::token_store` persists it
/// before use.
pub async fn refresh(cfg: &GoogleConfig, refresh_token: &str) -> Result<TokenSet, ProviderError> {
    let client = crate::cloud::http_client::client();
    let params = [
        ("client_id", cfg.client_id.as_str()),
        ("client_secret", cfg.client_secret.as_str()),
        ("refresh_token", refresh_token),
        ("grant_type", "refresh_token"),
    ];

    let resp = client
        .post(TOKEN_URL)
        .form(&params)
        .send()
        .await
        .map_err(|e| transport_error("token refresh", e))?;

    if !resp.status().is_success() {
        LOG.warn(
            format_args!("Google token refresh failed with status {}", resp.status()),
            logger::Metadata::new(),
        );
        return Err(ProviderError::new(
            ProviderErrorKind::AuthRequired,
            format!("token refresh rejected with status {}", resp.status()),
        ));
    }

    parse_token_response(resp).await
}

async fn parse_token_response(resp: reqwest::Response) -> Result<TokenSet, ProviderError> {
    let token: TokenResp = resp.json().await.map_err(|e| {
        ProviderError::new(
            ProviderErrorKind::Unknown,
            format!("token parse error: {e:?}"),
        )
    })?;

    Ok(TokenSet {
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        token_type: token.token_type.or_else(|| Some("Bearer".to_string())),
        expires_at: chrono::Utc::now().timestamp() + token.expires_in,
        scope: token.scope,
    })
}

/// Fetch the connected account's identity for display in Settings.
///
/// Best-effort by contract: `cloud::oauth_state`'s callers treat a failure here
/// as "no display name available", never as a reason to refuse a backup.
pub async fn userinfo(access_token: &str) -> Result<(String, String), ProviderError> {
    let client = crate::cloud::http_client::client();
    let resp = client
        .get(USERINFO_URL)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| transport_error("userinfo", e))?;

    if !resp.status().is_success() {
        LOG.warn(
            format_args!("Failed to fetch Google userinfo"),
            logger::Metadata::new(),
        );
        return Err(ProviderError::new(
            ProviderErrorKind::AuthRequired,
            format!("userinfo rejected with status {}", resp.status()),
        ));
    }

    #[derive(serde::Deserialize)]
    struct Info {
        id: String,
        email: String,
    }
    let info: Info = resp.json().await.map_err(|e| {
        ProviderError::new(
            ProviderErrorKind::Unknown,
            format!("userinfo parse error: {e:?}"),
        )
    })?;
    Ok((info.id, info.email))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Google only issues a refresh token on first consent. If a refresh
    /// response ever started carrying one, `token_store` must persist it rather
    /// than keep the old value — this pins the shape that makes that work.
    #[test]
    fn token_set_carries_a_rotateable_refresh_token() {
        let set = TokenSet {
            access_token: "a".into(),
            refresh_token: Some("r".into()),
            token_type: Some("Bearer".into()),
            expires_at: 1,
            scope: None,
        };
        assert_eq!(set.refresh_token.as_deref(), Some("r"));
    }
}
