use super::config::DropboxConfig;
use crate::cloud::{
    error::{ProviderError, ProviderErrorKind},
    provider::{ProviderAccount, TokenSet},
};
#[derive(serde::Deserialize)]
struct Tokens {
    access_token: String,
    expires_in: i64,
    refresh_token: Option<String>,
    token_type: Option<String>,
    scope: Option<String>,
}
fn err(e: impl std::fmt::Debug) -> ProviderError {
    ProviderError::new(
        ProviderErrorKind::RemoteUnavailable,
        format!("Dropbox OAuth transport: {e:?}"),
    )
}
async fn token_response(r: reqwest::Response) -> Result<TokenSet, ProviderError> {
    if !r.status().is_success() {
        return Err(ProviderError::new(
            ProviderErrorKind::AuthRequired,
            format!("Dropbox OAuth rejected with status {}", r.status()),
        ));
    }
    let t: Tokens = r.json().await.map_err(err)?;
    Ok(TokenSet {
        access_token: t.access_token,
        refresh_token: t.refresh_token,
        token_type: t.token_type,
        expires_at: chrono::Utc::now().timestamp() + t.expires_in,
        scope: t.scope,
    })
}
pub async fn exchange(c: &DropboxConfig, code: &str) -> Result<TokenSet, ProviderError> {
    token_response(
        crate::cloud::http_client::client()
            .post("https://api.dropboxapi.com/oauth2/token")
            .form(&[
                ("code", code),
                ("grant_type", "authorization_code"),
                ("client_id", &c.client_id),
                ("client_secret", &c.client_secret),
                ("redirect_uri", &c.redirect_uri),
            ])
            .send()
            .await
            .map_err(err)?,
    )
    .await
}
pub async fn refresh(c: &DropboxConfig, refresh: &str) -> Result<TokenSet, ProviderError> {
    token_response(
        crate::cloud::http_client::client()
            .post("https://api.dropboxapi.com/oauth2/token")
            .form(&[
                ("refresh_token", refresh),
                ("grant_type", "refresh_token"),
                ("client_id", &c.client_id),
                ("client_secret", &c.client_secret),
            ])
            .send()
            .await
            .map_err(err)?,
    )
    .await
}
pub async fn account(token: &str) -> Result<ProviderAccount, ProviderError> {
    #[derive(serde::Deserialize)]
    struct A {
        account_id: String,
        email: Option<String>,
    }
    let r = crate::cloud::http_client::client()
        .post("https://api.dropboxapi.com/2/users/get_current_account")
        .bearer_auth(token)
        .header("content-type", "application/json")
        .body("null")
        .send()
        .await
        .map_err(err)?;
    if !r.status().is_success() {
        return Err(ProviderError::new(
            ProviderErrorKind::AuthRequired,
            format!("Dropbox account lookup status {}", r.status()),
        ));
    }
    let a: A = r.json().await.map_err(err)?;
    Ok(ProviderAccount {
        account_id: Some(a.account_id),
        email: a.email,
    })
}
