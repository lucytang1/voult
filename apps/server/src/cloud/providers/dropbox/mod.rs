//! Dropbox OAuth and app-folder file operations.
pub mod config;
mod oauth;
mod transport;

use crate::cloud::{
    error::{ProviderError, ProviderErrorKind},
    provider::{
        CloudProvider, NoRevision, ProviderAccount, ProviderKind, RemoteVaultFile, StoredToken,
        TokenSet,
    },
};

#[derive(Clone, Debug)]
pub struct DropboxProvider {
    config: config::DropboxConfig,
}

impl DropboxProvider {
    pub fn from_env() -> Option<Self> {
        Some(Self {
            config: config::DropboxConfig::from_env()?,
        })
    }
}

impl CloudProvider for DropboxProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Dropbox
    }
    fn display_name(&self) -> &'static str {
        "Dropbox"
    }
    fn env_keys(&self) -> &'static [&'static str] {
        &[
            "DROPBOX_CLIENT_ID",
            "DROPBOX_CLIENT_SECRET",
            "DROPBOX_OAUTH_REDIRECT_URI",
        ]
    }
    fn redirect_uri(&self) -> &str {
        &self.config.redirect_uri
    }
    fn post_auth_redirect(&self) -> String {
        self.config
            .post_auth_redirect()
            .unwrap_or_else(crate::cloud::provider::default_post_auth_redirect)
    }
    fn authorize_url(&self, state: &str) -> String {
        format!(
            "https://www.dropbox.com/oauth2/authorize?client_id={}&response_type=code&redirect_uri={}&token_access_type=offline&state={}",
            urlencoding::encode(&self.config.client_id),
            urlencoding::encode(self.redirect_uri()),
            urlencoding::encode(state)
        )
    }
    async fn exchange_code(&self, code: &str) -> Result<TokenSet, ProviderError> {
        oauth::exchange(&self.config, code).await
    }
    async fn refresh(&self, current: &StoredToken) -> Result<TokenSet, ProviderError> {
        oauth::refresh(
            &self.config,
            current.refresh_token.as_deref().ok_or_else(|| {
                ProviderError::new(
                    ProviderErrorKind::AuthRequired,
                    "no refresh token stored; re-consent required",
                )
            })?,
        )
        .await
    }
    async fn account(&self, token: &str) -> Result<ProviderAccount, ProviderError> {
        oauth::account(token).await
    }
    async fn list_vault_files(&self, token: &str) -> Result<Vec<RemoteVaultFile>, ProviderError> {
        transport::list(token).await
    }
    async fn create_vault_file(
        &self,
        token: &str,
        vault_id: &str,
        bytes: &[u8],
    ) -> Result<RemoteVaultFile, ProviderError> {
        transport::create(token, vault_id, bytes).await
    }
    async fn read_vault_file(
        &self,
        token: &str,
        file_id: &str,
    ) -> Result<(Vec<u8>, String), ProviderError> {
        transport::read(token, file_id).await
    }
    async fn conditional_write(
        &self,
        token: &str,
        file_id: &str,
        bytes: &[u8],
        rev: Option<&str>,
    ) -> Result<String, ProviderError> {
        transport::write(
            token,
            file_id,
            bytes,
            rev.ok_or_else(|| {
                ProviderError::new(
                    ProviderErrorKind::RemoteRevisionUnavailable,
                    "Dropbox write requires a known revision",
                )
            })?,
        )
        .await
    }
    async fn file_revision(
        &self,
        token: &str,
        file_id: &str,
    ) -> Result<Result<String, NoRevision>, ProviderError> {
        match transport::metadata(token, file_id).await?.rev {
            Some(revision) => Ok(Ok(revision)),
            None => Ok(Err(NoRevision)),
        }
    }
    async fn delete_vault_file(&self, token: &str, file_id: &str) -> Result<(), ProviderError> {
        transport::delete(token, file_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_auth_redirect_uses_a_non_recursive_default() {
        let provider = DropboxProvider {
            config: config::DropboxConfig {
                client_id: "id".into(),
                client_secret: "secret".into(),
                redirect_uri: "http://localhost/callback".into(),
            },
        };
        assert!(!provider.post_auth_redirect().is_empty());
    }
}
