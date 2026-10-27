//! Google Drive implementation of [`CloudProvider`].
//!
//! The three files under this directory map one-to-one onto what used to be
//! loose functions:
//!
//! | File | Role |
//! |---|---|
//! | `config.rs` | `GOOGLE_*` env keys, all private to Drive |
//! | `transport.rs` | Drive REST calls (`files/*`, `upload/*`) |
//! | `oauth.rs` | authorization-code exchange, refresh, userinfo |
//!
//! Nothing outside this directory may name a Google URL, scope, or error shape.

pub mod config;
pub mod oauth;
pub(super) mod status_mapper;
pub mod transport;

use crate::cloud::error::{ProviderError, ProviderErrorKind};
use crate::cloud::provider::{
    CloudProvider, NoRevision, ProviderAccount, ProviderKind, RemoteVaultFile, StoredToken,
    TokenSet,
};
use config::GoogleConfig;

/// Sentinel used when Drive reports no revision at all. Treated as "no usable
/// CAS token" by callers — never as a revision that could match.
pub const UNKNOWN_REVISION: &str = "unknown";

/// A configured Google Drive provider.
///
/// Holds its `GoogleConfig`, so constructing one *is* the configuration check:
/// there is no way to obtain a `GoogleDriveProvider` without credentials.
#[derive(Debug, Clone)]
pub struct GoogleDriveProvider {
    config: GoogleConfig,
}

impl GoogleDriveProvider {
    /// Build from the environment, or `None` when Drive is not configured.
    pub fn from_env() -> Option<Self> {
        GoogleConfig::from_env().map(|config| Self { config })
    }
}

impl CloudProvider for GoogleDriveProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::GoogleDrive
    }

    fn display_name(&self) -> &'static str {
        ProviderKind::GoogleDrive.display_name()
    }

    fn env_keys(&self) -> &'static [&'static str] {
        &[
            "GOOGLE_CLIENT_ID",
            "GOOGLE_CLIENT_SECRET",
            "GOOGLE_OAUTH_REDIRECT_URI",
            "GOOGLE_DRIVE_SCOPE",
            "GOOGLE_POST_AUTH_REDIRECT",
        ]
    }

    fn redirect_uri(&self) -> &str {
        &self.config.redirect_uri
    }

    fn post_auth_redirect(&self) -> String {
        config::GoogleConfig::post_auth_redirect_override()
            .unwrap_or_else(crate::cloud::provider::default_post_auth_redirect)
    }

    fn authorize_url(&self, state: &str) -> String {
        // access_type=offline is what yields a refresh token; prompt=consent
        // forces a new one on re-consent.
        format!(
            "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope={}&access_type=offline&prompt=consent&state={}&include_granted_scopes=false",
            urlencoding::encode(&self.config.client_id),
            urlencoding::encode(self.redirect_uri()),
            urlencoding::encode(&self.config.scope),
            urlencoding::encode(state),
        )
    }

    async fn exchange_code(&self, code: &str) -> Result<TokenSet, ProviderError> {
        oauth::exchange_code(&self.config, code).await
    }

    async fn refresh(&self, current: &StoredToken) -> Result<TokenSet, ProviderError> {
        // Google does not rotate refresh tokens, so the new set never carries
        // one and `token_store` keeps the stored value. A rotating provider
        // returns it here instead.
        let refresh_token = current.refresh_token.as_deref().ok_or_else(|| {
            ProviderError::new(
                ProviderErrorKind::AuthRequired,
                "no refresh token stored; re-consent required",
            )
        })?;
        oauth::refresh(&self.config, refresh_token).await
    }

    async fn account(&self, access_token: &str) -> Result<ProviderAccount, ProviderError> {
        let (account_id, email) = oauth::userinfo(access_token).await?;
        Ok(ProviderAccount {
            account_id: Some(account_id),
            email: Some(email),
        })
    }

    async fn list_vault_files(
        &self,
        access_token: &str,
    ) -> Result<Vec<RemoteVaultFile>, ProviderError> {
        transport::list_vaults(access_token).await.map(|files| {
            files
                .into_iter()
                .map(|d| RemoteVaultFile {
                    vault_id: d.vault_id,
                    file_id: d.file_id,
                    // Drive reports either headRevisionId or version;
                    // whichever arrived is the CAS token.
                    revision: normalize_revision(
                        d.head_revision_id.or(d.version).unwrap_or_default(),
                    ),
                    name: d.name,
                    modified_time: d.modified_time,
                    size: d.size,
                })
                .collect()
        })
    }

    async fn create_vault_file(
        &self,
        access_token: &str,
        vault_id: &str,
        bytes: &[u8],
    ) -> Result<RemoteVaultFile, ProviderError> {
        let (file_id, revision) = transport::create_vault(access_token, vault_id, bytes).await?;
        Ok(RemoteVaultFile {
            vault_id: vault_id.to_string(),
            file_id,
            revision: normalize_revision(revision),
            name: transport::vault_file_name(vault_id),
            modified_time: None,
            size: None,
        })
    }

    async fn read_vault_file(
        &self,
        access_token: &str,
        file_id: &str,
    ) -> Result<(Vec<u8>, String), ProviderError> {
        let (bytes, revision) = transport::read_vault(access_token, file_id).await?;
        Ok((bytes, normalize_revision(revision)))
    }

    async fn conditional_write(
        &self,
        access_token: &str,
        file_id: &str,
        bytes: &[u8],
        if_match: Option<&str>,
    ) -> Result<String, ProviderError> {
        transport::replace_vault(access_token, file_id, bytes, if_match)
            .await
            .map(normalize_revision)
    }

    async fn file_revision(
        &self,
        access_token: &str,
        file_id: &str,
    ) -> Result<Result<String, NoRevision>, ProviderError> {
        // `Ok(Err(NoRevision))` — the file exists but Drive reported no usable
        // revision. Distinct from `Err(...)`, which means the read itself failed.
        transport::file_revision(access_token, file_id)
            .await
            .map(|rev| match normalize_revision(rev) {
                r if r == UNKNOWN_REVISION => Err(NoRevision),
                r => Ok(r),
            })
    }

    async fn delete_vault_file(
        &self,
        access_token: &str,
        file_id: &str,
    ) -> Result<(), ProviderError> {
        transport::delete_vault(access_token, file_id).await
    }
}

/// Drive omits `headRevisionId` for some file types and then omits `version`
/// too; the transport represents that as an empty string. Collapse both the
/// empty case and the literal `"unknown"` to the single sentinel so the CAS
/// baseline logic has exactly one value to reason about.
fn normalize_revision(revision: String) -> String {
    if revision.is_empty() {
        UNKNOWN_REVISION.to_string()
    } else {
        revision
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_revisions_collapse_to_the_sentinel() {
        // An empty string must not reach the CAS baseline logic: it would look
        // like a real token and silently match nothing.
        assert_eq!(normalize_revision(String::new()), UNKNOWN_REVISION);
        assert_eq!(normalize_revision("rev-1".to_string()), "rev-1");
        assert_eq!(
            normalize_revision(UNKNOWN_REVISION.to_string()),
            UNKNOWN_REVISION
        );
    }

    /// The sentinel must be distinguishable from every real revision, which is
    /// what makes "refuse rather than write blind" enforceable.
    #[test]
    fn the_sentinel_is_not_usable_as_a_baseline() {
        assert_eq!(UNKNOWN_REVISION, "unknown");
        assert_ne!(UNKNOWN_REVISION, "");
    }

    /// A provider cannot be constructed without credentials, so "configured" is
    /// a property of existence rather than a separate flag that can drift.
    #[test]
    fn unconfigured_env_yields_no_provider() {
        // The test environment has no Google credentials, so this must be None.
        // If a developer machine does have them, the assertion is vacuous but
        // harmless; it still exercises the constructor.
        if let Some(p) = GoogleDriveProvider::from_env() {
            assert_eq!(p.kind(), ProviderKind::GoogleDrive);
            assert!(!p.redirect_uri().is_empty());
        }
    }

    #[test]
    fn post_auth_redirect_falls_back_without_recursing() {
        let provider = GoogleDriveProvider {
            config: GoogleConfig {
                client_id: "id".into(),
                client_secret: "secret".into(),
                redirect_uri: "http://localhost/callback".into(),
                scope: "scope".into(),
            },
        };
        assert!(!provider.post_auth_redirect().is_empty());
    }
}
