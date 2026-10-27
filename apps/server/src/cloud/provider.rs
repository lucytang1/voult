//! Provider identity and the `CloudProvider` seam.
//!
//! # The model
//!
//! **The server is the write authority. A provider is the disaster-recovery
//! copy.** Nothing in this module participates in vault writes, merges, or
//! sessions — `cloud::mirror` is the only caller, and it runs out of band after
//! a CAS commits.
//!
//! # Why an enum, not `Box<dyn CloudProvider>`
//!
//! The provider set is closed and known at build time, so dispatch is a `match`
//! on [`ProviderKind`] rather than a trait object:
//!
//! * Adding a provider requires adding an enum variant, so every `match` over
//!   kinds becomes a compile error until it handles the new one. A `String`
//!   would let an unhandled provider fall through a catch-all and write to the
//!   wrong account at runtime.
//! * No `async-trait` dependency is needed: edition 2024 provides native `async
//!   fn` in traits, and the enum erases the concrete types for us.
//!
//! # What a provider is responsible for
//!
//! Exactly two things: an OAuth2 authorization-code flow, and a set of file
//! operations with a conditional-write (compare-and-swap) primitive. Everything
//! else — packaging the vault, deciding *what* to mirror, recording progress —
//! is provider-neutral and lives in `cloud::package` and `cloud::mirror`.
//!
//! # What a provider must never do
//!
//! * Touch key material. The only thing a provider ever receives is ciphertext
//!   plus public crypto metadata (`cloud::package`), because the server holds no
//!   keys. The `package` argument to the file operations is opaque bytes.
//! * Decide whether a write is safe. The conditional-write token comes from the
//!   binding's `remote_revision`, which is only ever a revision *we* recorded.

use std::fmt;
use std::str::FromStr;

use crate::cloud::error::ProviderError;
use crate::cloud::providers;

/// A cloud backup provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderKind {
    GoogleDrive,
    Dropbox,
}

impl ProviderKind {
    /// Every provider this build knows about, whether or not it is configured.
    /// Consumed by `GET /cloud/providers`, which lands with the generic routes.
    #[allow(dead_code)]
    pub const ALL: &'static [ProviderKind] = &[ProviderKind::GoogleDrive, ProviderKind::Dropbox];

    /// The persisted / wire value. Written to `provider_kind` columns and sent
    /// as JSON, so it is a stable contract across releases.
    pub const fn as_str(&self) -> &'static str {
        match self {
            ProviderKind::GoogleDrive => "google_drive",
            ProviderKind::Dropbox => "dropbox",
        }
    }

    /// Human-readable name for logs and for the client-facing provider list.
    #[allow(dead_code)]
    pub const fn display_name(&self) -> &'static str {
        match self {
            ProviderKind::GoogleDrive => "Google Drive",
            ProviderKind::Dropbox => "Dropbox",
        }
    }

    /// Parse a persisted or client-supplied wire value.
    ///
    /// Deliberately *not* `str::parse`-only: an inherent method lets callers
    /// write `ProviderKind::parse(x)?` without turbofishing the error type, and
    /// it keeps the unknown-value error next to the enum it belongs to.
    pub fn parse(raw: &str) -> Result<Self, UnknownProvider> {
        match raw {
            "google_drive" => Ok(ProviderKind::GoogleDrive),
            "dropbox" => Ok(ProviderKind::Dropbox),
            other => Err(UnknownProvider(other.to_string())),
        }
    }
}

impl fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Returned when a persisted or client-supplied kind names a provider this
/// build does not know. Never fall back to a default provider: an unrecognized
/// kind must fail loudly rather than mirror a vault to an account the user did
/// not choose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownProvider(pub String);

impl fmt::Display for UnknownProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Echo the value back: it originates in our own database or from a
        // client we already authenticated, and an operator needs to see which
        // value is unrecognized in order to fix it. Never ciphertext or a secret.
        write!(f, "unknown provider: {}", self.0)
    }
}

impl std::error::Error for UnknownProvider {}

impl FromStr for ProviderKind {
    type Err = UnknownProvider;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ProviderKind::parse(s)
    }
}

impl serde::Serialize for ProviderKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ProviderKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        ProviderKind::parse(&raw).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Data crossing the seam
// ---------------------------------------------------------------------------

/// A token set returned by an authorization-code exchange or a refresh.
///
/// `refresh_token` is `None` when the provider did not issue a new one. That is
/// normal for Google (refresh tokens are only sent on first consent) and means
/// "keep the stored one"; it is NOT the same as "revoke".
#[derive(Debug, Clone, Default)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: Option<String>,
    /// Absolute unix timestamp.
    pub expires_at: i64,
    pub scope: Option<String>,
}

/// The stored credential row, handed to [`CloudProvider::refresh`].
///
/// Deliberately a borrowed view rather than the SeaORM model: the provider must
/// not be able to mutate or persist the row itself. Rotation is the store's
/// job, so that "persist the new refresh token before returning" is enforced in
/// exactly one place (`cloud::token_store`).
///
/// Only `refresh_token` is read by the current implementations. The remaining
/// fields exist so a provider that needs them (scope narrowing, an account-level
/// precondition) does not force another signature change.
#[derive(Debug, Clone)]
pub struct StoredToken {
    #[allow(dead_code)]
    pub access_token: String,
    pub refresh_token: Option<String>,
    #[allow(dead_code)]
    pub token_type: String,
    #[allow(dead_code)]
    pub expires_at: i64,
    #[allow(dead_code)]
    pub scope: Option<String>,
}

/// Identity of the connected provider account, for display in Settings.
#[derive(Debug, Clone, Default)]
pub struct ProviderAccount {
    pub account_id: Option<String>,
    pub email: Option<String>,
}

/// A vault file living at a provider.
///
/// `Serialize` is what the client's restore chooser reads, so the field names
/// here are a wire contract. `head_revision_id`/`version` are the historical
/// Drive-shaped pair the client still consumes; `revision` is the neutral name
/// and carries the same value, so a provider that has no such notion simply
/// emits the sentinel.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RemoteVaultFile {
    /// Parsed from the canonical file name, so it round-trips with the vault.
    pub vault_id: String,
    pub file_id: String,
    #[serde(rename = "head_revision_id")]
    pub revision: String,
    pub name: String,
    pub modified_time: Option<String>,
    pub size: Option<String>,
}

// ---------------------------------------------------------------------------
// The trait
// ---------------------------------------------------------------------------

/// A cloud backup provider.
///
/// `t` is the caller's access token, resolved by `cloud::token_store`. Providers
/// never read tokens from the database themselves — that keeps the refresh and
/// rotation policy in one place and keeps providers free of database access.
///
/// `kind`, `display_name` and `env_keys` have no caller until the route layer
/// becomes provider-generic; they are part of the contract `GET /cloud/providers`
/// will need, so they are declared now rather than retrofitted.
#[allow(dead_code)]
pub trait CloudProvider {
    fn kind(&self) -> ProviderKind;

    fn display_name(&self) -> &'static str;

    /// Env keys this provider needs, for documentation and startup diagnostics.
    fn env_keys(&self) -> &'static [&'static str];

    /// The OAuth redirect URI registered with the provider. Each provider
    /// registers its own exact URI, so it is owned by the implementation rather
    /// than passed in per call.
    fn redirect_uri(&self) -> &str;

    /// Where the browser lands after a provider callback: the app's vault
    /// chooser, carrying status as query params.
    ///
    /// Defaults to the bundled-vs-dev heuristic (bundled mode serves the client
    /// from the server origin; dev runs Expo on :8081). A provider whose consent
    /// screen needs a different landing page overrides this.
    fn post_auth_redirect(&self) -> String {
        default_post_auth_redirect()
    }

    // --- authorization ---

    /// The URL to send the browser to. `state` is a CSRF token minted by
    /// `cloud::oauth_state` and already bound to this provider.
    fn authorize_url(&self, state: &str) -> String;

    /// Exchange an authorization code for credentials.
    async fn exchange_code(&self, code: &str) -> Result<TokenSet, ProviderError>;

    /// Refresh an expiring credential.
    ///
    /// CONTRACT: an implementation that **rotates** refresh tokens must return
    /// the new one in [`TokenSet::refresh_token`], and `cloud::token_store`
    /// persists it before the new access token is used. A provider that does not
    /// rotate returns `None`, which means "keep the stored refresh token" and
    /// never "revoke".
    async fn refresh(&self, current: &StoredToken) -> Result<TokenSet, ProviderError>;

    /// Identity of the connected account. Best-effort: an empty result is not a
    /// failure, since the backup is still valid without a display name.
    async fn account(&self, access_token: &str) -> Result<ProviderAccount, ProviderError>;

    // --- vault files ---

    /// List every vault file this provider holds, for the restore chooser.
    async fn list_vault_files(
        &self,
        access_token: &str,
    ) -> Result<Vec<RemoteVaultFile>, ProviderError>;

    /// Create the vault file, or return the existing one if `vault_id` is
    /// already present. Idempotent by `vault_id`: enrollment must not produce a
    /// duplicate, and a lost create response must be recoverable by retry.
    async fn create_vault_file(
        &self,
        access_token: &str,
        vault_id: &str,
        bytes: &[u8],
    ) -> Result<RemoteVaultFile, ProviderError>;

    /// Fetch the file's bytes along with its current revision.
    async fn read_vault_file(
        &self,
        access_token: &str,
        file_id: &str,
    ) -> Result<(Vec<u8>, String), ProviderError>;

    /// Write `bytes`, refusing unless the file is still at `if_match`.
    ///
    /// This is the gate that stops a stale mirror from clobbering a newer copy.
    /// Implementations must return [`ProviderErrorKind::RemoteConflict`] when
    /// `if_match` is `Some(_)` and the file has moved, and
    /// [`ProviderErrorKind::RemoteRevisionUnavailable`] when `if_match` is
    /// `None` and the provider offers no revision to condition on.
    async fn conditional_write(
        &self,
        access_token: &str,
        file_id: &str,
        bytes: &[u8],
        if_match: Option<&str>,
    ) -> Result<String, ProviderError>;

    /// The file's current revision token, for establishing a CAS baseline.
    ///
    /// Returns [`NoRevision`] when the provider offers no revision. Callers must
    /// treat that as *refuse*, never as "matches anything" — conditioning a
    /// write on an absent revision would defeat the whole gate.
    async fn file_revision(
        &self,
        access_token: &str,
        file_id: &str,
    ) -> Result<Result<String, NoRevision>, ProviderError>;

    /// Permanently remove the vault file.
    async fn delete_vault_file(
        &self,
        access_token: &str,
        file_id: &str,
    ) -> Result<(), ProviderError>;
}

/// Shared landing URL fallback for provider implementations that support an
/// optional environment override. Keep this outside the trait: invoking the
/// trait method from an override dispatches back to that override recursively.
pub fn default_post_auth_redirect() -> String {
    let is_bundled = std::env::var(crate::config::ENV_STATIC_DIR)
        .map(|d| d.contains("Resources/dist"))
        .unwrap_or_else(|_| {
            if let Ok(exe) = std::env::current_exe() {
                if let Some(dir) = exe.parent() {
                    return dir.join("../Resources/dist/index.html").exists()
                        || dir.join("../../Resources/dist/index.html").exists();
                }
            }
            false
        });
    if is_bundled {
        "http://localhost:8080/vault".to_string()
    } else {
        "http://localhost:8081/vault".to_string()
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// A provider that reported no revision token for a file.
///
/// Carrier for "no usable CAS token" across the seam, so the mirror can refuse
/// without naming any provider's sentinel value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoRevision;

impl fmt::Display for NoRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the provider reported no revision token")
    }
}

/// The set of providers this build knows, erased to one enum.
///
/// Adding a provider means: add a [`ProviderKind`] variant, add a variant here,
/// and handle it in the three `match`es below. The compiler finds all of them.
#[derive(Debug, Clone)]
pub enum AnyProvider {
    GoogleDrive(Box<providers::google_drive::GoogleDriveProvider>),
    Dropbox(Box<providers::dropbox::DropboxProvider>),
}

/// Resolve a provider implementation, or `None` when it is not configured on
/// this server (missing credentials).
///
/// `None` means "the server has no keys for this provider" — a distinct,
/// recoverable state from "the provider is broken".
pub fn provider(kind: ProviderKind) -> Option<AnyProvider> {
    match kind {
        ProviderKind::GoogleDrive => providers::google_drive::GoogleDriveProvider::from_env()
            .map(|p| AnyProvider::GoogleDrive(Box::new(p))),
        ProviderKind::Dropbox => providers::dropbox::DropboxProvider::from_env()
            .map(|p| AnyProvider::Dropbox(Box::new(p))),
    }
}

/// Providers this build knows and this server is configured to use. Drives
/// `GET /cloud/providers`, so an unconfigured provider simply does not appear in
/// the client picker.
#[allow(dead_code)]
pub fn configured_providers() -> Vec<ProviderKind> {
    ProviderKind::ALL
        .iter()
        .copied()
        .filter(|kind| provider(*kind).is_some())
        .collect()
}

impl CloudProvider for AnyProvider {
    fn kind(&self) -> ProviderKind {
        match self {
            AnyProvider::GoogleDrive(p) => p.kind(),
            AnyProvider::Dropbox(p) => p.kind(),
        }
    }

    fn display_name(&self) -> &'static str {
        match self {
            AnyProvider::GoogleDrive(p) => p.display_name(),
            AnyProvider::Dropbox(p) => p.display_name(),
        }
    }

    fn env_keys(&self) -> &'static [&'static str] {
        match self {
            AnyProvider::GoogleDrive(p) => p.env_keys(),
            AnyProvider::Dropbox(p) => p.env_keys(),
        }
    }

    fn redirect_uri(&self) -> &str {
        match self {
            AnyProvider::GoogleDrive(p) => p.redirect_uri(),
            AnyProvider::Dropbox(p) => p.redirect_uri(),
        }
    }

    fn post_auth_redirect(&self) -> String {
        match self {
            AnyProvider::GoogleDrive(p) => p.post_auth_redirect(),
            AnyProvider::Dropbox(p) => p.post_auth_redirect(),
        }
    }

    fn authorize_url(&self, state: &str) -> String {
        match self {
            AnyProvider::GoogleDrive(p) => p.authorize_url(state),
            AnyProvider::Dropbox(p) => p.authorize_url(state),
        }
    }

    async fn exchange_code(&self, code: &str) -> Result<TokenSet, ProviderError> {
        match self {
            AnyProvider::GoogleDrive(p) => p.exchange_code(code).await,
            AnyProvider::Dropbox(p) => p.exchange_code(code).await,
        }
    }

    async fn refresh(&self, current: &StoredToken) -> Result<TokenSet, ProviderError> {
        match self {
            AnyProvider::GoogleDrive(p) => p.refresh(current).await,
            AnyProvider::Dropbox(p) => p.refresh(current).await,
        }
    }

    async fn account(&self, access_token: &str) -> Result<ProviderAccount, ProviderError> {
        match self {
            AnyProvider::GoogleDrive(p) => p.account(access_token).await,
            AnyProvider::Dropbox(p) => p.account(access_token).await,
        }
    }

    async fn list_vault_files(
        &self,
        access_token: &str,
    ) -> Result<Vec<RemoteVaultFile>, ProviderError> {
        match self {
            AnyProvider::GoogleDrive(p) => p.list_vault_files(access_token).await,
            AnyProvider::Dropbox(p) => p.list_vault_files(access_token).await,
        }
    }

    async fn create_vault_file(
        &self,
        access_token: &str,
        vault_id: &str,
        bytes: &[u8],
    ) -> Result<RemoteVaultFile, ProviderError> {
        match self {
            AnyProvider::GoogleDrive(p) => p.create_vault_file(access_token, vault_id, bytes).await,
            AnyProvider::Dropbox(p) => p.create_vault_file(access_token, vault_id, bytes).await,
        }
    }

    async fn read_vault_file(
        &self,
        access_token: &str,
        file_id: &str,
    ) -> Result<(Vec<u8>, String), ProviderError> {
        match self {
            AnyProvider::GoogleDrive(p) => p.read_vault_file(access_token, file_id).await,
            AnyProvider::Dropbox(p) => p.read_vault_file(access_token, file_id).await,
        }
    }

    async fn conditional_write(
        &self,
        access_token: &str,
        file_id: &str,
        bytes: &[u8],
        if_match: Option<&str>,
    ) -> Result<String, ProviderError> {
        match self {
            AnyProvider::GoogleDrive(p) => {
                p.conditional_write(access_token, file_id, bytes, if_match)
                    .await
            }
            AnyProvider::Dropbox(p) => {
                p.conditional_write(access_token, file_id, bytes, if_match)
                    .await
            }
        }
    }

    async fn file_revision(
        &self,
        access_token: &str,
        file_id: &str,
    ) -> Result<Result<String, NoRevision>, ProviderError> {
        match self {
            AnyProvider::GoogleDrive(p) => p.file_revision(access_token, file_id).await,
            AnyProvider::Dropbox(p) => p.file_revision(access_token, file_id).await,
        }
    }

    async fn delete_vault_file(
        &self,
        access_token: &str,
        file_id: &str,
    ) -> Result<(), ProviderError> {
        match self {
            AnyProvider::GoogleDrive(p) => p.delete_vault_file(access_token, file_id).await,
            AnyProvider::Dropbox(p) => p.delete_vault_file(access_token, file_id).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_values_round_trip() {
        for kind in ProviderKind::ALL {
            assert_eq!(ProviderKind::parse(kind.as_str()), Ok(*kind));
            assert_eq!(kind.to_string(), kind.as_str());
        }
    }

    /// The persisted value is a database and wire contract. Changing it silently
    /// would orphan every stored binding and every client cache key.
    #[test]
    fn persisted_values_are_stable() {
        assert_eq!(ProviderKind::GoogleDrive.as_str(), "google_drive");
        assert_eq!(ProviderKind::Dropbox.as_str(), "dropbox");
    }

    #[test]
    fn unknown_kinds_are_rejected_rather_than_defaulted() {
        // A catch-all that mapped unknown input to a default provider would
        // write to the WRONG account. Failing loudly is the point.
        assert_eq!(
            ProviderKind::parse("onedrive"),
            Err(UnknownProvider("onedrive".to_string()))
        );
        assert_eq!(
            ProviderKind::parse(""),
            Err(UnknownProvider("".to_string()))
        );
        // Case must not be silently normalized: `Google_Drive` is not a value we
        // ever write, so accepting it would mean two spellings for one provider.
        assert!(ProviderKind::parse("Google_Drive").is_err());
    }

    #[test]
    fn json_uses_the_wire_value_not_the_variant_name() {
        let json = serde_json::to_string(&ProviderKind::GoogleDrive).unwrap();
        assert_eq!(json, "\"google_drive\"");
        let back: ProviderKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ProviderKind::GoogleDrive);
        assert!(serde_json::from_str::<ProviderKind>("\"onedrive\"").is_err());
    }

    #[test]
    fn display_name_is_human_readable() {
        assert_eq!(ProviderKind::GoogleDrive.display_name(), "Google Drive");
    }

    /// `ALL` and `as_str` must stay in step, or a provider could be reachable
    /// through the registry while being absent from the client's picker.
    #[test]
    fn all_agrees_with_the_wire_values() {
        for kind in ProviderKind::ALL {
            assert_eq!(ProviderKind::parse(kind.as_str()).unwrap(), *kind);
        }
    }

    /// The registry must never return a provider whose `kind()` disagrees with
    /// the kind it was asked for — callers cache the lookup result.
    #[test]
    fn registry_resolves_self_consistently() {
        for kind in ProviderKind::ALL {
            if let Some(p) = provider(*kind) {
                assert_eq!(p.kind(), *kind);
                assert_eq!(p.display_name(), kind.display_name());
                assert!(!p.env_keys().is_empty());
            }
        }
    }

    /// Providers with no credentials configured are simply absent, and must
    /// never be reported as configured.
    #[test]
    fn configured_providers_is_a_subset_of_all() {
        for kind in configured_providers() {
            assert!(ProviderKind::ALL.contains(&kind));
            assert!(provider(kind).is_some());
        }
    }
}
