use sea_orm::entity::prelude::*;

/// An OAuth code exchanged **before any vault exists** — the pre-session import
/// flow, where the user authorizes a provider in order to *discover* which
/// vaults they could restore.
///
/// Keyed by the CSRF state because that is the only handle the client holds at
/// that point; `provider_kind` records which provider issued the credential so a
/// pending token can never be exchanged against the wrong provider's endpoints.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cloud_pending_token")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub state: String,
    /// `cloud::provider::ProviderKind::as_str()`.
    pub provider_kind: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_at: i64,
    pub scope: Option<String>,
    pub provider_account_id: Option<String>,
    pub provider_email: Option<String>,
    pub local_email: Option<String>,
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
