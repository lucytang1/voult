use sea_orm::entity::prelude::*;

/// OAuth credentials for one (vault, provider) pair.
///
/// Keyed by `(vault_id, provider_kind)` rather than `vault_id` alone: only one
/// binding is active at a time, but credentials for a previously used provider
/// are RETAINED so switching back is instant instead of requiring a fresh
/// consent. A row with no matching `cloud_binding` row is therefore intentional
/// state — the switch-back cache — not orphaned credentials to be cleaned up.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cloud_token")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub vault_id: String,
    /// `cloud::provider::ProviderKind::as_str()`. Stored as text, not an integer,
    /// so the database stays readable and a value survives a rebuild of the
    /// enum's discriminants.
    #[sea_orm(primary_key, auto_increment = false)]
    pub provider_kind: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_at: i64,
    pub scope: Option<String>,
    pub provider_account_id: Option<String>,
    pub provider_email: Option<String>,
    pub updated_at: DateTimeUtc,
}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::vault::Entity",
        from = "Column::VaultId",
        to = "super::vault::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Vault,
}
impl Related<super::vault::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Vault.def()
    }
}
impl ActiveModelBehavior for ActiveModel {}
