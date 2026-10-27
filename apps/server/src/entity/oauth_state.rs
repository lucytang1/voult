use sea_orm::entity::prelude::*;

/// A short-lived CSRF state for one OAuth authorization attempt.
///
/// `provider_kind` is **security-relevant**, not bookkeeping. `validate_state`
/// only ever compared `vault_id`, so a callback arriving from provider A
/// carrying a state minted for provider B would validate. Once the callback
/// route becomes provider-generic, binding the provider into the state is what
/// keeps an authorization code from one provider being redeemed against another.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "oauth_state")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub state: String,
    /// `cloud::provider::ProviderKind::as_str()` — which provider minted this state.
    pub provider_kind: String,
    pub vault_id: Option<String>,
    pub created_at: DateTimeUtc,
    pub expires_at: DateTimeUtc,
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
