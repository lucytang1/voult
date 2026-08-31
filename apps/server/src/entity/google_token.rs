use sea_orm::entity::prelude::*;
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "google_token")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub vault_id: String,
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
    #[sea_orm(belongs_to = "super::vault::Entity", from = "Column::VaultId", to = "super::vault::Column::Id", on_update = "Cascade", on_delete = "Cascade")]
    Vault,
}
impl Related<super::vault::Entity> for Entity { fn to() -> RelationDef { Relation::Vault.def() } }
impl ActiveModelBehavior for ActiveModel {}
