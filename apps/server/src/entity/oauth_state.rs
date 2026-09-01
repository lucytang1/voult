use sea_orm::entity::prelude::*;
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "oauth_state")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub state: String,
    pub vault_id: Option<String>,
    pub created_at: DateTimeUtc,
    pub expires_at: DateTimeUtc,
}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(belongs_to = "super::vault::Entity", from = "Column::VaultId", to = "super::vault::Column::Id", on_update = "Cascade", on_delete = "Cascade")]
    Vault,
}
impl Related<super::vault::Entity> for Entity { fn to() -> RelationDef { Relation::Vault.def() } }
impl ActiveModelBehavior for ActiveModel {}
