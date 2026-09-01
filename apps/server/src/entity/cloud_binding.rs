use sea_orm::entity::prelude::*;
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cloud_binding")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub vault_id: String,
    pub provider_kind: String,
    pub provider_account_id: Option<String>,
    pub drive_file_id: Option<String>,
    pub remote_revision: Option<String>,
    pub sync_status: String,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(belongs_to = "super::vault::Entity", from = "Column::VaultId", to = "super::vault::Column::Id", on_update = "Cascade", on_delete = "Cascade")]
    Vault,
}
impl Related<super::vault::Entity> for Entity { fn to() -> RelationDef { Relation::Vault.def() } }
impl ActiveModelBehavior for ActiveModel {}
