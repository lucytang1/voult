use sea_orm::entity::prelude::*;

// One-time extension-pairing record. Created by an authenticated web session
// (`POST /api/pair/start`), consumed once by the extension
// (`POST /api/pair/consume`). Carries only the vault identity — never the
// verifier, wraps, or ciphertext. Short TTL, single-use, code stored hashed.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "pair_code")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub selector: String,
    pub vault_id: String,
    pub code_hash: String,
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
