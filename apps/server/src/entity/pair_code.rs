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
    // Consume attempts recorded against this code. Durable and shared so the
    // cap is not multiplied by the worker/instance count (the old in-memory map
    // was per process and never shrank). Bumped atomically by
    // `POST /api/pair/consume`; dies with the row.
    pub attempts: i32,
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
