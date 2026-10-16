use sea_orm::entity::prelude::*;

// One-time recovery challenge. Created unauthenticated by
// `POST /api/recovery/challenge` (the recovering client holds a paper recovery
// key but no session) and consumed exactly once by `POST /api/recovery/rewrap`,
// the only irreversible write in the recovery flow.
//
// Holds nothing secret: the selector is a public random UUID used to address
// the row, the challenge is handed back to the caller once and carries no
// information the caller does not already have. Never stores a verifier, a
// wrap, a proof, or ciphertext. Short TTL, single-use, cascades on vault delete.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "recovery_challenge")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub selector: String,
    pub vault_id: String,
    pub challenge: String,
    pub challenge_hash: String,
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