use sea_orm::entity::prelude::*;

/// The vault's ONE active cloud backup binding.
///
/// The primary key stays `vault_id` on purpose: the product model is "the user
/// picks one provider", not "a vault fans out to several". Multiple simultaneous
/// providers were considered and rejected — they would force a per-binding
/// rewrite of the mirror's coalescing guard for no user-visible benefit.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cloud_binding")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub vault_id: String,
    /// `cloud::provider::ProviderKind::as_str()`. Load-bearing: every
    /// provider-blind route resolves what to do from this column.
    pub provider_kind: String,
    pub provider_account_id: Option<String>,
    /// Opaque provider file handle. Was `drive_file_id`; for Drive it happens to
    /// be a Drive id, but nothing about the storage of this value is Drive-shaped.
    pub remote_file_id: Option<String>,
    /// The last provider revision *we* observed. Used as the conditional-write
    /// token, so it must never be a placeholder — see `cloud::drive::UNKNOWN_REVISION`.
    pub remote_revision: Option<String>,
    pub sync_status: String,
    /// Server `vault.version` that the provider copy currently corresponds to.
    /// `None` means the binding has never been mirrored. Comparing this with the
    /// live vault version is how a stale disaster-recovery copy is detected
    /// without decrypting anything.
    pub mirrored_vault_version: Option<i32>,
    /// ISO UTC timestamp of the last successful provider write.
    pub last_mirrored_at: Option<String>,
    /// Short provider error code from the last failed mirror attempt. Never a
    /// provider response body, token, or ciphertext.
    pub last_mirror_error: Option<String>,
    pub created_at: DateTimeUtc,
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
