use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

// Disaster-recovery mirror bookkeeping for the Drive copy of a vault.
//
// The server is the write authority for vault ciphertext; Drive holds an
// out-of-band encrypted copy that is re-written after a successful CAS on
// /update_vault. `mirrored_vault_version` is the server `vault.version` that
// the Drive copy corresponds to, so a stale backup is detectable without ever
// decrypting anything. `last_mirror_error` stores a short provider error code
// only — never a provider response body, token, or ciphertext.
//
// All columns are nullable and additive: existing bindings stay valid and
// simply read as "never mirrored" until the next vault write.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(CloudBinding::Table)
                    .add_column_if_not_exists(integer(CloudBinding::MirroredVaultVersion).null())
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(CloudBinding::Table)
                    .add_column_if_not_exists(string(CloudBinding::LastMirroredAt).null())
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(CloudBinding::Table)
                    .add_column_if_not_exists(string(CloudBinding::LastMirrorError).null())
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for col in [
            CloudBinding::LastMirrorError,
            CloudBinding::LastMirroredAt,
            CloudBinding::MirroredVaultVersion,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(CloudBinding::Table)
                        .drop_column(col)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

#[derive(DeriveIden)]
enum CloudBinding {
    Table,
    MirroredVaultVersion,
    LastMirroredAt,
    LastMirrorError,
}
