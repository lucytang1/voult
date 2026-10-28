use sea_orm_migration::{prelude::*, schema::*};

/// Monotonic counter naming which *incarnation* of a vault's cloud binding a row
/// describes.
///
/// `cloud_binding` is keyed by `vault_id`, so every provider switch, re-enroll,
/// import-adopt and disconnect rewrites the same row. The mirror runs detached
/// and may still be mid-flight when that happens: without a generations column a
/// pass that started on Google Drive would land its `remote_revision` (a Drive
/// revision string) on a row that now describes Dropbox, and would force
/// `sync_status = idle` over whatever the new binding actually is. Every mirror
/// state write therefore carries the generation it captured and is dropped when
/// the value no longer matches.
///
/// It is deliberately not the vault `version` (document CAS for sync) or
/// `credential_version` (password-credential CAS): bumping either of those from a
/// provider switch would invalidate unrelated pending work.
///
/// Additive and safe on existing rows: `DEFAULT 0` makes every live binding its
/// own first generation, and the next switch bumps it to 1.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(CloudBinding::Table)
                    .add_column_if_not_exists(
                        integer(CloudBinding::BindingGeneration)
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(CloudBinding::Table)
                    .drop_column(CloudBinding::BindingGeneration)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum CloudBinding {
    Table,
    BindingGeneration,
}
