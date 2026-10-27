use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

const LOCK_EPOCH_COL: &str = "lock_epoch";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Global lock signal for web ↔ extension consistency. A monotonic,
        // non-sensitive counter: any client that locks bumps it via
        // POST /api/lock; peers observe the bump in GET /session and wipe
        // local keys. Never carries key material or plaintext.
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .add_column_if_not_exists(integer(Vault::LockEpoch).not_null().default(0))
                    .to_owned(),
            )
            .await?;

        // Backfill defensively for drivers that ignore the column default on
        // ALTER (SQLite applies the default to existing rows, but be explicit).
        let db = manager.get_connection();
        db.execute_unprepared(&format!(
            "UPDATE vault SET {LOCK_EPOCH_COL} = 0 WHERE {LOCK_EPOCH_COL} IS NULL"
        ))
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .drop_column(Vault::LockEpoch)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Vault {
    Table,
    LockEpoch,
}
