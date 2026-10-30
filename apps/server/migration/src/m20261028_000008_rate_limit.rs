use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Rate-limit counters (P0 abuse limits) plus the per-code pairing attempt
/// counter that replaces a process-local map.
///
/// One row per `(policy, hashed subject)`. `kind` is the policy type name and
/// `key_hash` is `SHA-256(kind || 0x1F || subject)` — the raw IP / vault id is
/// never stored, so the table cannot be read as a targeting log. Windows are
/// epoch-aligned unix seconds; `expires_at` exists purely so the sweep can
/// delete whole windows with one indexed statement.
///
/// `pair_code.attempts` is incremented atomically by `POST /api/pair/consume`.
/// It lives on the row so the counter dies with the code, is shared by every
/// worker and instance, and cannot grow without bound (the old in-memory map
/// never shrank).
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(RateLimit::Table)
                    .if_not_exists()
                    .col(string(RateLimit::Kind).not_null())
                    .col(string(RateLimit::KeyHash).not_null())
                    .col(big_integer(RateLimit::WindowStart).not_null())
                    .col(big_integer(RateLimit::Count).not_null())
                    .col(big_integer(RateLimit::ExpiresAt).not_null())
                    .primary_key(Index::create().col(RateLimit::Kind).col(RateLimit::KeyHash))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_rate_limit_expires_at")
                    .table(RateLimit::Table)
                    .col(RateLimit::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        // NOT NULL with a constant default is valid for SQLite ADD COLUMN and
        // backfills existing rows, which is exactly what we want: a code minted
        // before this migration simply starts at 0 attempts.
        manager
            .alter_table(
                Table::alter()
                    .table(PairCode::Table)
                    .add_column(integer(PairCode::Attempts).not_null().default(0))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(PairCode::Table)
                    .drop_column(PairCode::Attempts)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(RateLimit::Table).if_exists().to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum RateLimit {
    Table,
    Kind,
    KeyHash,
    WindowStart,
    Count,
    ExpiresAt,
}

#[derive(DeriveIden)]
enum PairCode {
    Table,
    Attempts,
}
