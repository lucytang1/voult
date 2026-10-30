use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Replaces the plaintext `vault_verifier` column with a keyed hash of it.
///
/// Before this migration the `vault` row stored the exact string a client
/// presents to `POST /api/auth`, which made one row a replayable login
/// credential: anyone who could read it could establish a session without
/// knowing the master password. After it, the row stores
///
/// ```text
/// verifier_hash = HMAC-SHA256(verifier_salt, "voult-verifier-v1|" + presented)
/// ```
///
/// and the presented value (the HMAC preimage) is never persisted. See
/// `apps/server/src/credentials.rs` for the format and `plans/p0-verifier-replay.md`
/// for why a PAKE was not adopted here.
///
/// **No backfill, on purpose.** The old plaintext could be hashed in place and
/// would keep working, but that would put a second implementation of the
/// credential format inside the migration crate for pre-release development
/// data only. There are no releases; a migrated row therefore has an empty hash
/// and fails closed as an ordinary `AUTH_FAILED` (startup logs a count). Recreate
/// the vault. This mirrors the "clean-start schema" convention in
/// `migration/src/lib.rs`.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Additive first, so a failure between statements leaves the old column
        // readable rather than losing the only credential the row had.
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .add_column_if_not_exists(string(Vault::VerifierSalt).not_null().default(""))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .add_column_if_not_exists(string(Vault::VerifierHash).not_null().default(""))
                    .to_owned(),
            )
            .await?;

        // Drop the plaintext. Nothing may be able to write it after this point,
        // and the compiler finds every writer because the entity field is gone.
        // SQLite >= 3.35 supports DROP COLUMN; the build pins libsqlite3-sys
        // 0.30.1 (bundled SQLite 3.46).
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .drop_column(Vault::VaultVerifier)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Lossy by construction: the plaintext verifier cannot be reconstructed
        // from its hash, so a rollback restores the column shape but not the
        // credentials. Rows come back with an empty value and fail closed.
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .add_column_if_not_exists(string(Vault::VaultVerifier).not_null().default(""))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .drop_column(Vault::VerifierHash)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .drop_column(Vault::VerifierSalt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Vault {
    Table,
    VaultVerifier,
    VerifierSalt,
    VerifierHash,
}
