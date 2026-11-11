use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

// Re-wrap / rotate support. Only the recovery wrap holds `vaultKeyRaw`
// directly (R1: never the password-derived wrapping key), so rotating the
// password credential leaves recovery intact. A recovery rotation (§5.3) is likewise
// independent of the password envelope, so it never needs to move
// credential_version either — kept separate so the two histories cannot be
// conflated in a future refactor.
const CREDENTIAL_VERSION_COL: &str = "credential_version";

const ISO_UTC_NOW_SQL: &str = "STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'now')";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Vault recovery (case 3): a second envelope type wrapping `vaultKeyRaw`
        // under a key derived from the user's paper recovery secret.
        //
        // recovery_verifier is a 256-bit HMAC output over K_rec. Unlike
        // vault_verifier it is not derived from a password, so a database dump
        // yields nothing to brute force, and it is only ever presented bound to
        // a fresh server challenge — never as a static replayable credential.
        //
        // All six columns are nullable because SQLite cannot ALTER a NOT NULL
        // column without a default; `recovery_enabled` is DERIVED as
        // `recovery_verifier IS NOT NULL` and POST /register refuses a vault
        // that arrives without it, so no vault row can exist in the
        // no-recovery state through the API.
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .add_column_if_not_exists(string(Vault::RecoveryVerifier).null())
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .add_column_if_not_exists(string(Vault::RecoverySalt).null())
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .add_column_if_not_exists(string(Vault::RecoveryWrap).null())
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .add_column_if_not_exists(string(Vault::RecoveryWrapIv).null())
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .add_column_if_not_exists(string(Vault::RecoveryCreatedAt).null())
                    .to_owned(),
            )
            .await?;

        // Guards the single irreversible write in recovery (POST
        // /recovery/rewrap): the UPDATE is `WHERE id = ? AND credential_version
        // = ?`, so two concurrent recoveries cannot both believe they won. The
        // loser gets 409 CREDENTIAL_STALE. Starts at 0 and is bumped only by
        // that endpoint.
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .add_column_if_not_exists(
                        integer(Vault::CredentialVersion).not_null().default(0),
                    )
                    .to_owned(),
            )
            .await?;

        // Backfill defensively for drivers that ignore the column default on
        // ALTER (SQLite applies the default to existing rows, but be explicit).
        let db = manager.get_connection();
        db.execute_unprepared(&format!(
            "UPDATE vault SET {CREDENTIAL_VERSION_COL} = 0 WHERE {CREDENTIAL_VERSION_COL} IS NULL"
        ))
        .await?;

        // Ephemeral challenge records backing POST /recovery/{challenge,rewrap}.
        // Modelled on the pair_code table: a random public `selector`, the
        // challenge itself, an integrity hash over (vault_id, challenge), and a
        // hard expiry. Carries no credential and no key material — only values
        // the caller already holds.
        manager
            .create_table(
                Table::create()
                    .table(RecoveryChallenge::Table)
                    .if_not_exists()
                    .col(string(RecoveryChallenge::Selector).not_null().primary_key())
                    .col(string(RecoveryChallenge::VaultId).not_null())
                    // CSPRNG(32), base64. Returned to the caller once.
                    .col(string(RecoveryChallenge::Challenge).not_null())
                    // SHA256(vault_id || challenge), hex. Integrity check on the
                    // stored row — not a secrecy boundary, since the challenge is
                    // itself stored in the clear.
                    .col(string(RecoveryChallenge::ChallengeHash).not_null())
                    .col(
                        string(RecoveryChallenge::CreatedAt)
                            .not_null()
                            .default(Expr::cust(ISO_UTC_NOW_SQL)),
                    )
                    .col(string(RecoveryChallenge::ExpiresAt).not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_recovery_challenge_vault_id")
                            .from(RecoveryChallenge::Table, RecoveryChallenge::VaultId)
                            .to(Vault::Table, Vault::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_recovery_challenge_vault_id")
                    .table(RecoveryChallenge::Table)
                    .col(RecoveryChallenge::VaultId)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(RecoveryChallenge::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .drop_column(Vault::CredentialVersion)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .drop_column(Vault::RecoveryCreatedAt)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .drop_column(Vault::RecoveryWrapIv)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .drop_column(Vault::RecoveryWrap)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .drop_column(Vault::RecoverySalt)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .drop_column(Vault::RecoveryVerifier)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Vault {
    Table,
    RecoveryVerifier,
    RecoverySalt,
    RecoveryWrap,
    RecoveryWrapIv,
    RecoveryCreatedAt,
    CredentialVersion,
    Id,
}

#[derive(DeriveIden)]
enum RecoveryChallenge {
    Table,
    Selector,
    VaultId,
    Challenge,
    ChallengeHash,
    CreatedAt,
    ExpiresAt,
}
