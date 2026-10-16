use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

/// Makes the cloud-backup tables provider-neutral.
///
/// Drive stops being the only cloud provider, so the tables that stored *its*
/// credentials and *its* file ids are rebuilt with provider identity in the key:
///
///   google_token          -> cloud_token           PK (vault_id, provider_kind)
///   google_pending_token  -> cloud_pending_token   PK (state),           + provider_kind
///   oauth_state           -> oauth_state                            + provider_kind
///   cloud_binding         -> cloud_binding        PK (vault_id), drive_file_id -> remote_file_id
///
/// # Why drop and recreate rather than ALTER
///
/// These tables are dropped and rebuilt with no data carried over. There are no
/// installs in the wild to preserve, and SQLite cannot `RENAME COLUMN`, so a
/// preserving migration would need the create-copy-drop dance for no benefit.
/// The only consequence is that an existing Drive file becomes unreferenced —
/// see the warning below.
///
/// # `cloud_token` is keyed by (vault_id, provider_kind) on purpose
///
/// Only one binding is active at a time, but credentials for a previously used
/// provider are RETAINED so switching back is instant rather than requiring a
/// fresh OAuth consent. A `cloud_token` row with no matching `cloud_binding` row
/// is therefore intentional state — the switch-back cache — not garbage. Do not
/// add a cleanup job that deletes "credentials with no binding"; it would remove
/// the only reason for this key.

const ISO_UTC_NOW_SQL: &str = "STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'now')";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Tell the operator that any existing binding state is being discarded.
        // The provider-side file survives (Drive `create_vault` is idempotent by
        // vault_id and re-adopts it on re-enrollment), but the local pointer to it
        // does not, so a previously linked provider must be re-linked from
        // Settings before backing up resumes.
        //
        // Guarded on the table existing so a fresh install does not get a
        // warning about state it never had.
        for name in ["cloud_binding", "google_token", "google_pending_token"] {
            if manager.has_table(name).await? {
                log::warn!(
                    "{name}: dropping existing cloud backup state. Vaults are untouched and the \
                     provider-side backup file is not deleted, but if a provider was linked, \
                     re-link it from Settings to resume backing up."
                );
            }
        }

        manager
            .drop_table(Table::drop().table(LegacyGooglePendingToken::Table).if_exists().to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(LegacyGoogleToken::Table).if_exists().to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(OauthState::Table).if_exists().to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(CloudBinding::Table).if_exists().to_owned())
            .await?;

        // --- cloud_token: one row per (vault, provider) ---
        manager
            .create_table(
                Table::create()
                    .table(CloudToken::Table)
                    .if_not_exists()
                    .col(string(CloudToken::VaultId).not_null())
                    .col(string(CloudToken::ProviderKind).not_null())
                    .col(string(CloudToken::AccessToken).not_null())
                    .col(string(CloudToken::RefreshToken).null())
                    .col(string(CloudToken::TokenType).not_null().default("Bearer"))
                    .col(big_integer(CloudToken::ExpiresAt).not_null())
                    .col(string(CloudToken::Scope).null())
                    .col(string(CloudToken::ProviderAccountId).null())
                    .col(string(CloudToken::ProviderEmail).null())
                    .col(
                        string(CloudToken::UpdatedAt)
                            .not_null()
                            .default(Expr::cust(ISO_UTC_NOW_SQL)),
                    )
                    // Composite key, not vault_id alone: retained credentials for
                    // a non-active provider must coexist with the active one.
                    .primary_key(
                        Index::create()
                            .name("pk_cloud_token")
                            .col(CloudToken::VaultId)
                            .col(CloudToken::ProviderKind),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_cloud_token_vault_id")
                            .from(CloudToken::Table, CloudToken::VaultId)
                            .to(Vault::Table, Vault::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // --- cloud_pending_token: an OAuth code exchanged before any vault exists ---
        manager
            .create_table(
                Table::create()
                    .table(CloudPendingToken::Table)
                    .if_not_exists()
                    .col(string(CloudPendingToken::State).not_null().primary_key())
                    .col(string(CloudPendingToken::ProviderKind).not_null())
                    .col(string(CloudPendingToken::AccessToken).not_null())
                    .col(string(CloudPendingToken::RefreshToken).null())
                    .col(string(CloudPendingToken::TokenType).not_null().default("Bearer"))
                    .col(big_integer(CloudPendingToken::ExpiresAt).not_null())
                    .col(string(CloudPendingToken::Scope).null())
                    .col(string(CloudPendingToken::ProviderAccountId).null())
                    .col(string(CloudPendingToken::ProviderEmail).null())
                    .col(string(CloudPendingToken::LocalEmail).null())
                    .col(
                        string(CloudPendingToken::CreatedAt)
                            .not_null()
                            .default(Expr::cust(ISO_UTC_NOW_SQL)),
                    )
                    .to_owned(),
            )
            .await?;

        // --- oauth_state: provider_kind is SECURITY-relevant ---
        //
        // Without it, a callback from provider A carrying provider B's state
        // would validate, because validate_state only ever checked vault_id.
        manager
            .create_table(
                Table::create()
                    .table(OauthState::Table)
                    .if_not_exists()
                    .col(string(OauthState::State).not_null().primary_key())
                    .col(string(OauthState::ProviderKind).not_null())
                    .col(string(OauthState::VaultId).null())
                    .col(
                        string(OauthState::CreatedAt)
                            .not_null()
                            .default(Expr::cust(ISO_UTC_NOW_SQL)),
                    )
                    .col(
                        string(OauthState::ExpiresAt)
                            .not_null()
                            .default(Expr::cust(ISO_UTC_NOW_SQL)),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_oauth_state_vault_id")
                            .from(OauthState::Table, OauthState::VaultId)
                            .to(Vault::Table, Vault::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // --- cloud_binding: exactly ONE active binding per vault ---
        //
        // PK stays vault_id. Multiple simultaneous providers were considered and
        // rejected: they would force a per-binding rewrite of the mirror's
        // coalescing guard for no user-visible benefit, since the product model
        // is "the user picks one provider".
        manager
            .create_table(
                Table::create()
                    .table(CloudBinding::Table)
                    .if_not_exists()
                    .col(string(CloudBinding::VaultId).not_null().primary_key())
                    .col(string(CloudBinding::ProviderKind).not_null())
                    .col(string(CloudBinding::ProviderAccountId).null())
                    // Was `drive_file_id`. The column holds an opaque provider
                    // file handle, which for Drive happens to be a Drive id.
                    .col(string(CloudBinding::RemoteFileId).null())
                    .col(string(CloudBinding::RemoteRevision).null())
                    .col(string(CloudBinding::SyncStatus).not_null().default("idle"))
                    .col(integer(CloudBinding::MirroredVaultVersion).null())
                    .col(string(CloudBinding::LastMirroredAt).null())
                    .col(string(CloudBinding::LastMirrorError).null())
                    .col(
                        string(CloudBinding::CreatedAt)
                            .not_null()
                            .default(Expr::cust(ISO_UTC_NOW_SQL)),
                    )
                    .col(
                        string(CloudBinding::UpdatedAt)
                            .not_null()
                            .default(Expr::cust(ISO_UTC_NOW_SQL)),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_cloud_binding_vault_id")
                            .from(CloudBinding::Table, CloudBinding::VaultId)
                            .to(Vault::Table, Vault::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    // No index on provider_kind: every query against this table
                    // filters by vault_id (the PK), including the mirror's
                    // provider resolution, which reads provider_kind off the row
                    // it already loaded. An index here would be unused.
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Irreversible by design: no data was carried over, so there is nothing
        // to restore. An operator must re-link their provider after a downgrade.
        manager
            .drop_table(Table::drop().table(CloudBinding::Table).if_exists().to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(OauthState::Table).if_exists().to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(CloudPendingToken::Table).if_exists().to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(CloudToken::Table).if_exists().to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum CloudToken {
    Table,
    VaultId,
    ProviderKind,
    AccessToken,
    RefreshToken,
    TokenType,
    ExpiresAt,
    Scope,
    ProviderAccountId,
    ProviderEmail,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum CloudPendingToken {
    Table,
    State,
    ProviderKind,
    AccessToken,
    RefreshToken,
    TokenType,
    ExpiresAt,
    Scope,
    ProviderAccountId,
    ProviderEmail,
    LocalEmail,
    CreatedAt,
}

#[derive(DeriveIden)]
enum OauthState {
    Table,
    State,
    ProviderKind,
    VaultId,
    CreatedAt,
    ExpiresAt,
}

#[derive(DeriveIden)]
enum CloudBinding {
    Table,
    VaultId,
    ProviderKind,
    ProviderAccountId,
    RemoteFileId,
    RemoteRevision,
    SyncStatus,
    MirroredVaultVersion,
    LastMirroredAt,
    LastMirrorError,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Vault {
    Table,
    Id,
}

/// Pre-provider-neutral table names.
///
/// These MUST be renamed explicitly. A `DeriveIden` `Table` variant resolves to
/// the *enum's* name in snake_case, so an enum called `LegacyGoogleToken` would
/// silently produce `legacy_google_token` and the drop would no-op, leaving the
/// legacy credential table in place forever.
#[derive(DeriveIden)]
enum LegacyGoogleToken {
    #[sea_orm(iden = "google_token")]
    Table,
}

#[derive(DeriveIden)]
enum LegacyGooglePendingToken {
    #[sea_orm(iden = "google_pending_token")]
    Table,
}
