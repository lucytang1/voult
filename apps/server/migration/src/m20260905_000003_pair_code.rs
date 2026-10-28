use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

// One-time extension-pairing codes (see plans/extension-signin-flow.md §4b).
// A web session creates a short-lived record holding only the vault identity;
// the extension burns it with a 6-character code. No verifier, wraps, or
// ciphertext ever sits in this table.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(PairCode::Table)
                    .if_not_exists()
                    .col(string(PairCode::Selector).not_null().primary_key())
                    .col(string(PairCode::VaultId).not_null())
                    .col(string(PairCode::CodeHash).not_null())
                    .col(
                        string(PairCode::CreatedAt)
                            .not_null()
                            .default(Expr::cust("STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'now')")),
                    )
                    .col(string(PairCode::ExpiresAt).not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_pair_code_vault_id")
                            .from(PairCode::Table, PairCode::VaultId)
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
                    .name("idx_pair_code_vault_id")
                    .table(PairCode::Table)
                    .col(PairCode::VaultId)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(PairCode::Table).if_exists().to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum PairCode {
    Table,
    Selector,
    VaultId,
    CodeHash,
    CreatedAt,
    ExpiresAt,
}

#[derive(DeriveIden)]
enum Vault {
    Table,
    Id,
}
