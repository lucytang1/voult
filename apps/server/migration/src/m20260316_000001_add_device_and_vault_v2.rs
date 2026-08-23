use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Extend the vault schema for the version-2 format:
        // - a random vault key encrypts the vault;
        // - a password-derived key wraps the vault key (vault_key_wrap + iv);
        // - a device key wraps the vault key (stored in the device table).
        // SQLite only allows one alter option per ALTER TABLE statement.
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .add_column(integer(Vault::CryptoVersion).not_null().default(1))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .add_column(string(Vault::VaultKeyWrap).null())
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .add_column(string(Vault::VaultKeyWrapIv).null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .drop_column(Vault::VaultKeyWrapIv)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .drop_column(Vault::VaultKeyWrap)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Vault::Table)
                    .drop_column(Vault::CryptoVersion)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Vault {
    Table,
    CryptoVersion,
    VaultKeyWrap,
    VaultKeyWrapIv,
}
