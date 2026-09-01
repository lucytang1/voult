use sea_orm_migration::{prelude::*, schema::*};
#[derive(DeriveMigrationName)] pub struct Migration;
const ISO_UTC_NOW_SQL: &str = "STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'now')";
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // vault — primary identity, no user table
        manager.create_table(Table::create().table(Vault::Table).if_not_exists()
            .col(string(Vault::Id).not_null().primary_key())
            .col(string(Vault::Vault).not_null())
            .col(string(Vault::Salt).not_null())
            .col(integer(Vault::Iterations).not_null())
            .col(string(Vault::Vaultiv).not_null())
            .col(string(Vault::VaultVerifier).not_null())
            .col(string(Vault::CreatedAt).not_null().default(Expr::cust(ISO_UTC_NOW_SQL)))
            .col(integer(Vault::Version).not_null())
            .col(integer(Vault::CryptoVersion).not_null().default(1))
            .col(string(Vault::VaultKeyWrap).null())
            .col(string(Vault::VaultKeyWrapIv).null())
            .to_owned()).await?;
        manager.create_table(Table::create().table(Session::Table).if_not_exists()
            .col(string(Session::SessionId).not_null().primary_key())
            .col(string(Session::VaultId).not_null())
            .col(string(Session::CreatedAt).not_null().default(Expr::cust(ISO_UTC_NOW_SQL)))
            .col(string(Session::ExpiresAt).not_null())
            .foreign_key(ForeignKey::create().name("fk_session_vault_id").from(Session::Table, Session::VaultId).to(Vault::Table, Vault::Id).on_delete(ForeignKeyAction::Cascade).on_update(ForeignKeyAction::Cascade))
            .to_owned()).await?;
        manager.create_table(Table::create().table(GoogleToken::Table).if_not_exists()
            .col(string(GoogleToken::VaultId).not_null().primary_key())
            .col(string(GoogleToken::AccessToken).not_null())
            .col(string(GoogleToken::RefreshToken).null())
            .col(string(GoogleToken::TokenType).not_null().default("Bearer"))
            .col(big_integer(GoogleToken::ExpiresAt).not_null())
            .col(string(GoogleToken::Scope).null())
            .col(string(GoogleToken::ProviderAccountId).null())
            .col(string(GoogleToken::ProviderEmail).null())
            .col(string(GoogleToken::UpdatedAt).not_null().default(Expr::cust(ISO_UTC_NOW_SQL)))
            .foreign_key(ForeignKey::create().name("fk_google_token_vault_id").from(GoogleToken::Table, GoogleToken::VaultId).to(Vault::Table, Vault::Id).on_delete(ForeignKeyAction::Cascade).on_update(ForeignKeyAction::Cascade))
            .to_owned()).await?;
        manager.create_table(Table::create().table(CloudBinding::Table).if_not_exists()
            .col(string(CloudBinding::VaultId).not_null().primary_key())
            .col(string(CloudBinding::ProviderKind).not_null().default("google_drive"))
            .col(string(CloudBinding::ProviderAccountId).null())
            .col(string(CloudBinding::DriveFileId).null())
            .col(string(CloudBinding::RemoteRevision).null())
            .col(string(CloudBinding::SyncStatus).not_null().default("idle"))
            .col(string(CloudBinding::CreatedAt).not_null().default(Expr::cust(ISO_UTC_NOW_SQL)))
            .col(string(CloudBinding::UpdatedAt).not_null().default(Expr::cust(ISO_UTC_NOW_SQL)))
            .foreign_key(ForeignKey::create().name("fk_cloud_binding_vault_id").from(CloudBinding::Table, CloudBinding::VaultId).to(Vault::Table, Vault::Id).on_delete(ForeignKeyAction::Cascade).on_update(ForeignKeyAction::Cascade))
            .to_owned()).await?;
        manager.create_table(Table::create().table(OauthState::Table).if_not_exists()
            .col(string(OauthState::State).not_null().primary_key())
            .col(string(OauthState::VaultId).null())
            .col(string(OauthState::CreatedAt).not_null().default(Expr::cust(ISO_UTC_NOW_SQL)))
            .col(string(OauthState::ExpiresAt).not_null())
            .foreign_key(ForeignKey::create().name("fk_oauth_state_vault_id").from(OauthState::Table, OauthState::VaultId).to(Vault::Table, Vault::Id).on_delete(ForeignKeyAction::Cascade).on_update(ForeignKeyAction::Cascade))
            .to_owned()).await?;
        manager.create_table(Table::create().table(GooglePendingToken::Table).if_not_exists()
            .col(string(GooglePendingToken::State).not_null().primary_key())
            .col(string(GooglePendingToken::AccessToken).not_null())
            .col(string(GooglePendingToken::RefreshToken).null())
            .col(string(GooglePendingToken::TokenType).not_null().default("Bearer"))
            .col(big_integer(GooglePendingToken::ExpiresAt).not_null())
            .col(string(GooglePendingToken::Scope).null())
            .col(string(GooglePendingToken::ProviderAccountId).null())
            .col(string(GooglePendingToken::ProviderEmail).null())
            .col(string(GooglePendingToken::LocalEmail).null())
            .col(string(GooglePendingToken::CreatedAt).not_null().default(Expr::cust(ISO_UTC_NOW_SQL)))
            .to_owned()).await?;
        Ok(())
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(GooglePendingToken::Table).if_exists().to_owned()).await?;
        manager.drop_table(Table::drop().table(OauthState::Table).if_exists().to_owned()).await?;
        manager.drop_table(Table::drop().table(CloudBinding::Table).if_exists().to_owned()).await?;
        manager.drop_table(Table::drop().table(GoogleToken::Table).if_exists().to_owned()).await?;
        manager.drop_table(Table::drop().table(Session::Table).if_exists().to_owned()).await?;
        manager.drop_table(Table::drop().table(Vault::Table).if_exists().to_owned()).await?;
        Ok(())
    }
}
#[derive(DeriveIden)] enum Vault { Table, Id, Vault, Salt, Iterations, Vaultiv, VaultVerifier, CreatedAt, Version, CryptoVersion, VaultKeyWrap, VaultKeyWrapIv }
#[derive(DeriveIden)] enum Session { Table, SessionId, VaultId, CreatedAt, ExpiresAt }
#[derive(DeriveIden)] enum GoogleToken { Table, VaultId, AccessToken, RefreshToken, TokenType, ExpiresAt, Scope, ProviderAccountId, ProviderEmail, UpdatedAt }
#[derive(DeriveIden)] enum CloudBinding { Table, VaultId, ProviderKind, ProviderAccountId, DriveFileId, RemoteRevision, SyncStatus, CreatedAt, UpdatedAt }
#[derive(DeriveIden)] enum OauthState { Table, State, VaultId, CreatedAt, ExpiresAt }
#[derive(DeriveIden)] enum GooglePendingToken { Table, State, AccessToken, RefreshToken, TokenType, ExpiresAt, Scope, ProviderAccountId, ProviderEmail, LocalEmail, CreatedAt }
