use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

const ISO_UTC_NOW_SQL: &str = "STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'now')";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Intent::Table).if_exists().to_owned())
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Session::Table)
                    .if_not_exists()
                    .col(string(Session::SessionId).not_null().primary_key())
                    .col(string(Session::UserId).not_null())
                    .col(
                        string(Session::CreatedAt)
                            .not_null()
                            .default(Expr::cust(ISO_UTC_NOW_SQL)),
                    )
                    .col(string(Session::ExpiresAt).not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_session_user_id")
                            .from(Session::Table, Session::UserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Session::Table).if_exists().to_owned())
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Intent::Table)
                    .if_not_exists()
                    .col(string(Intent::Id).not_null().primary_key())
                    .col(string(Intent::VaultId).not_null())
                    .col(string(Intent::IntentType).not_null())
                    .col(string(Intent::Payload).not_null())
                    .col(string(Intent::Status).not_null())
                    .col(integer(Intent::VaultVersion).not_null())
                    .col(
                        string(Intent::CreatedAt)
                            .not_null()
                            .default(Expr::cust(ISO_UTC_NOW_SQL)),
                    )
                    .col(
                        string(Intent::AppliedAt)
                            .not_null()
                            .default(Expr::cust(ISO_UTC_NOW_SQL)),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_intent_vault_id")
                            .from(Intent::Table, Intent::VaultId)
                            .to(Vault::Table, Vault::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Vault {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum User {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Intent {
    Table,
    Id,
    VaultId,
    IntentType,
    Payload,
    Status,
    VaultVersion,
    CreatedAt,
    AppliedAt,
}

#[derive(DeriveIden)]
enum Session {
    Table,
    SessionId,
    UserId,
    CreatedAt,
    ExpiresAt,
}
