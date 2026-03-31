pub use sea_orm_migration::prelude::*;

mod m20260226_160000_intent_vault_users;
mod m20260314_000001_replace_intent_with_session;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260226_160000_intent_vault_users::Migration),
            Box::new(m20260314_000001_replace_intent_with_session::Migration),
        ]
    }
}
