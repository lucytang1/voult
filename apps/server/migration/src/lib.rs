pub use sea_orm_migration::prelude::*;

// Clean-start schema. The old migration history (intent_vault_users,
// replace_intent_with_session, add_device_and_vault_v2) is intentionally
// removed: this is a deliberate breaking change and existing development
// databases (apps/server/voult.db) must be deleted and recreated. The server
// migrates automatically on startup.
mod m20260901_000001_vault_centric_init;
mod m20260904_000002_vault_lock_epoch;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260901_000001_vault_centric_init::Migration),
            Box::new(m20260904_000002_vault_lock_epoch::Migration),
        ]
    }
}
