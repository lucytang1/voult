pub use sea_orm_migration::prelude::*;

// Clean-start schema. The old migration history (intent_vault_users,
// replace_intent_with_session, add_device_and_vault_v2) is intentionally
// removed: this is a deliberate breaking change and existing development
// databases (apps/server/voult.db) must be deleted and recreated. The server
// migrates automatically on startup.
mod m20260901_000001_vault_centric_init;
mod m20260904_000002_vault_lock_epoch;
mod m20260905_000003_pair_code;
mod m20261011_000004_cloud_binding_mirror_state;
mod m20261012_000005_cloud_provider_neutral;
mod m20261013_000006_vault_recovery;
mod m20261027_000007_cloud_binding_generation;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260901_000001_vault_centric_init::Migration),
            Box::new(m20260904_000002_vault_lock_epoch::Migration),
            Box::new(m20260905_000003_pair_code::Migration),
            Box::new(m20261011_000004_cloud_binding_mirror_state::Migration),
            Box::new(m20261012_000005_cloud_provider_neutral::Migration),
            Box::new(m20261013_000006_vault_recovery::Migration),
            Box::new(m20261027_000007_cloud_binding_generation::Migration),
        ]
    }
}
