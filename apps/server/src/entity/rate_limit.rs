use sea_orm::entity::prelude::*;

// One rate-limit counter row per `(policy, hashed subject)`.
//
// `kind` is the policy type name (`AuthIp`, `AuthTarget`, ...) and `key_hash`
// is SHA-256 over the policy plus its subject, so neither an IP nor a vault id
// is stored in the clear. The row is a counter, not an audit trail: it exists
// only to answer "has this subject spent its budget in the current window?".
//
// `window_start` and `expires_at` are unix seconds (SQLite's own clock), so
// every instance sharing the database agrees on window boundaries even when
// host clocks are skewed. See `apps/server/src/rate_limit.rs`.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "rate_limit")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub kind: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub key_hash: String,
    pub window_start: i64,
    pub count: i64,
    pub expires_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
