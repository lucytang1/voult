use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "google_pending_token")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub state: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: i64,
    pub provider_account_id: Option<String>,
    pub provider_email: Option<String>,
    pub local_email: Option<String>,
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
