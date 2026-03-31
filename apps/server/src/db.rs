use sea_orm::{Database, DatabaseConnection};

pub type DbPool = DatabaseConnection;

pub async fn establish_connection(database_url: &str) -> DatabaseConnection {
    Database::connect(database_url)
        .await
        .expect("Failed to connect to database")
}
