mod db;
mod datetime_codec;
mod endpoints;
mod entity;
mod id_codec;
// mod session;

use actix_web::{web, App, HttpServer};
use actix_web::middleware::Logger;
use actix_cors::Cors;
use dotenvy::dotenv;
use env_logger::Env;
use migration::{Migrator, MigratorTrait};
use std::env;

use endpoints::{auth, get_crypto_params, get_vault, register, update_vault};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env file");

    let db = db::establish_connection(&database_url).await;

    Migrator::up(&db, None)
        .await
        .expect("Failed to run database migrations");

    let db_data = web::Data::new(db);

    log::info!("Starting server at http://127.0.0.1:8080");
    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header();
        App::new()
            .app_data(db_data.clone())
            .wrap(Logger::default())
            .wrap(cors)
            .service(register::register)
            .service(auth::auth)
            .service(get_vault::get_vault)
            .service(get_crypto_params::get_crypto_params)
            .service(update_vault::update_vault)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
