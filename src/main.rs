mod db;

use axum::{
    routing::get,
    Router,
};
use sqlx::PgPool;
use std::env;
use crate::db::{init_db_pool, run_test_query};

async fn hello() -> &'static str {
    "Hello, Rust!"
}

#[tokio::main]
async fn main() {
    // Load environment variables
    dotenv::dotenv().ok();

    // Initialize the database connection pool and run a test query
    let db_con: PgPool = init_db_pool().await.unwrap();
    run_test_query(&db_con).await.unwrap();

    // Get port from environment variable or use default
    let port = env::var("BACKEND_PORT").unwrap_or_else(|_| "3000".to_string());
    let address = format!("0.0.0.0:{}", port);

    // build our application with a single route
    let app = Router::new()
        .route("/", get(hello));

    // run our app with hyper
    println!("Server running on http://{}", address);
    let listener = tokio::net::TcpListener::bind(address).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}