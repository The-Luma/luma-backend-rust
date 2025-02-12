mod db;

use axum::{
    routing::get,
    Router,
};
use sqlx::PgPool;
use crate::db::{init_db_pool, run_test_query};

async fn hello() -> &'static str {
    "Hello, Rust!"
}
#[tokio::main]
async fn main() {

    // Initialize the database connection pool and run a test query
    let db_con: PgPool = init_db_pool().await.unwrap();
    run_test_query(&db_con).await.unwrap();

    const ADDRESS: &str = "0.0.0.0:3000";

    // build our application with a single route
    let app = Router::new()
        .route("/", get(hello));

    // run our app with hyper, listening globally on port 3000
    println!("Server running on http://{}", ADDRESS);
    let listener = tokio::net::TcpListener::bind(ADDRESS).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}