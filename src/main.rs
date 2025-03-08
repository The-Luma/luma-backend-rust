mod handlers;
mod models;
mod services;

use std::env;
use axum::{
    routing::{post, get},
    Router,
    response::IntoResponse,
};
use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
use crate::{
    handlers::create_admin,
    services::user::UserService,
};

async fn hello() -> impl IntoResponse {
    "Hello Rust!"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenv().ok();
    
    // Get database URL and JWT secret from environment
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let jwt_secret = env::var("BACKEND_JWT_SECRET").expect("JWT_SECRET must be set");
    
    // Create database connection pool
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    // Create user service
    let service = UserService::new(pool, jwt_secret);

    // Build application with routes
    let app = Router::new()
        .route("/", get(hello))
        .route("/admin", post(create_admin))
        .with_state(service);

    // Run it
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("Server running on http://127.0.0.1:3000");
    axum::serve(listener, app).await?;

    Ok(())
}