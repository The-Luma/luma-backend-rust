mod handlers;
mod models;
mod services;
mod middleware;
mod pinecone;

use std::env;
use axum::{
    routing::{post, get, delete},
    Router,
    http::{Method, header},
    middleware::from_fn_with_state,
};
use dotenvy::dotenv;
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::CorsLayer;
use crate::{
    handlers::{create_admin, refresh_token, me, login, logout, create_invitation, register_with_invitation, delete_account, admin_delete_user, search_users, get_user_by_id, check_admin_setup},
    services::user::UserService,
    pinecone::PineconeService,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables
    dotenv().ok();
    
    // Get database URL and JWT secret from environment
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let jwt_secret = env::var("BACKEND_JWT_SECRET").expect("JWT_SECRET must be set");
    let frontend_url = env::var("FRONTEND_URL").expect("FRONTEND_URL must be set");
    
    // Initialize Pinecone
    let mut pinecone_service = PineconeService::new()?;
    println!("Testing Pinecone connection...");
    pinecone_service.check_connection().await?;
    
    // Get first available index
    match pinecone_service.get_first_available_index().await {
        Ok(_) => {
            if let Some(config) = pinecone_service.get_index_config() {
                println!("Successfully connected to Pinecone index: {}", config.name);
                println!("Index dimension: {}", config.dimension);
                println!("Index metric: {:?}", config.metric);
            }
        }
        Err(e) => {
            println!("Warning: Could not get Pinecone index: {}", e);
        }
    }
    
    // Create database connection pool
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    // Create user service
    let service = UserService::new(pool, jwt_secret);

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_credentials(true)
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            header::ORIGIN,
            header::COOKIE,
            header::SET_COOKIE,
        ])
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_origin([frontend_url.parse().unwrap()]);

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/", get(|| async { "Hello from Luma API!" }))
        .route("/admin", post(create_admin))
        .route("/admin/check", get(check_admin_setup))
        .route("/login", post(login))
        .route("/refresh", post(refresh_token))
        .route("/register", post(register_with_invitation));

    // Protected routes (any authenticated user)
    let protected_routes = Router::new()
        .route("/me", get(me))
        .route("/me", delete(delete_account))
        .route("/logout", post(logout))
        .route("/users", get(search_users))
        .route("/users/{id}", get(get_user_by_id))
        .layer(from_fn_with_state(
            service.clone(),
            crate::middleware::auth,
        ));

    // Admin-only routes
    let admin_routes = Router::new()
        .route("/invitations", post(create_invitation))
        .route("/users/{id}", delete(admin_delete_user))
        .layer(from_fn_with_state(
            service.clone(),
            crate::middleware::require_admin,
        ));

    // Combine them into the main router
    let app = Router::new()
        .nest("/api", admin_routes)      // admin-only routes under /api/...
        .nest("/api", protected_routes)  // authenticated routes under /api/...
        .nest("/api", public_routes)     // public routes under /api/...
        .layer(cors)
        .with_state(service);

    // Run it
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    println!("Server running on http://0.0.0.0:3000");
    axum::serve(listener, app).await?;

    Ok(())
}