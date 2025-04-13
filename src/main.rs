mod handlers;
mod models;
mod services;
mod middleware;
mod config;

use axum::{
    http::{header, Method},
    middleware::from_fn_with_state,
    routing::{delete, get, post},
    Router,
};
use dotenvy::dotenv;
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::CorsLayer;
use services::openai::OpenAIService;
use services::pinecone::PineconeService;
use crate::{
    config::Config,
    handlers::{
        admin_delete_user, check_admin_setup, create_admin, create_invitation,
        delete_account, get_user_by_id, login, logout, me, refresh_token,
        register_with_invitation, search_users, start_chat, send_message,
        get_chat_history, list_conversations, delete_conversation,
        create_namespace, list_namespaces, delete_namespace, share_namespace
    },
    services::{luma::LumaService, db::{init_db_pool, run_test_query}},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env().expect("Failed to load configuration");

    let openai_service = OpenAIService::new(&config)?;
    openai_service.check_connection().await?;

    let mut pinecone_service = PineconeService::new(&config)?;
    pinecone_service.check_connection(&config).await?;

    let pool = init_db_pool(&config).await?;
    run_test_query(&pool).await?;

    let service = LumaService::new(pool, config.jwt_secret, openai_service);

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
        .allow_origin([config.frontend_url.parse().unwrap()]);

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
        // Chat routes
        .route("/chat/start", post(start_chat))
        .route("/chat/message", post(send_message))
        .route("/chat/{id}", get(get_chat_history))
        .route("/chat", get(list_conversations))
        .route("/chat/{id}", delete(delete_conversation))
        // Namespace routes
        .route("/namespaces", post(create_namespace))
        .route("/namespaces", get(list_namespaces))
        .route("/namespaces/{id}", delete(delete_namespace))
        .route("/namespaces/{id}/share", post(share_namespace))
        .route("/namespaces/{id}/revoke", post(handlers::chat::revoke_namespace_access))
        .layer(from_fn_with_state(
            service.clone(),
            crate::middleware::auth::check_if_auth,
        ));

    // Admin-only routes
    let admin_routes = Router::new()
        .route("/invitations", post(create_invitation))
        .route("/users/{id}", delete(admin_delete_user))
        .layer(from_fn_with_state(
            service.clone(),
            crate::middleware::auth::check_if_admin,
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
    println!(
        r#"
 _       __     __                             __           __
| |     / /__  / /________  ____ ___  ___     / /_____     / /   __  ______ ___  ____ _
| | /| / / _ \/ / ___/ __ \/ __ `__ \/ _ \   / __/ __ \   / /   / / / / __ `__ \/ __ `/
| |/ |/ /  __/ / /__/ /_/ / / / / / /  __/  / /_/ /_/ /  / /___/ /_/ / / / / / / /_/ /
|__/|__/\___/_/\___/\____/_/ /_/ /_/\___/   \__/\____/  /_____/\__,_/_/ /_/ /_/\__,_/
        "#
    );
    println!("-------------------------------------");
    println!("Server running on http://0.0.0.0:3000");
    println!("-------------------------------------");
    axum::serve(listener, app).await?;

    Ok(())
}