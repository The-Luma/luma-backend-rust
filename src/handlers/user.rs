use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use validator::Validate;

use crate::{
    models::{AuthResponse, CreateAdminRequest},
    services::user::UserService,
};

/// Handler for creating an admin account
/// Validates the request and delegates business logic to UserService
pub async fn create_admin(
    State(service): State<UserService>,
    Json(req): Json<CreateAdminRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, String)> {
    // Validate request
    if let Err(e) = req.validate() {
        return Err((StatusCode::BAD_REQUEST, e.to_string()));
    }

    // Delegate to service
    let response = service.create_admin(req).await?;
    
    Ok(Json(response))
} 