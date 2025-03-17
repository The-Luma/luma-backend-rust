use axum::{
    middleware::Next,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::Response,
};
use axum_extra::extract::cookie::CookieJar;

use crate::services::user::UserService;

pub async fn auth(
    State(service): State<UserService>,
    jar: CookieJar,
    request: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    // Get access token from cookie
    let access_token = jar
        .get("access_token")
        .ok_or((StatusCode::UNAUTHORIZED, "No access token provided".to_string()))?
        .value()
        .to_string();

    // Validate token
    let _claims = service.validate_token(&access_token)?;

    // Continue with the request
    Ok(next.run(request).await)
}

pub async fn require_admin(
    State(service): State<UserService>,
    jar: CookieJar,
    request: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    // Get access token from cookie
    let access_token = jar
        .get("access_token")
        .ok_or((StatusCode::UNAUTHORIZED, "No access token provided".to_string()))?
        .value()
        .to_string();

    // Validate token and get claims
    let claims = service.validate_token(&access_token)?;

    // Check if user is admin
    if claims.role != "admin" {
        return Err((StatusCode::FORBIDDEN, "Admin access required".to_string()));
    }

    // Continue with the request
    Ok(next.run(request).await)
} 