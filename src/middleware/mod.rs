use axum::{
    middleware::Next,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::Response,
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use serde_json::json;

use crate::services::user::UserService;

pub async fn auth(
    State(service): State<UserService>,
    jar: CookieJar,
    request: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    // Get access token from cookie
    let access_token = jar
        .get("access_token")
        .ok_or_else(|| {
            let body = json!({
                "error": "Unauthorized",
                "message": "No access token provided"
            });
            (StatusCode::UNAUTHORIZED, Json(body))
        })?
        .value()
        .to_string();

    // Validate token
    let _claims = service.validate_token(&access_token)
        .map_err(|(_status, msg)| {
            let body = json!({
                "error": "Unauthorized",
                "message": msg
            });
            (StatusCode::UNAUTHORIZED, Json(body))
        })?;

    // Continue with the request
    Ok(next.run(request).await)
}

pub async fn require_admin(
    State(service): State<UserService>,
    jar: CookieJar,
    request: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    // Get access token from cookie
    let access_token = jar
        .get("access_token")
        .ok_or_else(|| {
            let body = json!({
                "error": "Unauthorized",
                "message": "No access token provided"
            });
            (StatusCode::UNAUTHORIZED, Json(body))
        })?
        .value()
        .to_string();

    // Validate token and get claims
    let claims = service.validate_token(&access_token)
        .map_err(|(_status, msg)| {
            let body = json!({
                "error": "Unauthorized",
                "message": msg
            });
            (StatusCode::UNAUTHORIZED, Json(body))
        })?;

    // Check if user is admin
    if claims.role != "admin" {
        let body = json!({
            "error": "Forbidden",
            "message": "Admin access required"
        });
        return Err((StatusCode::FORBIDDEN, Json(body)));
    }

    // Continue with the request
    Ok(next.run(request).await)
} 