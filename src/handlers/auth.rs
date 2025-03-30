use axum::{
    extract::{ State },
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde_json::json;
use validator::Validate;
use crate::handlers::error_response;
use crate::models::models::{
    CreateAdminRequest, LoginRequest,
    CreateInvitationRequest, RegisterWithInvitationRequest, InvitationResponse,
};

use crate::services::luma::LumaService;

pub async fn login(
    State(service): State<LumaService>,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    // Validate request
    if let Err(e) = req.validate() {
        return Err(error_response(StatusCode::BAD_REQUEST, e.to_string()));
    }

    // Delegate to service
    service.login(req, &jar).await
        .map_err(|(status, msg)| error_response(status, msg))
}

pub async fn check_admin_setup(
    State(service): State<LumaService>,
) -> Result<Json<bool>, (StatusCode, Json<serde_json::Value>)> {
    // Check if admin setup is required
    service.check_admin_setup().await
        .map_err(|(status, msg)| error_response(status, msg))
        .map(Json)
}
pub async fn logout(
    State(service): State<LumaService>,
    jar: CookieJar,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    // Extract access token from cookie
    let access_token = jar
        .get("access_token")
        .ok_or_else(|| error_response(
            StatusCode::UNAUTHORIZED,
            "No access token provided".to_string()
        ))?
        .value()
        .to_string();

    // Validate token to ensure the user is actually logged in
    let _claims = service.validate_token(&access_token)
        .map_err(|(status, msg)| error_response(status, msg))?;

    // Create expired cookies to clear the tokens
    let mut access_cookie = Cookie::new("access_token", "");
    access_cookie.set_path("/");
    access_cookie.set_max_age(time::Duration::ZERO);
    access_cookie.set_http_only(true);
    access_cookie.set_secure(true);

    let mut refresh_cookie = Cookie::new("refresh_token", "");
    refresh_cookie.set_path("/");
    refresh_cookie.set_max_age(time::Duration::ZERO);
    refresh_cookie.set_http_only(true);
    refresh_cookie.set_secure(true);

    // Add expired cookies to jar
    let jar = jar.add(access_cookie).add(refresh_cookie);

    // Return success with cleared cookies
    Ok((StatusCode::OK, jar, Json(json!({ "message": "Logged out successfully" }))).into_response())
}

pub async fn create_admin(
    State(service): State<LumaService>,
    jar: CookieJar,
    Json(req): Json<CreateAdminRequest>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    // Validate request
    if let Err(e) = req.validate() {
        return Err(error_response(StatusCode::BAD_REQUEST, e.to_string()));
    }

    // Delegate to service
    service.create_admin(req, &jar).await
        .map_err(|(status, msg)| error_response(status, msg))
}

/// Handler for refreshing access tokens
/// Extracts refresh token from cookie and delegates to LumaService
pub async fn refresh_token(
    State(service): State<LumaService>,
    jar: CookieJar,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    // Extract refresh token from cookie
    let refresh_token = jar
        .get("refresh_token")
        .ok_or_else(|| error_response(
            StatusCode::UNAUTHORIZED,
            "No refresh token provided".to_string()
        ))?
        .value()
        .to_string();

    // Delegate to service
    service.refresh_token(&refresh_token, &jar).await
        .map_err(|(status, msg)| error_response(status, msg))
}

pub async fn create_invitation(
    State(service): State<LumaService>,
    jar: CookieJar,
    Json(req): Json<CreateInvitationRequest>,
) -> Result<Json<InvitationResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Validate request
    if let Err(e) = req.validate() {
        return Err(error_response(StatusCode::BAD_REQUEST, e.to_string()));
    }

    // Extract access token from cookie
    let access_token = jar
        .get("access_token")
        .ok_or_else(|| error_response(
            StatusCode::UNAUTHORIZED,
            "No access token provided".to_string()
        ))?
        .value()
        .to_string();

    // Validate token and get claims
    let claims = service.validate_token(&access_token)
        .map_err(|(status, msg)| error_response(status, msg))?;

    // Create invitation using the admin's user ID from claims
    let invitation = service.create_invitation(req, claims.sub).await
        .map_err(|(status, msg)| error_response(status, msg))?;

    Ok(Json(invitation))
}

/// Handler for registering with an invitation
pub async fn register_with_invitation(
    State(service): State<LumaService>,
    jar: CookieJar,
    Json(req): Json<RegisterWithInvitationRequest>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    // Validate request
    if let Err(e) = req.validate() {
        return Err(error_response(StatusCode::BAD_REQUEST, e.to_string()));
    }

    // Register user
    service.register_with_invitation(req, &jar).await
        .map_err(|(status, msg)| error_response(status, msg))
}