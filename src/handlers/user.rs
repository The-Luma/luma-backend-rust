use axum::{
    extract::{State, Path, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use validator::Validate;
use time;
use axum_extra::extract::cookie::Cookie;
use serde::Serialize;
use serde_json::json;

use crate::models::user::{
    CreateAdminRequest, UserResponse, LoginRequest,
    CreateInvitationRequest, RegisterWithInvitationRequest, InvitationResponse,
    DeleteAccountRequest, SearchUsersQuery, SearchUsersResponse,
};
use crate::services::user::UserService;

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

fn error_response(status: StatusCode, message: String) -> (StatusCode, Json<serde_json::Value>) {
    let body = json!({
        "error": status.to_string(),
        "message": message
    });
    (status, Json(body))
}

/// Handler for creating an admin account
/// Validates the request and delegates business logic to UserService
pub async fn create_admin(
    State(service): State<UserService>,
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
/// Extracts refresh token from cookie and delegates to UserService
pub async fn refresh_token(
    State(service): State<UserService>,
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

/// Handler for getting current user information
/// Returns user data if authenticated, 401 if not
pub async fn me(
    State(service): State<UserService>,
    jar: CookieJar,
) -> Result<Json<UserResponse>, (StatusCode, Json<serde_json::Value>)> {
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

    // Get user from database
    let user = service.get_user_by_id(claims.sub).await
        .map_err(|(status, msg)| error_response(status, msg))?;

    // Return user response
    Ok(Json(user))
}

/// Handler for user login
/// Validates credentials and returns tokens if successful
pub async fn login(
    State(service): State<UserService>,
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

/// Handler for checking if admin setup is required
/// Returns true if no admin exists in the system
pub async fn check_admin_setup(
    State(service): State<UserService>,
) -> Result<Json<bool>, (StatusCode, Json<serde_json::Value>)> {
    // Check if admin setup is required
    service.check_admin_setup().await
        .map_err(|(status, msg)| error_response(status, msg))
        .map(Json)
}

/// Handler for creating an invitation
/// Only authenticated users can create invitations
pub async fn create_invitation(
    State(service): State<UserService>,
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
    State(service): State<UserService>,
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

/// Handler for deleting the current user's account
/// Only authenticated users can delete their own account
pub async fn delete_account(
    State(service): State<UserService>,
    jar: CookieJar,
    Json(req): Json<DeleteAccountRequest>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
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

    // Delete the user's account
    service.delete_user(claims.sub, &req.password).await
        .map_err(|(status, msg)| error_response(status, msg))?;

    // Create an empty cookie jar with expired tokens
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

    let jar = jar.add(access_cookie).add(refresh_cookie);

    // Return success response with cleared cookies
    Ok((jar, StatusCode::NO_CONTENT).into_response())
}

/// Handler for admin to delete any user account
/// Only admin users can access this endpoint
pub async fn admin_delete_user(
    State(service): State<UserService>,
    jar: CookieJar,
    Path(user_id): Path<i32>,
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

    // Validate token and get claims
    let claims = service.validate_token(&access_token)
        .map_err(|(status, msg)| error_response(status, msg))?;

    // Prevent admin from deleting themselves
    if claims.sub == user_id {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "Admins cannot delete their own account through this endpoint. Use DELETE /api/me instead.".to_string()
        ));
    }

    // Delete the specified user's account
    service.admin_delete_user(user_id).await
        .map_err(|(status, msg)| error_response(status, msg))?;

    // Return success response
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Handler for searching users
/// Available to all authenticated users
pub async fn search_users(
    State(service): State<UserService>,
    jar: CookieJar,
    Query(query): Query<SearchUsersQuery>,
) -> Result<Json<SearchUsersResponse>, (StatusCode, Json<serde_json::Value>)> {
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
    let _claims = service.validate_token(&access_token)
        .map_err(|(status, msg)| error_response(status, msg))?;

    // Search users
    let response = service.search_users(query).await
        .map_err(|(status, msg)| error_response(status, msg))?;
    Ok(Json(response))
}

/// Get a user by their ID
pub async fn get_user_by_id(
    State(service): State<UserService>,
    jar: CookieJar,
    Path(user_id): Path<i32>,
) -> Result<Json<UserResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Extract access token from cookie
    let access_token = jar
        .get("access_token")
        .ok_or_else(|| error_response(
            StatusCode::UNAUTHORIZED,
            "No access token provided".to_string()
        ))?
        .value()
        .to_string();

    // Validate token
    let _claims = service.validate_token(&access_token)
        .map_err(|(status, msg)| error_response(status, msg))?;

    // Get user
    let user = service.get_user_by_id(user_id).await
        .map_err(|(status, msg)| error_response(status, msg))?;
    Ok(Json(user))
}

/// Handler for logging out a user
/// Validates the session and clears authentication cookies
pub async fn logout(
    State(service): State<UserService>,
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