use axum::{
    extract::{State, Path, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use validator::Validate;
use jsonwebtoken::{decode, DecodingKey, Validation};
use time;
use axum_extra::extract::cookie::Cookie;

use crate::models::user::{
    AuthResponse, CreateAdminRequest, Claims, UserResponse, LoginRequest,
    CreateInvitationRequest, RegisterWithInvitationRequest, InvitationResponse,
    DeleteAccountRequest, SearchUsersQuery, SearchUsersResponse,
};
use crate::services::user::UserService;

/// Handler for creating an admin account
/// Validates the request and delegates business logic to UserService
pub async fn create_admin(
    State(service): State<UserService>,
    jar: CookieJar,
    Json(req): Json<CreateAdminRequest>,
) -> Result<Response, (StatusCode, String)> {
    // Validate request
    if let Err(e) = req.validate() {
        return Err((StatusCode::BAD_REQUEST, e.to_string()));
    }

    // Delegate to service
    service.create_admin(req, &jar).await
}

/// Handler for refreshing access tokens
/// Extracts refresh token from cookie and delegates to UserService
pub async fn refresh_token(
    State(service): State<UserService>,
    jar: CookieJar,
) -> Result<Response, (StatusCode, String)> {
    // Extract refresh token from cookie
    let refresh_token = jar
        .get("refresh_token")
        .ok_or((StatusCode::UNAUTHORIZED, "No refresh token provided".to_string()))?
        .value()
        .to_string();

    // Delegate to service
    service.refresh_token(&refresh_token, &jar).await
}

/// Handler for getting current user information
/// Returns user data if authenticated, 401 if not
pub async fn me(
    State(service): State<UserService>,
    jar: CookieJar,
) -> Result<Json<UserResponse>, (StatusCode, String)> {
    // Extract access token from cookie
    let access_token = jar
        .get("access_token")
        .ok_or((StatusCode::UNAUTHORIZED, "No access token provided".to_string()))?
        .value()
        .to_string();

    // Validate token and get claims
    let claims = service.validate_token(&access_token)?;

    // Get user from database
    let user = service.get_user_by_id(claims.sub).await?;

    // Return user response
    Ok(Json(user))
}

/// Handler for user login
/// Validates credentials and returns tokens if successful
pub async fn login(
    State(service): State<UserService>,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<Response, (StatusCode, String)> {
    // Validate request
    if let Err(e) = req.validate() {
        return Err((StatusCode::BAD_REQUEST, e.to_string()));
    }

    // Delegate to service
    service.login(req, &jar).await
}

/// Handler for creating an invitation
/// Only authenticated users can create invitations
pub async fn create_invitation(
    State(service): State<UserService>,
    jar: CookieJar,
    Json(req): Json<CreateInvitationRequest>,
) -> Result<Json<InvitationResponse>, (StatusCode, String)> {
    // Validate request
    if let Err(e) = req.validate() {
        return Err((StatusCode::BAD_REQUEST, e.to_string()));
    }

    // Extract access token from cookie
    let access_token = jar
        .get("access_token")
        .ok_or((StatusCode::UNAUTHORIZED, "No access token provided".to_string()))?
        .value()
        .to_string();

    // Validate token and get claims
    let claims = service.validate_token(&access_token)?;

    // Create invitation using the admin's user ID from claims
    let invitation = service.create_invitation(req, claims.sub).await?;
    Ok(Json(invitation))
}

/// Handler for registering with an invitation
pub async fn register_with_invitation(
    State(service): State<UserService>,
    jar: CookieJar,
    Json(req): Json<RegisterWithInvitationRequest>,
) -> Result<Response, (StatusCode, String)> {
    // Validate request
    if let Err(e) = req.validate() {
        return Err((StatusCode::BAD_REQUEST, e.to_string()));
    }

    // Register user
    service.register_with_invitation(req, &jar).await
}

/// Handler for deleting the current user's account
/// Only authenticated users can delete their own account
pub async fn delete_account(
    State(service): State<UserService>,
    jar: CookieJar,
    Json(req): Json<DeleteAccountRequest>,
) -> Result<Response, (StatusCode, String)> {
    // Validate request
    if let Err(e) = req.validate() {
        return Err((StatusCode::BAD_REQUEST, e.to_string()));
    }

    // Extract access token from cookie
    let access_token = jar
        .get("access_token")
        .ok_or((StatusCode::UNAUTHORIZED, "No access token provided".to_string()))?
        .value()
        .to_string();

    // Validate token and get claims
    let claims = service.validate_token(&access_token)?;

    // Delete the user's account
    service.delete_user(claims.sub, &req.password).await?;

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
) -> Result<Response, (StatusCode, String)> {
    // Extract access token from cookie
    let access_token = jar
        .get("access_token")
        .ok_or((StatusCode::UNAUTHORIZED, "No access token provided".to_string()))?
        .value()
        .to_string();

    // Validate token and get claims
    let claims = service.validate_token(&access_token)?;

    // Prevent admin from deleting themselves
    if claims.sub == user_id {
        return Err((
            StatusCode::FORBIDDEN,
            "Admins cannot delete their own account through this endpoint. Use DELETE /api/me instead.".to_string(),
        ));
    }

    // Delete the specified user's account
    service.admin_delete_user(user_id, claims.sub).await?;

    // Return success response
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Handler for searching users
/// Available to all authenticated users
pub async fn search_users(
    State(service): State<UserService>,
    jar: CookieJar,
    Query(query): Query<SearchUsersQuery>,
) -> Result<Json<SearchUsersResponse>, (StatusCode, String)> {
    // Extract access token from cookie
    let access_token = jar
        .get("access_token")
        .ok_or((StatusCode::UNAUTHORIZED, "No access token provided".to_string()))?
        .value()
        .to_string();

    // Validate token and get claims
    let _claims = service.validate_token(&access_token)?;

    // Search users
    let response = service.search_users(query).await?;
    Ok(Json(response))
}

/// Get a user by their ID
pub async fn get_user_by_id(
    State(service): State<UserService>,
    jar: CookieJar,
    Path(user_id): Path<i32>,
) -> Result<Json<UserResponse>, (StatusCode, String)> {
    // Extract access token from cookie
    let access_token = jar
        .get("access_token")
        .ok_or((StatusCode::UNAUTHORIZED, "No access token provided".to_string()))?
        .value()
        .to_string();

    // Validate token
    let _claims = service.validate_token(&access_token)?;

    // Get user
    let user = service.get_user_by_id(user_id).await?;
    Ok(Json(user))
} 