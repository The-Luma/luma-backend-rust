use axum::{
    extract::{State, Path, Query, Extension},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use validator::Validate;
use crate::handlers::error_response;
use crate::models::models::{
    UserResponse, DeleteAccountRequest, SearchUsersQuery, SearchUsersResponse,
    ChangeUsernameRequest, ChangePasswordRequest, SuccessResponse,
};

use crate::services::luma::LumaService;

pub async fn me(
    State(service): State<LumaService>,
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

pub async fn search_users(
    State(service): State<LumaService>,
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
    State(service): State<LumaService>,
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

pub async fn admin_delete_user(
    State(service): State<LumaService>,
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

pub async fn delete_account(
    State(service): State<LumaService>,
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

pub async fn change_username(
    State(service): State<LumaService>,
    Extension(user): Extension<UserResponse>,
    Json(req): Json<ChangeUsernameRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<serde_json::Value>)> {
    service
        .change_username(user.id, req)
        .await
        .map_err(|(status, error)| error_response(status, error))?;

    Ok(Json(SuccessResponse {
        success: true,
        message: "Username updated successfully".to_string(),
    }))
}

pub async fn change_password(
    State(service): State<LumaService>,
    Extension(user): Extension<UserResponse>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<serde_json::Value>)> {
    service
        .change_password(user.id, req)
        .await
        .map_err(|(status, error)| error_response(status, error))?;

    Ok(Json(SuccessResponse {
        success: true,
        message: "Password updated successfully".to_string(),
    }))
}