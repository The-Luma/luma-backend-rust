use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use uuid::Uuid;

use crate::models::models::{
    AuthResponse, Claims,
    User, UserResponse
};
use crate::services::luma::LumaService;

pub async fn check_admin_setup(service: &LumaService) -> Result<bool, (StatusCode, String)> {
    // Check if admin exists
    let admin_exists = sqlx::query_scalar!(
            "SELECT EXISTS(SELECT 1 FROM users WHERE role = 'admin')"
        )
        .fetch_one(service.db())
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
        })?
        .unwrap_or(false);

    // Return true if no admin exists (setup required)
    Ok(admin_exists)
}

pub fn generate_access_token(service: &LumaService, user: &User) -> Result<String, (StatusCode, String)> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::seconds(service.get_config().access_token_duration))
        .expect("Valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: user.id,
        username: user.username.clone(),
        role: user.role.clone(),
        exp: expiration,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(service.jwt_secret().as_bytes()),
    )
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Token generation error: {}", e))
        })
}

pub async fn create_refresh_token(service: &LumaService, user_id: i32) -> Result<String, (StatusCode, String)> {
    let token = Uuid::new_v4().to_string();
    let expires_at = (Utc::now() + Duration::seconds(service.get_config().refresh_token_duration)).naive_utc();

    // Store the refresh token
    sqlx::query!(
            r#"
            INSERT INTO refresh_tokens (user_id, token, expires_at)
            VALUES ($1, $2, $3)
            "#,
            user_id,
            token,
            expires_at,
        )
        .execute(service.db())
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store refresh token: {}", e))
        })?;

    Ok(token)
}

pub async fn refresh_token(
    service: &LumaService,
    refresh_token: &str,
    jar: &CookieJar,
) -> Result<Response, (StatusCode, String)> {
    // Find and validate the refresh token
    let stored_token = sqlx::query!(
            r#"
            SELECT id, user_id, token, expires_at
            FROM refresh_tokens
            WHERE token = $1 AND expires_at > NOW()
            "#,
            refresh_token,
        )
        .fetch_optional(service.db())
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
        })?;

    let stored_token = stored_token.ok_or((StatusCode::UNAUTHORIZED, "Invalid refresh token".to_string()))?;

    // Get the user
    let user = sqlx::query_as!(
            User,
            r#"
            SELECT id, username, email, password, role,
                   created_at AT TIME ZONE 'UTC' as "created_at!: DateTime<Utc>",
                   updated_at AT TIME ZONE 'UTC' as "updated_at!: DateTime<Utc>"
            FROM users
            WHERE id = $1
            "#,
            stored_token.user_id,
        )
        .fetch_one(service.db())
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
        })?;

    // Delete the used refresh token
    sqlx::query!(
            "DELETE FROM refresh_tokens WHERE id = $1",
            stored_token.id
        )
        .execute(service.db())
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
        })?;

    // Create new tokens and response
    service.create_auth_response(&user, jar).await
}

pub fn validate_token(service: &LumaService, token: &str) -> Result<Claims, (StatusCode, String)> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(service.jwt_secret().as_bytes()),
        &Validation::default(),
    )
        .map(|token_data| token_data.claims)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid token".to_string()))
}

pub async fn create_auth_response(
    service: &LumaService,
    user: &User,
    jar: &CookieJar,
) -> Result<Response, (StatusCode, String)> {
    let access_token = service.generate_access_token(user)?;
    let refresh_token = service.create_refresh_token(user.id).await?;

    // Create the response
    let auth_response = AuthResponse {
        user: UserResponse {
            id: user.id,
            username: user.username.clone(),
            email: user.email.clone(),
            role: user.role.clone(),
        },
        token: access_token.clone(),
    };

    // Create a new jar with our cookies
    let mut access_cookie = Cookie::new("access_token", access_token.clone());
    access_cookie.set_path("/");
    access_cookie.set_max_age(time::Duration::seconds(service.get_config().access_token_duration as i64));
    access_cookie.set_http_only(true);
    access_cookie.set_secure(true);
    access_cookie.set_same_site(axum_extra::extract::cookie::SameSite::Strict);

    let mut refresh_cookie = Cookie::new("refresh_token", refresh_token);
    refresh_cookie.set_path("/");
    refresh_cookie.set_max_age(time::Duration::seconds(service.get_config().refresh_token_duration as i64));
    refresh_cookie.set_http_only(true);
    refresh_cookie.set_secure(true);
    refresh_cookie.set_same_site(axum_extra::extract::cookie::SameSite::Strict);

    let jar = jar.clone().add(access_cookie).add(refresh_cookie);

    // Build the response with cookies
    let response = (jar, Json(auth_response)).into_response();
    Ok(response)
}