use axum::{
    http::StatusCode,
    response::{ Response }
};
use axum_extra::extract::cookie::{CookieJar};
use bcrypt::{ verify};
use chrono::{DateTime, Utc};
use crate::models::models::{
    LoginRequest, User
};
use crate::services::luma::LumaService;

pub async fn login(
    service: &LumaService,
    req: LoginRequest,
    jar: &CookieJar,
) -> Result<Response, (StatusCode, String)> {
    // Find user by username
    let user = sqlx::query_as!(
            User,
            r#"
            SELECT id, username, email, password, role,
                   created_at AT TIME ZONE 'UTC' as "created_at!: DateTime<Utc>",
                   updated_at AT TIME ZONE 'UTC' as "updated_at!: DateTime<Utc>"
            FROM users
            WHERE username = $1
            "#,
            req.username
        )
        .fetch_optional(service.db())
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
        })?
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid username or password".to_string()))?;

    // Verify password
    let valid = verify(req.password.as_bytes(), &user.password)
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Password verification error: {}", e))
        })?;

    if !valid {
        return Err((StatusCode::UNAUTHORIZED, "Invalid username or password".to_string()));
    }

    // Generate tokens and create response
    service.create_auth_response(&user, jar).await
}
