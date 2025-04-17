use axum::http::StatusCode;
use bcrypt::{hash, verify, DEFAULT_COST};
use sqlx::PgPool;

use crate::models::models::{ChangeUsernameRequest, ChangePasswordRequest, User};

pub async fn change_username(
    db: &PgPool,
    user_id: i32,
    req: ChangeUsernameRequest,
) -> Result<(), (StatusCode, String)> {
    // First verify the password
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT 
            id,
            username,
            email,
            password,
            role,
            created_at AT TIME ZONE 'UTC' as "created_at!",
            updated_at AT TIME ZONE 'UTC' as "updated_at!"
        FROM users 
        WHERE id = $1
        "#,
        user_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "User not found".to_string()))?;

    if !verify(&req.password, &user.password)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))? {
        return Err((StatusCode::UNAUTHORIZED, "Invalid password".to_string()));
    }

    // Check if username is already taken
    let existing_user = sqlx::query_as!(
        User,
        r#"
        SELECT 
            id,
            username,
            email,
            password,
            role,
            created_at AT TIME ZONE 'UTC' as "created_at!",
            updated_at AT TIME ZONE 'UTC' as "updated_at!"
        FROM users 
        WHERE username = $1 AND id != $2
        "#,
        req.new_username,
        user_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if existing_user.is_some() {
        return Err((StatusCode::CONFLICT, "Username already taken".to_string()));
    }

    // Update the username
    sqlx::query!(
        "UPDATE users SET username = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
        req.new_username,
        user_id
    )
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(())
}

pub async fn change_password(
    db: &PgPool,
    user_id: i32,
    req: ChangePasswordRequest,
) -> Result<(), (StatusCode, String)> {
    // First verify the current password
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT 
            id,
            username,
            email,
            password,
            role,
            created_at AT TIME ZONE 'UTC' as "created_at!",
            updated_at AT TIME ZONE 'UTC' as "updated_at!"
        FROM users 
        WHERE id = $1
        "#,
        user_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "User not found".to_string()))?;

    if !verify(&req.current_password, &user.password)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))? {
        return Err((StatusCode::UNAUTHORIZED, "Invalid current password".to_string()));
    }

    // Hash the new password
    let hashed_password = hash(req.new_password.as_bytes(), DEFAULT_COST)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Update the password
    sqlx::query!(
        "UPDATE users SET password = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
        hashed_password,
        user_id
    )
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(())
} 