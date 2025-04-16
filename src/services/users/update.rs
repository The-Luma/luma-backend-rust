use axum::http::StatusCode;
use bcrypt::verify;
use sqlx::PgPool;

use crate::models::models::{ChangeUsernameRequest, User};

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