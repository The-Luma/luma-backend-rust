use axum::{
    http::StatusCode,
};
use bcrypt::{verify};
use chrono::{DateTime, Utc};

use crate::models::models::{
    User
};
use crate::services::luma::LumaService;

pub async fn delete_user(service: &LumaService, user_id: i32, password: &str) -> Result<(), (StatusCode, String)> {
    // Start transaction
    let mut tx = service.db().begin().await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Transaction error: {}", e))
    })?;

    // Get user with password for verification
    let user = sqlx::query_as!(
            User,
            r#"
            SELECT id, username, email, password, role,
                   created_at AT TIME ZONE 'UTC' as "created_at!: DateTime<Utc>",
                   updated_at AT TIME ZONE 'UTC' as "updated_at!: DateTime<Utc>"
            FROM users
            WHERE id = $1
            "#,
            user_id
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
        })?
        .ok_or((StatusCode::NOT_FOUND, "User not found".to_string()))?;

    // Verify password
    let valid = verify(password.as_bytes(), &user.password)
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Password verification error: {}", e))
        })?;

    if !valid {
        return Err((StatusCode::UNAUTHORIZED, "Invalid password".to_string()));
    }

    // If user is admin, check if they're the last one
    if user.role == "admin" {
        let admin_count = sqlx::query_scalar!(
                "SELECT COUNT(*) FROM users WHERE role = 'admin'"
            )
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
            })?
            .unwrap_or(0);

        if admin_count <= 1 {
            return Err((
                StatusCode::FORBIDDEN,
                "Cannot delete the last admin account".to_string(),
            ));
        }
    }

    // Delete refresh tokens
    sqlx::query!(
            "DELETE FROM refresh_tokens WHERE user_id = $1",
            user_id
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete refresh tokens: {}", e))
        })?;

    // Delete user's invitations
    sqlx::query!(
            "DELETE FROM invitations WHERE invited_by = $1",
            user_id
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete invitations: {}", e))
        })?;

    // Delete the user
    sqlx::query!(
            "DELETE FROM users WHERE id = $1",
            user_id
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete user: {}", e))
        })?;

    // Commit transaction
    tx.commit().await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Transaction error: {}", e))
    })?;

    Ok(())
}

pub async fn admin_delete_user(service: &LumaService, target_user_id: i32) -> Result<(), (StatusCode, String)> {
    // Start transaction
    let mut tx = service.db().begin().await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Transaction error: {}", e))
    })?;

    // Get target user
    let target_user = sqlx::query!(
            "SELECT role FROM users WHERE id = $1",
            target_user_id
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
        })?
        .ok_or((StatusCode::NOT_FOUND, "User not found".to_string()))?;

    // If target is admin, check if they're the last one
    if target_user.role == "admin" {
        let admin_count = sqlx::query_scalar!(
                "SELECT COUNT(*) FROM users WHERE role = 'admin'"
            )
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
            })?
            .unwrap_or(0);

        if admin_count <= 1 {
            return Err((
                StatusCode::FORBIDDEN,
                "Cannot delete the last admin account".to_string(),
            ));
        }
    }

    // Delete refresh tokens
    sqlx::query!(
            "DELETE FROM refresh_tokens WHERE user_id = $1",
            target_user_id
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete refresh tokens: {}", e))
        })?;

    // Delete user's invitations
    sqlx::query!(
            "DELETE FROM invitations WHERE invited_by = $1",
            target_user_id
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete invitations: {}", e))
        })?;

    // Delete the user
    sqlx::query!(
            "DELETE FROM users WHERE id = $1",
            target_user_id
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete user: {}", e))
        })?;

    // Commit transaction
    tx.commit().await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Transaction error: {}", e))
    })?;

    Ok(())
}