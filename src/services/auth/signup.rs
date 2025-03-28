use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::user::{
    AuthResponse, Claims, CreateAdminRequest, CreateInvitationRequest,
    Invitation, InvitationResponse, LoginRequest, RegisterWithInvitationRequest,
    User, UserResponse, SearchUsersQuery, SearchUsersResponse,
};
use crate::services::auth;
use crate::services::luma::LumaService;

pub async fn create_admin(
    service: &LumaService,
    req: CreateAdminRequest,
    jar: &CookieJar,
) -> Result<Response, (StatusCode, String)> {
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

    if admin_exists {
        return Err((StatusCode::CONFLICT, "Admin already exists".to_string()));
    }

    // Hash password
    let password_hash = hash(req.password.as_bytes(), DEFAULT_COST)
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Password hashing error: {}", e))
        })?;

    // Create admin user
    let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (username, email, password, role)
            VALUES ($1, $2, $3, 'admin')
            RETURNING id, username, email, password, role,
                     created_at AT TIME ZONE 'UTC' as "created_at!: DateTime<Utc>",
                     updated_at AT TIME ZONE 'UTC' as "updated_at!: DateTime<Utc>"
            "#,
            req.username,
            req.email,
            password_hash,
        )
        .fetch_one(service.db())
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate key") {
                (StatusCode::CONFLICT, "Username or email already exists".to_string())
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
            }
        })?;

    // Generate tokens and create response
    service.create_auth_response(&user, jar).await
}

pub async fn register_with_invitation(service: &LumaService, req: RegisterWithInvitationRequest, jar: &CookieJar, ) -> Result<Response, (StatusCode, String)> {
    // Find and validate invitation
    let invitation = sqlx::query_as!(
            Invitation,
            r#"
            SELECT id, email, role, token, invited_by,
                   expires_at AT TIME ZONE 'UTC' as "expires_at!: DateTime<Utc>",
                   created_at AT TIME ZONE 'UTC' as "created_at!: DateTime<Utc>",
                   used_at AT TIME ZONE 'UTC' as "used_at?: DateTime<Utc>"
            FROM invitations
            WHERE token = $1 AND expires_at > NOW() AND used_at IS NULL
            "#,
            req.invitation_token
        )
        .fetch_optional(service.db())
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
        })?
        .ok_or((StatusCode::BAD_REQUEST, "Invalid or expired invitation".to_string()))?;

    // Hash password
    let password_hash = hash(req.password.as_bytes(), DEFAULT_COST)
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Password hashing error: {}", e))
        })?;

    // Start transaction
    let mut tx = service.db().begin().await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Transaction error: {}", e))
    })?;

    // Create user
    let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (username, email, password, role)
            VALUES ($1, $2, $3, $4)
            RETURNING id, username, email, password, role,
                     created_at AT TIME ZONE 'UTC' as "created_at!: DateTime<Utc>",
                     updated_at AT TIME ZONE 'UTC' as "updated_at!: DateTime<Utc>"
            "#,
            req.username,
            invitation.email,
            password_hash,
            invitation.role,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate key") {
                (StatusCode::CONFLICT, "Username already exists".to_string())
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
            }
        })?;

    // Mark invitation as used
    sqlx::query!(
            r#"
            UPDATE invitations
            SET used_at = NOW()
            WHERE id = $1
            "#,
            invitation.id
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update invitation: {}", e))
        })?;

    // Commit transaction
    tx.commit().await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Transaction error: {}", e))
    })?;

    // Generate tokens and create response
    service.create_auth_response(&user, jar).await
}
