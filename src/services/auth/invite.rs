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

pub async fn create_invitation(
    service: &LumaService,
    req: CreateInvitationRequest,
    inviter_id: i32,
) -> Result<InvitationResponse, (StatusCode, String)> {
    // Generate invitation token
    let token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::seconds(service.get_config().invitation_duration);

    // Store invitation
    let invitation = sqlx::query_as!(
            Invitation,
            r#"
            INSERT INTO invitations (email, role, token, invited_by, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, email, role, token, invited_by,
                     expires_at AT TIME ZONE 'UTC' as "expires_at!: DateTime<Utc>",
                     created_at AT TIME ZONE 'UTC' as "created_at!: DateTime<Utc>",
                     used_at AT TIME ZONE 'UTC' as "used_at?: DateTime<Utc>"
            "#,
            req.email,
            req.role,
            token,
            inviter_id,
            expires_at.naive_utc(),
        )
        .fetch_one(service.db())
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create invitation: {}", e))
        })?;

    // Create invitation response with frontend URL
    Ok(InvitationResponse {
        id: invitation.id,
        email: invitation.email,
        role: invitation.role,
        token: invitation.token.clone(),
        invited_by: invitation.invited_by,
        expires_at: invitation.expires_at,
        created_at: invitation.created_at,
        used_at: invitation.used_at,
        invitation_link: format!("{}/register?token={}", service.get_config().frontend_url, invitation.token),
    })
}
