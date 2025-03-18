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

const ACCESS_TOKEN_DURATION: i64 = 15 * 60; // 15 minutes in seconds
const REFRESH_TOKEN_DURATION: i64 = 7 * 24 * 60 * 60; // 7 days in seconds
const INVITATION_DURATION: i64 = 7 * 24 * 60 * 60; // 7 days in seconds
const FRONTEND_URL: &str = "http://localhost:5173"; // Frontend URL for invitation links

#[derive(Clone)]
pub struct UserService {
    db: PgPool,
    jwt_secret: String,
}

impl UserService {
    pub fn new(db: PgPool, jwt_secret: String) -> Self {
        Self { db, jwt_secret }
    }

    pub async fn check_admin_setup(&self) -> Result<bool, (StatusCode, String)> {
        // Check if admin exists
        let admin_exists = sqlx::query_scalar!(
            "SELECT EXISTS(SELECT 1 FROM users WHERE role = 'admin')"
        )
            .fetch_one(&self.db)
            .await
            .map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
            })?
            .unwrap_or(false);

        // Return true if no admin exists (setup required)
        Ok(admin_exists)
    }

    /// Creates a new admin user if none exists
    pub async fn create_admin(
        &self,
        req: CreateAdminRequest,
        jar: &CookieJar,
    ) -> Result<Response, (StatusCode, String)> {
        // Check if admin exists
        let admin_exists = sqlx::query_scalar!(
            "SELECT EXISTS(SELECT 1 FROM users WHERE role = 'admin')"
        )
        .fetch_one(&self.db)
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
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate key") {
                (StatusCode::CONFLICT, "Username or email already exists".to_string())
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
            }
        })?;

        // Generate tokens and create response
        self.create_auth_response(&user, jar).await
    }

    /// Generates a JWT access token for a user
    fn generate_access_token(&self, user: &User) -> Result<String, (StatusCode, String)> {
        let expiration = Utc::now()
            .checked_add_signed(Duration::seconds(ACCESS_TOKEN_DURATION))
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
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Token generation error: {}", e))
        })
    }

    /// Generates and stores a refresh token for a user
    async fn create_refresh_token(&self, user_id: i32) -> Result<String, (StatusCode, String)> {
        let token = Uuid::new_v4().to_string();
        let expires_at = (Utc::now() + Duration::seconds(REFRESH_TOKEN_DURATION)).naive_utc();

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
        .execute(&self.db)
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store refresh token: {}", e))
        })?;

        Ok(token)
    }

    /// Creates an authentication response with secure cookies
    async fn create_auth_response(
        &self,
        user: &User,
        jar: &CookieJar,
    ) -> Result<Response, (StatusCode, String)> {
        let access_token = self.generate_access_token(user)?;
        let refresh_token = self.create_refresh_token(user.id).await?;

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
        access_cookie.set_max_age(time::Duration::seconds(ACCESS_TOKEN_DURATION));
        access_cookie.set_http_only(true);
        access_cookie.set_secure(true);
        access_cookie.set_same_site(axum_extra::extract::cookie::SameSite::Strict);

        let mut refresh_cookie = Cookie::new("refresh_token", refresh_token);
        refresh_cookie.set_path("/");
        refresh_cookie.set_max_age(time::Duration::seconds(REFRESH_TOKEN_DURATION));
        refresh_cookie.set_http_only(true);
        refresh_cookie.set_secure(true);
        refresh_cookie.set_same_site(axum_extra::extract::cookie::SameSite::Strict);

        let jar = jar.clone().add(access_cookie).add(refresh_cookie);

        // Build the response with cookies
        let response = (jar, Json(auth_response)).into_response();
        Ok(response)
    }

    /// Refreshes the access token using a valid refresh token
    pub async fn refresh_token(
        &self,
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
        .fetch_optional(&self.db)
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
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
        })?;

        // Delete the used refresh token
        sqlx::query!(
            "DELETE FROM refresh_tokens WHERE id = $1",
            stored_token.id
        )
        .execute(&self.db)
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
        })?;

        // Create new tokens and response
        self.create_auth_response(&user, jar).await
    }

    /// Validates a JWT token and returns the claims if valid
    pub fn validate_token(&self, token: &str) -> Result<Claims, (StatusCode, String)> {
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map(|token_data| token_data.claims)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid token".to_string()))
    }

    /// Gets user information by ID
    pub async fn get_user_by_id(&self, user_id: i32) -> Result<UserResponse, (StatusCode, String)> {
        let user = sqlx::query!(
            r#"
            SELECT id, username, email, role
            FROM users
            WHERE id = $1
            "#,
            user_id
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
        })?;

        Ok(UserResponse {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
        })
    }

    /// Authenticates a user with username/password
    pub async fn login(
        &self,
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
        .fetch_optional(&self.db)
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
        self.create_auth_response(&user, jar).await
    }

    /// Creates a new invitation
    pub async fn create_invitation(
        &self,
        req: CreateInvitationRequest,
        inviter_id: i32,
    ) -> Result<InvitationResponse, (StatusCode, String)> {
        // Generate invitation token
        let token = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + Duration::seconds(INVITATION_DURATION);

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
        .fetch_one(&self.db)
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
            invitation_link: format!("{}/register?token={}", FRONTEND_URL, invitation.token),
        })
    }

    /// Registers a new user with an invitation
    pub async fn register_with_invitation(
        &self,
        req: RegisterWithInvitationRequest,
        jar: &CookieJar,
    ) -> Result<Response, (StatusCode, String)> {
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
        .fetch_optional(&self.db)
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
        let mut tx = self.db.begin().await.map_err(|e| {
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
        self.create_auth_response(&user, jar).await
    }

    /// Deletes a user account and all associated data
    pub async fn delete_user(&self, user_id: i32, password: &str) -> Result<(), (StatusCode, String)> {
        // Start transaction
        let mut tx = self.db.begin().await.map_err(|e| {
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

    /// Allows an admin to delete any user account
    pub async fn admin_delete_user(&self, target_user_id: i32) -> Result<(), (StatusCode, String)> {
        // Start transaction
        let mut tx = self.db.begin().await.map_err(|e| {
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

    /// Search users by email or username with wildcard support
    pub async fn search_users(&self, query: SearchUsersQuery) -> Result<SearchUsersResponse, (StatusCode, String)> {
        let search_pattern = query.search_string
            .clone()
            .map(|s| format!("%{}%", s))
            .unwrap_or_else(|| "%".to_string());

        let limit = query.get_limit();
        let offset = query.get_offset();

        // Get total count first
        let total: i64 = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM users
            WHERE email ILIKE $1 OR username ILIKE $1
            "#,
            search_pattern
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to count users: {}", e),
            )
        })?;

        // Then get paginated results
        let users = sqlx::query_as!(
            UserResponse,
            r#"
            SELECT id, username, email, role
            FROM users
            WHERE email ILIKE $1 OR username ILIKE $1
            ORDER BY id
            LIMIT $2 OFFSET $3
            "#,
            search_pattern,
            limit,
            offset
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to search users: {}", e),
            )
        })?;

        Ok(SearchUsersResponse {
            users,
            total,
            limit,
            offset,
        })
    }
} 