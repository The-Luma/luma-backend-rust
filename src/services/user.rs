use axum::http::StatusCode;
use bcrypt::{hash, DEFAULT_COST};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use sqlx::PgPool;

use crate::models::{AuthResponse, Claims, CreateAdminRequest, User, UserResponse};

#[derive(Clone)]
pub struct UserService {
    db: PgPool,
    jwt_secret: String,
}

impl UserService {
    pub fn new(db: PgPool, jwt_secret: String) -> Self {
        Self { db, jwt_secret }
    }

    /// Creates a new admin user if none exists
    /// Returns AuthResponse with user data and JWT token on success
    pub async fn create_admin(&self, req: CreateAdminRequest) -> Result<AuthResponse, (StatusCode, String)> {
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

        // Generate JWT token
        let token = self.generate_token(&user)?;

        // Create response
        Ok(AuthResponse {
            user: UserResponse {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
            },
            token,
        })
    }

    /// Generates a JWT token for a user
    fn generate_token(&self, user: &User) -> Result<String, (StatusCode, String)> {
        let expiration = Utc::now()
            .checked_add_signed(Duration::hours(24))
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
} 