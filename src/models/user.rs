use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use validator::{Validate, ValidationError};

/// Represents a user in the database
/// Maps directly to the 'users' table schema
#[derive(Debug, FromRow)]
#[allow(dead_code)]
pub struct User {
    pub id: i32,          // Maps to PostgreSQL SERIAL type
    pub username: String,
    pub email: String,
    pub password: String,  // Stored as bcrypt hash
    pub role: String,      // e.g., "admin" or "user"
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Custom validator for ensuring strong password requirements
/// Returns ValidationError with specific code for each validation failure
fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
    // Check minimum length
    if password.len() < 13 {
        return Err(ValidationError::new("password_length"));
    }

    // Check for at least one uppercase letter
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err(ValidationError::new("password_uppercase"));
    }

    // Check for at least one lowercase letter
    if !password.chars().any(|c| c.is_lowercase()) {
        return Err(ValidationError::new("password_lowercase"));
    }

    // Check for at least one number
    if !password.chars().any(|c| c.is_numeric()) {
        return Err(ValidationError::new("password_number"));
    }

    // Check for at least one special character
    if !password.chars().any(|c| !c.is_alphanumeric()) {
        return Err(ValidationError::new("password_special"));
    }

    Ok(())
}

/// Request payload for creating an admin account
/// Includes validation rules for each field
#[derive(Debug, Deserialize, Validate)]
pub struct CreateAdminRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 3, max = 50, message = "Username must be between 3 and 50 characters"))]
    pub username: String,
    #[validate(
        custom(
            function = "validate_password_strength",
            message = "Password must be at least 13 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character"
        )
    )]
    pub password: String,
}

/// Safe user data for responses
/// Excludes sensitive information like password
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: i32,          // Maps to PostgreSQL SERIAL type
    pub username: String,
    pub email: String,
    pub role: String,
}

/// Response payload for successful authentication
/// Includes user data and JWT token
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub user: UserResponse,
    pub token: String,  // JWT token for subsequent authenticated requests
}

/// JWT claims payload structure
/// Used for encoding user information in JWT tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: i32,          // Subject (user ID) - Maps to PostgreSQL SERIAL type
    pub username: String,  // User's username
    pub role: String,     // User's role (e.g., "admin")
    pub exp: i64,         // Expiration timestamp in seconds since Unix epoch
}

/// Request payload for user login
#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(length(min = 3, max = 50, message = "Username must be between 3 and 50 characters"))]
    pub username: String,
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
}

/// Request payload for creating an invitation
#[derive(Debug, Deserialize, Validate)]
pub struct CreateInvitationRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 1, message = "Role is required"))]
    pub role: String,
}

/// Request payload for user registration with invitation
#[derive(Debug, Deserialize, Validate)]
pub struct RegisterWithInvitationRequest {
    #[validate(length(min = 3, max = 50, message = "Username must be between 3 and 50 characters"))]
    pub username: String,
    #[validate(
        custom(
            function = "validate_password_strength",
            message = "Password must be at least 13 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character"
        )
    )]
    pub password: String,
    pub invitation_token: String,
}

/// Database model for invitations
#[derive(Debug, FromRow)]
pub struct Invitation {
    pub id: i32,
    pub email: String,
    pub role: String,
    pub token: String,
    pub invited_by: i32,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}

/// Response payload for invitation creation
#[derive(Debug, Serialize)]
pub struct InvitationResponse {
    pub id: i32,
    pub email: String,
    pub role: String,
    pub token: String,
    pub invited_by: i32,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_at: Option<DateTime<Utc>>,
    pub invitation_link: String,  // Frontend URL with token
}

/// Request payload for deleting an account
#[derive(Debug, Deserialize, Validate)]
pub struct DeleteAccountRequest {
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
}

/// Query parameters for searching users
#[derive(Debug, Deserialize)]
pub struct SearchUsersQuery {
    pub search_string: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl SearchUsersQuery {
    pub fn get_limit(&self) -> i64 {
        self.limit.unwrap_or(50).clamp(1, 100)
    }

    pub fn get_offset(&self) -> i64 {
        self.offset.unwrap_or(0).max(0)
    }
}

/// Response for user search results
#[derive(Debug, Serialize)]
pub struct SearchUsersResponse {
    pub users: Vec<UserResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
} 