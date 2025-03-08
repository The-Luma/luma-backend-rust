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
        custom(function ="validate_password_strength", message = "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character")
    )]
    pub password: String,
    #[validate(must_match(other = "password", message = "Passwords do not match"))]
    pub confirm_password: String,
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