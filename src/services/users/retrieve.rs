use axum::{
    http::StatusCode
};


use crate::models::models::{
    UserResponse, SearchUsersQuery, SearchUsersResponse,
};

use crate::services::luma::LumaService;

pub async fn get_user_by_id(service: &LumaService, user_id: i32) -> Result<UserResponse, (StatusCode, String)> {
    let user = sqlx::query!(
            r#"
            SELECT id, username, email, role
            FROM users
            WHERE id = $1
            "#,
            user_id
        )
        .fetch_one(service.db())
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

pub async fn search_users(service: &LumaService, query: SearchUsersQuery) -> Result<SearchUsersResponse, (StatusCode, String)> {
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
        .fetch_one(service.db())
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
        .fetch_all(service.db())
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

