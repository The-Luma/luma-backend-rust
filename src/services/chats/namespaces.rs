use sqlx::PgPool;
use axum::http::StatusCode;
use chrono::{DateTime, Utc, NaiveDateTime};
use crate::models::models::{CreateNamespaceRequest, Namespace};

pub async fn create_namespace(
    db: &PgPool,
    user_id: i32,
    name: String,
    description: Option<String>,
    is_public: bool,
) -> Result<Namespace, (StatusCode, String)> {
    // Insert new namespace
    let namespace = sqlx::query!(
        r#"
        INSERT INTO namespace (user_id, name, description, is_public, created_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, user_id, name, description, is_public, created_at
        "#,
        user_id,
        name,
        description,
        is_public,
        Utc::now().naive_utc()
    )
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Namespace {
        id: namespace.id,
        user_id: namespace.user_id,
        name: namespace.name,
        description: namespace.description,
        is_public: namespace.is_public,
        created_at: DateTime::from_naive_utc_and_offset(namespace.created_at, Utc),
    })
}

pub async fn list_user_namespaces(
    db: &PgPool,
    user_id: i32,
    include_public: bool,
) -> Result<Vec<Namespace>, (StatusCode, String)> {
    let namespaces = sqlx::query!(
        r#"
        SELECT DISTINCT n.id, n.user_id, n.name, n.description, n.is_public, n.created_at
        FROM namespace n
        LEFT JOIN namespace_auth na ON n.id = na.namespace_id
        WHERE n.user_id = $1 
        OR ($2 = true AND na.user_id = $1 AND (n.is_public = true OR na.auth_level >= 1))
        ORDER BY n.created_at DESC
        "#,
        user_id,
        include_public
    )
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(namespaces
        .into_iter()
        .map(|n| Namespace {
            id: n.id,
            user_id: n.user_id,
            name: n.name,
            description: n.description,
            is_public: n.is_public,
            created_at: DateTime::from_naive_utc_and_offset(n.created_at, Utc),
        })
        .collect())
}

pub async fn delete_namespace(
    db: &PgPool,
    user_id: i32,
    namespace_id: i32,
) -> Result<(), (StatusCode, String)> {
    // Verify namespace ownership
    let namespace = sqlx::query!(
        r#"
        SELECT id, user_id
        FROM namespace
        WHERE id = $1 AND user_id = $2
        "#,
        namespace_id,
        user_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Namespace not found".to_string()))?;

    // Delete all messages in conversations in this namespace
    sqlx::query!(
        r#"
        DELETE FROM message m
        USING chats c
        WHERE m.chat_id = c.id AND c.namespace_id = $1
        "#,
        namespace_id
    )
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Delete all conversations in this namespace
    sqlx::query!(
        r#"
        DELETE FROM chats
        WHERE namespace_id = $1
        "#,
        namespace_id
    )
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Delete all namespace access records
    sqlx::query!(
        r#"
        DELETE FROM namespace_auth
        WHERE namespace_id = $1
        "#,
        namespace_id
    )
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Delete the namespace
    sqlx::query!(
        r#"
        DELETE FROM namespace
        WHERE id = $1
        "#,
        namespace_id
    )
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(())
}

pub async fn share_namespace(
    db: &PgPool,
    owner_id: i32,
    namespace_id: i32,
    target_user_id: i32,
    auth_level: i32,
) -> Result<(), (StatusCode, String)> {
    // Verify namespace ownership
    let namespace = sqlx::query!(
        r#"
        SELECT id, user_id
        FROM namespace
        WHERE id = $1 AND user_id = $2
        "#,
        namespace_id,
        owner_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Namespace not found".to_string()))?;

    // Verify target user exists
    let user = sqlx::query!(
        r#"
        SELECT id
        FROM users
        WHERE id = $1
        "#,
        target_user_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Target user not found".to_string()))?;

    // Insert or update namespace access
    sqlx::query!(
        r#"
        INSERT INTO namespace_auth (user_id, namespace_id, auth_level)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_id, namespace_id) 
        DO UPDATE SET auth_level = $3
        "#,
        target_user_id,
        namespace_id,
        auth_level
    )
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(())
} 