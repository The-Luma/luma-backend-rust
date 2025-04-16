use crate::models::models::{Namespace, UserResponse, NamespaceAccessResponse};
use sqlx::PgPool;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};

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
        auth_level: Some(3), // Creator has full access (level 3)
    })
}

pub async fn list_user_namespaces(
    db: &PgPool,
    user_id: i32,
) -> Result<Vec<Namespace>, (StatusCode, String)> {
    let namespaces = sqlx::query!(
        r#"
        SELECT DISTINCT n.id, n.user_id, n.name, n.description, n.is_public, n.created_at,
               CASE 
                   WHEN n.user_id = $1 THEN 3  -- Owner has full access (level 3)
                   ELSE COALESCE(na.auth_level, 0)  -- Other users have their assigned level or 0
               END as auth_level
        FROM namespace n
        LEFT JOIN namespace_auth na ON n.id = na.namespace_id AND na.user_id = $1
        WHERE n.user_id = $1 
        OR (na.user_id = $1 AND (n.is_public = true OR na.auth_level >= 1))
        ORDER BY n.created_at DESC
        "#,
        user_id
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
            auth_level: n.auth_level,
        })
        .collect())
}

pub async fn delete_namespace(
    db: &PgPool,
    user_id: i32,
    namespace_id: i32,
) -> Result<String, (StatusCode, String)> {
    // Verify namespace ownership
    let namespace = sqlx::query!(
        r#"
        SELECT n.id, n.user_id
        FROM namespace n
        LEFT JOIN namespace_auth na ON n.id = na.namespace_id AND na.user_id = $2
        WHERE (n.id = $1 AND n.user_id = $2)  -- Check direct ownership
           OR (n.id = $1 AND na.user_id = $2 AND na.auth_level = 3)  -- Check access level 3
        "#,
        namespace_id,
        user_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    match namespace {
        Some(_) => (),
        None => {
            return Err((StatusCode::NOT_FOUND, "Namespace not found or you do not have a permission".to_string()));
        }
    }

    // Delete all messages in conversations in this namespace
    let result = sqlx::query!(
        r#"
        DELETE FROM message m
        USING chats c
        WHERE m.chat_id = c.id AND c.namespace_id = $1
        "#,
        namespace_id
    )
    .execute(db)
    .await;

    match result {
        Ok(_) => (),
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR, 
                format!("Failed to delete messages: {}", e.to_string())
            ));
        }
    }

    // Delete all conversations in this namespace
    let result = sqlx::query!(
        r#"
        DELETE FROM chats
        WHERE namespace_id = $1
        "#,
        namespace_id
    )
    .execute(db)
    .await;

    match result {
        Ok(_) => (),
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR, 
                format!("Failed to delete conversations: {}", e.to_string())
            ));
        }
    }

    // Delete all namespace access records
    let result = sqlx::query!(
        r#"
        DELETE FROM namespace_auth
        WHERE namespace_id = $1
        "#,
        namespace_id
    )
    .execute(db)
    .await;

    match result {
        Ok(_) => (),
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR, 
                format!("Failed to delete namespace access records: {}", e.to_string())
            ));
        }
    }

    // Delete the namespace
    let result = sqlx::query!(
        r#"
        DELETE FROM namespace
        WHERE id = $1
        "#,
        namespace_id
    )
    .execute(db)
    .await;

    match result {
        Ok(_) => Ok("Namespace deleted successfully".to_string()),
        Err(e) => {
            Err((
                StatusCode::INTERNAL_SERVER_ERROR, 
                format!("Failed to delete namespace: {}", e.to_string())
            ))
        }
    }
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
        SELECT n.id, n.user_id
        FROM namespace n
        LEFT JOIN namespace_auth na ON n.id = na.namespace_id AND na.user_id = $2
        WHERE (n.id = $1 AND n.user_id = $2)  -- Check direct ownership
           OR (n.id = $1 AND na.user_id = $2 AND na.auth_level = 3)  -- Check access level 3
        "#,
        namespace_id,
        owner_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Namespace not found or you do not have a permission".to_string()))?;

    // Verify target user exists
    sqlx::query!(
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

    // Check if the target user is the owner of the namespace
    if namespace.user_id == target_user_id {
        return Err((StatusCode::BAD_REQUEST, "Cannot share namespace with the owner".to_string()));
    }

    // Insert or update namespace access
    let mut transaction = db.begin().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Check if the access record already exists
    let existing_access = sqlx::query!(
        r#"
        SELECT id FROM namespace_auth
        WHERE user_id = $1 AND namespace_id = $2
        "#,
        target_user_id,
        namespace_id
    )
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    if existing_access.is_some() {
        // Update existing access
        sqlx::query!(
            r#"
            UPDATE namespace_auth
            SET auth_level = $1
            WHERE user_id = $2 AND namespace_id = $3
            "#,
            auth_level,
            target_user_id,
            namespace_id
        )
        .execute(&mut *transaction)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    } else {
        // Insert new access
        sqlx::query!(
            r#"
            INSERT INTO namespace_auth (user_id, namespace_id, auth_level)
            VALUES ($1, $2, $3)
            "#,
            target_user_id,
            namespace_id,
            auth_level
        )
        .execute(&mut *transaction)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    
    // Commit the transaction
    transaction.commit().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(())
}

pub async fn revoke_namespace_access(
    db: &PgPool,
    owner_id: i32,
    namespace_id: i32,
    target_user_id: i32,
) -> Result<(), (StatusCode, String)> {
    // Verify namespace ownership
    let namespace = sqlx::query!(
        r#"
        SELECT n.id, n.user_id
        FROM namespace n
        LEFT JOIN namespace_auth na ON n.id = na.namespace_id AND na.user_id = $2
        WHERE (n.id = $1 AND n.user_id = $2)  -- Check direct ownership
           OR (n.id = $1 AND na.user_id = $2 AND na.auth_level = 3)  -- Check access level 3
        "#,
        namespace_id,
        owner_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Namespace not found or you do not have a permission".to_string()))?;

    // Verify target user exists
    sqlx::query!(
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

    // Check if the target user is the owner of the namespace
    if namespace.user_id == target_user_id {
        return Err((StatusCode::BAD_REQUEST, "Cannot revoke access from the owner of the namespace".to_string()));
    }

    // Delete namespace access
    sqlx::query!(
        r#"
        DELETE FROM namespace_auth
        WHERE user_id = $1 AND namespace_id = $2
        "#,
        target_user_id,
        namespace_id
    )
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(())
}

pub async fn get_namespace_access_list(
    db: &PgPool,
    user_id: i32,
    namespace_id: i32,
) -> Result<Vec<NamespaceAccessResponse>, (StatusCode, String)> {
    // Verify namespace ownership or access
    sqlx::query!(
        r#"
        SELECT n.id, n.user_id, n.is_public
        FROM namespace n
        LEFT JOIN namespace_auth na ON n.id = na.namespace_id AND na.user_id = $2
        WHERE (n.id = $1 AND n.user_id = $2)  -- Check direct ownership
           OR (n.id = $1 AND na.user_id = $2 AND na.auth_level >= 1)  -- Check access level
        "#,
        namespace_id,
        user_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Namespace not found or you do not have permission".to_string()))?;

    // Get all users with access to the namespace
    let access_list = sqlx::query!(
        r#"
        WITH namespace_users AS (
            -- Get the owner
            SELECT 
                u.id as user_id,
                u.username,
                u.email,
                u.role,
                3 as auth_level,
                n.created_at as granted_at
            FROM namespace n
            JOIN users u ON n.user_id = u.id
            WHERE n.id = $1
            
            UNION
            
            -- Get users with access
            SELECT 
                u.id as user_id,
                u.username,
                u.email,
                u.role,
                na.auth_level,
                n.created_at as granted_at
            FROM namespace_auth na
            JOIN users u ON na.user_id = u.id
            JOIN namespace n ON na.namespace_id = n.id
            WHERE na.namespace_id = $1
        )
        SELECT 
            user_id,
            username,
            email,
            role,
            auth_level,
            granted_at
        FROM namespace_users
        WHERE user_id IS NOT NULL 
          AND username IS NOT NULL 
          AND email IS NOT NULL 
          AND role IS NOT NULL 
          AND auth_level IS NOT NULL
          AND granted_at IS NOT NULL
        ORDER BY auth_level DESC, username ASC
        "#,
        namespace_id
    )
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(access_list
        .into_iter()
        .map(|row| NamespaceAccessResponse {
            user: UserResponse {
                id: row.user_id.expect("User ID cannot be null"),
                username: row.username.expect("Username cannot be null"),
                email: row.email.expect("Email cannot be null"),
                role: row.role.expect("Role cannot be null"),
            },
            auth_level: row.auth_level.expect("Auth level cannot be null"),
            granted_at: DateTime::from_naive_utc_and_offset(row.granted_at.expect("Granted at cannot be null"), Utc),
        })
        .collect())
}

pub async fn get_user_namespace_access_level(
    db: &PgPool,
    user_id: i32,
    namespace_id: i32,
) -> Result<i32, (StatusCode, String)> {
    let access_level = sqlx::query!(
        r#"
        SELECT 
            CASE 
                WHEN n.user_id = $1 THEN 3  -- Owner has full access (level 3)
                WHEN na.auth_level IS NOT NULL THEN na.auth_level  -- User with explicit access
                WHEN n.is_public = true THEN 1  -- Public namespace gives read access (level 1)
                ELSE 0  -- No access
            END as access_level
        FROM namespace n
        LEFT JOIN namespace_auth na ON n.id = na.namespace_id AND na.user_id = $1
        WHERE n.id = $2
        "#,
        user_id,
        namespace_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Namespace not found".to_string()))?;

    Ok(access_level.access_level.unwrap_or(0))
} 