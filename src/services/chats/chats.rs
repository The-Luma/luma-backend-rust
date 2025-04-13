use sqlx::PgPool;
use axum::http::StatusCode;
use chrono::{DateTime, Utc, NaiveDateTime};
use crate::models::models::{ChatMessage, ChatResponse, Conversation, ConversationListItem};

pub async fn start_chat_conversation(
    db: &PgPool,
    user_id: i32,
    namespace_id: Option<i32>,
) -> Result<Conversation, (StatusCode, String)> {
    let namespace_id = namespace_id.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "Namespace ID is required".to_string())
    })?;

    // Verify namespace access
    let has_access = sqlx::query!(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM namespace n
            LEFT JOIN namespace_auth na ON na.namespace_id = n.id AND na.user_id = $1
            WHERE n.id = $2
            AND (
                n.user_id = $1
                OR na.user_id IS NOT NULL
                OR n.is_public = true
            )
        ) as "exists!"
        "#,
        user_id,
        namespace_id
    )
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .exists;

    if !has_access {
        return Err((StatusCode::FORBIDDEN, "No access to this namespace".to_string()));
    }

    // Insert new chat conversation
    let chat = sqlx::query!(
        r#"
        INSERT INTO chats (user_id, namespace_id, started_at)
        VALUES ($1, $2, $3)
        RETURNING id, user_id, namespace_id, started_at
        "#,
        user_id,
        namespace_id,
        Utc::now().naive_utc()
    )
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Conversation {
        id: chat.id,
        user_id: chat.user_id,
        namespace_id: chat.namespace_id,
        started_at: DateTime::from_naive_utc_and_offset(chat.started_at, Utc),
        messages: Vec::new(),
    })
}

pub async fn send_chat_message(
    db: &PgPool,
    user_id: i32,
    content: String,
    conversation_id: Option<i32>,
    namespace_id: Option<i32>,
) -> Result<ChatResponse, (StatusCode, String)> {
    let conversation_id = conversation_id.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "Conversation ID is required".to_string())
    })?;

    // Verify conversation ownership
    let chat = sqlx::query!(
        r#"
        SELECT c.id, c.user_id, c.started_at, n.id as namespace_id
        FROM chats c
        JOIN namespace n ON c.namespace_id = n.id
        WHERE c.id = $1 AND c.user_id = $2
        "#,
        conversation_id,
        user_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Conversation not found".to_string()))?;

    // Verify namespace access
    let has_access = sqlx::query!(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM namespace n
            LEFT JOIN namespace_auth na ON na.namespace_id = n.id AND na.user_id = $1
            WHERE n.id = $2
            AND (
                n.user_id = $1
                OR na.user_id IS NOT NULL
                OR n.is_public = true
            )
        ) as "exists!"
        "#,
        user_id,
        chat.namespace_id
    )
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .exists;

    if !has_access {
        return Err((StatusCode::FORBIDDEN, "No access to this namespace".to_string()));
    }

    // Insert user message
    let message = sqlx::query_as!(
        ChatResponse,
        r#"
        INSERT INTO message (chat_id, sender_type, content, time_sent)
        VALUES ($1, 'user', $2, $3)
        RETURNING id, content, sender_type, time_sent, chat_id as conversation_id
        "#,
        conversation_id,
        content,
        Utc::now().naive_utc()
    )
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(message)
}

pub async fn get_chat_history(
    db: &PgPool,
    user_id: i32,
    conversation_id: i32,
) -> Result<Conversation, (StatusCode, String)> {
    // Verify conversation ownership and get chat details
    let chat = sqlx::query!(
        r#"
        SELECT c.id, c.user_id, c.started_at, n.id as namespace_id
        FROM chats c
        JOIN namespace n ON c.namespace_id = n.id
        WHERE c.id = $1 AND c.user_id = $2
        "#,
        conversation_id,
        user_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Conversation not found".to_string()))?;

    // Verify namespace access
    let has_access = sqlx::query!(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM namespace n
            LEFT JOIN namespace_auth na ON na.namespace_id = n.id AND na.user_id = $1
            WHERE n.id = $2
            AND (
                n.user_id = $1
                OR na.user_id IS NOT NULL
                OR n.is_public = true
            )
        ) as "exists!"
        "#,
        user_id,
        chat.namespace_id
    )
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .exists;

    if !has_access {
        return Err((StatusCode::FORBIDDEN, "No access to this namespace".to_string()));
    }

    // Get all messages for the conversation
    let messages = sqlx::query_as!(
        ChatResponse,
        r#"
        SELECT id, content, sender_type, time_sent, chat_id as conversation_id
        FROM message
        WHERE chat_id = $1
        ORDER BY time_sent ASC
        "#,
        conversation_id
    )
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Conversation {
        id: chat.id,
        user_id: chat.user_id,
        namespace_id: chat.namespace_id,
        started_at: DateTime::from_naive_utc_and_offset(chat.started_at, Utc),
        messages,
    })
}

pub async fn list_user_conversations(
    db: &PgPool,
    user_id: i32,
    include_public: bool,
) -> Result<Vec<ConversationListItem>, (StatusCode, String)> {
    let chats = sqlx::query!(
        r#"
        SELECT DISTINCT c.id, c.user_id, c.started_at, n.id as namespace_id
        FROM chats c
        JOIN namespace n ON c.namespace_id = n.id
        LEFT JOIN namespace_auth na ON n.id = na.namespace_id
        WHERE c.user_id = $1 
        OR ($2 = true AND na.user_id = $1 AND (n.is_public = true OR na.auth_level >= 1))
        ORDER BY c.started_at DESC
        "#,
        user_id,
        include_public
    )
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(chats
        .into_iter()
        .map(|chat| ConversationListItem {
            id: chat.id,
            user_id: chat.user_id,
            namespace_id: chat.namespace_id,
            started_at: DateTime::from_naive_utc_and_offset(chat.started_at, Utc),
        })
        .collect())
}

pub async fn delete_conversation(
    db: &PgPool,
    user_id: i32,
    conversation_id: i32,
) -> Result<(), (StatusCode, String)> {
    // Verify conversation ownership
    let chat = sqlx::query!(
        r#"
        SELECT c.id, c.user_id, c.started_at, n.id as namespace_id
        FROM chats c
        JOIN namespace n ON c.namespace_id = n.id
        WHERE c.id = $1 AND c.user_id = $2
        "#,
        conversation_id,
        user_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Conversation not found".to_string()))?;

    // Delete all messages first
    sqlx::query!(
        r#"
        DELETE FROM message
        WHERE chat_id = $1
        "#,
        conversation_id
    )
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Delete the conversation
    sqlx::query!(
        r#"
        DELETE FROM chats
        WHERE id = $1
        "#,
        conversation_id
    )
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(())
} 