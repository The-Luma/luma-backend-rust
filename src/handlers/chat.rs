use axum::{
    extract::{Path, State, Query, Extension},
    Json,
    response::IntoResponse,
    http::StatusCode,
};
use crate::services::luma::LumaService;
use crate::models::models::{
    UserResponse,
    ChatMessage,
    ChatStart,
    ChatResponse,
    Conversation,
    CreateNamespaceRequest,
    Namespace,
    NamespaceQuery,
    ShareNamespaceRequest
};
use chrono::{DateTime, Utc};
use serde_json::json;

/// Start a new chat conversation
pub async fn start_chat(
    State(service): State<LumaService>,
    Extension(user): Extension<UserResponse>,
    Json(message): Json<ChatStart>,
) -> impl IntoResponse {
    match service.start_chat_conversation(user.id, message.namespace_id).await {
        Ok(conversation) => (StatusCode::OK, Json(json!({ "conversation": conversation }))),
        Err((status, message)) => (status, Json(json!({ "error": message }))),
    }
}

/// Send a message in a chat conversation
pub async fn send_message(
    State(service): State<LumaService>,
    Extension(user): Extension<UserResponse>,
    Json(message): Json<ChatMessage>,
) -> impl IntoResponse {
    match service.send_chat_message(
        user.id,
        message.content,
        message.conversation_id,
        message.namespace_id
    ).await {
        Ok(message) => (StatusCode::OK, Json(json!({ "message": message }))),
        Err((status, message)) => (status, Json(json!({ "error": message }))),
    }
}

/// Get chat history for a conversation
pub async fn get_chat_history(
    State(service): State<LumaService>,
    Extension(user): Extension<UserResponse>,
    Path(conversation_id): Path<i32>,
) -> impl IntoResponse {
    match service.get_chat_history(user.id, conversation_id).await {
        Ok(conversation) => (StatusCode::OK, Json(json!({ "conversation": conversation }))),
        Err((status, message)) => (status, Json(json!({ "error": message }))),
    }
}

/// List all conversations for a user
pub async fn list_conversations(
    State(service): State<LumaService>,
    Extension(user): Extension<UserResponse>,
    Query(query): Query<NamespaceQuery>,
) -> impl IntoResponse {
    match service.list_user_conversations(user.id, query.include_public.unwrap_or(false)).await {
        Ok(conversations) => (StatusCode::OK, Json(json!({ "conversations": conversations }))),
        Err((status, message)) => (status, Json(json!({ "error": message }))),
    }
}

/// Delete a conversation
pub async fn delete_conversation(
    State(service): State<LumaService>,
    Extension(user): Extension<UserResponse>,
    Path(conversation_id): Path<i32>,
) -> impl IntoResponse {
    match service.delete_conversation(user.id, conversation_id).await {
        Ok(_) => (StatusCode::NO_CONTENT, Json(json!({ "message": "Conversation deleted successfully" }))),
        Err((status, message)) => (status, Json(json!({ "error": message }))),
    }
}

/// Create a new namespace
pub async fn create_namespace(
    State(service): State<LumaService>,
    Extension(user): Extension<UserResponse>,
    Json(request): Json<CreateNamespaceRequest>,
) -> impl IntoResponse {
    match service.create_namespace(
        user.id,
        request.name,
        request.description,
        request.is_public.unwrap_or(false)
    ).await {
        Ok(namespace) => (StatusCode::OK, Json(json!({ "namespace": namespace }))),
        Err((status, message)) => (status, Json(json!({ "error": message }))),
    }
}

/// List namespaces for a user
pub async fn list_namespaces(
    State(service): State<LumaService>,
    Extension(user): Extension<UserResponse>,
    Query(query): Query<NamespaceQuery>,
) -> impl IntoResponse {
    match service.list_user_namespaces(user.id, query.include_public.unwrap_or(false)).await {
        Ok(namespaces) => (StatusCode::OK, Json(json!({ "namespaces": namespaces }))),
        Err((status, message)) => (status, Json(json!({ "error": message }))),
    }
}

/// Delete a namespace
pub async fn delete_namespace(
    State(service): State<LumaService>,
    Extension(user): Extension<UserResponse>,
    Path(namespace_id): Path<i32>,
) -> impl IntoResponse {
    match service.delete_namespace(user.id, namespace_id).await {
        Ok(_) => (StatusCode::NO_CONTENT, Json(json!({ "message": "Namespace deleted successfully" }))),
        Err((status, message)) => (status, Json(json!({ "error": message }))),
    }
}

/// Share a namespace with another user
pub async fn share_namespace(
    State(service): State<LumaService>,
    Extension(user): Extension<UserResponse>,
    Path(namespace_id): Path<i32>,
    Json(request): Json<ShareNamespaceRequest>,
) -> impl IntoResponse {
    match service.share_namespace(
        user.id,
        namespace_id,
        request.user_id,
        request.auth_level
    ).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "message": "Namespace shared successfully" }))),
        Err((status, message)) => (status, Json(json!({ "error": message }))),
    }
}
