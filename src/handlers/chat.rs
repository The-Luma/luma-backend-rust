use axum::{
    extract::{Path, State, Query, Extension, Multipart},
    Json,
    response::IntoResponse,
    http::StatusCode,
    http::header,
};
use crate::services::luma::LumaService;
use crate::models::models::{
    UserResponse,
    ChatMessage,
    ChatStart,
    CreateNamespaceRequest,
    NamespaceQuery,
    ShareNamespaceRequest,
    RevokeNamespaceRequest,
};
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
        message.conversation_id
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
        Ok(_) => (StatusCode::OK, Json(json!({ "message": "Conversation deleted successfully" }))),
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
    Query(_query): Query<NamespaceQuery>,
) -> impl IntoResponse {
    match service.list_user_namespaces(user.id).await {
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
        Ok(message) => (StatusCode::OK, Json(json!({ "message": message }))),
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

/// Revoke namespace access from a user
pub async fn revoke_namespace_access(
    State(service): State<LumaService>,
    Extension(user): Extension<UserResponse>,
    Path(namespace_id): Path<i32>,
    Json(request): Json<RevokeNamespaceRequest>,
) -> impl IntoResponse {
    match service.revoke_namespace_access(
        user.id,
        namespace_id,
        request.user_id,
    ).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "message": "Namespace access revoked successfully" }))),
        Err((status, message)) => (status, Json(json!({ "error": message }))),
    }
}

/// Upload a document to a namespace
pub async fn upload_document(
    State(service): State<LumaService>,
    Extension(user): Extension<UserResponse>,
    Path(namespace_id): Path<i32>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, impl IntoResponse> {
    let mut file_name: Option<String> = None;
    let mut file_content: Option<Vec<u8>> = None;

    // Process multipart form data
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("Failed to process form data: {}", e) })))
    })? {
        let name = field.name().unwrap_or("").to_string();
        
        match name.as_str() {
            "file" => {
                file_name = Some(field.file_name().unwrap_or("unnamed.pdf").to_string());
                file_content = Some(field.bytes().await.map_err(|e| {
                    (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("Failed to read file: {}", e) })))
                })?.to_vec());
            },
            _ => {}
        }
    }
    
    let file_name = file_name.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, Json(json!({ "error": "file is required" })))
    })?;
    
    let file_content = file_content.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, Json(json!({ "error": "file content is required" })))
    })?;

    // Upload document
    match service.upload_document(
        user.id,
        namespace_id,
        file_name,
        file_content,
    ).await {
        Ok(document) => Ok((StatusCode::OK, Json(json!({ "document": document })))),
        Err((status, message)) => Err((status, Json(json!({ "error": message })))),
    }
}

/// Delete a document from a namespace
pub async fn delete_document(
    State(service): State<LumaService>,
    Extension(user): Extension<UserResponse>,
    Path((namespace_id, document_id)): Path<(i32, i32)>,
) -> impl IntoResponse {
    match service.delete_document(user.id, namespace_id, document_id).await {
        Ok(message) => (StatusCode::OK, Json(json!({ "message": message }))),
        Err((status, message)) => (status, Json(json!({ "error": message }))),
    }
}

/// List documents in a namespace
pub async fn list_documents(
    State(service): State<LumaService>,
    Extension(user): Extension<UserResponse>,
    Path(namespace_id): Path<i32>,
) -> impl IntoResponse {
    match service.list_documents(user.id, namespace_id).await {
        Ok(documents) => (StatusCode::OK, Json(json!({ "documents": documents }))),
        Err((status, message)) => (status, Json(json!({ "error": message }))),
    }
}

/// Download a document from a namespace
pub async fn download_document(
    State(service): State<LumaService>,
    Extension(user): Extension<UserResponse>,
    Path((namespace_id, document_id)): Path<(i32, i32)>,
) -> impl IntoResponse {
    match service.download_document(user.id, namespace_id, document_id).await {
        Ok((file_content, title, file_path)) => {
            let extension = file_path.split('.').last().unwrap_or("pdf");
            let content_type = match extension {
                "pdf" => "application/pdf",
                _ => "application/octet-stream",
            };

            // Create owned strings for the headers
            let content_disposition = format!("attachment; filename=\"{}\"", title);
            
            // Use owned values in the headers array
            let headers = [
                (header::CONTENT_TYPE, content_type.to_string()),
                (header::CONTENT_DISPOSITION, content_disposition),
            ];

            (StatusCode::OK, headers, file_content)
        },
        Err((status, message)) => {
            // Create the error JSON value directly
            let error_json = json!({ "error": message });
            let error_bytes = serde_json::to_vec(&error_json).unwrap_or_default();
            
            // Use owned values for error headers
            let headers = [
                (header::CONTENT_TYPE, "application/json".to_string()),
                (header::CONTENT_DISPOSITION, "inline".to_string()),
            ];
            
            (status, headers, error_bytes)
        },
    }
}
