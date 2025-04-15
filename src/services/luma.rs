use axum::{
    http::StatusCode,
    response::{ Response}
};
use axum_extra::extract::cookie::{CookieJar};
use sqlx::PgPool;

use crate::models::models::{
    Claims, CreateAdminRequest, CreateInvitationRequest,
    InvitationResponse, LoginRequest, RegisterWithInvitationRequest,
    User, UserResponse, SearchUsersQuery, SearchUsersResponse,
    ChatMessage, ChatResponse, Conversation, ConversationListItem,
    CreateNamespaceRequest, Namespace, NamespaceQuery, ShareNamespaceRequest,
    DocumentResponse, DocumentListItem
};
use crate::services::auth;
use crate::services::users;
use crate::services::chats;
use crate::services::chats::namespaces;
use crate::services::documents::documents;
use crate::services::openai::OpenAIService;
use crate::services::pinecone::PineconeService;

pub struct AppConfig {
    pub access_token_duration: i64,
    pub refresh_token_duration: i64,
    pub invitation_duration: i64,
    pub frontend_url: &'static str,
}

const ACCESS_TOKEN_DURATION: i64 = 15 * 60; // 15 minutes in seconds
const REFRESH_TOKEN_DURATION: i64 = 7 * 24 * 60 * 60; // 7 days in seconds
const INVITATION_DURATION: i64 = 7 * 24 * 60 * 60; // 7 days in seconds
const FRONTEND_URL: &str = "http://localhost:5173"; // Frontend URL for invitation links

#[derive(Clone)]
pub struct LumaService {
    db: PgPool,
    jwt_secret: String,
    openai: OpenAIService,
    pinecone: PineconeService,
}

impl LumaService {
    pub fn new(db: PgPool, jwt_secret: String, openai: OpenAIService, pinecone: PineconeService) -> Self {
        Self { 
            db, 
            jwt_secret, 
            openai,
            pinecone
        }
    }
    pub fn db(&self) -> &PgPool {
        &self.db
    }
    pub fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }

    pub fn get_config(&self) -> AppConfig {
        AppConfig {
            access_token_duration: ACCESS_TOKEN_DURATION,
            refresh_token_duration: REFRESH_TOKEN_DURATION,
            invitation_duration: INVITATION_DURATION,
            frontend_url: FRONTEND_URL,
        }
    }

    // AUTH METHODS
    pub async fn login(&self, req: LoginRequest, jar: &CookieJar) -> Result<Response, (StatusCode, String)> {
        auth::login::login(&self, req, jar).await
    }
    pub async fn create_admin(&self, req: CreateAdminRequest, jar: &CookieJar) -> Result<Response, (StatusCode, String)> {
       auth::signup::create_admin(&self, req, jar).await
    }

    pub async fn check_admin_setup(&self) -> Result<bool, (StatusCode, String)> {
        auth::utils::check_admin_setup(&self).await
    }

    pub fn generate_access_token(&self, user: &User) -> Result<String, (StatusCode, String)> {
        auth::utils::generate_access_token(&self, user)
    }

    pub async fn create_refresh_token(&self, user_id: i32) -> Result<String, (StatusCode, String)> {
        auth::utils::create_refresh_token(&self, user_id).await
    }

    pub async fn refresh_token(&self, refresh_token: &str, jar: &CookieJar, ) -> Result<Response, (StatusCode, String)> {
        auth::utils::refresh_token(&self, refresh_token, jar).await
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, (StatusCode, String)> {
        auth::utils::validate_token(&self, token)
    }

    pub async fn create_auth_response(&self, user: &User, jar: &CookieJar, ) -> Result<Response, (StatusCode, String)> {
        auth::utils::create_auth_response(&self, user, jar).await
    }

    pub async fn register_with_invitation(&self, req: RegisterWithInvitationRequest, jar: &CookieJar, ) -> Result<Response, (StatusCode, String)> {
        auth::signup::register_with_invitation(&self, req, jar).await
    }

    pub async fn create_invitation(&self, req: CreateInvitationRequest, inviter_id: i32, ) -> Result<InvitationResponse, (StatusCode, String)> {
        auth::invite::create_invitation(&self, req, inviter_id).await
    }

    // USER METHODS
    pub async fn get_user_by_id(&self, user_id: i32) -> Result<UserResponse, (StatusCode, String)> {
        users::retrieve::get_user_by_id(&self, user_id).await
    }

    pub async fn search_users(&self, query: SearchUsersQuery) -> Result<SearchUsersResponse, (StatusCode, String)> {
        users::retrieve::search_users(&self, query).await
    }

    pub async fn delete_user(&self, user_id: i32, password: &str) -> Result<(), (StatusCode, String)> {
        users::delete::delete_user(&self, user_id, password).await
    }

    pub async fn admin_delete_user(&self, target_user_id: i32) -> Result<(), (StatusCode, String)> {
        users::delete::admin_delete_user(&self, target_user_id).await
    }

    // CHAT METHODS
    pub async fn start_chat_conversation(&self, user_id: i32, namespace_id: Option<i32>) -> Result<Conversation, (StatusCode, String)> {
        chats::chats::start_chat_conversation(&self.db, user_id, namespace_id).await
    }

    pub async fn send_chat_message(
        &self,
        user_id: i32,
        content: String,
        conversation_id: Option<i32>,
        namespace_id: Option<i32>,
    ) -> Result<ChatResponse, (StatusCode, String)> {
        let conversation_id = conversation_id.ok_or_else(|| {
            (StatusCode::BAD_REQUEST, "Conversation ID is required".to_string())
        })?;

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
        .fetch_optional(&self.db)
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
        .fetch_one(&self.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .exists;

        if !has_access {
            return Err((StatusCode::FORBIDDEN, "No access to this namespace".to_string()));
        }

        // Get conversation history for context
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
        .fetch_all(&self.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        // Insert user message
        let _ = sqlx::query_as!(
            ChatResponse,
            r#"
            INSERT INTO message (chat_id, sender_type, content, time_sent)
            VALUES ($1, 'user', $2, $3)
            RETURNING id, content, sender_type, time_sent, chat_id as conversation_id
            "#,
            conversation_id,
            content,
            chrono::Utc::now().naive_utc()
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        // Prepare messages for OpenAI
        let mut chat_messages = messages.iter()
            .map(|m| (m.sender_type.clone(), m.content.clone()))
            .collect::<Vec<_>>();
        chat_messages.push(("user".to_string(), content));

        // Get OpenAI response
        let bot_response = self.openai.create_chat_completion(chat_messages, 1000)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to get bot response".to_string()))?;

        // Insert bot response
        let bot_message = sqlx::query_as!(
            ChatResponse,
            r#"
            INSERT INTO message (chat_id, sender_type, content, time_sent)
            VALUES ($1, 'assistant', $2, $3)
            RETURNING id, content, sender_type, time_sent, chat_id as conversation_id
            "#,
            conversation_id,
            bot_response,
            chrono::Utc::now().naive_utc()
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        Ok(bot_message)
    }

    pub async fn get_chat_history(&self, user_id: i32, conversation_id: i32) -> Result<Conversation, (StatusCode, String)> {
        chats::chats::get_chat_history(&self.db, user_id, conversation_id).await
    }

    pub async fn list_user_conversations(&self, user_id: i32, include_public: bool) -> Result<Vec<ConversationListItem>, (StatusCode, String)> {
        chats::chats::list_user_conversations(&self.db, user_id, include_public).await
    }

    pub async fn delete_conversation(&self, user_id: i32, conversation_id: i32) -> Result<(), (StatusCode, String)> {
        chats::chats::delete_conversation(&self.db, user_id, conversation_id).await
    }

    // NAMESPACE METHODS
    pub async fn create_namespace(&self, user_id: i32, name: String, description: Option<String>, is_public: bool,) -> Result<Namespace, (StatusCode, String)> {
        chats::namespaces::create_namespace(&self.db, user_id, name, description, is_public).await
    }

    pub async fn list_user_namespaces(&self, user_id: i32) -> Result<Vec<Namespace>, (StatusCode, String)> {
        chats::namespaces::list_user_namespaces(&self.db, user_id).await
    }

    pub async fn delete_namespace(&self, user_id: i32, namespace_id: i32) -> Result<String, (StatusCode, String)> {
        chats::namespaces::delete_namespace(&self.db, user_id, namespace_id).await
    }

    pub async fn share_namespace(&self, owner_id: i32, namespace_id: i32, target_user_id: i32, auth_level: i32,) -> Result<(), (StatusCode, String)> {
        chats::namespaces::share_namespace(&self.db, owner_id, namespace_id, target_user_id, auth_level).await
    }

    pub async fn revoke_namespace_access(&self, owner_id: i32, namespace_id: i32, target_user_id: i32,) -> Result<(), (StatusCode, String)> {
        namespaces::revoke_namespace_access(&self.db,owner_id, namespace_id, target_user_id,).await
    }

    // DOCUMENT METHODS
    pub async fn upload_document(&self, user_id: i32, namespace_id: i32, file_name: String,file_content: Vec<u8>,) -> Result<DocumentResponse, (StatusCode, String)> {
        documents::upload_document(&self.db, user_id, namespace_id, file_name, file_content, &self.pinecone, &self.openai,).await
    }

    pub async fn delete_document(&self, user_id: i32, namespace_id: i32, document_id: i32,) -> Result<String, (StatusCode, String)> {
        documents::delete_document(&self.db, user_id, namespace_id, document_id, &self.pinecone,).await
    }

    pub async fn list_documents(&self, user_id: i32, namespace_id: i32,) -> Result<Vec<DocumentListItem>, (StatusCode, String)> {
        documents::list_documents( &self.db, user_id, namespace_id,).await
    }
}
