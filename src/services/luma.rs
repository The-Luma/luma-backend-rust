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
    ChatResponse, Conversation, ConversationListItem, Namespace,
    DocumentResponse, DocumentListItem, NamespaceAccessResponse,
    ChangeUsernameRequest, ChangePasswordRequest,
};
use crate::services::auth;
use crate::services::users;
use crate::services::chats;
use crate::services::chats::namespaces;
use crate::services::documents::documents;
use crate::services::openai::OpenAIService;
use crate::services::pinecone_ie::PineconeIEService;

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
    pinecone_ie: PineconeIEService,
}

impl LumaService {
    pub fn new(
        db: PgPool,
        jwt_secret: String,
        openai: OpenAIService,
        pinecone_ie: PineconeIEService,
    ) -> Self {
        Self {
            db,
            jwt_secret,
            openai,
            pinecone_ie,
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

    pub async fn change_username(&self, user_id: i32, req: ChangeUsernameRequest) -> Result<(), (StatusCode, String)> {
        users::update::change_username(self.db(), user_id, req).await
    }

    pub async fn change_password(&self, user_id: i32, req: ChangePasswordRequest) -> Result<(), (StatusCode, String)> {
        users::update::change_password(self.db(), user_id, req).await
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
    ) -> Result<ChatResponse, (StatusCode, String)> {
        chats::chats::send_chat_message(
            &self.db,
            user_id,
            content,
            conversation_id,
            &self.openai,
            &self.pinecone_ie
        ).await
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

    pub async fn get_namespace_access_list(&self, user_id: i32, namespace_id: i32) -> Result<Vec<NamespaceAccessResponse>, (StatusCode, String)> {
        namespaces::get_namespace_access_list(&self.db, user_id, namespace_id).await
    }

    pub async fn get_user_namespace_access_level(
        &self,
        db: &PgPool,
        user_id: i32,
        namespace_id: i32,
    ) -> Result<i32, (StatusCode, String)> {
        namespaces::get_user_namespace_access_level(db, user_id, namespace_id).await
    }

    // DOCUMENT METHODS
    pub async fn upload_document(&self, user_id: i32, namespace_id: i32, file_name: String,file_content: Vec<u8>,) -> Result<DocumentResponse, (StatusCode, String)> {
        documents::upload_document(&self.db, user_id, namespace_id, file_name, file_content, &self.pinecone_ie).await
    }

    pub async fn delete_document(&self, user_id: i32, namespace_id: i32, document_id: i32,) -> Result<String, (StatusCode, String)> {
        documents::delete_document(&self.db, user_id, namespace_id, document_id, &self.pinecone_ie,).await
    }

    pub async fn list_documents(&self, user_id: i32, namespace_id: i32,) -> Result<Vec<DocumentListItem>, (StatusCode, String)> {
        documents::list_documents( &self.db, user_id, namespace_id,).await
    }

    pub async fn download_document(&self, user_id: i32, namespace_id: i32, document_id: i32,) -> Result<(Vec<u8>, String, String), (StatusCode, String)> {
        documents::download_document(&self.db, user_id, namespace_id, document_id).await
    }
}
