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
};
use crate::services::auth;
use crate::services::users;

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
}

impl LumaService {
    pub fn new(db: PgPool, jwt_secret: String) -> Self {
        Self { db, jwt_secret }
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

}
