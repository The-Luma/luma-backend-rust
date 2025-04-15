use serde::Deserialize;
use std::env;
use dotenvy::dotenv;

/// Configuration struct that holds all environment variables
#[derive(Debug, Deserialize)]
pub struct Config {
    // Database configuration
    pub backend_db_connection: String,
    
    // Authentication
    pub jwt_secret: String,
    
    // Server configuration
    pub frontend_url: String,
    pub backend_port: u16,
    
    // Pinecone configuration
    pub pinecone_api_key: String,
    pub pinecone_index: String,
    
    // OpenAI configuration
    pub openai_api_key: String,
    pub openai_org_id: String,
    // pub openai_completion_model: String,
    pub openai_chat_model: String,
    // pub openai_embedding_model: String,
    // pub openai_embedding_dimensions: u32,
}

impl Config {
    /// Creates a new Config instance from environment variables
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {

        dotenv().ok();

        Ok(Self {
            backend_db_connection: env::var("BACKEND_DB_CONNECTION")?,
            jwt_secret: env::var("BACKEND_JWT_SECRET")?,
            frontend_url: env::var("FRONTEND_URL")?,
            backend_port: env::var("BACKEND_PORT").unwrap_or_else(|_| "3000".to_string()).parse()?,
            pinecone_api_key: env::var("BACKEND_PINECONE_API_KEY")?,
            pinecone_index: env::var("BACKEND_PINECONE_INDEX")?,
            openai_api_key: env::var("BACKEND_OPENAI_API_KEY")?,
            openai_org_id: env::var("BACKEND_OPENAI_ORG_ID")?,
            openai_chat_model: env::var("BACKEND_OPENAI_CHAT_MODEL")?,
            // openai_completion_model: env::var("BACKEND_OPENAI_COMPLETION_MODEL")?,
            // openai_embedding_model: env::var("BACKEND_OPENAI_EMBEDDING_MODEL")?,
            // openai_embedding_dimensions: env::var("BACKEND_OPENAI_EMBEDDING_DIMENSIONS")?.parse()?,
        })
    }
} 