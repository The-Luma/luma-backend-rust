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
    
    // Pinecone configuration
    pub pinecone_api_key: String,
    pub pinecone_url: String,
    
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
            pinecone_api_key: env::var("BACKEND_PINECONE_API_KEY")?,
            pinecone_url: env::var("BACKEND_PINECONE_URL")?,
            openai_api_key: env::var("BACKEND_OPENAI_API_KEY")?,
            openai_org_id: env::var("BACKEND_OPENAI_ORG_ID")?,
            openai_chat_model: env::var("BACKEND_OPENAI_CHAT_MODEL")?,
            // openai_completion_model: env::var("BACKEND_OPENAI_COMPLETION_MODEL")?,
            // openai_embedding_model: env::var("BACKEND_OPENAI_EMBEDDING_MODEL")?,
            // openai_embedding_dimensions: env::var("BACKEND_OPENAI_EMBEDDING_DIMENSIONS")?.parse()?,
        })
    }
} 