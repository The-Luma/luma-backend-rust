use pinecone_sdk::pinecone::{PineconeClient, PineconeClientConfig};
use std::env;

pub struct PineconeService {
    pub client: PineconeClient,
}

impl PineconeService {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Get API key from environment
        let api_key = env::var("BACKEND_PINECONE_API_KEY")
            .expect("BACKEND_PINECONE_API_KEY must be set in environment");

        // Create Pinecone configuration
        let config = PineconeClientConfig {
            api_key: Some(api_key),
            ..Default::default()
        };

        // Initialize Pinecone client
        let client = config.client().expect("Failed to create Pinecone instance");

        Ok(Self { client })
    }

    pub async fn check_connection(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Try to list indexes to verify connection
        self.client.list_indexes().await?;
        Ok(())
    }
} 