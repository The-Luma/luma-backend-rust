use pinecone_sdk::pinecone::{PineconeClient, PineconeClientConfig};
use pinecone_sdk::models::{IndexModel, Metric};
use std::env;

#[derive(Debug, Clone)]
pub struct PineconeIndexConfig {
    pub name: String,
    pub dimension: i32,
    pub metric: Metric,
}

pub struct PineconeService {
    pub client: PineconeClient,
    pub index_config: Option<PineconeIndexConfig>,
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

        Ok(Self { 
            client,
            index_config: None,
        })
    }

    pub async fn check_connection(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Try to list indexes to verify connection
        self.client.list_indexes().await?;
        Ok(())
    }

    pub async fn get_first_available_index(&mut self) -> Result<IndexModel, Box<dyn std::error::Error>> {
        // List all indexes
        let index_list = self.client.list_indexes().await?;
        
        // Get the indexes vector or return an error if None
        let indexes = index_list.indexes.ok_or("No Pinecone indexes found. Please create an index first.")?;
        
        // Check if there are any indexes available
        if indexes.is_empty() {
            return Err("No Pinecone indexes found. Please create an index first.".into());
        }

        // Get the first index
        let first_index = &indexes[0];
        println!("Found Pinecone index: {}", first_index.name);

        // Get detailed information about the index
        let index_details = self.client.describe_index(&first_index.name).await?;
        
        // Store the index configuration
        self.index_config = Some(PineconeIndexConfig {
            name: index_details.name.clone(),
            dimension: index_details.dimension,
            metric: index_details.metric.clone(),
        });
        
        Ok(index_details)
    }

    pub fn get_index_config(&self) -> Option<&PineconeIndexConfig> {
        self.index_config.as_ref()
    }
} 