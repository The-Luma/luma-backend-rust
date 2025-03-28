use pinecone_sdk::pinecone::{PineconeClient, PineconeClientConfig};
use pinecone_sdk::models::{IndexModel, Metric, Vector, Value, Kind, Metadata, QueryResponse};
use std::env;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct PineconeIndexConfig {
    pub name: String,
    pub dimension: i32,
    pub metric: Metric,
    pub host: String,
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
    pub async fn initialize_index(&mut self) -> Result<IndexModel, Box<dyn std::error::Error>> {
        // Get the expected index name from environment
        let expected_index_name = env::var("BACKEND_PINECONE_INDEX_NAME")
            .expect("BACKEND_PINECONE_INDEX_NAME must be set in environment");

        // List all indexes
        let index_list = self.client.list_indexes().await?;
        
        // Get the indexes vector or return an error if None
        let indexes = index_list.indexes.ok_or("No Pinecone indexes found. Please create an index first.")?;
        
        // Check if there are any indexes available
        if indexes.is_empty() {
            return Err("No Pinecone indexes found. Please create an index first.".into());
        }

        // Find the index with matching name
        let target_index = indexes.iter()
            .find(|index| index.name == expected_index_name)
            .ok_or_else(|| {
                let available_indexes: Vec<String> = indexes.iter()
                    .map(|i| i.name.clone())
                    .collect();
                format!("Pinecone index '{}' not found. Available indexes: {}", 
                    expected_index_name,
                    available_indexes.join(", ")
                )
            })?;

        println!("Found Pinecone index: {}", target_index.name);

        // Get detailed information about the index
        let index_details = self.client.describe_index(&target_index.name).await?;
        
        // Store the index configuration
        self.index_config = Some(PineconeIndexConfig {
            name: index_details.name.clone(),
            dimension: index_details.dimension,
            metric: index_details.metric.clone(),
            host: index_details.host.clone(),
        });
        
        Ok(index_details)
    }

    pub fn get_index_config(&self) -> Option<&PineconeIndexConfig> {
        self.index_config.as_ref()
    }

    pub async fn upsert_document(
        &self,
        namespace: &str,
        document_id: &str,
        vector: Vec<f32>,
        metadata: Option<Metadata>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Get the index name and host from config
        let index_config = self.index_config
            .as_ref()
            .ok_or("Pinecone index not initialized. Call initialize_index first.")?;

        // Verify vector dimension matches index dimension
        if vector.len() != index_config.dimension as usize {
            return Err(format!(
                "Vector dimension mismatch. Expected {}, got {}",
                index_config.dimension,
                vector.len()
            ).into());
        }

        // Get the index client using the host URL
        let mut index = self.client.index(&index_config.host).await?;

        // Create the vector
        let vector = Vector {
            id: document_id.to_string(),
            values: vector,
            sparse_values: None,
            metadata,
        };

        // Upsert the vector to the specified namespace
        index.upsert(&[vector], &namespace.into()).await?;
        
        println!("Successfully upserted document {} to namespace {}", document_id, namespace);
        Ok(())
    }

    pub async fn search(
        &self,
        namespace: &str,
        query_vector: Vec<f32>,
        top_k: u32,
        metadata_filter: Option<Metadata>,
        include_metadata: bool,
    ) -> Result<QueryResponse, Box<dyn std::error::Error>> {
        // Get the index name and host from config
        let index_config = self.index_config
            .as_ref()
            .ok_or("Pinecone index not initialized. Call initialize_index first.")?;

        // Verify vector dimension matches index dimension
        if query_vector.len() != index_config.dimension as usize {
            return Err(format!(
                "Vector dimension mismatch. Expected {}, got {}",
                index_config.dimension,
                query_vector.len()
            ).into());
        }

        // Get the index client using the host URL
        let mut index = self.client.index(&index_config.host).await?;

        // Execute the query using query_by_value
        let response = index.query_by_value(
            query_vector,
            None, // sparse_values
            top_k,
            &namespace.into(),
            metadata_filter,
            Some(include_metadata),
            None, // include_values
        ).await?;
        
        println!("Found {} matches in namespace {}", response.matches.len(), namespace);
        Ok(response)
    }

    // Helper function to create metadata from a string key-value map
    pub fn create_metadata_filter(filter: BTreeMap<String, String>) -> Metadata {
        let mut pinecone_metadata = Metadata::default();
        
        for (key, value) in filter {
            pinecone_metadata.fields.insert(key, Value {
                kind: Some(Kind::StringValue(value)),
            });
        }
        pinecone_metadata
    }
} 