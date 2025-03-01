use dotenv::dotenv;
use std::env;
use pinecone_sdk::pinecone::{PineconeClient, PineconeClientConfig};

let config = PineconeClientConfig {
    api_key: Some("INSERT_API_KEY".to_string()),
    control_plane_host: Some("INSERT_CONTROLLER_HOST".to_string()),
    ..Default::default()
};

let pinecone: PineconeClient = config.client().expect("Failed to create Pinecone instance");