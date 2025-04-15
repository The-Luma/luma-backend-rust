use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::io::Write;

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchRequest {
    query: Vec<f32>,
    top_k: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Document {
    #[serde(rename = "_id")]
    id: String,
    text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchResponse {
    usage: Usage,
    result: SearchResult,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Usage {
    embed_total_tokens: i32,
    read_units: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchResult {
    hits: Vec<Hit>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Hit {
    #[serde(rename = "_id")]
    id: String,
    #[serde(rename = "_score")]
    score: f32,
    fields: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteRequest {
    ids: Vec<String>,
    namespace: String,
}

#[derive(Clone)]
pub struct PineconeIEService {
    client: Client,
    base_url: String,
    api_key: String,
}

impl PineconeIEService {
    pub fn new(api_key: String, base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
            api_key,
        }
    }

    pub async fn search(
        &self,
        namespace_id: &str,
        query: Vec<f32>,
        top_k: i32,
    ) -> Result<SearchResponse, Box<dyn Error>> {
        let url = format!(
            "{}/records/namespaces/{}/search",
            self.base_url, namespace_id
        );

        let request = SearchRequest {
            query,
            top_k,
        };

        let response = self.client
            .post(&url)
            .header("Api-Key", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        if response.status() == StatusCode::OK {
            let search_response = response.json::<SearchResponse>().await?;
            Ok(search_response)
        } else {
            let error_message = format!(
                "Search request failed with status: {}",
                response.status()
            );
            Err(error_message.into())
        }
    }

    pub async fn upsert(
        &self,
        namespace_id: &str,
        documents: Vec<(String, String)>, // (doc_id, text) pairs
    ) -> Result<(), Box<dyn Error>> {
        let url = format!(
            "{}/records/namespaces/{}/upsert",
            self.base_url, namespace_id
        );

        // Split documents into batches of 96 (Pinecone IE limit)
        const BATCH_SIZE: usize = 96;
        let total_documents = documents.len();
        
        for batch_index in 0..(total_documents + BATCH_SIZE - 1) / BATCH_SIZE {
            let start_idx = batch_index * BATCH_SIZE;
            let end_idx = std::cmp::min(start_idx + BATCH_SIZE, total_documents);
            let batch = &documents[start_idx..end_idx];

            // Convert documents to NDJSON format
            let mut ndjson = Vec::new();
            for (doc_id, text) in batch {
                let doc = Document {
                    id: doc_id.clone(),
                    text: text.clone(),
                };
                let json = serde_json::to_string(&doc)?;
                writeln!(ndjson, "{}", json)?;
            }

            let response = self.client
                .post(&url)
                .header("Api-Key", &self.api_key)
                .header("Content-Type", "application/x-ndjson")
                .body(ndjson)
                .send()
                .await?;

            if response.status() == StatusCode::CREATED {
                // Success
            } else {
                // Get the response body for more detailed error information
                let status = response.status();
                let body = response.text().await?;
                
                let error_message = format!(
                    "Upsert request failed with status: {}. Response body: {}",
                    status, body
                );
                return Err(error_message.into());
            }
        }

        Ok(())
    }

    pub async fn delete_vectors(
        &self,
        namespace_id: &str,
        vector_ids: &[String],
    ) -> Result<(), Box<dyn Error>> {
        let url = format!(
            "{}/vectors/delete",
            self.base_url
        );

        let request = DeleteRequest {
            ids: vector_ids.to_vec(),
            namespace: namespace_id.to_string(),
        };

        let response = self.client
            .post(&url)
            .header("Api-Key", &self.api_key)
            .header("Content-Type", "application/json")
            .header("X-Pinecone-API-Version", "2025-01")
            .json(&request)
            .send()
            .await?;

        if response.status() == StatusCode::OK {
            Ok(())
        } else {
            // Get the response body for more detailed error information
            let status = response.status();
            let body = response.text().await?;
            
            let error_message = format!(
                "Delete vectors request failed with status: {}. Response body: {}",
                status, body
            );
            Err(error_message.into())
        }
    }
}
