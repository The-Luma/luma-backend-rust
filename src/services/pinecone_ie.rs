use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::io::Write;

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchRequest {
    #[serde(rename = "query")]
    query: QueryInput,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QueryInput {
    #[serde(rename = "inputs")]
    inputs: QueryInputs,
    #[serde(rename = "top_k")]
    top_k: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QueryInputs {
    #[serde(rename = "text")]
    text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Document {
    #[serde(rename = "_id")]
    id: String,
    text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchResponse {
    pub usage: Usage,
    pub result: SearchResult,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Usage {
    #[serde(rename = "embed_total_tokens")]
    pub embed_total_tokens: i32,
    #[serde(rename = "read_units")]
    pub read_units: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchResult {
    pub hits: Vec<Hit>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Hit {
    #[serde(rename = "_id")]
    pub id: String,
    #[serde(rename = "_score")]
    pub score: f32,
    pub fields: HitFields,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HitFields {
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteRequest {
    ids: Vec<String>,
    namespace: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IndexInfo {
    pub name: String,
    pub host: String,
    pub status: IndexStatus,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IndexStatus {
    pub ready: bool,
    pub state: String,
}

#[derive(Clone)]
pub struct PineconeIEService {
    client: Client,
    base_url: String,
    api_key: String,
    index_name: String,
}

impl PineconeIEService {
    pub fn new(api_key: String, index_name: String) -> Self {
        Self {
            client: Client::new(),
            base_url: String::new(), // Will be set when fetching index info
            api_key,
            index_name,
        }
    }

    pub async fn initialize(&mut self) -> Result<(), Box<dyn Error>> {
        // Fetch index info to get the host URL
        let url = format!(
            "https://api.pinecone.io/indexes/{}",
            self.index_name
        );
        
        let response = self.client
            .get(&url)
            .header("Api-Key", &self.api_key)
            .header("X-Pinecone-API-Version", "2025-01")
            .send()
            .await?;
        
        if response.status() != StatusCode::OK {
            return Err(format!(
                "Failed to fetch index info: {}",
                response.text().await?
            ).into());
        }
        
        let index_info: IndexInfo = response.json().await?;
        
        // Set the base URL using the host from the index info
        self.base_url = format!("https://{}", index_info.host);
        
        println!("Pinecone index host: {}", self.base_url);
        
        Ok(())
    }

    pub async fn search(
        &self,
        namespace_id: &str,
        top_k: i32,
        query_text: Option<String>,
    ) -> Result<SearchResponse, Box<dyn Error>> {
        // Ensure namespace_id is a valid string
        let namespace_id = namespace_id.trim();
        
        let url = format!(
            "{}/records/namespaces/{}/search",
            self.base_url, namespace_id
        );

        // Use the query text if provided, otherwise use a placeholder
        let query_text = query_text.unwrap_or_else(|| "Search query".to_string());
        //println!("Pinecone IE search: namespace='{}', query='{}', top_k={}",
                 //namespace_id, query_text, top_k);

        // Create the request with the expected format
        let request = SearchRequest {
            query: QueryInput {
                inputs: QueryInputs {
                    text: query_text,
                },
                top_k,
            },
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
            //println!("Pinecone IE search successful, found {} hits", search_response.result.hits.len());
            Ok(search_response)
        } else {
            // Get the response body for more detailed error information
            let status = response.status();
            let body = response.text().await?;
            
            println!("Pinecone IE search error: status={}, body={}", status, body);
            
            let error_message = format!(
                "Search request failed with status: {}. Response body: {}",
                status, body
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
