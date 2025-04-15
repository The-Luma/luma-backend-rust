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

        // Convert documents to NDJSON format
        let mut ndjson = Vec::new();
        for (doc_id, text) in documents {
            let doc = Document {
                id: doc_id,
                text,
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
            Ok(())
        } else {
            let error_message = format!(
                "Upsert request failed with status: {}",
                response.status()
            );
            Err(error_message.into())
        }
    }
}
