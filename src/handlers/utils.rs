use axum::{
    http::StatusCode, Json,
};
use serde::Serialize;
use serde_json::json;

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

pub fn error_response(status: StatusCode, message: String) -> (StatusCode, Json<serde_json::Value>) {
    let body = json!({
        "error": status.to_string(),
        "message": message
    });
    (status, Json(body))
}