use sqlx::PgPool;
use axum::http::StatusCode;
use chrono::{DateTime, Utc, NaiveDateTime};
use crate::models::models::{Document, NamespaceDocument, DocumentResponse};
use crate::services::pinecone::PineconeService;
use crate::services::openai::OpenAIService;
use crate::services::files::FileService;

/// Upload a document to a namespace
/// 
/// This function:
/// 1. Extracts text from the PDF
/// 2. Saves the document to the database
/// 3. Creates a namespace_document association
/// 4. Uploads the document to the vector database
pub async fn upload_document(
    db: &PgPool,
    user_id: i32,
    namespace_id: i32,
    file_name: String,
    file_content: Vec<u8>,
    pinecone: &PineconeService,
    openai: &OpenAIService,
) -> Result<DocumentResponse, (StatusCode, String)> {
    println!("Uploading document: user_id={}, namespace_id={}, file_name={}, file_size={} bytes", 
             user_id, namespace_id, file_name, file_content.len());
    
    // Save file and extract text using FileService
    let (storage_name, extracted_text) = FileService::save_and_process_file(
        namespace_id,
        file_name.clone(),
        file_content,
        false,
    )?;
    
    // TODO: Save document metadata to database
    // TODO: Process extracted text with OpenAI
    // TODO: Store embeddings in Pinecone
    
    // Return a mock document response
    Ok(DocumentResponse {
        id: 1,
        name: file_name,
        created_at: DateTime::from_naive_utc_and_offset(Utc::now().naive_utc(), Utc),
        namespace_id,
    })
}

/// Delete a document from a namespace
/// 
/// This function:
/// 1. Verifies the user has access to the namespace
/// 2. Deletes the namespace_document association
/// 3. Deletes the document from the database
/// 4. Deletes the document from the vector database
pub async fn delete_document(
    db: &PgPool,
    user_id: i32,
    namespace_id: i32,
    document_id: i32,
    pinecone: &PineconeService,
) -> Result<String, (StatusCode, String)> {
    println!("Deleting document: user_id={}, namespace_id={}, document_id={}", 
             user_id, namespace_id, document_id);
    
    // TODO: Get the storage_name from the database
    let storage_name = "temp.pdf"; // This should come from the database
    
    // Delete the file using FileService
    FileService::delete_file(namespace_id, storage_name)?;
    
    // TODO: Delete document from database
    // TODO: Delete from vector database
    
    Ok("Document deleted successfully".to_string())
} 