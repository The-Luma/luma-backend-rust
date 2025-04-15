use crate::models::models::ChunkInfo;
use sqlx::PgPool;
use axum::http::StatusCode;
use chrono::{DateTime, Utc, NaiveDateTime};
use crate::models::models::{Document, NamespaceDocument, DocumentResponse, DocumentListItem};
use crate::services::pinecone_ie::PineconeIEService;
use crate::services::openai::OpenAIService;
use crate::services::files::FileService;
use uuid::Uuid;
use std::collections::BTreeMap;
use pinecone_sdk::models::{Metadata, Value, Kind};
use serde_json;
use tokio::task;
use futures::future::join_all;
use std::sync::Arc;

/// Upload a document to a namespace
/// 
/// This function:
/// 1. Verifies user has access level >= 2 or is the owner
/// 2. Extracts text from the PDF
/// 3. Saves the document to the database
/// 4. Creates a namespace_document association
/// 5. Uploads the document to the vector database
pub async fn upload_document(
    db: &PgPool,
    user_id: i32,
    namespace_id: i32,
    file_name: String,
    file_content: Vec<u8>,
    pinecone: &PineconeIEService,
    openai: &OpenAIService,
) -> Result<DocumentResponse, (StatusCode, String)> {
    // Verify namespace access
    let has_access = sqlx::query!(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM namespace n
            LEFT JOIN namespace_auth na ON n.id = na.namespace_id AND na.user_id = $1
            WHERE n.id = $2
            AND (
                n.user_id = $1  -- User is the owner
                OR na.auth_level >= 2  -- User has access level >= 2
            )
        ) as "exists!"
        "#,
        user_id,
        namespace_id
    )
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .exists;

    if !has_access {
        return Err((StatusCode::FORBIDDEN, "You do not have permission to upload documents to this namespace".to_string()));
    }
    
    // Save file and extract text using FileService
    let (storage_name, extracted_text) = FileService::save_and_process_file(
        namespace_id,
        file_name.clone(),
        file_content.clone(),
        false,
    )?;
    
    // Split text into chunks of 1000 characters
    let chunks = FileService::split_text_into_chunks(&extracted_text, 1000);
    let chunks_len = chunks.len();
    
    // Check if any text was extracted
    if chunks_len == 0 {
        return Err((StatusCode::BAD_REQUEST, "No text could be extracted from the document. Please ensure the document contains readable text.".to_string()));
    }
    
    // Generate a unique document ID for the parent document
    let parent_document_id = Uuid::new_v4().to_string();
    
    // Start a database transaction for atomic operations
    let mut transaction = db.begin().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Store parent document metadata in database
    let parent_document = sqlx::query!(
        r#"
        INSERT INTO document (user_id, title, file_path, file_metadata, type, is_public, uploaded_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, title, file_path, file_metadata, type, is_public, uploaded_at
        "#,
        user_id,
        file_name,
        storage_name,
        serde_json::json!({
            "size": file_content.len(),
            "chunks": chunks_len,
            "original_filename": file_name,
            "storage_path": storage_name,
            "parent_document_id": parent_document_id
        }),
        "pdf", // TODO: Determine file type from extension
        false,  // Default to private
        Utc::now().naive_utc()
    )
    .fetch_one(&mut *transaction)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Create a vector to store chunk document IDs
    let mut chunk_document_ids = Vec::with_capacity(chunks_len);
    let mut documents_for_pinecone = Vec::with_capacity(chunks_len);
    
    // Create a document record for each chunk
    for i in 0..chunks_len {
        let chunk_id = format!("{}-{}", parent_document_id, i);
        let chunk = chunks[i].clone();
        
        // Insert chunk document
        let chunk_document = sqlx::query!(
            r#"
            INSERT INTO document (user_id, title, file_path, file_metadata, type, is_public, uploaded_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
            "#,
            user_id,
            format!("{} (Chunk {})", file_name, i + 1),
            format!("{}-chunk-{}", storage_name, i),
            serde_json::json!({
                "parent_document_id": parent_document_id,
                "chunk_index": i,
                "total_chunks": chunks_len,
                "original_filename": file_name
            }),
            "chunk",
            false,
            Utc::now().naive_utc()
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        
        // Store the chunk document ID
        chunk_document_ids.push(chunk_document.id);
        
        // Add to Pinecone documents
        documents_for_pinecone.push((chunk_id, chunk));
    }

    // Upload to Pinecone IE
    match pinecone.upsert(&namespace_id.to_string(), documents_for_pinecone).await {
        Ok(_) => (),
        Err(e) => {
            println!("Pinecone IE upsert error details: {:?}", e);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, 
                format!("Failed to store in vector database: {}", e)));
        }
    }

    // Create namespace_document association for the parent document
    sqlx::query!(
        r#"
        INSERT INTO namespace_doc (namespace_id, doc_id, vec_id)
        VALUES ($1, $2, $3)
        "#,
        namespace_id,
        parent_document.id,
        &chunk_document_ids.iter().map(|id| id.to_string()).collect::<Vec<String>>()
    )
    .execute(&mut *transaction)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Create namespace_document associations for each chunk
    for chunk_id in &chunk_document_ids {
        sqlx::query!(
            r#"
            INSERT INTO namespace_doc (namespace_id, doc_id, vec_id)
            VALUES ($1, $2, $3)
            "#,
            namespace_id,
            chunk_id,
            &[format!("{}-{}", parent_document_id, chunk_id)]
        )
        .execute(&mut *transaction)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    
    // Commit the transaction
    transaction.commit().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Return the document response with comprehensive information
    Ok(DocumentResponse {
        id: parent_document.id,
        name: parent_document.title,
        created_at: DateTime::from_naive_utc_and_offset(parent_document.uploaded_at, Utc),
        namespace_id,
        file_metadata: serde_json::json!({
            "size_bytes": file_content.len(),
            "total_chunks": chunks_len,
            "storage_path": storage_name,
            "original_filename": file_name
        }),
        is_public: parent_document.is_public,
        type_: parent_document.r#type,
        chunks: ChunkInfo {
            count: chunks_len,
            vector_ids: chunk_document_ids.iter().map(|id| id.to_string()).collect(),
            embedding_dimension: 0, // No embeddings are created with the new service
        },
        text_preview: if chunks_len == 0 {
            "No text extracted".to_string()
        } else {
            chunks[0][..chunks[0].len().min(200)].to_string()
        }
    })
}

/// Delete a document from a namespace
/// 
/// This function:
/// 1. Verifies user has access to the namespace
/// 2. Retrieves the document metadata from the database
/// 3. Deletes the document from the file system
/// 4. Deletes the document from the vector database
/// 5. Deletes the document from the database
pub async fn delete_document(
    db: &PgPool,
    user_id: i32,
    namespace_id: i32,
    document_id: i32,
    pinecone: &PineconeIEService,
) -> Result<String, (StatusCode, String)> {
    // Verify namespace access
    let has_access = sqlx::query!(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM namespace n
            LEFT JOIN namespace_auth na ON n.id = na.namespace_id AND na.user_id = $1
            WHERE n.id = $2
            AND (
                n.user_id = $1  -- User is the owner
                OR na.auth_level >= 2  -- User has access level >= 2
            )
        ) as "exists!"
        "#,
        user_id,
        namespace_id
    )
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .exists;

    if !has_access {
        return Err((StatusCode::FORBIDDEN, "You do not have permission to delete documents from this namespace".to_string()));
    }

    // Get document metadata and vector IDs
    let document_info = sqlx::query!(
        r#"
        SELECT d.file_path, d.file_metadata, nd.vec_id
        FROM document d
        JOIN namespace_doc nd ON d.id = nd.doc_id
        WHERE nd.namespace_id = $1 AND d.id = $2
        "#,
        namespace_id,
        document_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Document not found".to_string()))?;

    // Extract parent document ID from metadata
    let parent_document_id = document_info.file_metadata
        .get("parent_document_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Delete the file using FileService
    FileService::delete_file(namespace_id, &document_info.file_path)?;

    // Delete vectors from Pinecone
    let namespace_str = namespace_id.to_string();
    //TODO
    // pinecone.delete_vectors(&namespace_str, &document_info.vec_id)
    //     .await
    //     .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR,
    //                  format!("Failed to delete vectors from Pinecone: {}", e)))?;

    // Start a transaction for atomic operations
    let mut transaction = db.begin().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // If this is a parent document, delete all associated chunk documents
    if parent_document_id.is_empty() {
        // Find all chunk documents associated with this parent
        let chunk_documents = sqlx::query!(
            r#"
            SELECT d.id, d.file_path
            FROM document d
            WHERE d.file_metadata->>'parent_document_id' = $1
            "#,
            document_id.to_string()
        )
        .fetch_all(&mut *transaction)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        // Delete each chunk document
        for chunk in chunk_documents {
            // Delete the chunk file
            FileService::delete_file(namespace_id, &chunk.file_path)?;

            // Delete namespace_doc association for the chunk
            sqlx::query!(
                r#"
                DELETE FROM namespace_doc
                WHERE namespace_id = $1 AND doc_id = $2
                "#,
                namespace_id,
                chunk.id
            )
            .execute(&mut *transaction)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            // Delete the chunk document
            sqlx::query!(
                r#"
                DELETE FROM document
                WHERE id = $1
                "#,
                chunk.id
            )
            .execute(&mut *transaction)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
    }

    // Delete namespace_doc association for the main document
    sqlx::query!(
        r#"
        DELETE FROM namespace_doc
        WHERE namespace_id = $1 AND doc_id = $2
        "#,
        namespace_id,
        document_id
    )
    .execute(&mut *transaction)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Delete the document record
    sqlx::query!(
        r#"
        DELETE FROM document
        WHERE id = $1
        "#,
        document_id
    )
    .execute(&mut *transaction)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Commit the transaction
    transaction.commit().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok("Document deleted successfully".to_string())
}

/// List documents in a namespace
/// 
/// This function:
/// 1. Verifies user has access to the namespace
/// 2. Retrieves all documents associated with the namespace
/// 3. Returns a list of document metadata
pub async fn list_documents(
    db: &PgPool,
    user_id: i32,
    namespace_id: i32,
) -> Result<Vec<DocumentListItem>, (StatusCode, String)> {
    // Verify namespace access
    let has_access = sqlx::query!(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM namespace n
            LEFT JOIN namespace_auth na ON n.id = na.namespace_id AND na.user_id = $1
            WHERE n.id = $2
            AND (
                n.user_id = $1  -- User is the owner
                OR na.auth_level >= 1  -- User has at least read access
                OR n.is_public = true  -- Namespace is public
            )
        ) as "exists!"
        "#,
        user_id,
        namespace_id
    )
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .exists;

    if !has_access {
        return Err((StatusCode::FORBIDDEN, "You do not have permission to view documents in this namespace".to_string()));
    }
    
    // Retrieve documents associated with the namespace
    let documents = sqlx::query!(
        r#"
        SELECT d.id, d.title, d.file_metadata, d.type, d.is_public, d.uploaded_at, d.user_id
        FROM document d
        JOIN namespace_doc nd ON d.id = nd.doc_id
        WHERE nd.namespace_id = $1
        ORDER BY d.uploaded_at DESC
        "#,
        namespace_id
    )
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Convert to DocumentListItem
    let document_list = documents
        .into_iter()
        .map(|d| DocumentListItem {
            id: d.id,
            name: d.title,
            created_at: DateTime::from_naive_utc_and_offset(d.uploaded_at, Utc),
            namespace_id,
            file_metadata: d.file_metadata,
            is_public: d.is_public,
            type_: d.r#type,
            user_id: d.user_id,
        })
        .collect();
    
    Ok(document_list)
}

/// Download a document from a namespace
/// 
/// This function:
/// 1. Verifies user has access to the namespace
/// 2. Retrieves the document metadata from the database
/// 3. Returns the file content and metadata
pub async fn download_document(
    db: &PgPool,
    user_id: i32,
    namespace_id: i32,
    document_id: i32,
) -> Result<(Vec<u8>, String, String), (StatusCode, String)> {
    // Verify namespace access
    let has_access = sqlx::query!(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM namespace n
            LEFT JOIN namespace_auth na ON n.id = na.namespace_id AND na.user_id = $1
            WHERE n.id = $2
            AND (
                n.user_id = $1  -- User is the owner
                OR na.auth_level >= 1  -- User has at least read access
                OR n.is_public = true  -- Namespace is public
            )
        ) as "exists!"
        "#,
        user_id,
        namespace_id
    )
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .exists;

    if !has_access {
        return Err((StatusCode::FORBIDDEN, "You do not have permission to download documents from this namespace".to_string()));
    }

    // Get document metadata
    let document = sqlx::query!(
        r#"
        SELECT d.file_path, d.title
        FROM document d
        JOIN namespace_doc nd ON d.id = nd.doc_id
        WHERE nd.namespace_id = $1 AND d.id = $2
        "#,
        namespace_id,
        document_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Document not found".to_string()))?;

    // Read file content
    let file_path = std::path::PathBuf::from("uploads")
        .join(namespace_id.to_string())
        .join(&document.file_path);

    let file_content = tokio::fs::read(&file_path)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, 
                     format!("Failed to read file: {}", e)))?;

    Ok((file_content, document.title, document.file_path))
} 