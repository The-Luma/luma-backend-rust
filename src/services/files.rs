use std::fs;
use std::path::PathBuf;
use uuid::Uuid;
use axum::http::StatusCode;
use pdf_extract::extract_text;

const UPLOAD_DIR: &str = "uploads";

pub struct FileService;

impl FileService {
    /// Save a file to disk and extract text if it's a PDF
    /// 
    /// Returns a tuple of (storage_name, extracted_text)
    pub fn save_and_process_file(
        namespace_id: i32,
        file_name: String,
        file_content: Vec<u8>,
        print: bool,
    ) -> Result<(String, String), (StatusCode, String)> {
        // Create uploads directory structure if it doesn't exist
        let namespace_dir = PathBuf::from(UPLOAD_DIR)
            .join(namespace_id.to_string());
        
        fs::create_dir_all(&namespace_dir)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, 
                         format!("Failed to create upload directory: {}", e)))?;
        
        // Generate unique filename to avoid collisions
        let file_uuid = Uuid::new_v4();
        let file_extension = file_name.split('.').last()
            .unwrap_or("pdf");
        let storage_name = format!("{}.{}", file_uuid, file_extension);
        let file_path = namespace_dir.join(&storage_name);
        
        // Save the file
        fs::write(&file_path, &file_content)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, 
                         format!("Failed to save file: {}", e)))?;
        
        // Extract text from PDF
        let extracted_text = match extract_text(&file_path) {
            Ok(text) => {
                if print {
                    println!("Successfully extracted text from PDF:");
                    println!("---BEGIN EXTRACTED TEXT---");
                    println!("{}", text);
                    println!("---END EXTRACTED TEXT---");
                }
                text
            },
            Err(e) => {
                println!("Failed to extract text from PDF: {}", e);
                // Don't return error here - we might want to support other file types later
                String::new()
            }
        };
        
        Ok((storage_name, extracted_text))
    }

    /// Delete a file from disk
    pub fn delete_file(namespace_id: i32, storage_name: &str) -> Result<(), (StatusCode, String)> {
        let file_path = PathBuf::from(UPLOAD_DIR)
            .join(namespace_id.to_string())
            .join(storage_name);
            
        fs::remove_file(file_path)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, 
                         format!("Failed to delete file: {}", e)))?;
                         
        Ok(())
    }
    
    /// Split text into chunks of specified size
    /// 
    /// This function splits text by words to avoid cutting words in half.
    /// Each chunk will be as close to the specified size as possible without exceeding it.
    pub fn split_text_into_chunks(text: &str, chunk_size: usize) -> Vec<String> {
        let mut chunks = Vec::new();
        let mut current_chunk = String::new();
        
        // Split by words to avoid cutting words in half
        let words: Vec<&str> = text.split_whitespace().collect();
        
        for word in words {
            // If adding this word would exceed the chunk size, start a new chunk
            if current_chunk.len() + word.len() + 1 > chunk_size && !current_chunk.is_empty() {
                chunks.push(current_chunk);
                current_chunk = String::new();
            }
            
            // Add the word to the current chunk
            if !current_chunk.is_empty() {
                current_chunk.push(' ');
            }
            current_chunk.push_str(word);
        }
        
        // Add the last chunk if it's not empty
        if !current_chunk.is_empty() {
            chunks.push(current_chunk);
        }
        
        chunks
    }
} 