use std::path::Path;
use std::error::Error;
use std::collections::HashMap;
use reqwest::{Client, multipart};
use infer;
use serde_json;

fn get_metadata(file_path: &Path) -> Result<HashMap<String, String>, Box<dyn Error>> {
    let mut metadata = HashMap::new();
    
    // Get file extension
    if let Some(ext) = file_path.extension() {
        metadata.insert("extension".to_string(), ext.to_string_lossy().to_string());
    }
    
    // Get file size
    if let Ok(size) = std::fs::metadata(file_path).map(|m| m.len()) {
        metadata.insert("size".to_string(), size.to_string());
    }
    
    // Get file type
    if let Ok(file_type) = infer::get_from_path(file_path) {
        if let Some(mime_type) = file_type.map(|t| t.mime_type()) {
            metadata.insert("mime_type".to_string(), mime_type.to_string());
        }
    }
    
    Ok(metadata)
}

pub async fn upload(file_path: &Path, client: &Client) -> Result<(), Box<dyn Error>> {
    let metadata = get_metadata(file_path)?;
    let file_name = file_path.file_name()
        .ok_or("Invalid file name")?
        .to_string_lossy()
        .to_string();
    
    let mut form = multipart::Form::new()
        .text("metadata", serde_json::to_string(&metadata)?)
        .text("filename", file_name);
    
    let file = std::fs::File::open(file_path)?;
    form = form.file("file", file_path)?;
    
    let response = client
        .post("http://localhost:3000/upload")
        .multipart(form)
        .send()
        .await?;
    
    if !response.status().is_success() {
        return Err(format!("Upload failed: {}", response.status()).into());
    }
    
    Ok(())
} 