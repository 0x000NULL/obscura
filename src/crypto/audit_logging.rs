use crate::crypto::audit::{AuditEntry, AuditLevel, CryptoOperationType};
use crate::crypto::{CryptoError, CryptoResult};
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

/// The format of audit log output
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogFormat {
    /// Plain text format
    Text,
    /// JSON format
    Json,
    /// Comma-separated values
    Csv,
}

/// The destination for audit logs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogDestination {
    /// Log to a file
    File(PathBuf),
    /// Log to the system logger
    Syslog,
    /// Log to a remote server
    RemoteServer {
        /// The URL of the server
        url: String,
        /// Authentication token (if required)
        auth_token: Option<String>,
    },
    /// Custom log destination with callback
    Custom(String),
}

/// Configuration for a log destination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogDestinationConfig {
    /// The destination for logs
    pub destination: LogDestination,
    /// The format of the logs
    pub format: LogFormat,
    /// The minimum log level to output
    pub min_level: AuditLevel,
    /// Whether to buffer logs before writing
    pub buffered: bool,
    /// Maximum buffer size before flushing (if buffered)
    pub buffer_size: usize,
    /// Whether to include stack traces for errors
    pub include_stack_traces: bool,
}

/// Configuration for the structured logging system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredLoggingConfig {
    /// Whether the logging system is enabled
    pub enabled: bool,
    /// The log destinations
    pub destinations: Vec<LogDestinationConfig>,
    /// Whether to include the caller context (function/method name)
    pub include_caller_context: bool,
    /// Whether to redact sensitive fields
    pub redact_sensitive_data: bool,
    /// Fields to always redact
    pub redacted_fields: Vec<String>,
    /// Whether to format duration as human-readable
    pub human_readable_duration: bool,
    /// Whether to include host information
    pub include_host_info: bool,
}

impl Default for StructuredLoggingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            destinations: vec![
                LogDestinationConfig {
                    destination: LogDestination::File(PathBuf::from("crypto_audit.log")),
                    format: LogFormat::Text,
                    min_level: AuditLevel::Info,
                    buffered: true,
                    buffer_size: 8192,
                    include_stack_traces: true,
                },
            ],
            include_caller_context: true,
            redact_sensitive_data: true,
            redacted_fields: vec![
                "private_key".to_string(),
                "password".to_string(),
                "secret".to_string(),
                "token".to_string(),
            ],
            human_readable_duration: true,
            include_host_info: false,
        }
    }
}

/// Buffer for audit log entries
struct LogBuffer {
    /// The buffered entries
    entries: Vec<String>,
    /// The current size of the buffer
    size: usize,
    /// The maximum size of the buffer
    max_size: usize,
}

impl LogBuffer {
    /// Create a new log buffer
    fn new(max_size: usize) -> Self {
        Self {
            entries: Vec::new(),
            size: 0,
            max_size,
        }
    }

    /// Add an entry to the buffer
    fn add(&mut self, entry: String) -> bool {
        self.entries.push(entry.clone());
        self.size += entry.len();
        self.size >= self.max_size
    }

    /// Flush the buffer and return the entries
    fn flush(&mut self) -> Vec<String> {
        let entries = std::mem::take(&mut self.entries);
        self.size = 0;
        entries
    }

    /// Check if the buffer is empty
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A writer for audit logs
struct LogWriter {
    /// The configuration for this writer
    config: LogDestinationConfig,
    /// The file handle (if writing to a file)
    file: Option<File>,
    /// Buffer for log entries (if buffered)
    buffer: Option<LogBuffer>,
}

impl LogWriter {
    /// Create a new log writer
    fn new(config: LogDestinationConfig) -> CryptoResult<Self> {
        let file = match &config.destination {
            LogDestination::File(path) => {
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| CryptoError::IoError(e))?;
                Some(file)
            }
            _ => None,
        };

        let buffer = if config.buffered {
            Some(LogBuffer::new(config.buffer_size))
        } else {
            None
        };

        Ok(Self {
            config,
            file,
            buffer,
        })
    }

    /// Write an audit entry to the log
    fn write(&mut self, entry: &AuditEntry) -> CryptoResult<()> {
        // Skip entries below the minimum level
        if entry.level < self.config.min_level {
            return Ok(());
        }

        // Format the entry
        let formatted = match self.config.format {
            LogFormat::Text => entry.format_log_entry(),
            LogFormat::Json => serde_json::to_string(entry)
                .map_err(|e| CryptoError::SerializationError(e.to_string()))?,
            LogFormat::Csv => format_as_csv(entry),
        };

        // Write or buffer the entry
        if let Some(buffer) = &mut self.buffer {
            let should_flush = buffer.add(formatted);
            if should_flush {
                self.flush_buffer()?;
            }
        } else {
            self.write_entry(&formatted)?;
        }

        Ok(())
    }

    /// Write a formatted entry directly
    fn write_entry(&mut self, formatted: &str) -> CryptoResult<()> {
        match &self.config.destination {
            LogDestination::File(_) => {
                if let Some(file) = &mut self.file {
                    writeln!(file, "{}", formatted)
                        .map_err(|e| CryptoError::IoError(e))?;
                }
            }
            LogDestination::Syslog => {
                // In a real implementation, we would use a syslog crate
                // For now, we'll just log to the standard logger
                info!("Audit log: {}", formatted);
            }
            LogDestination::RemoteServer { url, auth_token } => {
                // In a real implementation, we would send HTTP requests
                // For now, we'll just log that we would send it
                debug!(
                    "Would send audit log to {} with auth token {}: {}",
                    url,
                    auth_token.as_ref().map(|_| "provided").unwrap_or("none"),
                    formatted
                );
            }
            LogDestination::Custom(name) => {
                // In a real implementation, we would call a registered callback
                debug!("Would send audit log to custom destination {}: {}", name, formatted);
            }
        }

        Ok(())
    }

    /// Flush the buffer
    fn flush_buffer(&mut self) -> CryptoResult<()> {
        if let Some(buffer) = &mut self.buffer {
            if buffer.is_empty() {
                return Ok(());
            }

            let entries = buffer.flush();
            match &self.config.destination {
                LogDestination::File(_) => {
                    if let Some(file) = &mut self.file {
                        for entry in &entries {
                            writeln!(file, "{}", entry)
                                .map_err(|e| CryptoError::IoError(e))?;
                        }
                    }
                }
                LogDestination::Syslog => {
                    // For demonstration, just log the count
                    info!("Flushed {} audit log entries to syslog", entries.len());
                }
                LogDestination::RemoteServer { url, .. } => {
                    // For demonstration, just log the count
                    debug!(
                        "Would send {} audit log entries to {}",
                        entries.len(),
                        url
                    );
                }
                LogDestination::Custom(name) => {
                    // For demonstration, just log the count
                    debug!(
                        "Would send {} audit log entries to custom destination {}",
                        entries.len(),
                        name
                    );
                }
            }
        }

        Ok(())
    }

    /// Force a flush of the buffer
    fn force_flush(&mut self) -> CryptoResult<()> {
        self.flush_buffer()?;
        if let Some(file) = &mut self.file {
            file.flush().map_err(|e| CryptoError::IoError(e))?;
        }
        Ok(())
    }
}

/// Format an audit entry as CSV
fn format_as_csv(entry: &AuditEntry) -> String {
    format!(
        "{},{},{},{},{},\"{}\",\"{}\",{},{},{}",
        entry.id,
        entry.timestamp.to_rfc3339(),
        entry.operation_type,
        entry.status,
        entry.level,
        entry.module.replace("\"", "\"\""), // Escape quotes in CSV
        entry.description.replace("\"", "\"\""), // Escape quotes in CSV
        entry.algorithm.as_ref().unwrap_or(&"".to_string()),
        entry.duration_ms.unwrap_or(0),
        entry.error.as_ref().unwrap_or(&"".to_string()).replace("\"", "\"\"") // Escape quotes in CSV
    )
}

/// The structured logging system
pub struct StructuredLogger {
    /// Configuration for the logger
    config: RwLock<StructuredLoggingConfig>,
    /// Writers for each destination
    writers: Mutex<Vec<LogWriter>>,
    /// Host information
    host_info: Option<serde_json::Value>,
}

impl StructuredLogger {
    /// Create a new structured logger
    pub fn new(config: StructuredLoggingConfig) -> CryptoResult<Self> {
        let mut writers = Vec::new();
        for dest_config in &config.destinations {
            let writer = LogWriter::new(dest_config.clone())?;
            writers.push(writer);
        }

        let host_info = if config.include_host_info {
            Some(collect_host_info())
        } else {
            None
        };

        let logger = Self {
            config: RwLock::new(config),
            writers: Mutex::new(writers),
            host_info,
        };

        Ok(logger)
    }

    /// Log an audit entry
    pub fn log(&self, entry: &AuditEntry) -> CryptoResult<()> {
        let config = self.config.read().map_err(|_| 
            CryptoError::internal_error("Failed to read logging config")
        )?;

        if !config.enabled {
            return Ok(());
        }

        let mut writers = self.writers.lock().map_err(|_| 
            CryptoError::internal_error("Failed to lock writers")
        )?;

        for writer in &mut *writers {
            writer.write(entry)?;
        }

        Ok(())
    }

    /// Update the logging configuration
    pub fn update_config(&self, config: StructuredLoggingConfig) -> CryptoResult<()> {
        // Flush existing writers first
        {
            let mut writers = self.writers.lock().map_err(|_| 
                CryptoError::internal_error("Failed to lock writers")
            )?;

            for writer in &mut *writers {
                writer.force_flush()?;
            }
        }

        // Create new writers
        let mut new_writers = Vec::new();
        for dest_config in &config.destinations {
            let writer = LogWriter::new(dest_config.clone())?;
            new_writers.push(writer);
        }

        // Update configuration and writers
        {
            let mut cfg = self.config.write().map_err(|_| 
                CryptoError::internal_error("Failed to write logging config")
            )?;
            *cfg = config;

            let mut writers = self.writers.lock().map_err(|_| 
                CryptoError::internal_error("Failed to lock writers")
            )?;
            *writers = new_writers;
        }

        Ok(())
    }

    /// Force a flush of all log writers
    pub fn flush(&self) -> CryptoResult<()> {
        let mut writers = self.writers.lock().map_err(|_| 
            CryptoError::internal_error("Failed to lock writers")
        )?;

        for writer in &mut *writers {
            writer.force_flush()?;
        }

        Ok(())
    }

    /// Get the logging configuration
    pub fn get_config(&self) -> CryptoResult<StructuredLoggingConfig> {
        let config = self.config.read().map_err(|_| 
            CryptoError::internal_error("Failed to read logging config")
        )?;

        Ok(config.clone())
    }

    /// Sanitize sensitive data in the entry
    pub fn sanitize_entry(&self, entry: &mut AuditEntry) -> CryptoResult<()> {
        let config = self.config.read().map_err(|_| 
            CryptoError::internal_error("Failed to read logging config")
        )?;

        if config.redact_sensitive_data && entry.parameters.is_some() {
            let mut params = entry.parameters.take().unwrap();
            sanitize_json(&mut params, &config.redacted_fields);
            entry.parameters = Some(params);
        }

        Ok(())
    }
}

/// Sanitize sensitive fields in JSON
fn sanitize_json(json: &mut serde_json::Value, redacted_fields: &[String]) {
    match json {
        serde_json::Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                if redacted_fields.contains(&key.to_lowercase()) {
                    *value = serde_json::Value::String("[REDACTED]".to_string());
                } else if value.is_object() || value.is_array() {
                    sanitize_json(value, redacted_fields);
                }
            }
        }
        serde_json::Value::Array(array) => {
            for value in array.iter_mut() {
                sanitize_json(value, redacted_fields);
            }
        }
        _ => {}
    }
}

/// Collect information about the host system
fn collect_host_info() -> serde_json::Value {
    let mut info = serde_json::Map::new();

    // Add basic platform information
    info.insert(
        "os".to_string(),
        serde_json::Value::String(std::env::consts::OS.to_string()),
    );
    info.insert(
        "arch".to_string(),
        serde_json::Value::String(std::env::consts::ARCH.to_string()),
    );

    // Add hostname from environment variable if available
    if let Ok(hostname) = std::env::var("HOSTNAME").or_else(|_| std::env::var("COMPUTERNAME")) {
        info.insert(
            "hostname".to_string(),
            serde_json::Value::String(hostname),
        );
    }

    // Add process ID
    info.insert(
        "pid".to_string(),
        serde_json::Value::Number(serde_json::Number::from(std::process::id())),
    );

    serde_json::Value::Object(info)
}

impl Drop for StructuredLogger {
    fn drop(&mut self) {
        // Try to flush on drop
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::audit::{AuditEntry, CryptoOperationType, OperationStatus};
    use std::fs::read_to_string;
    use tempfile::tempdir;

    #[test]
    fn test_log_format() {
        let entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Info,
            "test_module",
            "Test encryption operation",
        )
        .with_algorithm("AES-256-GCM")
        .with_duration(100);

        // Test text format
        let text = entry.format_log_entry();
        assert!(text.contains("INFO"));
        assert!(text.contains("ENCRYPTION"));
        assert!(text.contains("SUCCESS"));

        // Test CSV format
        let csv = format_as_csv(&entry);
        let parts: Vec<&str> = csv.split(',').collect();
        assert!(parts.len() >= 9);
        assert!(parts[4] == "INFO");

        // Test JSON format
        let json_str = serde_json::to_string(&entry).unwrap();
        let json: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(json["level"], "Info");
        assert_eq!(json["operation_type"], "Encryption");
        assert_eq!(json["status"], "Success");
    }

    #[test]
    fn test_log_writer() -> CryptoResult<()> {
        let temp_dir = tempdir().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let config = LogDestinationConfig {
            destination: LogDestination::File(log_path.clone()),
            format: LogFormat::Text,
            min_level: AuditLevel::Info,
            buffered: false,
            buffer_size: 1024,
            include_stack_traces: false,
        };

        let mut writer = LogWriter::new(config)?;

        let entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Info,
            "test_module",
            "Test encryption operation",
        );

        writer.write(&entry)?;
        writer.force_flush()?;

        let content = read_to_string(&log_path).unwrap();
        assert!(content.contains("INFO"));
        assert!(content.contains("ENCRYPTION"));
        assert!(content.contains("SUCCESS"));

        Ok(())
    }

    #[test]
    fn test_buffered_writing() -> CryptoResult<()> {
        let temp_dir = tempdir().unwrap();
        let log_path = temp_dir.path().join("buffered.log");

        let config = LogDestinationConfig {
            destination: LogDestination::File(log_path.clone()),
            format: LogFormat::Text,
            min_level: AuditLevel::Info,
            buffered: true,
            buffer_size: 1024, // Large enough that we won't auto-flush
            include_stack_traces: false,
        };

        let mut writer = LogWriter::new(config)?;

        // Write multiple entries
        for i in 0..5 {
            let entry = AuditEntry::new(
                CryptoOperationType::Encryption,
                OperationStatus::Success,
                AuditLevel::Info,
                "test_module",
                format!("Test operation {}", i),
            );

            writer.write(&entry)?;
        }

        // Content shouldn't be written yet (buffered)
        let content = read_to_string(&log_path).unwrap_or_default();
        assert!(content.is_empty());

        // Force flush should write everything
        writer.force_flush()?;

        let content = read_to_string(&log_path).unwrap();
        assert_eq!(content.lines().count(), 5);

        Ok(())
    }

    #[test]
    fn test_structured_logger() -> CryptoResult<()> {
        let temp_dir = tempdir().unwrap();
        let log_path = temp_dir.path().join("structured.log");

        let config = StructuredLoggingConfig {
            enabled: true,
            destinations: vec![LogDestinationConfig {
                destination: LogDestination::File(log_path.clone()),
                format: LogFormat::Text,
                min_level: AuditLevel::Info,
                buffered: false,
                buffer_size: 1024,
                include_stack_traces: false,
            }],
            include_caller_context: true,
            redact_sensitive_data: true,
            redacted_fields: vec!["private_key".to_string()],
            human_readable_duration: true,
            include_host_info: false,
        };

        let logger = StructuredLogger::new(config)?;

        let entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Info,
            "test_module",
            "Test encryption operation",
        )
        .with_parameters(serde_json::json!({
            "algorithm": "AES-256-GCM",
            "private_key": "secret_data"
        }));

        logger.log(&entry)?;
        logger.flush()?;

        let content = read_to_string(&log_path).unwrap();
        assert!(content.contains("INFO"));
        assert!(content.contains("ENCRYPTION"));

        Ok(())
    }

    #[test]
    fn test_sanitize_json() {
        let redacted_fields = vec!["password".to_string(), "key".to_string()];

        let mut json = serde_json::json!({
            "user": "test_user",
            "password": "secret123",
            "data": {
                "key": "sensitive_key",
                "value": "non_sensitive"
            },
            "items": [
                {
                    "id": 1,
                    "key": "another_secret"
                }
            ]
        });

        sanitize_json(&mut json, &redacted_fields);

        assert_eq!(json["user"], "test_user");
        assert_eq!(json["password"], "[REDACTED]");
        assert_eq!(json["data"]["key"], "[REDACTED]");
        assert_eq!(json["data"]["value"], "non_sensitive");
        assert_eq!(json["items"][0]["key"], "[REDACTED]");
    }
} 