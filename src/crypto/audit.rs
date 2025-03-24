use crate::crypto::{CryptoError, CryptoResult};
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn, Level};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use subtle::ConstantTimeEq;

/// The severity level of an audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuditLevel {
    /// Informational events - normal operation
    Info,
    /// Warning events - suspicious but not critical
    Warning,
    /// Critical events - potential security breaches
    Critical,
    /// Fatal events - serious security issues that require immediate attention
    Fatal,
}

impl fmt::Display for AuditLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditLevel::Info => write!(f, "INFO"),
            AuditLevel::Warning => write!(f, "WARNING"),
            AuditLevel::Critical => write!(f, "CRITICAL"),
            AuditLevel::Fatal => write!(f, "FATAL"),
        }
    }
}

impl From<AuditLevel> for Level {
    fn from(level: AuditLevel) -> Self {
        match level {
            AuditLevel::Info => Level::Info,
            AuditLevel::Warning => Level::Warn,
            AuditLevel::Critical => Level::Error,
            AuditLevel::Fatal => Level::Error,
        }
    }
}

/// Defines types of cryptographic operations that can be audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoOperationType {
    /// Key generation operations
    KeyGeneration,
    /// Key derivation operations
    KeyDerivation,
    /// Encryption operations
    Encryption,
    /// Decryption operations
    Decryption,
    /// Signature creation
    Signing,
    /// Signature verification
    Verification,
    /// Commitment creation
    Commitment,
    /// Zero-knowledge proof creation
    ZkProofCreate,
    /// Zero-knowledge proof verification
    ZkProofVerify,
    /// Secret sharing operations
    SecretSharing,
    /// Memory protection operations
    MemoryProtection,
    /// Side-channel countermeasures
    SideChannelProtection,
    /// Key management operations
    KeyManagement,
    /// View key operations
    ViewKeyOperation,
    /// Privacy features
    PrivacyOperation,
    /// Authentication operations
    Authentication,
    /// General cryptographic operations
    General,
}

impl fmt::Display for CryptoOperationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoOperationType::KeyGeneration => write!(f, "KEY_GENERATION"),
            CryptoOperationType::KeyDerivation => write!(f, "KEY_DERIVATION"),
            CryptoOperationType::Encryption => write!(f, "ENCRYPTION"),
            CryptoOperationType::Decryption => write!(f, "DECRYPTION"),
            CryptoOperationType::Signing => write!(f, "SIGNING"),
            CryptoOperationType::Verification => write!(f, "VERIFICATION"),
            CryptoOperationType::Commitment => write!(f, "COMMITMENT"),
            CryptoOperationType::ZkProofCreate => write!(f, "ZK_PROOF_CREATE"),
            CryptoOperationType::ZkProofVerify => write!(f, "ZK_PROOF_VERIFY"),
            CryptoOperationType::SecretSharing => write!(f, "SECRET_SHARING"),
            CryptoOperationType::MemoryProtection => write!(f, "MEMORY_PROTECTION"),
            CryptoOperationType::SideChannelProtection => write!(f, "SIDE_CHANNEL_PROTECTION"),
            CryptoOperationType::KeyManagement => write!(f, "KEY_MANAGEMENT"),
            CryptoOperationType::ViewKeyOperation => write!(f, "VIEW_KEY_OPERATION"),
            CryptoOperationType::PrivacyOperation => write!(f, "PRIVACY_OPERATION"),
            CryptoOperationType::Authentication => write!(f, "AUTHENTICATION"),
            CryptoOperationType::General => write!(f, "GENERAL"),
        }
    }
}

/// Status of a cryptographic operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationStatus {
    /// Operation started
    Started,
    /// Operation completed successfully
    Success,
    /// Operation failed
    Failed,
    /// Operation was denied
    Denied,
    /// Operation was attempted but expired
    Expired,
}

impl fmt::Display for OperationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OperationStatus::Started => write!(f, "STARTED"),
            OperationStatus::Success => write!(f, "SUCCESS"),
            OperationStatus::Failed => write!(f, "FAILED"),
            OperationStatus::Denied => write!(f, "DENIED"),
            OperationStatus::Expired => write!(f, "EXPIRED"),
        }
    }
}

/// An individual audit entry for a cryptographic operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique identifier for this audit entry
    pub id: String,
    /// Timestamp when the event occurred
    pub timestamp: DateTime<Utc>,
    /// The type of cryptographic operation
    pub operation_type: CryptoOperationType,
    /// The status of the operation
    pub status: OperationStatus,
    /// The severity level of the event
    pub level: AuditLevel,
    /// Module or component that generated the event
    pub module: String,
    /// Brief description of the event
    pub description: String,
    /// Cryptographic algorithm used (if applicable)
    pub algorithm: Option<String>,
    /// Operation parameters (sanitized to avoid sensitive data)
    pub parameters: Option<serde_json::Value>,
    /// Duration of the operation in milliseconds (if complete)
    pub duration_ms: Option<u64>,
    /// Error information (if operation failed)
    pub error: Option<String>,
    /// Related audit entries (by ID)
    pub related_entries: Vec<String>,
    /// The caller's context (function/method)
    pub caller_context: Option<String>,
}

impl AuditEntry {
    /// Creates a new audit entry with the given parameters.
    pub fn new(
        operation_type: CryptoOperationType,
        status: OperationStatus,
        level: AuditLevel,
        module: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: generate_audit_id(),
            timestamp: Utc::now(),
            operation_type,
            status,
            level,
            module: module.into(),
            description: description.into(),
            algorithm: None,
            parameters: None,
            duration_ms: None,
            error: None,
            related_entries: Vec::new(),
            caller_context: None,
        }
    }

    /// Sets the algorithm used in the operation.
    pub fn with_algorithm(mut self, algorithm: impl Into<String>) -> Self {
        self.algorithm = Some(algorithm.into());
        self
    }

    /// Sets sanitized parameters for the operation.
    pub fn with_parameters(mut self, parameters: serde_json::Value) -> Self {
        self.parameters = Some(parameters);
        self
    }

    /// Sets the duration of the operation.
    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }

    /// Sets error information if the operation failed.
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }

    /// Adds related audit entry IDs.
    pub fn with_related_entries(mut self, related_entries: Vec<String>) -> Self {
        self.related_entries = related_entries;
        self
    }

    /// Sets the caller's context.
    pub fn with_caller_context(mut self, caller_context: impl Into<String>) -> Self {
        self.caller_context = Some(caller_context.into());
        self
    }

    /// Updates an existing entry with completion information.
    pub fn complete(
        &mut self,
        status: OperationStatus,
        duration_ms: u64,
        error: Option<impl Into<String>>,
    ) {
        self.status = status;
        self.duration_ms = Some(duration_ms);
        if let Some(err) = error {
            self.error = Some(err.into());
            if status == OperationStatus::Failed {
                // Increase severity for failed operations
                if self.level == AuditLevel::Info {
                    self.level = AuditLevel::Warning;
                }
            }
        }
    }

    /// Formats the entry as a string for logging.
    pub fn format_log_entry(&self) -> String {
        let mut entry = format!(
            "[{}] [{}] [{}] [{}] {}",
            self.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),
            self.level,
            self.operation_type,
            self.status,
            self.description
        );

        if let Some(ref algorithm) = self.algorithm {
            entry.push_str(&format!(" [Algorithm: {}]", algorithm));
        }

        if let Some(duration) = self.duration_ms {
            entry.push_str(&format!(" [Duration: {}ms]", duration));
        }

        if let Some(ref error) = self.error {
            entry.push_str(&format!(" [Error: {}]", error));
        }

        entry
    }

    /// Converts the entry to a structured JSON object.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_else(|_| serde_json::Value::Null)
    }
}

/// Configuration for the audit system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Whether the audit system is enabled.
    pub enabled: bool,
    /// The minimum level to record in the audit log.
    pub min_level: AuditLevel,
    /// Whether to output audit events to log as well.
    pub log_output: bool,
    /// Maximum number of events to keep in memory.
    pub in_memory_limit: usize,
    /// Path to the audit log file (None for no file logging).
    pub log_file_path: Option<PathBuf>,
    /// Whether to rotate log files.
    pub rotate_logs: bool,
    /// Maximum size of log file before rotation (in bytes).
    pub max_log_size: u64,
    /// Number of backup log files to keep.
    pub max_backup_count: usize,
    /// Whether to redact sensitive parameters.
    pub redact_sensitive_params: bool,
    /// List of fields to always redact.
    pub redacted_fields: Vec<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_level: AuditLevel::Info,
            log_output: true,
            in_memory_limit: 1000,
            log_file_path: None,
            rotate_logs: true,
            max_log_size: 10 * 1024 * 1024, // 10 MB
            max_backup_count: 5,
            redact_sensitive_params: true,
            redacted_fields: vec![
                "private_key".to_string(),
                "secret".to_string(),
                "password".to_string(),
                "key".to_string(),
                "seed".to_string(),
                "token".to_string(),
            ],
        }
    }
}

/// Errors that can occur within the audit system.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("Failed to write to audit log: {0}")]
    LogWriteError(#[from] io::Error),
    
    #[error("Failed to serialize audit entry: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("Audit system is disabled")]
    Disabled,
    
    #[error("Failed to access audit storage: {0}")]
    StorageError(String),
    
    #[error("Invalid configuration: {0}")]
    ConfigError(String),
}

impl From<AuditError> for CryptoError {
    fn from(err: AuditError) -> Self {
        CryptoError::UnexpectedError(err.to_string())
    }
}

/// Result type for audit operations.
pub type AuditResult<T> = Result<T, AuditError>;

/// Helper function to generate a unique ID for audit entries.
fn generate_audit_id() -> String {
    let mut rng = rand::thread_rng();
    let id: u64 = rng.gen();
    format!("{:x}-{}", id, Utc::now().timestamp_millis())
}

/// Main implementation of the cryptographic audit system.
pub struct CryptoAudit {
    /// Configuration for the audit system
    config: RwLock<AuditConfig>,
    /// In-memory buffer of recent audit entries
    entries: RwLock<VecDeque<AuditEntry>>,
    /// File handle for the audit log file (if enabled)
    log_file: Mutex<Option<File>>,
    /// Size of the current log file
    current_log_size: Mutex<u64>,
}

impl CryptoAudit {
    /// Creates a new audit system with the given configuration.
    pub fn new(config: AuditConfig) -> CryptoResult<Self> {
        // Create the instance first
        let audit = Self {
            config: RwLock::new(config.clone()),
            log_file: Mutex::new(None),
            entries: RwLock::new(VecDeque::new()),
            current_log_size: Mutex::new(0),
        };
        
        // Then handle the log file
        let log_file = if let Some(ref path) = config.log_file_path {
            let file = Self::open_or_create_log_file(path)?;
            let size = file.metadata()
                .map(|m| m.len())
                .unwrap_or_else(|_| {
                    warn!("Failed to get audit log file metadata");
                    0
                });
            
            // Update the current log size
            let mut size_lock = audit.current_log_size.lock()
                .map_err(|_| CryptoError::UnexpectedError("Failed to acquire size lock".to_string()))?;
            *size_lock = size;
            Some(file)
        } else {
            None
        };

        // Create the final instance with the log file
        Ok(Self {
            config: RwLock::new(config),
            log_file: Mutex::new(log_file),
            entries: audit.entries,
            current_log_size: audit.current_log_size,
        })
    }

    /// Opens or creates the audit log file.
    fn open_or_create_log_file(path: &Path) -> CryptoResult<File> {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| {
                CryptoError::IoError(io::Error::new(
                    e.kind(),
                    format!("Failed to open audit log file: {}", e),
                ))
            })
    }

    /// Update the audit system configuration.
    pub fn update_config(&self, config: AuditConfig) -> CryptoResult<()> {
        let mut config_lock = self
            .config
            .write()
            .map_err(|_| CryptoError::UnexpectedError("Failed to acquire config lock".to_string()))?;

        // Check if log file path has changed
        if config.log_file_path != config_lock.log_file_path {
            let mut log_file_lock = self
                .log_file
                .lock()
                .map_err(|_| CryptoError::UnexpectedError("Failed to acquire log file lock".to_string()))?;

            *log_file_lock = if let Some(ref path) = config.log_file_path {
                Some(Self::open_or_create_log_file(path)?)
            } else {
                None
            };

            let mut size_lock = self
                .current_log_size
                .lock()
                .map_err(|_| CryptoError::UnexpectedError("Failed to acquire size lock".to_string()))?;
            *size_lock = 0;
        }

        *config_lock = config;
        Ok(())
    }

    /// Records a new audit entry.
    pub fn record(&self, entry: AuditEntry) -> CryptoResult<String> {
        let config = self
            .config
            .read()
            .map_err(|_| CryptoError::UnexpectedError("Failed to acquire config lock".to_string()))?;

        if !config.enabled || entry.level < config.min_level {
            return Ok(entry.id.clone());
        }

        // Add to in-memory buffer
        {
            let mut entries_lock = self
                .entries
                .write()
                .map_err(|_| CryptoError::UnexpectedError("Failed to acquire entries lock".to_string()))?;

            while entries_lock.len() >= config.in_memory_limit {
                entries_lock.pop_front();
            }
            entries_lock.push_back(entry.clone());
        }

        // Write to log file if enabled
        if let Some(ref _path) = config.log_file_path {
            let mut log_file_lock = self
                .log_file
                .lock()
                .map_err(|_| CryptoError::UnexpectedError("Failed to acquire log file lock".to_string()))?;
            let mut size_lock = self
                .current_log_size
                .lock()
                .map_err(|_| CryptoError::UnexpectedError("Failed to acquire size lock".to_string()))?;

            if let Some(file) = log_file_lock.as_mut() {
                let log_entry = format!("{}\n", entry.format_log_entry());
                let bytes_written = file.write(log_entry.as_bytes())?;
                *size_lock += bytes_written as u64;

                // Rotate log file if needed
                if config.rotate_logs && *size_lock > config.max_log_size {
                    if let Some(ref path) = config.log_file_path {
                        Self::rotate_log_file(path, config.max_backup_count)?;
                        *log_file_lock = Some(Self::open_or_create_log_file(path)?);
                        *size_lock = 0;
                    }
                }
            }
        }

        // Also log to standard logging system if configured
        if config.log_output {
            let log_level: Level = entry.level.into();
            let message = entry.format_log_entry();
            match log_level {
                Level::Error => error!("{}", message),
                Level::Warn => warn!("{}", message),
                Level::Info => info!("{}", message),
                Level::Debug => debug!("{}", message),
                Level::Trace => debug!("{}", message),
            }
        }

        Ok(entry.id.clone())
    }

    /// Rotates the log file by renaming existing logs.
    fn rotate_log_file(path: &Path, max_backups: usize) -> CryptoResult<()> {
        let path_str = path.to_string_lossy().to_string();
        
        // Remove oldest backup if it exists
        if max_backups > 0 {
            let oldest_backup = format!("{}.{}", path_str, max_backups);
            let _ = std::fs::remove_file(oldest_backup);
        }
        
        // Shift existing backups
        for i in (1..max_backups).rev() {
            let from = format!("{}.{}", path_str, i);
            let to = format!("{}.{}", path_str, i + 1);
            if Path::new(&from).exists() {
                let _ = std::fs::rename(&from, &to);
            }
        }
        
        // Rename current log to .1
        if Path::new(&path_str).exists() {
            let backup = format!("{}.1", path_str);
            std::fs::rename(&path_str, backup)?;
        }
        
        Ok(())
    }

    /// Retrieves recent audit entries filtered by criteria.
    pub fn get_entries(
        &self,
        min_level: Option<AuditLevel>,
        operation_type: Option<CryptoOperationType>,
        since: Option<DateTime<Utc>>,
        limit: Option<usize>,
    ) -> CryptoResult<Vec<AuditEntry>> {
        let entries_lock = self
            .entries
            .read()
            .map_err(|_| CryptoError::UnexpectedError("Failed to acquire entries lock".to_string()))?;

        let filtered = entries_lock
            .iter()
            .filter(|e| {
                min_level.map_or(true, |level| e.level >= level)
                    && operation_type.map_or(true, |op| e.operation_type == op)
                    && since.map_or(true, |ts| e.timestamp >= ts)
            })
            .cloned()
            .collect::<Vec<_>>();

        if let Some(limit) = limit {
            Ok(filtered.into_iter().take(limit).collect())
        } else {
            Ok(filtered)
        }
    }

    /// Create a helper to track a cryptographic operation from start to finish.
    pub fn track_operation(
        &self,
        operation_type: CryptoOperationType,
        level: AuditLevel,
        module: impl Into<String>,
        description: impl Into<String>,
    ) -> OperationTracker {
        OperationTracker::new(self, operation_type, level, module, description)
    }

    /// Sanitizes parameters by redacting sensitive fields.
    pub fn sanitize_parameters(&self, params: &serde_json::Value) -> serde_json::Value {
        let config = match self.config.read() {
            Ok(config) => config,
            Err(_) => return serde_json::Value::Null,
        };

        if !config.redact_sensitive_params {
            return params.clone();
        }

        match params {
            serde_json::Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                
                for (key, value) in map {
                    let new_value = if config.redacted_fields.iter().any(|field| {
                        key.to_lowercase().contains(&field.to_lowercase())
                    }) {
                        serde_json::Value::String("[REDACTED]".to_string())
                    } else if let serde_json::Value::Object(_) = value {
                        self.sanitize_parameters(value)
                    } else {
                        value.clone()
                    };
                    
                    new_map.insert(key.clone(), new_value);
                }
                
                serde_json::Value::Object(new_map)
            }
            serde_json::Value::Array(arr) => {
                let new_arr = arr
                    .iter()
                    .map(|v| self.sanitize_parameters(v))
                    .collect();
                serde_json::Value::Array(new_arr)
            }
            _ => params.clone(),
        }
    }

    /// Gets the current audit configuration.
    pub fn get_config(&self) -> CryptoResult<AuditConfig> {
        self.config
            .read()
            .map(|c| c.clone())
            .map_err(|_| CryptoError::UnexpectedError("Failed to acquire config lock".to_string()))
    }
}

/// Helper struct to track a cryptographic operation from start to finish.
pub struct OperationTracker {
    /// Reference to the audit system
    audit: Arc<CryptoAudit>,
    /// The audit entry being tracked
    entry: AuditEntry,
    /// Start time of the operation
    start_time: std::time::Instant,
    /// Whether the operation has been completed
    completed: bool,
}

impl OperationTracker {
    /// Creates a new operation tracker.
    pub fn new(
        audit: &CryptoAudit,
        operation_type: CryptoOperationType,
        level: AuditLevel,
        module: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        let entry = AuditEntry::new(
            operation_type,
            OperationStatus::Started,
            level,
            module,
            description,
        );
        
        // Try to record initial "started" entry
        let _ = audit.record(entry.clone());
        
        Self {
            audit: Arc::new(audit.clone()),
            entry,
            start_time: std::time::Instant::now(),
            completed: false,
        }
    }

    /// Sets the algorithm used in the operation.
    pub fn with_algorithm(mut self, algorithm: impl Into<String>) -> Self {
        self.entry = self.entry.clone().with_algorithm(algorithm);
        self
    }

    /// Sets sanitized parameters for the operation.
    pub fn with_parameters(mut self, parameters: serde_json::Value) -> Self {
        let sanitized = self.audit.sanitize_parameters(&parameters);
        self.entry = self.entry.clone().with_parameters(sanitized);
        self
    }

    /// Sets the caller's context.
    pub fn with_caller_context(mut self, caller_context: impl Into<String>) -> Self {
        self.entry = self.entry.clone().with_caller_context(caller_context);
        self
    }

    /// Completes the operation with success status.
    pub fn complete_success(mut self) -> CryptoResult<String> {
        if self.completed {
            return Ok(self.entry.id.clone());
        }
        
        let duration = self.start_time.elapsed().as_millis() as u64;
        self.entry.complete(OperationStatus::Success, duration, None::<String>);
        self.completed = true;
        self.audit.record(self.entry.clone())
    }

    /// Completes the operation with failure status.
    pub fn complete_failure(mut self, error: impl Into<String>) -> CryptoResult<String> {
        if self.completed {
            return Ok(self.entry.id.clone());
        }
        
        let duration = self.start_time.elapsed().as_millis() as u64;
        let error_msg = error.into();
        self.entry.complete(OperationStatus::Failed, duration, Some(error_msg));
        self.completed = true;
        self.audit.record(self.entry.clone())
    }

    /// Returns the ID of the audit entry.
    pub fn id(&self) -> &str {
        &self.entry.id
    }
}

impl Clone for CryptoAudit {
    fn clone(&self) -> Self {
        Self {
            config: RwLock::new(
                self.config
                    .read()
                    .unwrap_or_else(|_| panic!("Failed to acquire config lock"))
                    .clone(),
            ),
            entries: RwLock::new(VecDeque::new()),
            log_file: Mutex::new(None),
            current_log_size: Mutex::new(0),
        }
    }
}

impl Drop for OperationTracker {
    fn drop(&mut self) {
        if !self.completed {
            let duration = self.start_time.elapsed().as_millis() as u64;
            let mut entry = self.entry.clone();
            entry.complete(
                OperationStatus::Failed,
                duration,
                Some("Operation tracker dropped without completion"),
            );
            let _ = self.audit.record(entry);
        }
    }
}

/// Wrapper function around a cryptographic operation to ensure it's audited.
pub fn audit_crypto_operation<F, T>(
    audit: &CryptoAudit,
    operation_type: CryptoOperationType,
    level: AuditLevel,
    module: impl Into<String>,
    description: impl Into<String>,
    f: F,
) -> CryptoResult<T>
where
    F: FnOnce() -> CryptoResult<T>,
{
    let module_str = module.into();
    let desc_str = description.into();
    
    let tracker = audit
        .track_operation(operation_type, level, module_str, desc_str)
        .with_caller_context(std::panic::Location::caller().to_string());
    
    match f() {
        Ok(result) => {
            let _ = tracker.complete_success();
            Ok(result)
        }
        Err(e) => {
            let _ = tracker.complete_failure(e.to_string());
            Err(e)
        }
    }
} 