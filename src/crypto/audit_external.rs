use crate::crypto::audit::{AuditEntry, AuditLevel, CryptoOperationType, OperationStatus};
use crate::crypto::audit_alerting::Alert;
use crate::crypto::{CryptoError, CryptoResult};
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

/// Supported external security systems
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExternalSystem {
    /// SIEM (Security Information and Event Management)
    Siem(String),
    /// SOC (Security Operations Center)
    Soc(String),
    /// IDS (Intrusion Detection System)
    Ids(String),
    /// EDR (Endpoint Detection and Response)
    Edr(String),
    /// Custom system
    Custom(String),
}

impl std::fmt::Display for ExternalSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExternalSystem::Siem(name) => write!(f, "SIEM:{}", name),
            ExternalSystem::Soc(name) => write!(f, "SOC:{}", name),
            ExternalSystem::Ids(name) => write!(f, "IDS:{}", name),
            ExternalSystem::Edr(name) => write!(f, "EDR:{}", name),
            ExternalSystem::Custom(name) => write!(f, "Custom:{}", name),
        }
    }
}

/// Configuration for external system integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalIntegrationConfig {
    /// Whether external integration is enabled
    pub enabled: bool,
    /// Minimum level to send to external systems
    pub min_level: AuditLevel,
    /// Configured external systems
    pub systems: Vec<ExternalSystemConfig>,
    /// Maximum batch size when sending events
    pub max_batch_size: usize,
    /// Whether to enable secure transport (TLS)
    pub secure_transport: bool,
    /// Authentication configuration
    pub authentication: ExternalAuthConfig,
    /// Whether to retry failed connections
    pub retry_on_failure: bool,
    /// Maximum number of retries
    pub max_retries: u32,
    /// Retry delay in seconds
    pub retry_delay_seconds: u64,
}

impl Default for ExternalIntegrationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_level: AuditLevel::Warning,
            systems: Vec::new(),
            max_batch_size: 100,
            secure_transport: true,
            authentication: ExternalAuthConfig::None,
            retry_on_failure: true,
            max_retries: 3,
            retry_delay_seconds: 5,
        }
    }
}

/// Configuration for an external system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalSystemConfig {
    /// The type of external system
    pub system: ExternalSystem,
    /// The endpoint URL
    pub endpoint_url: String,
    /// The format to use when sending data
    pub format: ExternalDataFormat,
    /// System-specific configuration 
    pub config: Option<serde_json::Value>,
    /// Whether this system is enabled
    pub enabled: bool,
    /// Authentication override for this specific system
    pub authentication: Option<ExternalAuthConfig>,
}

/// Data format for external system integration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExternalDataFormat {
    /// JSON format
    Json,
    /// CELF (Common Event Format)
    Cef,
    /// LEEF (Log Event Extended Format)
    Leef,
    /// Syslog format
    Syslog,
    /// Custom format
    Custom(String),
}

/// Authentication configuration for external systems
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExternalAuthConfig {
    /// No authentication
    None,
    /// API key authentication
    ApiKey {
        /// The name of the header or parameter
        key_name: String,
        /// The API key value
        key_value: String,
    },
    /// Bearer token authentication
    BearerToken(String),
    /// Basic authentication
    BasicAuth {
        /// Username
        username: String,
        /// Password
        password: String,
    },
    /// OAuth2 authentication
    OAuth2 {
        /// Client ID
        client_id: String,
        /// Client secret
        client_secret: String,
        /// Token URL
        token_url: String,
        /// Scope
        scope: Option<String>,
        /// Current token (will be populated at runtime)
        #[serde(skip)]
        current_token: Option<String>,
        /// Token expiration (will be populated at runtime)
        #[serde(skip)]
        token_expiration: Option<DateTime<Utc>>,
    },
    /// Certificate-based authentication
    Certificate {
        /// Path to certificate file
        cert_path: String,
        /// Path to key file
        key_path: String,
    },
}

/// Connection status for external systems
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalSystemStatus {
    /// The external system
    pub system: ExternalSystem,
    /// Whether the system is connected
    pub connected: bool,
    /// Last connection time
    pub last_connection: Option<DateTime<Utc>>,
    /// Last error message
    pub last_error: Option<String>,
    /// Number of successful sends
    pub successful_sends: u64,
    /// Number of failed sends
    pub failed_sends: u64,
    /// Average response time in milliseconds
    pub avg_response_time_ms: Option<f64>,
}

/// The external integration manager
pub struct ExternalIntegrationManager {
    /// Configuration
    config: RwLock<ExternalIntegrationConfig>,
    /// Status of each system
    status: RwLock<HashMap<ExternalSystem, ExternalSystemStatus>>,
    /// Message queue for retry
    retry_queue: Mutex<Vec<(ExternalSystem, AuditEntry, u32)>>,
}

impl ExternalIntegrationManager {
    /// Create a new external integration manager
    pub fn new(config: ExternalIntegrationConfig) -> Self {
        let mut status = HashMap::new();
        
        // Initialize status for each system
        for system_config in &config.systems {
            if system_config.enabled {
                status.insert(
                    system_config.system.clone(),
                    ExternalSystemStatus {
                        system: system_config.system.clone(),
                        connected: false,
                        last_connection: None,
                        last_error: None,
                        successful_sends: 0,
                        failed_sends: 0,
                        avg_response_time_ms: None,
                    },
                );
            }
        }
        
        Self {
            config: RwLock::new(config),
            status: RwLock::new(status),
            retry_queue: Mutex::new(Vec::new()),
        }
    }

    /// Send an audit entry to all configured external systems
    pub fn send_entry(&self, entry: &AuditEntry) -> CryptoResult<()> {
        let config = self.config.read().map_err(|_| 
            CryptoError::internal_error("Failed to read external integration config"))?;
        
        if !config.enabled || entry.level < config.min_level {
            return Ok(());
        }
        
        for system_config in &config.systems {
            if !system_config.enabled {
                continue;
            }
            
            match self.send_to_system(entry, system_config, &config) {
                Ok(_) => {
                    // Update successful sends count
                    if let Ok(mut status_map) = self.status.write() {
                        if let Some(status) = status_map.get_mut(&system_config.system) {
                            status.connected = true;
                            status.last_connection = Some(Utc::now());
                            status.successful_sends += 1;
                        }
                    }
                },
                Err(e) => {
                    // Log the error
                    error!("Failed to send audit entry to external system {}: {}", 
                           system_config.system, e);
                    
                    // Update status
                    if let Ok(mut status_map) = self.status.write() {
                        if let Some(status) = status_map.get_mut(&system_config.system) {
                            status.connected = false;
                            status.last_error = Some(e.to_string());
                            status.failed_sends += 1;
                        }
                    }
                    
                    // Queue for retry if configured
                    if config.retry_on_failure {
                        if let Ok(mut queue) = self.retry_queue.lock() {
                            queue.push((system_config.system.clone(), entry.clone(), 0));
                        }
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Send an alert to all configured external systems
    pub fn send_alert(&self, alert: &Alert) -> CryptoResult<()> {
        // Convert alert to audit entry
        let entry = AuditEntry::new(
            CryptoOperationType::General,
            OperationStatus::Failed,
            alert.level,
            "security_alert",
            format!("Security Alert: {}", alert.alert_type)
        );
        
        self.send_entry(&entry)
    }

    /// Send an audit entry to a specific external system
    fn send_to_system(
        &self,
        entry: &AuditEntry,
        system_config: &ExternalSystemConfig,
        global_config: &ExternalIntegrationConfig,
    ) -> CryptoResult<()> {
        // In a real implementation, this would:
        // 1. Format the entry according to the system's format
        // 2. Authenticate with the system if needed
        // 3. Send the data via HTTP/HTTPS or other protocol
        // 4. Handle the response
        
        // For this implementation, we'll just log what would happen
        debug!(
            "Would send audit entry to {} at {} using {} format",
            system_config.system,
            system_config.endpoint_url,
            format!("{:?}", system_config.format)
        );
        
        // Use authentication config
        let auth_config = system_config.authentication.as_ref().unwrap_or(&global_config.authentication);
        debug!("Would use authentication: {:?}", auth_config);
        
        // Format the data
        let formatted = match system_config.format {
            ExternalDataFormat::Json => serde_json::to_string(entry)
                .map_err(|e| CryptoError::SerializationError(e.to_string()))?,
            ExternalDataFormat::Cef => format_as_cef(entry, &system_config.system)?,
            ExternalDataFormat::Leef => format_as_leef(entry, &system_config.system)?,
            ExternalDataFormat::Syslog => format_as_syslog(entry, &system_config.system)?,
            ExternalDataFormat::Custom(ref format_name) => {
                format!("Would format using custom format: {}", format_name)
            },
        };
        
        debug!("Formatted data: {}", formatted);
        
        // In a real implementation:
        // let client = reqwest::Client::new();
        // let response = client.post(&system_config.endpoint_url)
        //     .header("Content-Type", "application/json")
        //     .body(formatted)
        //     .send()?;
        
        Ok(())
    }

    /// Process the retry queue
    pub fn process_retry_queue(&self) -> CryptoResult<()> {
        let config = self.config.read().map_err(|_| 
            CryptoError::internal_error("Failed to read external integration config"))?;
        
        if !config.enabled || !config.retry_on_failure {
            return Ok(());
        }
        
        let mut entries_to_retry = Vec::new();
        
        // Get entries to retry
        {
            let mut queue = self.retry_queue.lock().map_err(|_| 
                CryptoError::internal_error("Failed to lock retry queue"))?;
            
            std::mem::swap(&mut entries_to_retry, &mut queue);
        }
        
        if entries_to_retry.is_empty() {
            return Ok(());
        }
        
        debug!("Processing {} entries in retry queue", entries_to_retry.len());
        
        let mut still_to_retry = Vec::new();
        
        for (system, entry, retries) in entries_to_retry {
            // Find the system config
            let system_config = config.systems.iter()
                .find(|s| s.enabled && s.system == system)
                .cloned();
            
            if let Some(system_config) = system_config {
                match self.send_to_system(&entry, &system_config, &config) {
                    Ok(_) => {
                        // Update successful sends count
                        if let Ok(mut status_map) = self.status.write() {
                            if let Some(status) = status_map.get_mut(&system) {
                                status.connected = true;
                                status.last_connection = Some(Utc::now());
                                status.successful_sends += 1;
                            }
                        }
                        
                        info!("Successfully retried sending audit entry to {}", system);
                    },
                    Err(e) => {
                        // Update status
                        if let Ok(mut status_map) = self.status.write() {
                            if let Some(status) = status_map.get_mut(&system) {
                                status.connected = false;
                                status.last_error = Some(e.to_string());
                                status.failed_sends += 1;
                            }
                        }
                        
                        // If we haven't reached the max retries, queue again
                        if retries < config.max_retries {
                            still_to_retry.push((system, entry, retries + 1));
                        } else {
                            error!("Gave up retrying to send audit entry to {} after {} attempts",
                                   system, retries + 1);
                        }
                    }
                }
            }
        }
        
        // Store entries still to be retried
        if !still_to_retry.is_empty() {
            let mut queue = self.retry_queue.lock().map_err(|_| 
                CryptoError::internal_error("Failed to lock retry queue"))?;
            
            queue.extend(still_to_retry);
        }
        
        Ok(())
    }

    /// Get the status of all external systems
    pub fn get_system_status(&self) -> CryptoResult<Vec<ExternalSystemStatus>> {
        let status = self.status.read().map_err(|_| 
            CryptoError::internal_error("Failed to read system status"))?;
        
        Ok(status.values().cloned().collect())
    }

    /// Update the configuration
    pub fn update_config(&self, config: ExternalIntegrationConfig) -> CryptoResult<()> {
        // Update status map with new systems
        {
            let mut status = self.status.write().map_err(|_| 
                CryptoError::internal_error("Failed to write system status"))?;
            
            // Remove systems that are no longer configured
            status.retain(|system, _| {
                config.systems.iter().any(|s| s.enabled && s.system == *system)
            });
            
            // Add new systems
            for system_config in &config.systems {
                if system_config.enabled && !status.contains_key(&system_config.system) {
                    status.insert(
                        system_config.system.clone(),
                        ExternalSystemStatus {
                            system: system_config.system.clone(),
                            connected: false,
                            last_connection: None,
                            last_error: None,
                            successful_sends: 0,
                            failed_sends: 0,
                            avg_response_time_ms: None,
                        },
                    );
                }
            }
        }
        
        // Update config
        {
            let mut cfg = self.config.write().map_err(|_| 
                CryptoError::internal_error("Failed to write external integration config"))?;
            *cfg = config;
        }
        
        Ok(())
    }

    /// Test connection to a specific external system
    pub fn test_connection(&self, system: &ExternalSystem) -> CryptoResult<bool> {
        let config = self.config.read().map_err(|_| 
            CryptoError::internal_error("Failed to read external integration config"))?;
        
        let system_config = config.systems.iter()
            .find(|s| s.enabled && s.system == *system)
            .ok_or_else(|| CryptoError::ValidationError(format!("System {} not found or not enabled", system)))?;
        
        // Create a test entry
        let test_entry = AuditEntry::new(
            CryptoOperationType::General,
            OperationStatus::Success,
            AuditLevel::Info,
            "external_integration",
            format!("Test connection to {}", system)
        );
        
        // Attempt to send
        match self.send_to_system(&test_entry, system_config, &config) {
            Ok(_) => {
                // Update status
                if let Ok(mut status_map) = self.status.write() {
                    if let Some(status) = status_map.get_mut(system) {
                        status.connected = true;
                        status.last_connection = Some(Utc::now());
                        status.last_error = None;
                    }
                }
                
                Ok(true)
            },
            Err(e) => {
                // Update status
                if let Ok(mut status_map) = self.status.write() {
                    if let Some(status) = status_map.get_mut(system) {
                        status.connected = false;
                        status.last_error = Some(e.to_string());
                    }
                }
                
                Ok(false)
            }
        }
    }
}

/// Format an audit entry in Common Event Format (CEF)
fn format_as_cef(entry: &AuditEntry, system: &ExternalSystem) -> CryptoResult<String> {
    // CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    let severity = match entry.level {
        AuditLevel::Info => "0",
        AuditLevel::Warning => "5",
        AuditLevel::Critical => "8",
        AuditLevel::Fatal => "10",
    };
    
    let cef = format!(
        "CEF:0|Obscura|CryptoModule|1.0|{}|{}|{}|eventId={} msg={} status={}",
        entry.operation_type,
        entry.description,
        severity,
        entry.id,
        entry.description.replace('|', "\\|").replace('=', "\\="),
        entry.status
    );
    
    Ok(cef)
}

/// Format an audit entry in Log Event Extended Format (LEEF)
fn format_as_leef(entry: &AuditEntry, system: &ExternalSystem) -> CryptoResult<String> {
    // LEEF format: LEEF:Version|Vendor|Product|Version|EventID|key1=value1\tkey2=value2
    // Convert AuditLevel to string explicitly to ensure consistent format
    let level_str = match entry.level {
        AuditLevel::Info => "Info",
        AuditLevel::Warning => "Warning",
        AuditLevel::Critical => "Critical",
        AuditLevel::Fatal => "Fatal",
    };
    
    let leef = format!(
        "LEEF:1.0|Obscura|CryptoModule|1.0|{}|level={}\tmodule={}\tstatus={}\tmsg={}",
        entry.operation_type,
        level_str,
        entry.module,
        entry.status,
        entry.description.replace('\t', "\\t")
    );
    
    Ok(leef)
}

/// Format an audit entry in Syslog format
fn format_as_syslog(entry: &AuditEntry, system: &ExternalSystem) -> CryptoResult<String> {
    // Syslog priority calculation (facility * 8 + severity)
    // Using facility 10 (security/authorization) and mapping our levels to syslog severity
    let severity = match entry.level {
        AuditLevel::Info => 6,    // Informational
        AuditLevel::Warning => 4, // Warning
        AuditLevel::Critical => 2, // Critical
        AuditLevel::Fatal => 0,   // Emergency
    };
    
    let priority = 10 * 8 + severity;
    let timestamp = entry.timestamp.format("%b %d %H:%M:%S").to_string();
    
    let syslog = format!(
        "<{}>{} obscura-crypto[{}]: {} [{}] {} - {}",
        priority,
        timestamp,
        std::process::id(),
        entry.level,
        entry.operation_type,
        entry.status,
        entry.description
    );
    
    Ok(syslog)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_external_system_display() {
        let siem = ExternalSystem::Siem("Splunk".to_string());
        let soc = ExternalSystem::Soc("ArcSight".to_string());
        
        assert_eq!(siem.to_string(), "SIEM:Splunk");
        assert_eq!(soc.to_string(), "SOC:ArcSight");
    }

    #[test]
    fn test_cef_format() -> CryptoResult<()> {
        let entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Warning,
            "test_module",
            "Test encryption operation",
        );
        
        let system = ExternalSystem::Siem("Splunk".to_string());
        let cef = format_as_cef(&entry, &system)?;
        
        assert!(cef.starts_with("CEF:0|Obscura|CryptoModule|1.0|"));
        assert!(cef.contains("Test encryption operation"));
        assert!(cef.contains("|5|")); // Warning severity
        
        Ok(())
    }

    #[test]
    fn test_leef_format() -> CryptoResult<()> {
        let entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Critical,
            "test_module",
            "Test encryption operation",
        );
        
        let system = ExternalSystem::Soc("ArcSight".to_string());
        let leef = format_as_leef(&entry, &system)?;
        
        assert!(leef.starts_with("LEEF:1.0|Obscura|CryptoModule|1.0|"));
        assert!(leef.contains("level=Critical"));
        assert!(leef.contains("module=test_module"));
        
        Ok(())
    }

    #[test]
    fn test_external_integration_manager() -> CryptoResult<()> {
        let config = ExternalIntegrationConfig {
            enabled: true,
            min_level: AuditLevel::Warning,
            systems: vec![
                ExternalSystemConfig {
                    system: ExternalSystem::Siem("Splunk".to_string()),
                    endpoint_url: "https://example.com/splunk".to_string(),
                    format: ExternalDataFormat::Json,
                    config: None,
                    enabled: true,
                    authentication: None,
                }
            ],
            max_batch_size: 100,
            secure_transport: true,
            authentication: ExternalAuthConfig::None,
            retry_on_failure: true,
            max_retries: 3,
            retry_delay_seconds: 5,
        };
        
        let manager = ExternalIntegrationManager::new(config);
        
        // Test info level entry should not be sent (below min_level)
        let info_entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Info,
            "test_module",
            "Info level entry",
        );
        
        manager.send_entry(&info_entry)?;
        
        // Test warning level entry should be sent
        let warning_entry = AuditEntry::new(
            CryptoOperationType::Encryption,
            OperationStatus::Success,
            AuditLevel::Warning,
            "test_module",
            "Warning level entry",
        );
        
        manager.send_entry(&warning_entry)?;
        
        // Check system status
        let status = manager.get_system_status()?;
        assert_eq!(status.len(), 1);
        
        // In a real implementation, we would validate the connection and sends
        // For now, just check that the status entry exists
        assert_eq!(status[0].system, ExternalSystem::Siem("Splunk".to_string()));
        
        Ok(())
    }
} 