use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use log::{debug, error, info, trace, warn};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use rand::{seq::SliceRandom, thread_rng};
use rand_core::RngCore;

/// Error types for DNS-over-HTTPS operations
#[derive(Error, Debug)]
pub enum DoHError {
    #[error("DNS resolver request failed: {0}")]
    RequestFailed(String),
    
    #[error("DNS response invalid: {0}")]
    InvalidResponse(String),
    
    #[error("DNS resolver configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("DNS resolver unavailable")]
    ResolverUnavailable,
    
    #[error("DNS resolution failed: No results for {0}")]
    ResolutionFailed(String),
    
    #[error("DNS resolution timeout for {0}")]
    Timeout(String),
    
    #[error("DNS cache error: {0}")]
    CacheError(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// DNS-over-HTTPS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    A,     // IPv4 address
    AAAA,  // IPv6 address
    SRV,   // Service record
    TXT,   // Text record
}

impl RecordType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::SRV => "SRV",
            RecordType::TXT => "TXT",
        }
    }
}

/// Public DNS-over-HTTPS providers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoHProvider {
    Cloudflare,
    Google,
    Quad9,
    Custom,
}

impl DoHProvider {
    pub fn url(&self) -> &'static str {
        match self {
            DoHProvider::Cloudflare => "https://cloudflare-dns.com/dns-query",
            DoHProvider::Google => "https://dns.google/resolve",
            DoHProvider::Quad9 => "https://dns.quad9.net/dns-query",
            DoHProvider::Custom => "",  // Set by the user
        }
    }
    
    /// Get a random DoH provider
    pub fn random() -> Self {
        let providers = [
            DoHProvider::Cloudflare,
            DoHProvider::Google,
            DoHProvider::Quad9,
            DoHProvider::Custom,
        ];
        
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 8];
        rng.try_fill_bytes(&mut bytes);
        let value = u64::from_le_bytes(bytes) as usize;
        providers[value % providers.len()]
    }
}

/// DNS-over-HTTPS response formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoHFormat {
    Json,
    Wire,
}

/// DNS-over-HTTPS configuration
#[derive(Debug, Clone)]
pub struct DoHConfig {
    /// Enable or disable DNS-over-HTTPS
    pub enabled: bool,
    
    /// Primary DNS-over-HTTPS provider
    pub primary_provider: DoHProvider,
    
    /// Fallback DNS-over-HTTPS provider
    pub fallback_provider: DoHProvider,
    
    /// Custom DNS-over-HTTPS URL (used if primary_provider is Custom)
    pub custom_url: String,
    
    /// Request format (JSON or DNS wire format)
    pub format: DoHFormat,
    
    /// Request timeout in seconds
    pub timeout_secs: u64,
    
    /// Cache TTL for successful resolutions
    pub cache_ttl_secs: u64,
    
    /// Cache TTL for failed resolutions
    pub negative_cache_ttl_secs: u64,
    
    /// Maximum cache size
    pub max_cache_size: usize,
    
    /// Randomize resolver selection for enhanced privacy
    pub randomize_resolver: bool,
    
    /// Use multiple resolvers and compare results for security
    pub verify_with_multiple_resolvers: bool,
    
    /// Automatically rotate resolvers
    pub rotate_resolvers: bool,
    
    /// Time interval between resolver rotations
    pub rotation_interval_secs: u64,
}

impl Default for DoHConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            primary_provider: DoHProvider::Cloudflare,
            fallback_provider: DoHProvider::Google,
            custom_url: String::new(),
            format: DoHFormat::Json,
            timeout_secs: 10,
            cache_ttl_secs: 300,  // 5 minutes
            negative_cache_ttl_secs: 60,  // 1 minute
            max_cache_size: 1000,
            randomize_resolver: true,
            verify_with_multiple_resolvers: false,
            rotate_resolvers: true,
            rotation_interval_secs: 3600,  // 1 hour
        }
    }
}

/// DNS cache entry
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Resolved IP addresses
    addresses: Vec<IpAddr>,
    /// Time when the entry was created
    created_at: Instant,
    /// Time-to-live in seconds
    ttl: u64,
    /// Record type
    record_type: RecordType,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.created_at.elapsed().as_secs() > self.ttl
    }
}

/// DNS-over-HTTPS response structure (JSON format)
#[derive(Debug, Deserialize, Serialize)]
struct DoHResponse {
    #[serde(default)]
    #[serde(rename = "Answer")]
    answer: Vec<DoHAnswer>,
    #[serde(rename = "Status")]
    status: Option<u32>,
    #[serde(rename = "Question")]
    #[serde(default)]
    questions: Vec<DoHQuestion>,
}

#[derive(Debug, Deserialize, Serialize)]
struct DoHAnswer {
    name: String,
    #[serde(rename = "type")]
    record_type: u32,
    #[serde(rename = "TTL")]
    ttl: u32,
    data: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct DoHQuestion {
    name: String,
    #[serde(rename = "type")]
    record_type: u32,
}

/// DNS-over-HTTPS service
pub struct DoHService {
    /// Service configuration
    config: DoHConfig,
    
    /// HTTP client for DNS-over-HTTPS requests
    client: Client,
    
    /// DNS cache
    cache: Arc<RwLock<HashMap<(String, RecordType), CacheEntry>>>,
    
    /// Current resolver
    current_resolver: Arc<Mutex<DoHProvider>>,
    
    /// Last resolver rotation time
    last_rotation: Arc<Mutex<Instant>>,
}

impl DoHService {
    /// Create a new DNS-over-HTTPS service with default configuration
    pub fn new() -> Self {
        Self::with_config(DoHConfig::default())
    }
    
    /// Create a new DNS-over-HTTPS service with custom configuration
    pub fn with_config(config: DoHConfig) -> Self {
        // Create an HTTP client with appropriate timeout
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .expect("Failed to create HTTP client");
        
        Self {
            config,
            client,
            cache: Arc::new(RwLock::new(HashMap::new())),
            current_resolver: Arc::new(Mutex::new(DoHProvider::Cloudflare)),
            last_rotation: Arc::new(Mutex::new(Instant::now())),
        }
    }
    
    /// Resolve a hostname to IP addresses
    pub async fn resolve(&self, hostname: &str, record_type: RecordType) -> Result<Vec<IpAddr>, DoHError> {
        if !self.config.enabled {
            return Err(DoHError::ConfigurationError("DNS-over-HTTPS is disabled".to_string()));
        }
        
        // Check the cache first
        let cache_key = (hostname.to_lowercase(), record_type);
        {
            let cache_read = self.cache.read().map_err(|e| 
                DoHError::CacheError(format!("Failed to acquire cache read lock: {}", e)))?;
            
            if let Some(entry) = cache_read.get(&cache_key) {
                if !entry.is_expired() {
                    trace!("DNS cache hit for {}", hostname);
                    return Ok(entry.addresses.clone());
                }
                trace!("DNS cache expired for {}", hostname);
            } else {
                trace!("DNS cache miss for {}", hostname);
            }
        }
        
        // Check if we need to rotate resolvers
        self.maybe_rotate_resolver().await;
        
        // Get the current resolver
        let resolver = if self.config.randomize_resolver {
            DoHProvider::random()
        } else {
            self.current_resolver.lock().map_err(|e| 
                DoHError::InternalError(format!("Failed to acquire resolver lock: {}", e)))?.clone()
        };
        
        // Resolve the hostname
        let result = self.resolve_with_provider(hostname, record_type, resolver).await;
        
        // If resolution failed, try the fallback resolver
        if result.is_err() && resolver != self.config.fallback_provider {
            debug!("Primary resolver failed, trying fallback for {}", hostname);
            return self.resolve_with_provider(hostname, record_type, self.config.fallback_provider).await;
        }
        
        // Verify with multiple resolvers if configured
        if self.config.verify_with_multiple_resolvers && result.is_ok() {
            let primary_results = result.as_ref().unwrap();
            let fallback_resolver = if resolver == self.config.primary_provider {
                self.config.fallback_provider
            } else {
                self.config.primary_provider
            };
            
            match self.resolve_with_provider(hostname, record_type, fallback_resolver).await {
                Ok(fallback_results) => {
                    // Compare results
                    if primary_results != &fallback_results {
                        warn!("DNS resolution mismatch for {}: primary and fallback resolvers returned different results", 
                            hostname);
                        // Could implement more sophisticated validation here
                    } else {
                        debug!("DNS resolution verified for {}", hostname);
                    }
                }
                Err(e) => {
                    warn!("Failed to verify DNS resolution for {}: {:?}", hostname, e);
                }
            }
        }
        
        result
    }
    
    /// Resolve a hostname using a specific DNS-over-HTTPS provider
    async fn resolve_with_provider(&self, hostname: &str, record_type: RecordType, provider: DoHProvider) 
        -> Result<Vec<IpAddr>, DoHError> {
        let resolver_url = match provider {
            DoHProvider::Custom => {
                if self.config.custom_url.is_empty() {
                    return Err(DoHError::ConfigurationError("Custom DNS-over-HTTPS URL not set".to_string()));
                }
                &self.config.custom_url
            }
            _ => provider.url(),
        };
        
        // Determine which resolver format to use
        match self.config.format {
            DoHFormat::Json => self.resolve_json(hostname, record_type, resolver_url).await,
            DoHFormat::Wire => self.resolve_wire(hostname, record_type, resolver_url).await,
        }
    }
    
    /// Resolve a hostname using JSON format
    async fn resolve_json(&self, hostname: &str, record_type: RecordType, resolver_url: &str) 
        -> Result<Vec<IpAddr>, DoHError> {
        let url = Url::parse_with_params(
            resolver_url, 
            &[
                ("name", hostname), 
                ("type", record_type.as_str()),
                ("ct", "application/dns-json"),
            ]
        ).map_err(|e| DoHError::ConfigurationError(format!("Invalid resolver URL: {}", e)))?;
        
        let response = self.client.get(url)
            .header("Accept", "application/dns-json")
            .send()
            .await
            .map_err(|e| DoHError::RequestFailed(format!("Request failed: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(DoHError::RequestFailed(format!(
                "Request failed with status: {}", response.status()
            )));
        }
        
        let dns_response: DoHResponse = response.json()
            .await
            .map_err(|e| DoHError::InvalidResponse(format!("Invalid response format: {}", e)))?;
        
        // Check for DNS error codes
        if let Some(status) = dns_response.status {
            if status != 0 {
                return Err(DoHError::ResolutionFailed(format!(
                    "DNS resolution failed with status: {}", status
                )));
            }
        }
        
        if dns_response.answer.is_empty() {
            return Err(DoHError::ResolutionFailed(format!(
                "No DNS records found for {}", hostname
            )));
        }
        
        // Process answers
        let mut addresses = Vec::new();
        let mut min_ttl = u64::MAX;
        
        for answer in dns_response.answer {
            // Check if the record type matches what we requested
            let answer_type = match answer.record_type {
                1 => RecordType::A,
                28 => RecordType::AAAA,
                33 => RecordType::SRV,
                16 => RecordType::TXT,
                _ => continue, // Skip unknown record types
            };
            
            if answer_type != record_type {
                continue;
            }
            
            // Parse IP address from data
            match record_type {
                RecordType::A | RecordType::AAAA => {
                    match IpAddr::from_str(&answer.data) {
                        Ok(ip) => addresses.push(ip),
                        Err(e) => warn!("Failed to parse IP address '{}': {}", answer.data, e),
                    }
                },
                _ => {} // Handle other record types if needed
            }
            
            // Track minimum TTL
            min_ttl = min_ttl.min(answer.ttl as u64);
        }
        
        if addresses.is_empty() {
            return Err(DoHError::ResolutionFailed(format!(
                "No valid IP addresses found for {}", hostname
            )));
        }
        
        // Cache the result
        let cache_key = (hostname.to_lowercase(), record_type);
        let ttl = if min_ttl == u64::MAX { self.config.cache_ttl_secs } else { min_ttl };
        
        let entry = CacheEntry {
            addresses: addresses.clone(),
            created_at: Instant::now(),
            ttl,
            record_type,
        };
        
        let mut cache_write = self.cache.write().map_err(|e| 
            DoHError::CacheError(format!("Failed to acquire cache write lock: {}", e)))?;
        
        // Enforce cache size limit
        if cache_write.len() >= self.config.max_cache_size {
            // Remove oldest entries
            let mut entries: Vec<_> = cache_write.iter().collect();
            entries.sort_by_key(|(_, entry)| entry.created_at);
            
            // Remove oldest 10% of entries
            let to_remove = (self.config.max_cache_size / 10).max(1);
            
            // Collect keys to remove first, then remove them afterwards to avoid borrowing issues
            let keys_to_remove: Vec<_> = entries.iter().take(to_remove).map(|(k, _)| (*k).clone()).collect();
            for key in keys_to_remove {
                cache_write.remove(&key);
            }
        }
        
        cache_write.insert(cache_key, entry);
        
        Ok(addresses)
    }
    
    /// Resolve a hostname using DNS wire format
    async fn resolve_wire(&self, _hostname: &str, _record_type: RecordType, _resolver_url: &str) 
        -> Result<Vec<IpAddr>, DoHError> {
        // Implementation for DNS wire format (RFC 8484)
        // This is more complex and would require DNS packet construction
        // For simplicity, we'll use the JSON format as primary implementation
        Err(DoHError::ConfigurationError("DNS wire format not yet implemented".to_string()))
    }
    
    /// Resolve a hostname to socket addresses
    pub async fn resolve_to_sockets(&self, hostname: &str, port: u16) -> Result<Vec<SocketAddr>, DoHError> {
        // Try IPv4 first
        let mut addresses = Vec::new();
        
        match self.resolve(hostname, RecordType::A).await {
            Ok(ipv4_addrs) => {
                for ip in ipv4_addrs {
                    addresses.push(SocketAddr::new(ip, port));
                }
            }
            Err(e) => {
                debug!("Failed to resolve IPv4 addresses for {}: {:?}", hostname, e);
                // Continue to IPv6, don't return error yet
            }
        }
        
        // Try IPv6 if no IPv4 addresses found
        if addresses.is_empty() {
            match self.resolve(hostname, RecordType::AAAA).await {
                Ok(ipv6_addrs) => {
                    for ip in ipv6_addrs {
                        addresses.push(SocketAddr::new(ip, port));
                    }
                }
                Err(e) => {
                    if addresses.is_empty() {
                        return Err(e); // Return error only if no addresses were found
                    }
                }
            }
        }
        
        if addresses.is_empty() {
            return Err(DoHError::ResolutionFailed(format!(
                "No addresses found for {}", hostname
            )));
        }
        
        Ok(addresses)
    }
    
    /// Clear the DNS cache
    pub fn clear_cache(&self) -> Result<(), DoHError> {
        let mut cache_write = self.cache.write().map_err(|e| 
            DoHError::CacheError(format!("Failed to acquire cache write lock: {}", e)))?;
        
        cache_write.clear();
        Ok(())
    }
    
    /// Check if we need to rotate resolvers
    async fn maybe_rotate_resolver(&self) {
        if !self.config.rotate_resolvers {
            return;
        }
        
        let rotation_needed = {
            let last_rotation = self.last_rotation.lock().unwrap();
            last_rotation.elapsed().as_secs() > self.config.rotation_interval_secs
        };
        
        if rotation_needed {
            let mut last_rotation = self.last_rotation.lock().unwrap();
            let mut current_resolver = self.current_resolver.lock().unwrap();
            
            // Rotate between primary and fallback
            *current_resolver = if *current_resolver == self.config.primary_provider {
                self.config.fallback_provider
            } else {
                self.config.primary_provider
            };
            
            *last_rotation = Instant::now();
            debug!("Rotated DNS resolver to {:?}", *current_resolver);
        }
    }
    
    /// Periodically clean expired cache entries
    pub fn prune_cache(&self) -> Result<usize, DoHError> {
        let mut cache_write = self.cache.write().map_err(|e| 
            DoHError::CacheError(format!("Failed to acquire cache write lock: {}", e)))?;
        
        let before_count = cache_write.len();
        cache_write.retain(|_, entry| !entry.is_expired());
        let after_count = cache_write.len();
        
        Ok(before_count - after_count)
    }
    
    /// Get a reference to the config
    pub fn config(&self) -> &DoHConfig {
        &self.config
    }
    
    /// Get mutable reference to the config
    pub fn config_mut(&mut self) -> &mut DoHConfig {
        &mut self.config
    }
    
    /// Resolve seed nodes
    pub async fn resolve_seed_nodes(&self, seeds: &[String], default_port: u16) -> Vec<SocketAddr> {
        let mut resolved_addresses = Vec::new();
        
        for seed in seeds {
            // Parse hostname and port
            let (hostname, port) = if let Some(colon_pos) = seed.rfind(':') {
                let port_str = &seed[colon_pos+1..];
                let hostname = &seed[0..colon_pos];
                
                match port_str.parse::<u16>() {
                    Ok(port) => (hostname, port),
                    Err(_) => (seed.as_str(), default_port),
                }
            } else {
                (seed.as_str(), default_port)
            };
            
            // Check if it's already an IP address
            if let Ok(ip) = hostname.parse::<IpAddr>() {
                resolved_addresses.push(SocketAddr::new(ip, port));
                continue;
            }
            
            // Resolve the hostname
            match self.resolve_to_sockets(hostname, port).await {
                Ok(addresses) => {
                    info!("Resolved seed node {} to {} addresses", hostname, addresses.len());
                    resolved_addresses.extend(addresses);
                }
                Err(e) => {
                    warn!("Failed to resolve seed node {}: {:?}", hostname, e);
                }
            }
        }
        
        resolved_addresses
    }
    
    /// Check if the service is available
    pub async fn is_available(&self) -> bool {
        if !self.config.enabled {
            return false;
        }
        
        // Try a simple query to check availability
        match self.resolve("example.com", RecordType::A).await {
            Ok(_) => true,
            Err(e) => {
                warn!("DNS-over-HTTPS service check failed: {:?}", e);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;
    
    #[test]
    fn test_doh_provider_url() {
        assert_eq!(DoHProvider::Cloudflare.url(), "https://cloudflare-dns.com/dns-query");
        assert_eq!(DoHProvider::Google.url(), "https://dns.google/resolve");
        assert_eq!(DoHProvider::Quad9.url(), "https://dns.quad9.net/dns-query");
    }
    
    #[test]
    fn test_record_type_as_str() {
        assert_eq!(RecordType::A.as_str(), "A");
        assert_eq!(RecordType::AAAA.as_str(), "AAAA");
        assert_eq!(RecordType::SRV.as_str(), "SRV");
        assert_eq!(RecordType::TXT.as_str(), "TXT");
    }
    
    #[test]
    fn test_cache_entry_expiration() {
        let entry = CacheEntry {
            addresses: vec![],
            created_at: Instant::now() - Duration::from_secs(100),
            ttl: 60,
            record_type: RecordType::A,
        };
        
        assert!(entry.is_expired());
        
        let entry = CacheEntry {
            addresses: vec![],
            created_at: Instant::now(),
            ttl: 60,
            record_type: RecordType::A,
        };
        
        assert!(!entry.is_expired());
    }
    
    #[test]
    fn test_doh_config_default() {
        let config = DoHConfig::default();
        assert!(config.enabled);
        assert_eq!(config.primary_provider, DoHProvider::Cloudflare);
        assert_eq!(config.fallback_provider, DoHProvider::Google);
        assert_eq!(config.format, DoHFormat::Json);
        assert_eq!(config.timeout_secs, 10);
    }
    
    // Integration tests requiring network access
    #[test]
    #[ignore] // Marked as ignored because it requires network access
    fn test_resolve_hostname() {
        let rt = Runtime::new().unwrap();
        
        rt.block_on(async {
            let doh = DoHService::new();
            
            // Resolve a known hostname
            let result = doh.resolve("example.com", RecordType::A).await;
            assert!(result.is_ok());
            assert!(!result.unwrap().is_empty());
            
            // Resolve an invalid hostname
            let result = doh.resolve("invalid-hostname-that-does-not-exist-123456.example", RecordType::A).await;
            assert!(result.is_err());
        });
    }
    
    #[test]
    #[ignore] // Marked as ignored because it requires network access
    fn test_cache() {
        let rt = Runtime::new().unwrap();
        
        rt.block_on(async {
            let doh = DoHService::new();
            
            // First query (cache miss)
            let _ = doh.resolve("example.com", RecordType::A).await.unwrap();
            
            // Get current cache size
            let cache_size = doh.cache.read().unwrap().len();
            assert_eq!(cache_size, 1);
            
            // Second query (cache hit)
            let _ = doh.resolve("example.com", RecordType::A).await.unwrap();
            
            // Cache size should remain the same
            let cache_size = doh.cache.read().unwrap().len();
            assert_eq!(cache_size, 1);
            
            // Clear cache
            doh.clear_cache().unwrap();
            
            // Cache should be empty
            let cache_size = doh.cache.read().unwrap().len();
            assert_eq!(cache_size, 0);
        });
    }
} 