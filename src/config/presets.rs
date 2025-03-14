use std::fmt;
use serde::{Serialize, Deserialize};

/// Privacy levels available in Obscura
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrivacyLevel {
    /// Standard privacy (basic protections)
    Standard,
    /// Medium privacy (enhanced protections)
    Medium,
    /// High privacy (maximum protections)
    High,
    /// Custom privacy (user-defined settings)
    Custom,
}

impl Default for PrivacyLevel {
    fn default() -> Self {
        PrivacyLevel::Medium
    }
}

impl fmt::Display for PrivacyLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrivacyLevel::Standard => write!(f, "Standard"),
            PrivacyLevel::Medium => write!(f, "Medium"),
            PrivacyLevel::High => write!(f, "High"),
            PrivacyLevel::Custom => write!(f, "Custom"),
        }
    }
}

/// Unified privacy preset configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyPreset {
    /// The privacy level of this preset
    pub level: PrivacyLevel,
    
    /// Network privacy settings
    
    // Tor settings
    pub use_tor: bool,
    pub tor_stream_isolation: bool,
    pub tor_only_connections: bool,
    
    // I2P settings
    pub use_i2p: bool,
    
    // Dandelion++ settings
    pub use_dandelion: bool,
    pub dandelion_stem_phase_hops: usize,
    pub dandelion_traffic_analysis_protection: bool,
    
    // Circuit-based routing
    pub use_circuit_routing: bool,
    pub circuit_min_hops: usize,
    pub circuit_max_hops: usize,
    
    // Connection obfuscation
    pub connection_obfuscation_enabled: bool,
    pub traffic_pattern_obfuscation: bool,
    pub use_bridge_relays: bool,
    
    /// Transaction privacy settings
    
    // Stealth addresses
    pub use_stealth_addresses: bool,
    pub stealth_address_reuse_prevention: bool,
    
    // Confidential transactions
    pub use_confidential_transactions: bool,
    pub use_range_proofs: bool,
    
    // Transaction obfuscation
    pub transaction_obfuscation_enabled: bool,
    pub transaction_graph_protection: bool,
    pub metadata_stripping: bool,
    
    /// Cryptographic privacy settings
    
    // Side-channel protection
    pub constant_time_operations: bool,
    pub operation_masking: bool,
    pub timing_jitter: bool,
    pub cache_attack_mitigation: bool,
    
    // Memory protection
    pub secure_memory_clearing: bool,
    pub encrypted_memory: bool,
    pub guard_pages: bool,
    pub access_pattern_obfuscation: bool,
    
    /// View key settings
    pub view_key_granular_control: bool,
    pub time_bound_view_keys: bool,
}

impl PrivacyPreset {
    /// Create a standard privacy preset (basic protections)
    pub fn standard() -> Self {
        Self {
            level: PrivacyLevel::Standard,
            
            // Network privacy - Standard
            use_tor: false,
            tor_stream_isolation: false,
            tor_only_connections: false,
            use_i2p: false,
            use_dandelion: true,
            dandelion_stem_phase_hops: 2,
            dandelion_traffic_analysis_protection: false,
            use_circuit_routing: false,
            circuit_min_hops: 1,
            circuit_max_hops: 2,
            connection_obfuscation_enabled: true,
            traffic_pattern_obfuscation: false,
            use_bridge_relays: false,
            
            // Transaction privacy - Standard
            use_stealth_addresses: true,
            stealth_address_reuse_prevention: true,
            use_confidential_transactions: false,
            use_range_proofs: false,
            transaction_obfuscation_enabled: true,
            transaction_graph_protection: false,
            metadata_stripping: true,
            
            // Cryptographic privacy - Standard
            constant_time_operations: true,
            operation_masking: false,
            timing_jitter: false,
            cache_attack_mitigation: false,
            secure_memory_clearing: true,
            encrypted_memory: false,
            guard_pages: false,
            access_pattern_obfuscation: false,
            
            // View keys - Standard
            view_key_granular_control: false,
            time_bound_view_keys: false,
        }
    }
    
    /// Create a medium privacy preset (enhanced protections)
    pub fn medium() -> Self {
        Self {
            level: PrivacyLevel::Medium,
            
            // Network privacy - Medium
            use_tor: true,
            tor_stream_isolation: true,
            tor_only_connections: false,
            use_i2p: false,
            use_dandelion: true,
            dandelion_stem_phase_hops: 3,
            dandelion_traffic_analysis_protection: true,
            use_circuit_routing: true,
            circuit_min_hops: 2,
            circuit_max_hops: 3,
            connection_obfuscation_enabled: true,
            traffic_pattern_obfuscation: true,
            use_bridge_relays: false,
            
            // Transaction privacy - Medium
            use_stealth_addresses: true,
            stealth_address_reuse_prevention: true,
            use_confidential_transactions: true,
            use_range_proofs: true,
            transaction_obfuscation_enabled: true,
            transaction_graph_protection: true,
            metadata_stripping: true,
            
            // Cryptographic privacy - Medium
            constant_time_operations: true,
            operation_masking: true,
            timing_jitter: true,
            cache_attack_mitigation: true,
            secure_memory_clearing: true,
            encrypted_memory: true,
            guard_pages: true,
            access_pattern_obfuscation: false,
            
            // View keys - Medium
            view_key_granular_control: true,
            time_bound_view_keys: false,
        }
    }
    
    /// Create a high privacy preset (maximum protections)
    pub fn high() -> Self {
        Self {
            level: PrivacyLevel::High,
            
            // Network privacy - High
            use_tor: true,
            tor_stream_isolation: true,
            tor_only_connections: true,
            use_i2p: true,
            use_dandelion: true,
            dandelion_stem_phase_hops: 5,
            dandelion_traffic_analysis_protection: true,
            use_circuit_routing: true,
            circuit_min_hops: 3,
            circuit_max_hops: 5,
            connection_obfuscation_enabled: true,
            traffic_pattern_obfuscation: true,
            use_bridge_relays: true,
            
            // Transaction privacy - High
            use_stealth_addresses: true,
            stealth_address_reuse_prevention: true,
            use_confidential_transactions: true,
            use_range_proofs: true,
            transaction_obfuscation_enabled: true,
            transaction_graph_protection: true,
            metadata_stripping: true,
            
            // Cryptographic privacy - High
            constant_time_operations: true,
            operation_masking: true,
            timing_jitter: true,
            cache_attack_mitigation: true,
            secure_memory_clearing: true,
            encrypted_memory: true,
            guard_pages: true,
            access_pattern_obfuscation: true,
            
            // View keys - High
            view_key_granular_control: true,
            time_bound_view_keys: true,
        }
    }
    
    /// Create a custom privacy preset from specific settings
    pub fn custom() -> Self {
        let mut preset = Self::medium();
        preset.level = PrivacyLevel::Custom;
        preset
    }
} 