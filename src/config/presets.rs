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

/// Field descriptor for PrivacyPreset fields
#[derive(Debug, Clone)]
pub struct FieldDescriptor {
    /// Name of the field
    pub name: &'static str,
    /// Type of field (for debugging)
    pub field_type: &'static str,
    /// Function to get the value from a PrivacyPreset
    getter: fn(&PrivacyPreset) -> String,
}

impl FieldDescriptor {
    /// Get the value from a PrivacyPreset
    pub fn get_from(&self, preset: &PrivacyPreset) -> String {
        (self.getter)(preset)
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
    /// Returns an iterator over all field descriptors in the PrivacyPreset
    pub fn field_iter(&self) -> impl Iterator<Item = FieldDescriptor> {
        vec![
            FieldDescriptor { 
                name: "level", 
                field_type: "PrivacyLevel",
                getter: |p| format!("{:?}", p.level)
            },
            FieldDescriptor { 
                name: "use_tor", 
                field_type: "bool",
                getter: |p| format!("{}", p.use_tor)
            },
            FieldDescriptor { 
                name: "tor_stream_isolation", 
                field_type: "bool",
                getter: |p| format!("{}", p.tor_stream_isolation)
            },
            FieldDescriptor { 
                name: "tor_only_connections", 
                field_type: "bool",
                getter: |p| format!("{}", p.tor_only_connections)
            },
            FieldDescriptor { 
                name: "use_i2p", 
                field_type: "bool",
                getter: |p| format!("{}", p.use_i2p)
            },
            FieldDescriptor { 
                name: "use_dandelion", 
                field_type: "bool",
                getter: |p| format!("{}", p.use_dandelion)
            },
            FieldDescriptor { 
                name: "dandelion_stem_phase_hops", 
                field_type: "usize",
                getter: |p| format!("{}", p.dandelion_stem_phase_hops)
            },
            FieldDescriptor { 
                name: "dandelion_traffic_analysis_protection", 
                field_type: "bool",
                getter: |p| format!("{}", p.dandelion_traffic_analysis_protection)
            },
            FieldDescriptor { 
                name: "use_circuit_routing", 
                field_type: "bool",
                getter: |p| format!("{}", p.use_circuit_routing)
            },
            FieldDescriptor { 
                name: "circuit_min_hops", 
                field_type: "usize",
                getter: |p| format!("{}", p.circuit_min_hops)
            },
            FieldDescriptor { 
                name: "circuit_max_hops", 
                field_type: "usize",
                getter: |p| format!("{}", p.circuit_max_hops)
            },
            FieldDescriptor { 
                name: "connection_obfuscation_enabled", 
                field_type: "bool",
                getter: |p| format!("{}", p.connection_obfuscation_enabled)
            },
            FieldDescriptor { 
                name: "traffic_pattern_obfuscation", 
                field_type: "bool",
                getter: |p| format!("{}", p.traffic_pattern_obfuscation)
            },
            FieldDescriptor { 
                name: "use_bridge_relays", 
                field_type: "bool",
                getter: |p| format!("{}", p.use_bridge_relays)
            },
            FieldDescriptor { 
                name: "use_stealth_addresses", 
                field_type: "bool",
                getter: |p| format!("{}", p.use_stealth_addresses)
            },
            FieldDescriptor { 
                name: "stealth_address_reuse_prevention", 
                field_type: "bool",
                getter: |p| format!("{}", p.stealth_address_reuse_prevention)
            },
            FieldDescriptor { 
                name: "use_confidential_transactions", 
                field_type: "bool",
                getter: |p| format!("{}", p.use_confidential_transactions)
            },
            FieldDescriptor { 
                name: "use_range_proofs", 
                field_type: "bool",
                getter: |p| format!("{}", p.use_range_proofs)
            },
            FieldDescriptor { 
                name: "transaction_obfuscation_enabled", 
                field_type: "bool",
                getter: |p| format!("{}", p.transaction_obfuscation_enabled)
            },
            FieldDescriptor { 
                name: "transaction_graph_protection", 
                field_type: "bool",
                getter: |p| format!("{}", p.transaction_graph_protection)
            },
            FieldDescriptor { 
                name: "metadata_stripping", 
                field_type: "bool",
                getter: |p| format!("{}", p.metadata_stripping)
            },
            FieldDescriptor { 
                name: "constant_time_operations", 
                field_type: "bool",
                getter: |p| format!("{}", p.constant_time_operations)
            },
            FieldDescriptor { 
                name: "operation_masking", 
                field_type: "bool",
                getter: |p| format!("{}", p.operation_masking)
            },
            FieldDescriptor { 
                name: "timing_jitter", 
                field_type: "bool",
                getter: |p| format!("{}", p.timing_jitter)
            },
            FieldDescriptor { 
                name: "cache_attack_mitigation", 
                field_type: "bool",
                getter: |p| format!("{}", p.cache_attack_mitigation)
            },
            FieldDescriptor { 
                name: "secure_memory_clearing", 
                field_type: "bool",
                getter: |p| format!("{}", p.secure_memory_clearing)
            },
            FieldDescriptor { 
                name: "encrypted_memory", 
                field_type: "bool",
                getter: |p| format!("{}", p.encrypted_memory)
            },
            FieldDescriptor { 
                name: "guard_pages", 
                field_type: "bool",
                getter: |p| format!("{}", p.guard_pages)
            },
            FieldDescriptor { 
                name: "access_pattern_obfuscation", 
                field_type: "bool",
                getter: |p| format!("{}", p.access_pattern_obfuscation)
            },
            FieldDescriptor { 
                name: "view_key_granular_control", 
                field_type: "bool",
                getter: |p| format!("{}", p.view_key_granular_control)
            },
            FieldDescriptor { 
                name: "time_bound_view_keys", 
                field_type: "bool",
                getter: |p| format!("{}", p.time_bound_view_keys)
            },
        ].into_iter()
    }

    /// Get the value of a field by name
    pub fn get_field_value(&self, field_name: &str) -> Option<String> {
        match field_name {
            "level" => Some(format!("{:?}", self.level)),
            "use_tor" => Some(format!("{}", self.use_tor)),
            "tor_stream_isolation" => Some(format!("{}", self.tor_stream_isolation)),
            "tor_only_connections" => Some(format!("{}", self.tor_only_connections)),
            "use_i2p" => Some(format!("{}", self.use_i2p)),
            "use_dandelion" => Some(format!("{}", self.use_dandelion)),
            "dandelion_stem_phase_hops" => Some(format!("{}", self.dandelion_stem_phase_hops)),
            "dandelion_traffic_analysis_protection" => Some(format!("{}", self.dandelion_traffic_analysis_protection)),
            "use_circuit_routing" => Some(format!("{}", self.use_circuit_routing)),
            "circuit_min_hops" => Some(format!("{}", self.circuit_min_hops)),
            "circuit_max_hops" => Some(format!("{}", self.circuit_max_hops)),
            "connection_obfuscation_enabled" => Some(format!("{}", self.connection_obfuscation_enabled)),
            "traffic_pattern_obfuscation" => Some(format!("{}", self.traffic_pattern_obfuscation)),
            "use_bridge_relays" => Some(format!("{}", self.use_bridge_relays)),
            "use_stealth_addresses" => Some(format!("{}", self.use_stealth_addresses)),
            "stealth_address_reuse_prevention" => Some(format!("{}", self.stealth_address_reuse_prevention)),
            "use_confidential_transactions" => Some(format!("{}", self.use_confidential_transactions)),
            "use_range_proofs" => Some(format!("{}", self.use_range_proofs)),
            "transaction_obfuscation_enabled" => Some(format!("{}", self.transaction_obfuscation_enabled)),
            "transaction_graph_protection" => Some(format!("{}", self.transaction_graph_protection)),
            "metadata_stripping" => Some(format!("{}", self.metadata_stripping)),
            "constant_time_operations" => Some(format!("{}", self.constant_time_operations)),
            "operation_masking" => Some(format!("{}", self.operation_masking)),
            "timing_jitter" => Some(format!("{}", self.timing_jitter)),
            "cache_attack_mitigation" => Some(format!("{}", self.cache_attack_mitigation)),
            "secure_memory_clearing" => Some(format!("{}", self.secure_memory_clearing)),
            "encrypted_memory" => Some(format!("{}", self.encrypted_memory)),
            "guard_pages" => Some(format!("{}", self.guard_pages)),
            "access_pattern_obfuscation" => Some(format!("{}", self.access_pattern_obfuscation)),
            "view_key_granular_control" => Some(format!("{}", self.view_key_granular_control)),
            "time_bound_view_keys" => Some(format!("{}", self.time_bound_view_keys)),
            _ => None,
        }
    }

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