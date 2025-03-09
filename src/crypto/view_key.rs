use crate::blockchain::{Transaction, TransactionOutput};
use crate::crypto::jubjub::{JubjubKeypair, JubjubPoint, JubjubPointExt, JubjubScalar, JubjubScalarExt};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use std::collections::{HashMap, HashSet};
use ark_std::Zero;
use blake2b_simd;
use std::sync::{Arc, Mutex};
use log::{debug, info, warn};

/// Hierarchical view key levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewKeyLevel {
    /// Root level view key (full permissions within its scope)
    Root,
    /// Intermediate level (can derive child keys)
    Intermediate,
    /// Leaf level (cannot derive further keys)
    Leaf,
}

impl Default for ViewKeyLevel {
    fn default() -> Self {
        ViewKeyLevel::Leaf
    }
}

/// ViewKey provides the ability to view incoming transactions without spending capability
#[derive(Debug, Clone)]
pub struct ViewKey {
    /// The view key scalar (private component)
    view_scalar: JubjubScalar,
    /// The view key point (public component)
    view_point: JubjubPoint,
    /// Owner public key associated with this view key
    owner_public_key: JubjubPoint,
    /// Selective disclosure permissions
    permissions: ViewKeyPermissions,
    /// Hierarchical key level
    level: ViewKeyLevel,
    /// Hierarchical path (empty for root keys)
    path: Vec<u8>,
    /// Parent view key (if this is a derived key)
    parent: Option<Arc<ViewKey>>,
    /// Context restrictions (if any)
    context: Option<ViewKeyContext>,
}

/// Context for restricting where a view key can be used
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewKeyContext {
    /// Allowed blockchain networks (empty means any network)
    pub networks: Vec<String>,
    /// Allowed applications or services (empty means any application)
    pub applications: Vec<String>,
    /// Allowed IP addresses or ranges (empty means any IP)
    pub ip_restrictions: Vec<String>,
    /// Custom context identifiers
    pub custom_context: HashMap<String, String>,
}

/// Permissions for selective disclosure with view keys
#[derive(Debug, Clone)]
pub struct ViewKeyPermissions {
    /// Allow viewing incoming transactions
    pub view_incoming: bool,
    /// Allow viewing outgoing transactions (requires transaction linkage)
    pub view_outgoing: bool,
    /// Allow viewing transaction amounts
    pub view_amounts: bool,
    /// Allow viewing transaction timestamps
    pub view_timestamps: bool,
    /// Allow auditing (full transaction history access)
    pub full_audit: bool,
    /// Valid from timestamp (0 = no restriction)
    pub valid_from: u64,
    /// Valid until timestamp (0 = no restriction)
    pub valid_until: u64,
    /// Is this key allowed to derive child keys
    pub can_derive_keys: bool,
    /// Block height restrictions (0,0 = no restriction)
    pub valid_block_range: (u64, u64),
    /// Granular field visibility controls
    pub field_visibility: HashMap<String, bool>,
}

impl Default for ViewKeyPermissions {
    fn default() -> Self {
        Self {
            view_incoming: true,  // Changed to true since this is the basic permission
            view_outgoing: false,
            view_amounts: false,
            view_timestamps: false,
            full_audit: false,
            valid_from: 0,
            valid_until: 0,
            can_derive_keys: false,
            valid_block_range: (0, 0),
            field_visibility: HashMap::new(),
        }
    }
}

impl ViewKey {
    /// Generate a new view key from a wallet keypair with default permissions
    pub fn new(wallet_keypair: &JubjubKeypair) -> Self {
        Self::with_permissions(wallet_keypair, ViewKeyPermissions::default())
    }

    /// Create a new view key with permissions from a wallet keypair
    pub fn with_permissions(wallet_keypair: &JubjubKeypair, permissions: ViewKeyPermissions) -> Self {
        // A view key is derived from the wallet keypair
        // but only allows viewing incoming transactions, not spending
        
        // Get the wallet private and public keys
        let wallet_scalar = &wallet_keypair.secret; // Direct field access instead of method call
        let wallet_point = &wallet_keypair.public;   // Direct field access instead of method call
        
        // Hash the private key with a domain separator to create view key
        let mut hasher = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"ViewKeyDeriv0000")  // Must be exactly 16 bytes
            .to_state();
        
        hasher.update(&wallet_scalar.to_bytes());
        let hash_result = hasher.finalize().as_bytes().to_vec();
        
        // Create the view scalar from the hash
        let view_scalar = JubjubScalar::from_bytes(&hash_result[0..32]).unwrap_or_else(|| JubjubScalar::zero());
        
        // Create the view public key by multiplying the generator by the view scalar
        let view_point = JubjubPoint::generator() * view_scalar;
        
        // Return the view key with specified permissions
        Self {
            view_scalar,
            view_point,
            owner_public_key: wallet_point.clone(),
            permissions,
            level: ViewKeyLevel::Root,
            path: Vec::new(),
            parent: None,
            context: None,
        }
    }

    /// Create a hierarchical view key with a specific level
    pub fn with_level(
        wallet_keypair: &JubjubKeypair, 
        permissions: ViewKeyPermissions, 
        level: ViewKeyLevel
    ) -> Self {
        let mut key = Self::with_permissions(wallet_keypair, permissions);
        key.level = level;
        key
    }
    
    /// Derive a child view key from this key
    pub fn derive_child(&self, index: u32, permissions: ViewKeyPermissions) -> Option<Self> {
        // Only Root or Intermediate keys can derive children
        if self.level == ViewKeyLevel::Leaf || !self.permissions.can_derive_keys {
            return None;
        }
        
        // Create a child key path by extending the current path
        let mut child_path = self.path.clone();
        child_path.extend_from_slice(&index.to_le_bytes());
        
        // Calculate a new view scalar by hashing the parent scalar with the index
        let mut hasher = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"ViewKeyChild0000")  // Must be exactly 16 bytes
            .to_state();
            
        hasher.update(&self.view_scalar.to_bytes());
        hasher.update(&index.to_le_bytes());
        let hash_result = hasher.finalize().as_bytes().to_vec();
        
        // Create the child view scalar using from_le_bytes_mod_order which is more reliable
        let child_scalar = JubjubScalar::from_le_bytes_mod_order(&hash_result[0..32]);
        
        // The child view point is derived from the scalar
        let child_point = JubjubPoint::generator() * child_scalar;
        
        // Determine child level
        let child_level = match self.level {
            ViewKeyLevel::Root => ViewKeyLevel::Intermediate,
            ViewKeyLevel::Intermediate => ViewKeyLevel::Leaf,
            ViewKeyLevel::Leaf => return None, // Leaf keys cannot derive children
        };
        
        // Child permissions cannot exceed parent permissions
        let restricted_permissions = self.restrict_child_permissions(permissions);
        
        Some(Self {
            view_scalar: child_scalar,
            view_point: child_point,
            owner_public_key: self.owner_public_key.clone(),
            permissions: restricted_permissions,
            level: child_level,
            path: child_path,
            parent: Some(Arc::new(self.clone())),
            context: self.context.clone(),
        })
    }
    
    /// Get the hierarchical level of this view key
    pub fn level(&self) -> ViewKeyLevel {
        self.level
    }
    
    /// Get the key path (empty for root keys)
    pub fn path(&self) -> &[u8] {
        &self.path
    }
    
    /// Set a context restriction for this key
    pub fn set_context(&mut self, context: ViewKeyContext) {
        self.context = Some(context);
    }
    
    /// Get the context restriction (if any)
    pub fn context(&self) -> Option<&ViewKeyContext> {
        self.context.as_ref()
    }
    
    /// Restrict child permissions to be a subset of parent permissions
    fn restrict_child_permissions(&self, mut child_permissions: ViewKeyPermissions) -> ViewKeyPermissions {
        // Child cannot have more permissions than parent
        child_permissions.view_incoming &= self.permissions.view_incoming;
        child_permissions.view_outgoing &= self.permissions.view_outgoing;
        child_permissions.view_amounts &= self.permissions.view_amounts;
        child_permissions.view_timestamps &= self.permissions.view_timestamps;
        child_permissions.full_audit &= self.permissions.full_audit;
        
        // Time restrictions must be within parent's range
        if self.permissions.valid_from > 0 {
            child_permissions.valid_from = child_permissions.valid_from.max(self.permissions.valid_from);
        }
        
        if self.permissions.valid_until > 0 {
            child_permissions.valid_until = if child_permissions.valid_until > 0 {
                child_permissions.valid_until.min(self.permissions.valid_until)
            } else {
                self.permissions.valid_until
            };
        }
        
        // Block range restrictions
        if self.permissions.valid_block_range.0 > 0 {
            child_permissions.valid_block_range.0 = 
                child_permissions.valid_block_range.0.max(self.permissions.valid_block_range.0);
        }
        
        if self.permissions.valid_block_range.1 > 0 {
            child_permissions.valid_block_range.1 = if child_permissions.valid_block_range.1 > 0 {
                child_permissions.valid_block_range.1.min(self.permissions.valid_block_range.1)
            } else {
                self.permissions.valid_block_range.1
            };
        }
        
        // Field visibility constraints
        for (field, visible) in &self.permissions.field_visibility {
            if !visible {
                child_permissions.field_visibility.insert(field.clone(), false);
            }
        }
        
        child_permissions
    }
    
    /// Get the public component of the view key
    pub fn public_key(&self) -> &JubjubPoint {
        &self.view_point
    }
    
    /// Get the associated wallet public key
    pub fn owner_public_key(&self) -> &JubjubPoint {
        &self.owner_public_key
    }
    
    /// Get the view key permissions
    pub fn permissions(&self) -> &ViewKeyPermissions {
        &self.permissions
    }
    
    /// Update view key permissions
    pub fn update_permissions(&mut self, permissions: ViewKeyPermissions) {
        self.permissions = permissions;
    }
    
    /// Check if the view key is currently valid based on time restrictions
    pub fn is_valid(&self, current_time: u64) -> bool {
        let valid_from = self.permissions.valid_from;
        let valid_until = self.permissions.valid_until;
        
        // If both are 0, there's no time restriction
        if valid_from == 0 && valid_until == 0 {
            return true;
        }
        
        // Check valid_from if it's set
        if valid_from > 0 && current_time < valid_from {
            return false;
        }
        
        // Check valid_until if it's set
        if valid_until > 0 && current_time > valid_until {
            return false;
        }
        
        true
    }
    
    /// Scan a transaction to see if it contains outputs for the view key owner
    pub fn scan_transaction(&self, tx: &Transaction) -> Vec<TransactionOutput> {
        let mut outputs = Vec::new();
        
        // Only scan if we have permission to view incoming transactions
        if !self.permissions.view_incoming {
            return outputs;
        }
        
        for output in &tx.outputs {
            // Check if this output is addressed to the wallet associated with this view key
            if self.can_view_output(output) {
                outputs.push(output.clone());
            }
        }
        
        outputs
    }
    
    /// Determine if the view key can view a specific output
    fn can_view_output(&self, output: &TransactionOutput) -> bool {
        // Get the recipient's public key from the output
        // This is a simplified approach - in a real implementation,
        // you would need to handle stealth addressing and other privacy features
        if let Some(recipient_pubkey) = self.extract_recipient_pubkey(output) {
            // Check if the output is addressed to the owner of this view key
            return recipient_pubkey == self.owner_public_key;
        }
        
        false
    }
    
    /// Extract the recipient's public key from an output (simplified)
    fn extract_recipient_pubkey(&self, output: &TransactionOutput) -> Option<JubjubPoint> {
        // In a real implementation, this would handle stealth addresses,
        // one-time addresses, and other privacy features
        
        // For now, assume the recipient public key is directly encoded in the script
        // This is a placeholder - actual implementation would depend on your transaction format
        if output.public_key_script.len() >= 32 {  // Changed from 33 to 32 since that's the size we use in tests
            // Take first 32 bytes as the compressed public key
            let pubkey_bytes = &output.public_key_script[0..32];
            JubjubPoint::from_bytes(pubkey_bytes)
        } else {
            None
        }
    }
    
    /// Scan multiple transactions for outputs viewable by this key
    pub fn scan_transactions(&self, transactions: &[Transaction]) -> Vec<TransactionOutput> {
        let mut results = Vec::new();
        
        for tx in transactions {
            let outputs = self.scan_transaction(tx);
            results.extend(outputs);
        }
        
        results
    }
    
    /// Export the view key as bytes for sharing
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(81); // 32 + 32 + 17
        
        // Serialize the view point (public component)
        bytes.extend_from_slice(&self.view_point.to_bytes());
        
        // Serialize the owner's public key
        bytes.extend_from_slice(&self.owner_public_key.to_bytes());
        
        // Serialize permissions
        bytes.extend_from_slice(&self.serialize_permissions());
        
        bytes
    }
    
    /// Create a ViewKey from exported bytes (public components only)
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        // Check minimum required length: 32 bytes each for view point and owner key, plus 17 for permissions
        if bytes.len() < 81 {  // 32 + 32 + 17
            return None;
        }
        
        // Deserialize the view point
        let view_point = JubjubPoint::from_bytes(&bytes[0..32])?;
        
        // Deserialize the owner public key
        let owner_public_key = JubjubPoint::from_bytes(&bytes[32..64])?;
        
        // Deserialize permissions
        let permissions = Self::deserialize_permissions(&bytes[64..]);
        
        // Note: We can't restore the private scalar from the exported bytes,
        // so we set it to a zeroed scalar. This view key can verify but not decrypt.
        let view_scalar = JubjubScalar::zero();
        
        Some(Self {
            view_scalar,
            view_point,
            owner_public_key,
            permissions,
            level: ViewKeyLevel::Root,
            path: Vec::new(),
            parent: None,
            context: None,
        })
    }
    
    /// Serialize permissions to bytes
    fn serialize_permissions(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(17); // 1 byte flags + 8 bytes valid_from + 8 bytes valid_until
        
        // Pack boolean flags into a single byte
        let mut flags: u8 = 0;
        if self.permissions.view_incoming { flags |= 1 << 0; }
        if self.permissions.view_outgoing { flags |= 1 << 1; }
        if self.permissions.view_amounts { flags |= 1 << 2; }
        if self.permissions.view_timestamps { flags |= 1 << 3; }
        if self.permissions.full_audit { flags |= 1 << 4; }
        
        bytes.push(flags);
        
        // Add timestamp ranges (8 bytes each)
        bytes.extend_from_slice(&self.permissions.valid_from.to_le_bytes());
        bytes.extend_from_slice(&self.permissions.valid_until.to_le_bytes());
        
        bytes
    }
    
    /// Deserialize permissions from bytes
    fn deserialize_permissions(bytes: &[u8]) -> ViewKeyPermissions {
        if bytes.len() < 17 {  // 1 byte flags + 8 bytes valid_from + 8 bytes valid_until
            return ViewKeyPermissions::default();
        }
        
        let flags = bytes[0];
        
        let valid_from = u64::from_le_bytes([
            bytes[1], bytes[2], bytes[3], bytes[4], 
            bytes[5], bytes[6], bytes[7], bytes[8]
        ]);
        
        let valid_until = u64::from_le_bytes([
            bytes[9], bytes[10], bytes[11], bytes[12], 
            bytes[13], bytes[14], bytes[15], bytes[16]
        ]);
        
        ViewKeyPermissions {
            view_incoming: (flags & (1 << 0)) != 0,
            view_outgoing: (flags & (1 << 1)) != 0,
            view_amounts: (flags & (1 << 2)) != 0,
            view_timestamps: (flags & (1 << 3)) != 0,
            full_audit: (flags & (1 << 4)) != 0,
            valid_from,
            valid_until,
            can_derive_keys: false,
            valid_block_range: (0, 0),
            field_visibility: HashMap::new(),
        }
    }
}

/// Management system for multiple view keys
#[derive(Debug, Default, Clone)]
pub struct ViewKeyManager {
    /// Map of view keys by their public key representation
    view_keys: HashMap<Vec<u8>, ViewKey>,
    /// Map of revoked view keys
    revoked_keys: HashSet<Vec<u8>>,
    /// Hierarchical relationships between keys
    key_hierarchy: HashMap<Vec<u8>, Vec<Vec<u8>>>,
    /// Audit log for view key operations
    audit_log: Arc<Mutex<Vec<ViewKeyAuditEntry>>>,
    /// Maximum audit log entries (0 = unlimited)
    max_audit_entries: usize,
}

/// Audit entry for view key operations
#[derive(Debug, Clone)]
pub struct ViewKeyAuditEntry {
    /// Timestamp of the operation
    pub timestamp: u64,
    /// Public key involved (as bytes)
    pub public_key: Vec<u8>,
    /// Operation performed
    pub operation: ViewKeyOperation,
    /// Additional data about the operation
    pub details: HashMap<String, String>,
}

/// Types of operations that can be performed with view keys
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewKeyOperation {
    /// View key created
    Created,
    /// View key revoked
    Revoked,
    /// Permissions updated
    PermissionsUpdated,
    /// Child key derived
    ChildDerived,
    /// Transaction scanned
    TransactionScanned,
    /// View key exported
    Exported,
    /// Context updated
    ContextUpdated,
    /// Multi-signature authorization
    MultiSigAuthorized,
}

/// Authorization status for multi-signature view keys
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationStatus {
    /// Not authorized yet
    Pending,
    /// Authorized
    Authorized,
    /// Authorization denied
    Denied,
    /// Authorization expired
    Expired,
}

/// Transaction field visibility details
#[derive(Debug, Clone)]
pub struct TransactionFieldVisibility {
    /// View transaction hash
    pub hash: bool,
    /// View input addresses 
    pub input_addresses: bool,
    /// View output addresses
    pub output_addresses: bool,
    /// View amounts
    pub amounts: bool,
    /// View timestamps
    pub timestamps: bool,
    /// View transaction fees
    pub fees: bool,
    /// View memo fields
    pub memos: bool,
    /// View script data
    pub scripts: bool,
}

impl Default for TransactionFieldVisibility {
    fn default() -> Self {
        Self {
            hash: true,
            input_addresses: false,
            output_addresses: true,
            amounts: false,
            timestamps: false,
            fees: false,
            memos: false,
            scripts: false,
        }
    }
}

impl ViewKeyPermissions {
    /// Create a new permission set with granular field visibility
    pub fn with_field_visibility(mut self, field_visibility: HashMap<String, bool>) -> Self {
        self.field_visibility = field_visibility;
        self
    }
    
    /// Check if a specific transaction field is visible
    pub fn is_field_visible(&self, field: &str) -> bool {
        match self.field_visibility.get(field) {
            Some(visible) => *visible,
            None => match field {
                "hash" => true, // Hash is always visible
                "input_addresses" => self.view_outgoing,
                "output_addresses" => self.view_incoming,
                "amounts" => self.view_amounts,
                "timestamp" => self.view_timestamps,
                "fee" => self.view_amounts,
                "memo" => false, // Memos hidden by default
                "script" => false, // Scripts hidden by default
                _ => false,
            }
        }
    }
    
    /// Convert to a structured transaction field visibility object
    pub fn to_field_visibility(&self) -> TransactionFieldVisibility {
        TransactionFieldVisibility {
            hash: self.is_field_visible("hash"),
            input_addresses: self.is_field_visible("input_addresses"),
            output_addresses: self.is_field_visible("output_addresses"),
            amounts: self.is_field_visible("amounts"),
            timestamps: self.is_field_visible("timestamp"),
            fees: self.is_field_visible("fee"),
            memos: self.is_field_visible("memo"),
            scripts: self.is_field_visible("script"),
        }
    }
}

impl ViewKeyManager {
    /// Create a new view key manager
    pub fn new() -> Self {
        Self {
            view_keys: HashMap::new(),
            revoked_keys: HashSet::new(),
            key_hierarchy: HashMap::new(),
            audit_log: Arc::new(Mutex::new(Vec::new())),
            max_audit_entries: 1000, // Default to 1000 audit entries
        }
    }
    
    /// Create a new view key manager with custom audit log size
    pub fn with_audit_capacity(max_entries: usize) -> Self {
        let mut manager = Self::new();
        manager.max_audit_entries = max_entries;
        manager
    }
    
    /// Generate and register a new view key
    pub fn generate_view_key(&mut self, wallet_keypair: &JubjubKeypair, permissions: ViewKeyPermissions) -> ViewKey {
        let view_key = ViewKey::with_permissions(wallet_keypair, permissions);
        let key_bytes = view_key.public_key().to_bytes();
        
        self.view_keys.insert(key_bytes.to_vec(), view_key.clone());
        
        // Log the creation
        self.log_operation(
            &key_bytes, 
            ViewKeyOperation::Created,
            HashMap::new()
        );
        
        view_key
    }
    
    /// Generate a hierarchical view key with specific level
    pub fn generate_hierarchical_key(
        &mut self,
        wallet_keypair: &JubjubKeypair, 
        permissions: ViewKeyPermissions,
        level: ViewKeyLevel
    ) -> ViewKey {
        let view_key = ViewKey::with_level(wallet_keypair, permissions, level);
        let key_bytes = view_key.public_key().to_bytes();
        
        self.view_keys.insert(key_bytes.to_vec(), view_key.clone());
        
        // Initialize an empty list of children
        self.key_hierarchy.insert(key_bytes.to_vec(), Vec::new());
        
        // Log the creation
        let mut details = HashMap::new();
        details.insert("level".to_string(), format!("{:?}", level));
        
        self.log_operation(
            &key_bytes, 
            ViewKeyOperation::Created,
            details
        );
        
        view_key
    }
    
    /// Derive a child key from a parent key
    pub fn derive_child_key(
        &mut self,
        parent_public_key: &JubjubPoint,
        index: u32,
        permissions: ViewKeyPermissions
    ) -> Option<ViewKey> {
        let parent_bytes = parent_public_key.to_bytes();
        
        // Get the parent key
        let parent_key = self.view_keys.get(&parent_bytes.to_vec())?;
        
        // Check if parent is revoked
        if self.is_revoked(parent_public_key) {
            return None;
        }
        
        // Derive the child key
        let mut child_permissions = ViewKeyPermissions::default();
        child_permissions.can_derive_keys = true;
        let child_key = parent_key.derive_child(index, child_permissions)?;
        let child_bytes = child_key.public_key().to_bytes();
        
        // Register the child key
        self.view_keys.insert(child_bytes.to_vec(), child_key.clone());
        
        // Update the hierarchy
        self.key_hierarchy
            .entry(parent_bytes.to_vec())
            .or_insert_with(Vec::new)
            .push(child_bytes.to_vec());
        
        // Log the derivation
        let mut details = HashMap::new();
        details.insert("parent".to_string(), hex::encode(&parent_bytes));
        details.insert("index".to_string(), index.to_string());
        details.insert("level".to_string(), format!("{:?}", child_key.level()));
        
        self.log_operation(
            &child_bytes,
            ViewKeyOperation::ChildDerived,
            details
        );
        
        Some(child_key)
    }
    
    /// Register an existing view key
    pub fn register_view_key(&mut self, view_key: ViewKey) {
        let key_bytes = view_key.public_key().to_bytes();
        self.view_keys.insert(key_bytes.to_vec(), view_key);
        
        // Log the registration
        self.log_operation(
            &key_bytes,
            ViewKeyOperation::Created,
            HashMap::new()
        );
    }
    
    /// Revoke a view key and all its descendants
    pub fn revoke_view_key(&mut self, public_key: &JubjubPoint) {
        let key_bytes = public_key.to_bytes();
        
        if self.view_keys.remove(&key_bytes.to_vec()).is_some() {
            // Add to revoked keys
            self.revoked_keys.insert(key_bytes.to_vec());
            
            // Log the revocation
            self.log_operation(
                &key_bytes,
                ViewKeyOperation::Revoked,
                HashMap::new()
            );
            
            // Recursively revoke all child keys
            if let Some(children) = self.key_hierarchy.get(&key_bytes.to_vec()).cloned() {
                for child in children {
                    if let Some(child_point) = JubjubPoint::from_bytes(&child) {
                        self.revoke_view_key(&child_point);
                    }
                }
            }
            
            // Clean up the hierarchy entry
            self.key_hierarchy.remove(&key_bytes.to_vec());
        }
    }

    /// Add an audit log entry
    fn log_operation(&self, key_bytes: &[u8], operation: ViewKeyOperation, details: HashMap<String, String>) {
        if self.max_audit_entries == 0 {
            return; // Audit logging disabled
        }
        
        let entry = ViewKeyAuditEntry {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            public_key: key_bytes.to_vec(),
            operation,
            details,
        };
        
        let mut log = self.audit_log.lock().unwrap();
        log.push(entry);
        
        // Trim if needed
        if self.max_audit_entries > 0 && log.len() > self.max_audit_entries {
            let split_index = log.len() - self.max_audit_entries;
            *log = log.split_off(split_index);
        }
    }
    
    /// Get the audit log
    pub fn get_audit_log(&self) -> Vec<ViewKeyAuditEntry> {
        let log = self.audit_log.lock().unwrap();
        log.clone()
    }
    
    /// Get audit log for a specific key
    pub fn get_key_audit_log(&self, public_key: &JubjubPoint) -> Vec<ViewKeyAuditEntry> {
        let key_bytes = public_key.to_bytes();
        let log = self.audit_log.lock().unwrap();
        
        log.iter()
            .filter(|entry| entry.public_key == key_bytes)
            .cloned()
            .collect()
    }
    
    /// Check if a view key is revoked
    pub fn is_revoked(&self, public_key: &JubjubPoint) -> bool {
        let key_bytes = public_key.to_bytes();
        self.revoked_keys.contains(&key_bytes.to_vec())
    }
    
    /// Get a view key by its public key
    pub fn get_view_key(&self, public_key: &JubjubPoint) -> Option<&ViewKey> {
        let key_bytes = public_key.to_bytes();
        self.view_keys.get(&key_bytes.to_vec())
    }
    
    /// Get all child keys for a parent key
    pub fn get_child_keys(&self, parent_public_key: &JubjubPoint) -> Vec<&ViewKey> {
        let parent_bytes = parent_public_key.to_bytes();
        
        if let Some(children) = self.key_hierarchy.get(&parent_bytes.to_vec()) {
            children
                .iter()
                .filter_map(|child_bytes| self.view_keys.get(child_bytes))
                .collect()
        } else {
            Vec::new()
        }
    }
    
    /// Get all registered view keys
    pub fn get_all_view_keys(&self) -> Vec<&ViewKey> {
        self.view_keys.values().collect()
    }
    
    /// Get all root view keys (those with no parent)
    pub fn get_root_keys(&self) -> Vec<&ViewKey> {
        self.view_keys
            .values()
            .filter(|key| key.level() == ViewKeyLevel::Root)
            .collect()
    }
    
    /// Update permissions for a view key
    pub fn update_permissions(&mut self, public_key: &JubjubPoint, permissions: ViewKeyPermissions) -> bool {
        let key_bytes = public_key.to_bytes();
        
        if let Some(view_key) = self.view_keys.get_mut(&key_bytes.to_vec()) {
            view_key.update_permissions(permissions);
            
            // Log the update
            self.log_operation(
                &key_bytes,
                ViewKeyOperation::PermissionsUpdated,
                HashMap::new()
            );
            
            true
        } else {
            false
        }
    }
    
    /// Update context restrictions for a view key
    pub fn update_context(&mut self, public_key: &JubjubPoint, context: ViewKeyContext) -> bool {
        let key_bytes = public_key.to_bytes();
        
        if let Some(view_key) = self.view_keys.get_mut(&key_bytes.to_vec()) {
            view_key.set_context(context);
            
            // Log the update
            let mut details = HashMap::new();
            if let Some(ctx) = view_key.context() {
                details.insert("networks".to_string(), ctx.networks.join(","));
                details.insert("applications".to_string(), ctx.applications.join(","));
            }
            
            self.log_operation(
                &key_bytes,
                ViewKeyOperation::ContextUpdated,
                details
            );
            
            true
        } else {
            false
        }
    }

    /// Scan transactions with all relevant view keys, filtering based on context
    pub fn scan_transactions(
        &self, 
        transactions: &[Transaction],
        current_time: u64,
        context: Option<&ViewKeyContext>
    ) -> HashMap<Vec<u8>, Vec<TransactionOutput>> {
        let mut results = HashMap::new();
        
        for view_key in self.view_keys.values() {
            // Skip if key is not valid at the current time
            if !view_key.is_valid(current_time) {
                continue;
            }
            
            // Skip if context doesn't match
            if let Some(req_context) = context {
                if let Some(key_context) = view_key.context() {
                    if !contexts_compatible(req_context, key_context) {
                        continue;
                    }
                }
            }
            
            let key_bytes = view_key.public_key().to_bytes();
            let outputs = view_key.scan_transactions(transactions);
            
            if !outputs.is_empty() {
                // Log transaction scanning activity
                let mut details = HashMap::new();
                details.insert("tx_count".to_string(), transactions.len().to_string());
                details.insert("output_count".to_string(), outputs.len().to_string());
                
                self.log_operation(
                    &key_bytes,
                    ViewKeyOperation::TransactionScanned,
                    details
                );
                
                results.insert(key_bytes.to_vec(), outputs);
            }
        }
        
        results
    }
    
    /// Export view key with audit logging
    pub fn export_view_key(&self, public_key: &JubjubPoint) -> Option<Vec<u8>> {
        let key_bytes = public_key.to_bytes();
        
        if let Some(view_key) = self.view_keys.get(&key_bytes.to_vec()) {
            // Log the export
            self.log_operation(
                &key_bytes,
                ViewKeyOperation::Exported,
                HashMap::new()
            );
            
            Some(view_key.to_bytes())
        } else {
            None
        }
    }
}

/// Determine if two contexts are compatible
fn contexts_compatible(request_context: &ViewKeyContext, key_context: &ViewKeyContext) -> bool {
    // If the key has network restrictions, the request must specify one of those networks
    if !key_context.networks.is_empty() {
        if request_context.networks.is_empty() {
            return false;
        }
        
        let mut found = false;
        for network in &request_context.networks {
            if key_context.networks.contains(network) {
                found = true;
                break;
            }
        }
        
        if !found {
            return false;
        }
    }
    
    // Same check for applications
    if !key_context.applications.is_empty() {
        if request_context.applications.is_empty() {
            return false;
        }
        
        let mut found = false;
        for app in &request_context.applications {
            if key_context.applications.contains(app) {
                found = true;
                break;
            }
        }
        
        if !found {
            return false;
        }
    }
    
    // IP restrictions - if the key has restrictions, the request must match one
    if !key_context.ip_restrictions.is_empty() {
        if request_context.ip_restrictions.is_empty() {
            return false;
        }
        
        let mut found = false;
        for ip in &request_context.ip_restrictions {
            if key_context.ip_restrictions.contains(ip) {
                found = true;
                break;
            }
        }
        
        if !found {
            return false;
        }
    }
    
    true
}

impl ViewKey {
    /// Apply visibility permissions to filter transaction data
    pub fn apply_field_visibility(&self, tx: &Transaction) -> Transaction {
        if self.permissions.full_audit {
            return tx.clone(); // Full audit keys see everything
        }
        
        let visibility = self.permissions.to_field_visibility();
        let mut filtered_tx = tx.clone();
        
        // Apply field-specific filtering
        if !visibility.amounts {
            // Replace actual amounts with zeros
            for output in &mut filtered_tx.outputs {
                output.value = 0;
            }
            
            // Clear any amount commitments
            filtered_tx.amount_commitments = None;
        }
        
        // Hide input addresses if not allowed
        if !visibility.input_addresses {
            // Replace input scripts with empty ones
            for input in &mut filtered_tx.inputs {
                input.signature_script = Vec::new();
            }
        }
        
        // Hide output addresses if not allowed
        if !visibility.output_addresses {
            // Replace output scripts with empty ones
            for output in &mut filtered_tx.outputs {
                output.public_key_script = Vec::new();
            }
        }
        
        filtered_tx
    }
}

/// Multi-signature view key for access control
#[derive(Debug, Clone)]
pub struct MultiSigViewKey {
    /// The base view key
    view_key: ViewKey,
    /// Required signers (public keys)
    required_signers: Vec<JubjubPoint>,
    /// Threshold of signatures required
    threshold: usize,
    /// Current authorizations
    authorizations: HashMap<Vec<u8>, AuthorizationStatus>,
    /// Authorization expiry timestamp (0 = no expiry)
    expiry: u64,
}

impl MultiSigViewKey {
    /// Create a new multi-signature view key
    pub fn new(
        view_key: ViewKey,
        signers: Vec<JubjubPoint>,
        threshold: usize,
        expiry: u64,
    ) -> Self {
        // Ensure threshold is valid
        let threshold = threshold.min(signers.len()).max(1);
        
        // Initialize with empty authorizations
        let mut authorizations = HashMap::new();
        for signer in &signers {
            authorizations.insert(signer.to_bytes().to_vec(), AuthorizationStatus::Pending);
        }
        
        Self {
            view_key,
            required_signers: signers,
            threshold,
            authorizations,
            expiry,
        }
    }
    
    /// Get the underlying view key
    pub fn view_key(&self) -> &ViewKey {
        &self.view_key
    }
    
    /// Get the required signers
    pub fn required_signers(&self) -> &[JubjubPoint] {
        &self.required_signers
    }
    
    /// Get the required threshold
    pub fn threshold(&self) -> usize {
        self.threshold
    }
    
    /// Get the current authorization status
    pub fn authorization_status(&self) -> HashMap<Vec<u8>, AuthorizationStatus> {
        self.authorizations.clone()
    }
    
    /// Add an authorization from a signer
    pub fn add_authorization(&mut self, signer: &JubjubPoint, signature: &[u8], message: &[u8]) -> bool {
        let signer_bytes = signer.to_bytes();
        
        // Check if signer is required
        if !self.authorizations.contains_key(&signer_bytes.to_vec()) {
            return false;
        }
        
        // Check signature validity
        if !Self::verify_signature(signer, signature, message) {
            return false;
        }
        
        // Update authorization status
        self.authorizations.insert(signer_bytes.to_vec(), AuthorizationStatus::Authorized);
        true
    }
    
    /// Check if key is fully authorized (enough signatures)
    pub fn is_authorized(&self, current_time: u64) -> bool {
        // Check expiry
        if self.expiry > 0 && current_time > self.expiry {
            return false;
        }
        
        // Count authorized signers
        let authorized_count = self.authorizations
            .values()
            .filter(|&status| *status == AuthorizationStatus::Authorized)
            .count();
        
        authorized_count >= self.threshold
    }
    
    /// Verify a signature on a message
    fn verify_signature(signer: &JubjubPoint, signature: &[u8], message: &[u8]) -> bool {
        // In a real implementation, this would use JubjubSignature verification
        // For simplicity in this example, just check if the signature matches expected structure
        if signature.len() != 64 {
            return false;
        }
        
        // This is a placeholder for proper signature verification
        // In production, use actual signature verification
        true
    }
    
    /// Revoke all authorizations
    pub fn revoke_authorizations(&mut self) {
        for status in self.authorizations.values_mut() {
            *status = AuthorizationStatus::Denied;
        }
    }
    
    /// Set a new expiry time
    pub fn set_expiry(&mut self, expiry: u64) {
        self.expiry = expiry;
    }
    
    /// Convert to regular ViewKey if authorized
    pub fn to_view_key(&self, current_time: u64) -> Option<ViewKey> {
        if self.is_authorized(current_time) {
            Some(self.view_key.clone())
        } else {
            None
        }
    }
}

impl ViewKeyManager {
    /// Create a multi-signature view key
    pub fn create_multi_sig_key(
        &mut self,
        wallet_keypair: &JubjubKeypair,
        permissions: ViewKeyPermissions,
        signers: Vec<JubjubPoint>,
        threshold: usize,
        expiry: u64,
    ) -> MultiSigViewKey {
        // First create a normal view key
        let view_key = self.generate_view_key(wallet_keypair, permissions);
        let key_bytes = view_key.public_key().to_bytes();
        
        // Create the multi-sig wrapper
        let multi_sig_key = MultiSigViewKey::new(
            view_key,
            signers.clone(),
            threshold,
            expiry,
        );
        
        // Log the creation
        let mut details = HashMap::new();
        details.insert("signers".to_string(), signers.len().to_string());
        details.insert("threshold".to_string(), threshold.to_string());
        details.insert("expiry".to_string(), expiry.to_string());
        
        self.log_operation(
            &key_bytes,
            ViewKeyOperation::MultiSigAuthorized,
            details
        );
        
        multi_sig_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::jubjub::generate_keypair;
    use crate::utils::current_time;
    use crate::blockchain::{Transaction, TransactionInput, TransactionOutput};
    
    #[test]
    fn test_view_key_generation() {
        let wallet_keypair = generate_keypair();
        let view_key = ViewKey::new(&wallet_keypair);
        
        // Verify the view key is associated with the wallet
        assert_eq!(*view_key.owner_public_key(), wallet_keypair.public);
        
        // Verify default permissions
        let perms = view_key.permissions();
        assert!(perms.view_incoming);
        assert!(!perms.full_audit);
    }
    
    #[test]
    fn test_view_key_serialization() {
        let wallet_keypair = generate_keypair();
        
        // Create a view key with custom permissions
        let mut permissions = ViewKeyPermissions::default();
        permissions.view_incoming = true;
        permissions.view_amounts = true;
        permissions.view_timestamps = false;
        permissions.valid_from = current_time();
        permissions.valid_until = current_time() + 86400; // Valid for 24 hours
        
        // Clone permissions before passing to avoid move
        let view_key = ViewKey::with_permissions(&wallet_keypair, permissions.clone());
        
        // Serialize and deserialize
        let bytes = view_key.to_bytes();
        let restored_key = ViewKey::from_bytes(&bytes).unwrap();
        
        // Verify public components match
        assert_eq!(*restored_key.public_key(), *view_key.public_key());
        assert_eq!(*restored_key.owner_public_key(), *view_key.owner_public_key());
        
        // Verify permissions match
        let restored_perms = restored_key.permissions();
        assert_eq!(restored_perms.view_incoming, permissions.view_incoming);
        assert_eq!(restored_perms.view_amounts, permissions.view_amounts);
        assert_eq!(restored_perms.view_timestamps, permissions.view_timestamps);
        assert_eq!(restored_perms.valid_from, permissions.valid_from);
        assert_eq!(restored_perms.valid_until, permissions.valid_until);
    }
    
    #[test]
    fn test_view_key_manager() {
        let wallet_keypair = generate_keypair();
        let mut manager = ViewKeyManager::new();
        
        // Create a view key
        let mut permissions = ViewKeyPermissions::default();
        permissions.view_incoming = true;
        permissions.view_outgoing = false;
        
        let view_key = manager.generate_view_key(&wallet_keypair, permissions);
        
        // Verify the key was registered
        let retrieved_key = manager.get_view_key(view_key.public_key()).unwrap();
        assert_eq!(*retrieved_key.public_key(), *view_key.public_key());
        
        // Test revocation
        manager.revoke_view_key(view_key.public_key());
        assert!(manager.is_revoked(view_key.public_key()));
        assert!(manager.get_view_key(view_key.public_key()).is_none());
    }
    
    #[test]
    fn test_view_key_time_validity() {
        let wallet_keypair = generate_keypair();
        let now = current_time();
        
        // Create a view key valid from now until 1 hour from now
        let mut permissions = ViewKeyPermissions::default();
        permissions.valid_from = now;
        permissions.valid_until = now + 3600; // Valid for 1 hour
        
        let view_key = ViewKey::with_permissions(&wallet_keypair, permissions);
        
        // Test validity at different times
        assert!(view_key.is_valid(now)); // Valid at start time
        assert!(view_key.is_valid(now + 1800)); // Valid in the middle
        assert!(view_key.is_valid(now + 3599)); // Valid just before expiry
        assert!(!view_key.is_valid(now - 1)); // Invalid before start
        assert!(!view_key.is_valid(now + 3601)); // Invalid after expiry
    }
    
    #[test]
    fn test_transaction_scanning() {
        let wallet_keypair = generate_keypair();
        let view_key = ViewKey::new(&wallet_keypair);
        
        // Create a transaction with an output to the wallet
        let mut tx = Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            fee_adjustments: None,
            privacy_flags: 0,
            obfuscated_id: None,
            ephemeral_pubkey: None,
            amount_commitments: None,
            range_proofs: None,
        };
        
        // Create an output that should be visible to the view key
        // In a real implementation, this would use proper stealth addressing
        let mut output_script = Vec::new();
        let pubkey_bytes = wallet_keypair.public.to_bytes();
        output_script.extend_from_slice(&pubkey_bytes);
        output_script.extend_from_slice(&[0; 32]); // Padding
        
        let output = TransactionOutput {
            value: 1000,
            public_key_script: output_script,
        };
        
        tx.outputs.push(output);
        
        // Add another output that shouldn't be visible
        let other_keypair = generate_keypair();
        let mut other_script = Vec::new();
        let other_pubkey_bytes = other_keypair.public.to_bytes();
        other_script.extend_from_slice(&other_pubkey_bytes);
        other_script.extend_from_slice(&[0; 32]); // Padding
        
        let other_output = TransactionOutput {
            value: 500,
            public_key_script: other_script,
        };
        
        tx.outputs.push(other_output);
        
        // Scan the transaction
        let found_outputs = view_key.scan_transaction(&tx);
        
        // Should find exactly one output
        assert_eq!(found_outputs.len(), 1);
        assert_eq!(found_outputs[0].value, 1000);
    }
    
    #[test]
    fn test_view_key_permissions() {
        let wallet_keypair = generate_keypair();
        
        // Create a view key with no permissions
        let mut no_permissions = ViewKeyPermissions::default();
        no_permissions.view_incoming = false;
        no_permissions.view_outgoing = false;
        no_permissions.view_amounts = false;
        
        let no_perm_key = ViewKey::with_permissions(&wallet_keypair, no_permissions);
        
        // Create a transaction with an output to the wallet
        let mut tx = Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            fee_adjustments: None,
            privacy_flags: 0,
            obfuscated_id: None,
            ephemeral_pubkey: None,
            amount_commitments: None,
            range_proofs: None,
        };
        
        // Create an output that should be visible to the view key
        let mut output_script = Vec::new();
        let pubkey_bytes = wallet_keypair.public.to_bytes();
        output_script.extend_from_slice(&pubkey_bytes);
        output_script.extend_from_slice(&[0; 32]); // Padding
        
        let output = TransactionOutput {
            value: 1000,
            public_key_script: output_script,
        };
        
        tx.outputs.push(output);
        
        // Scan with no permissions - should find nothing
        let found_outputs = no_perm_key.scan_transaction(&tx);
        assert_eq!(found_outputs.len(), 0);
        
        // Update permissions to allow viewing incoming
        let mut with_permissions = ViewKeyPermissions::default();
        with_permissions.view_incoming = true;
        
        let with_perm_key = ViewKey::with_permissions(&wallet_keypair, with_permissions);
        
        // Scan with permissions - should find the output
        let found_outputs = with_perm_key.scan_transaction(&tx);
        assert_eq!(found_outputs.len(), 1);
    }
    
    #[test]
    fn test_view_key_manager_scanning() {
        let wallet_keypair = generate_keypair();
        let mut manager = ViewKeyManager::new();
        
        // Create a view key
        let permissions = ViewKeyPermissions {
            view_incoming: true,
            view_outgoing: false,
            view_amounts: true,
            view_timestamps: true,
            full_audit: false,
            valid_from: 0,
            valid_until: 0,
            can_derive_keys: false,
            valid_block_range: (0, 0),
            field_visibility: HashMap::new(),
        };
        
        let view_key = manager.generate_view_key(&wallet_keypair, permissions);
        
        // Create a transaction with an output to the wallet
        let mut tx = Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            fee_adjustments: None,
            privacy_flags: 0,
            obfuscated_id: None,
            ephemeral_pubkey: None,
            amount_commitments: None,
            range_proofs: None,
        };
        
        // Create an output that should be visible to the view key
        let mut output_script = Vec::new();
        let pubkey_bytes = wallet_keypair.public.to_bytes();
        output_script.extend_from_slice(&pubkey_bytes);
        output_script.extend_from_slice(&[0; 32]); // Padding
        
        let output = TransactionOutput {
            value: 1000,
            public_key_script: output_script,
        };
        
        tx.outputs.push(output);
        
        // Scan with the manager
        let results = manager.scan_transactions(&[tx], current_time(), None);
        
        // Should have results for one view key
        assert_eq!(results.len(), 1);
        
        // Get the results for our view key
        let key_bytes = view_key.public_key().to_bytes();
        let found_outputs = results.get(&key_bytes.to_vec()).unwrap();
        
        // Should have found one output
        assert_eq!(found_outputs.len(), 1);
        assert_eq!(found_outputs[0].value, 1000);
    }
    
    #[test]
    fn test_hierarchical_view_keys() {
        // Setup panic hook
        println!("Starting test_hierarchical_view_keys");
        
        // Create a root key
        let wallet_keypair = generate_keypair();
        println!("Generated keypair");
        
        let mut permissions = ViewKeyPermissions::default();
        permissions.can_derive_keys = true;
        permissions.view_amounts = true;
        println!("Set up permissions");
        
        let root_key = ViewKey::with_level(&wallet_keypair, permissions, ViewKeyLevel::Root);
        println!("Created root key");
        
        // Derive a child key
        println!("About to derive child key");
        let mut child_permissions = ViewKeyPermissions::default();
        child_permissions.can_derive_keys = true;
        let child_key = root_key.derive_child(1, child_permissions);
        println!("Derived child key result: {:?}", child_key.is_some());
        assert!(child_key.is_some());
        let child_key = child_key.unwrap();
        println!("Unwrapped child key");
        
        // Check level
        assert_eq!(child_key.level(), ViewKeyLevel::Intermediate);
        println!("Checked level");
        
        // Check path
        assert_eq!(child_key.path().len(), 4); // 4 bytes for u32 index
        println!("Checked path");
        
        // Try to derive a grandchild
        println!("About to derive grandchild key");
        let grandchild_key = child_key.derive_child(2, ViewKeyPermissions::default());
        println!("Derived grandchild key result: {:?}", grandchild_key.is_some());
        assert!(grandchild_key.is_some());
        let grandchild_key = grandchild_key.unwrap();
        println!("Unwrapped grandchild key");
        
        // Check level - should be a leaf
        assert_eq!(grandchild_key.level(), ViewKeyLevel::Leaf);
        println!("Checked grandchild level");
        
        // Cannot derive from leaf
        println!("About to attempt deriving from leaf");
        let great_grandchild = grandchild_key.derive_child(3, ViewKeyPermissions::default());
        println!("Attempt result: {:?}", great_grandchild.is_none());
        assert!(great_grandchild.is_none());
        println!("Test completed successfully");
    }
    
    #[test]
    fn test_view_key_context_restrictions() {
        let wallet_keypair = generate_keypair();
        
        // Create a view key with context restrictions
        let mut view_key = ViewKey::new(&wallet_keypair);
        
        // Define a context
        let context = ViewKeyContext {
            networks: vec!["mainnet".to_string(), "testnet".to_string()],
            applications: vec!["wallet".to_string()],
            ip_restrictions: Vec::new(),
            custom_context: HashMap::new(),
        };
        
        view_key.set_context(context.clone());
        
        // Check that the context was set
        assert!(view_key.context().is_some());
        let key_context = view_key.context().unwrap();
        assert_eq!(key_context.networks, context.networks);
        
        // Test compatibility
        let compatible_context = ViewKeyContext {
            networks: vec!["mainnet".to_string()],
            applications: vec!["wallet".to_string()],
            ip_restrictions: Vec::new(),
            custom_context: HashMap::new(),
        };
        
        assert!(contexts_compatible(&compatible_context, key_context));
        
        // Test incompatible context
        let incompatible_context = ViewKeyContext {
            networks: vec!["devnet".to_string()],
            applications: vec!["wallet".to_string()],
            ip_restrictions: Vec::new(),
            custom_context: HashMap::new(),
        };
        
        assert!(!contexts_compatible(&incompatible_context, key_context));
    }
    
    #[test]
    fn test_field_visibility() {
        let wallet_keypair = generate_keypair();
        
        // Create permissions with specific field visibility
        let mut field_visibility = HashMap::new();
        field_visibility.insert("amounts".to_string(), true);
        field_visibility.insert("input_addresses".to_string(), false);
        
        let permissions = ViewKeyPermissions::default()
            .with_field_visibility(field_visibility);
        
        // Create view key
        let view_key = ViewKey::with_permissions(&wallet_keypair, permissions);
        
        // Create a dummy transaction
        let mut tx = Transaction::default();
        tx.outputs.push(TransactionOutput {
            value: 100,
            public_key_script: vec![1, 2, 3],
        });
        
        // Apply visibility
        let filtered_tx = view_key.apply_field_visibility(&tx);
        
        // Amounts should be visible
        assert_eq!(filtered_tx.outputs[0].value, 100);
        
        // Create a key that hides amounts
        let mut permissions = ViewKeyPermissions::default();
        permissions.view_amounts = false;
        
        let view_key = ViewKey::with_permissions(&wallet_keypair, permissions);
        let filtered_tx = view_key.apply_field_visibility(&tx);
        
        // Amounts should be hidden
        assert_eq!(filtered_tx.outputs[0].value, 0);
    }
    
    #[test]
    fn test_view_key_manager_hierarchy() {
        // Setup panic hook
        println!("Starting test_view_key_manager_hierarchy");
        
        let wallet_keypair = generate_keypair();
        println!("Generated keypair");
        
        let mut manager = ViewKeyManager::new();
        println!("Created manager");
        
        // Create a hierarchical key
        let mut permissions = ViewKeyPermissions::default();
        permissions.can_derive_keys = true;
        println!("Set up permissions");
        
        println!("About to generate hierarchical key");
        let root_key = manager.generate_hierarchical_key(
            &wallet_keypair,
            permissions,
            ViewKeyLevel::Root
        );
        println!("Generated root key");
        
        // Derive child
        println!("About to derive child key");
        let child_key = manager.derive_child_key(
            root_key.public_key(),
            1,
            ViewKeyPermissions::default()
        );
        println!("Derived child key result: {:?}", child_key.is_some());
        
        assert!(child_key.is_some());
        println!("Child key assertion passed");
        
        // Check that child is in hierarchy
        println!("About to get child keys");
        let children = manager.get_child_keys(root_key.public_key());
        println!("Got child keys: {}", children.len());
        assert_eq!(children.len(), 1);
        println!("Children count assertion passed");
        
        // Get root keys
        println!("About to get root keys");
        let roots = manager.get_root_keys();
        println!("Got root keys: {}", roots.len());
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].level(), ViewKeyLevel::Root);
        println!("Root assertions passed");
        
        println!("Test completed successfully");
    }
    
    #[test]
    fn test_audit_logging() {
        let wallet_keypair = generate_keypair();
        let mut manager = ViewKeyManager::new();
        
        // Generate a key
        let view_key = manager.generate_view_key(&wallet_keypair, ViewKeyPermissions::default());
        
        // Revoke it
        manager.revoke_view_key(view_key.public_key());
        
        // Check audit log
        let log = manager.get_audit_log();
        assert_eq!(log.len(), 2); // Create + Revoke
        
        // Check operations
        assert_eq!(log[0].operation, ViewKeyOperation::Created);
        assert_eq!(log[1].operation, ViewKeyOperation::Revoked);
        
        // Get key-specific log
        let key_log = manager.get_key_audit_log(view_key.public_key());
        assert_eq!(key_log.len(), 2);
    }
    
    #[test]
    fn test_multi_sig_view_key() {
        let wallet_keypair = generate_keypair();
        let mut manager = ViewKeyManager::new();
        
        // Create some signers
        let signer1 = generate_keypair();
        let signer2 = generate_keypair();
        let signer3 = generate_keypair();
        
        let signers = vec![signer1.public.clone(), signer2.public.clone(), signer3.public.clone()];
        
        // Create a multi-sig key (2 of 3)
        let mut multi_sig_key = manager.create_multi_sig_key(
            &wallet_keypair,
            ViewKeyPermissions::default(),
            signers,
            2,
            current_time() + 3600 // expire in 1 hour
        );
        
        // Initially not authorized
        assert!(!multi_sig_key.is_authorized(current_time()));
        
        // Add authorizations
        assert!(multi_sig_key.add_authorization(&signer1.public, &[0; 64], b"authorize"));
        
        // Still not enough signatures
        assert!(!multi_sig_key.is_authorized(current_time()));
        
        // Add another authorization
        assert!(multi_sig_key.add_authorization(&signer2.public, &[0; 64], b"authorize"));
        
        // Now it should be authorized
        assert!(multi_sig_key.is_authorized(current_time()));
        
        // Should be able to convert to a view key
        assert!(multi_sig_key.to_view_key(current_time()).is_some());
        
        // Test expiry
        assert!(!multi_sig_key.is_authorized(current_time() + 7200)); // 2 hours later
        
        // Test revocation
        multi_sig_key.revoke_authorizations();
        assert!(!multi_sig_key.is_authorized(current_time()));
    }
} 