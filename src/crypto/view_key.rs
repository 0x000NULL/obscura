use crate::blockchain::{Transaction, TransactionOutput};
use crate::crypto::jubjub::{JubjubKeypair, JubjubPoint, JubjubPointExt, JubjubScalar, JubjubScalarExt};
use ark_ec::CurveGroup;
use std::collections::{HashMap, HashSet};
use ark_std::Zero;
use blake2b_simd;

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
        }
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
}

impl ViewKeyManager {
    /// Create a new view key manager
    pub fn new() -> Self {
        Self {
            view_keys: HashMap::new(),
            revoked_keys: HashSet::new(),
        }
    }
    
    /// Generate and register a new view key
    pub fn generate_view_key(&mut self, wallet_keypair: &JubjubKeypair, permissions: ViewKeyPermissions) -> ViewKey {
        let view_key = ViewKey::with_permissions(wallet_keypair, permissions);
        let key_bytes = view_key.public_key().to_bytes();
        
        self.view_keys.insert(key_bytes.to_vec(), view_key.clone());
        
        view_key
    }
    
    /// Register an existing view key
    pub fn register_view_key(&mut self, view_key: ViewKey) {
        let key_bytes = view_key.public_key().to_bytes();
        self.view_keys.insert(key_bytes.to_vec(), view_key);
    }
    
    /// Revoke a view key
    pub fn revoke_view_key(&mut self, public_key: &JubjubPoint) {
        let key_bytes = public_key.to_bytes();
        
        if self.view_keys.remove(&key_bytes.to_vec()).is_some() {
            self.revoked_keys.insert(key_bytes.to_vec());
        }
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
    
    /// Get all registered view keys
    pub fn get_all_view_keys(&self) -> Vec<&ViewKey> {
        self.view_keys.values().collect()
    }
    
    /// Update permissions for a view key
    pub fn update_permissions(&mut self, public_key: &JubjubPoint, permissions: ViewKeyPermissions) -> bool {
        let key_bytes = public_key.to_bytes();
        
        if let Some(view_key) = self.view_keys.get_mut(&key_bytes.to_vec()) {
            view_key.update_permissions(permissions);
            true
        } else {
            false
        }
    }
    
    /// Scan transactions with all registered view keys
    pub fn scan_transactions(&self, 
                            transactions: &[Transaction],
                            current_time: u64) -> HashMap<Vec<u8>, Vec<TransactionOutput>> {
        let mut results = HashMap::new();
        
        for (key_bytes, view_key) in &self.view_keys {
            // Skip revoked or time-invalid keys
            if self.revoked_keys.contains(key_bytes) || !view_key.is_valid(current_time) {
                continue;
            }
            
            let outputs = view_key.scan_transactions(transactions);
            if !outputs.is_empty() {
                results.insert(key_bytes.clone(), outputs);
            }
        }
        
        results
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
        let results = manager.scan_transactions(&[tx], current_time());
        
        // Should have results for one view key
        assert_eq!(results.len(), 1);
        
        // Get the results for our view key
        let key_bytes = view_key.public_key().to_bytes();
        let found_outputs = results.get(&key_bytes.to_vec()).unwrap();
        
        // Should have found one output
        assert_eq!(found_outputs.len(), 1);
        assert_eq!(found_outputs[0].value, 1000);
    }
} 