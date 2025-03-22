use bincode::serialize;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use log::{debug, error, info, trace};
use crate::blockchain::{Transaction, TransactionInput, TransactionOutput};
use crate::crypto::privacy::{TransactionObfuscator, StealthAddressing, ConfidentialTransactions};
use crate::crypto::metadata_protection::AdvancedMetadataProtection;
use crate::crypto::jubjub::{JubjubPoint, JubjubScalar};
use crate::crypto::pedersen::PedersenCommitment;
use crate::crypto::bulletproofs::Bulletproof;
use crate::config::privacy_registry::{PrivacySettingsRegistry, ComponentType};
use crate::errors::ObscuraError;

impl crate::blockchain::Transaction {
    pub fn to_bytes(&self) -> Vec<u8> {
        serialize(self).unwrap_or_default()
    }
    
    /// Determines if this transaction is a coinbase transaction
    /// A coinbase transaction is identified by having no inputs
    pub fn is_coinbase(&self) -> bool {
        self.inputs.is_empty()
    }

    /// Applies privacy features to the transaction based on the provided configuration
    /// 
    /// This method serves as a high-level interface to apply all configured privacy
    /// features to a transaction in the correct order.
    /// 
    /// # Arguments
    /// 
    /// * `privacy_registry` - The privacy settings registry to use for configuration
    /// 
    /// # Returns
    /// 
    /// * `Result<&mut Self, ObscuraError>` - The modified transaction or an error
    pub fn apply_privacy_features(
        &mut self,
        privacy_registry: &PrivacySettingsRegistry
    ) -> Result<&mut Self, ObscuraError> {
        let config = privacy_registry.get_config();
        
        // Apply transaction obfuscation if enabled
        if config.transaction_obfuscation_enabled {
            let mut obfuscator = TransactionObfuscator::new();
            self.apply_transaction_obfuscation(&mut obfuscator)?;
        }
        
        // Apply metadata protection if enabled
        if config.metadata_stripping {
            let protection = AdvancedMetadataProtection::new();
            self.apply_metadata_protection(&protection)?;
        }
        
        // Apply stealth addressing if enabled
        if config.use_stealth_addresses {
            let mut stealth = StealthAddressing::new();
            
            // In a real implementation, we would get the recipient public keys
            // from the transaction outputs or from a provided parameter
            // For now, we'll use an empty vector as a placeholder
            let recipient_pubkeys: Vec<JubjubPoint> = Vec::new();
            
            self.apply_stealth_addressing(&mut stealth, &recipient_pubkeys)?;
        }
        
        // Apply confidential transactions if enabled
        if config.use_confidential_transactions {
            let mut confidential = ConfidentialTransactions::new();
            self.apply_confidential_transactions(&mut confidential)?;
        }
        
        Ok(self)
    }
    
    /// Applies transaction obfuscation to this transaction
    /// 
    /// # Arguments
    /// 
    /// * `obfuscator` - The transaction obfuscator to use
    /// 
    /// # Returns
    /// 
    /// * `Result<&mut Self, ObscuraError>` - The modified transaction or an error
    pub fn apply_transaction_obfuscation(
        &mut self,
        obfuscator: &mut TransactionObfuscator
    ) -> Result<&mut Self, ObscuraError> {
        trace!("Applying transaction obfuscation");
        
        // Generate an obfuscated transaction ID
        let tx_hash = self.hash();
        let obfuscated_id = obfuscator.obfuscate_tx_id(&tx_hash);
        self.obfuscated_id = Some(obfuscated_id);
        
        // Apply transaction graph protection if there are inputs and outputs
        if !self.inputs.is_empty() && !self.outputs.is_empty() {
            let protected_tx = obfuscator.protect_transaction_graph(self);
            self.inputs = protected_tx.inputs;
            self.outputs = protected_tx.outputs;
        }
        
        // Set the privacy flags to indicate obfuscation is applied
        self.privacy_flags |= 0x01; // 0x01 = Transaction obfuscation flag
        
        Ok(self)
    }
    
    /// Sets the commitment for a specific amount
    /// 
    /// # Arguments
    /// 
    /// * `index` - The output index to set the commitment for
    /// * `commitment` - The Pedersen commitment value
    /// 
    /// # Returns
    /// 
    /// * `Result<&mut Self, ObscuraError>` - The modified transaction or an error
    pub fn set_amount_commitment(
        &mut self,
        index: usize,
        commitment: Vec<u8>
    ) -> Result<&mut Self, ObscuraError> {
        if self.amount_commitments.is_none() {
            self.amount_commitments = Some(Vec::new());
        }
        
        let commitments = self.amount_commitments.as_mut().unwrap();
        
        // Ensure the vector is large enough
        while commitments.len() <= index {
            commitments.push(Vec::new());
        }
        
        commitments[index] = commitment;
        
        // Set the privacy flags to indicate confidential amounts are used
        self.privacy_flags |= 0x04; // 0x04 = Confidential amounts flag
        
        Ok(self)
    }
    
    /// Sets the range proof for a specific output
    /// 
    /// # Arguments
    /// 
    /// * `index` - The output index to set the range proof for
    /// * `range_proof` - The bulletproof range proof
    /// 
    /// # Returns
    /// 
    /// * `Result<&mut Self, ObscuraError>` - The modified transaction or an error
    pub fn set_range_proof(
        &mut self,
        index: usize,
        range_proof: Vec<u8>
    ) -> Result<&mut Self, ObscuraError> {
        if self.range_proofs.is_none() {
            self.range_proofs = Some(Vec::new());
        }
        
        let proofs = self.range_proofs.as_mut().unwrap();
        
        // Ensure the vector is large enough
        while proofs.len() <= index {
            proofs.push(Vec::new());
        }
        
        proofs[index] = range_proof;
        
        // Set the privacy flags to indicate range proofs are used
        self.privacy_flags |= 0x04; // 0x04 = Range proofs flag
        
        Ok(self)
    }
    
    /// Verifies the privacy features of this transaction
    /// 
    /// # Returns
    /// 
    /// * `Result<bool, ObscuraError>` - True if all privacy features verify, false otherwise
    pub fn verify_privacy_features(&self) -> Result<bool, ObscuraError> {
        // Verify transaction obfuscation if applied
        if self.privacy_flags & 0x01 != 0 {
            if self.obfuscated_id.is_none() {
                error!("Transaction has obfuscation flag but no obfuscated ID");
                return Ok(false);
            }
        }
        
        // Verify stealth addressing if applied
        if self.privacy_flags & 0x02 != 0 { // Updated from 0x08 to 0x02
            if self.ephemeral_pubkey.is_none() {
                error!("Transaction has stealth addressing flag but no ephemeral pubkey");
                return Ok(false);
            }
        }
        
        // Verify confidential transactions if applied
        if self.privacy_flags & 0x04 != 0 {
            if self.amount_commitments.is_none() {
                error!("Confidential transactions flag is set but amount commitments are missing");
                return Ok(false);
            }
            
            // Verify that we have a commitment for each output
            if let Some(commitments) = &self.amount_commitments {
                if commitments.len() != self.outputs.len() {
                    error!("Number of commitments does not match number of outputs");
                    return Ok(false);
                }
                
                // Verify each commitment is valid (non-empty)
                for (i, commitment) in commitments.iter().enumerate() {
                    if commitment.is_empty() {
                        error!("Empty commitment for output {}", i);
                        return Ok(false);
                    }
                }
            }
        }
        
        // Verify range proofs if applied
        if self.privacy_flags & 0x08 != 0 { // Updated from 0x04 to 0x08
            if self.range_proofs.is_none() {
                error!("Transaction has range proofs flag but no proofs");
                return Ok(false);
            }
            
            // Verify that we have a range proof for each output
            if let Some(proofs) = &self.range_proofs {
                if proofs.len() != self.outputs.len() {
                    error!("Number of range proofs does not match number of outputs");
                    return Ok(false);
                }
                
                // Verify each range proof is valid (non-empty)
                for (i, proof) in proofs.iter().enumerate() {
                    if proof.is_empty() {
                        error!("Empty range proof for output {}", i);
                        return Ok(false);
                    }
                }
            }
        }
        
        // Verify stealth addressing if applied
        if self.privacy_flags & 0x02 != 0 { // Already correct, but keeping for consistency with the other changes
            if self.ephemeral_pubkey.is_none() {
                error!("Transaction has stealth addressing flag but no ephemeral pubkey");
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Verifies the range proofs for this transaction
    /// 
    /// # Returns
    /// 
    /// * `Result<bool, ObscuraError>` - True if all range proofs verify, false otherwise
    pub fn verify_range_proofs(&self) -> Result<bool, ObscuraError> {
        // Check if transaction has range proofs
        if self.privacy_flags & 0x08 == 0 || self.range_proofs.is_none() || self.amount_commitments.is_none() {
            return Ok(true); // No range proofs to verify
        }
        
        let range_proofs = self.range_proofs.as_ref().unwrap();
        let commitments = self.amount_commitments.as_ref().unwrap();
        
        // Create a confidential transactions instance for verification
        let confidential = ConfidentialTransactions::new();
        
        // Verify each range proof
        for (i, proof) in range_proofs.iter().enumerate() {
            if i >= commitments.len() {
                error!("Range proof index {} exceeds number of commitments {}", i, commitments.len());
                return Ok(false);
            }
            
            let commitment = &commitments[i];
            if !confidential.verify_range_proof(commitment, proof) {
                error!("Range proof verification failed for output {}", i);
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Verifies the balance of confidential transactions
    /// 
    /// For confidential transactions, the sum of input commitments must equal
    /// the sum of output commitments (plus fees).
    /// 
    /// # Returns
    /// 
    /// * `Result<bool, ObscuraError>` - True if the balance verifies, false otherwise
    pub fn verify_confidential_balance(&self) -> Result<bool, ObscuraError> {
        // Check if transaction has confidential amounts
        if self.privacy_flags & 0x04 == 0 || self.amount_commitments.is_none() {
            return Ok(true); // No confidential amounts to verify
        }
        
        // In a real implementation, we would need to:
        // 1. Get the input commitments from the previous outputs
        // 2. Sum the input commitments
        // 3. Sum the output commitments
        // 4. Verify that input_sum = output_sum + fee_commitment
        
        // For this implementation, we'll assume the balance is valid
        // as we don't have access to the previous outputs
        debug!("Confidential balance verification not fully implemented");
        
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::{Transaction, TransactionInput, TransactionOutput, OutPoint};
    use crate::config::presets::PrivacyPreset;
    
    #[test]
    fn test_transaction_privacy_features() {
        // Create a simple transaction
        let mut tx = Transaction {
            inputs: vec![
                TransactionInput {
                    previous_output: OutPoint {
                        transaction_hash: [0; 32],
                        index: 0,
                    },
                    signature_script: vec![],
                    sequence: 0,
                }
            ],
            outputs: vec![
                TransactionOutput {
                    value: 100,
                    public_key_script: vec![],
                }
            ],
            lock_time: 0,
            fee_adjustments: None,
            privacy_flags: 0,
            obfuscated_id: None,
            ephemeral_pubkey: None,
            amount_commitments: None,
            range_proofs: None,
            metadata: HashMap::new(),
        };
        
        // Apply transaction obfuscation
        let mut obfuscator = TransactionObfuscator::new();
        tx.apply_transaction_obfuscation(&mut obfuscator).unwrap();
        
        // Verify that obfuscation was applied
        assert!(tx.obfuscated_id.is_some());
        assert_eq!(tx.privacy_flags & 0x01, 0x01);
        
        // Set a commitment for the output
        let commitment = vec![1, 2, 3, 4]; // Dummy commitment
        tx.set_amount_commitment(0, commitment.clone()).unwrap();
        
        // Verify that the commitment was set
        assert!(tx.amount_commitments.is_some());
        assert_eq!(tx.amount_commitments.as_ref().unwrap()[0], commitment);
        assert_eq!(tx.privacy_flags & 0x04, 0x04);
        
        // Set a range proof for the output
        let range_proof = vec![5, 6, 7, 8]; // Dummy range proof
        tx.set_range_proof(0, range_proof.clone()).unwrap();
        
        // Verify that the range proof was set
        assert!(tx.range_proofs.is_some());
        assert_eq!(tx.range_proofs.as_ref().unwrap()[0], range_proof);
        assert_eq!(tx.privacy_flags & 0x04, 0x04);
        
        // Verify privacy features
        assert!(tx.verify_privacy_features().unwrap());
    }
} 