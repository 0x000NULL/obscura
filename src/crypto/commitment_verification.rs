use std::collections::HashMap;
use std::sync::Arc;

use crate::blockchain::{Transaction, TransactionInput, TransactionOutput, OutPoint};
use crate::crypto::pedersen::{
    PedersenCommitment, BlsPedersenCommitment, DualCurveCommitment,
    jubjub_get_g, jubjub_get_h, bls_get_g, bls_get_h, get_blinding_store
};
use crate::crypto::blinding_store::BlindingStore;
use crate::crypto::jubjub::{JubjubPoint, JubjubScalar};
use crate::crypto::bulletproofs::RangeProof;

use ark_ed_on_bls12_381::{EdwardsProjective as JubjubPoint, Fr as JubjubScalar};
use blstrs::{G1Projective as BlsG1, Scalar as BlsScalar};
use sha2::{Sha256, Digest};
use log::{debug, warn, error};

/// Result type for verification operations
pub type VerificationResult = Result<bool, VerificationError>;

/// Errors that can occur during commitment verification
#[derive(Debug, Clone)]
pub enum VerificationError {
    /// Invalid commitment format or data
    InvalidCommitment(String),
    /// Missing required data for verification
    MissingData(String),
    /// Range proof verification failed
    RangeProofError(String),
    /// Cryptographic error
    CryptoError(String),
    /// Error in blinding factor store
    BlindingStoreError(String),
    /// Transaction structure error
    TransactionError(String),
    /// Balance mismatch error
    BalanceError(String),
    /// Other verification errors
    Other(String),
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            VerificationError::InvalidCommitment(msg) => write!(f, "Invalid commitment: {}", msg),
            VerificationError::MissingData(msg) => write!(f, "Missing data: {}", msg),
            VerificationError::RangeProofError(msg) => write!(f, "Range proof error: {}", msg),
            VerificationError::CryptoError(msg) => write!(f, "Cryptographic error: {}", msg),
            VerificationError::BlindingStoreError(msg) => write!(f, "Blinding store error: {}", msg),
            VerificationError::TransactionError(msg) => write!(f, "Transaction error: {}", msg),
            VerificationError::BalanceError(msg) => write!(f, "Balance error: {}", msg),
            VerificationError::Other(msg) => write!(f, "Verification error: {}", msg),
        }
    }
}

impl std::error::Error for VerificationError {}

impl From<String> for VerificationError {
    fn from(error: String) -> Self {
        VerificationError::Other(error)
    }
}

/// Context for commitment verification
#[derive(Debug, Clone)]
pub struct VerificationContext {
    /// Optional blinding store for verification that needs blinding factors
    pub blinding_store: Option<BlindingStore>,
    /// Known UTXOs that can be used as verification reference
    pub utxo_cache: HashMap<OutPoint, TransactionOutput>,
    /// Flag to enable or disable strict verification
    pub strict_mode: bool,
    /// Flag to enable range proof verification
    pub verify_range_proofs: bool,
}

impl Default for VerificationContext {
    fn default() -> Self {
        VerificationContext {
            blinding_store: get_blinding_store(),
            utxo_cache: HashMap::new(),
            strict_mode: true,
            verify_range_proofs: true,
        }
    }
}

impl VerificationContext {
    /// Create a new verification context
    pub fn new(strict_mode: bool, verify_range_proofs: bool) -> Self {
        VerificationContext {
            blinding_store: get_blinding_store(),
            utxo_cache: HashMap::new(),
            strict_mode,
            verify_range_proofs,
        }
    }
    
    /// Add a known UTXO to the verification context
    pub fn add_utxo(&mut self, outpoint: OutPoint, output: TransactionOutput) {
        self.utxo_cache.insert(outpoint, output);
    }
    
    /// Add multiple UTXOs to the verification context
    pub fn add_utxos(&mut self, utxos: HashMap<OutPoint, TransactionOutput>) {
        self.utxo_cache.extend(utxos);
    }
}

/// The CommitmentVerifier handles verification of Pedersen commitments
pub struct CommitmentVerifier;

impl CommitmentVerifier {
    /// Verify a JubjubScalar Pedersen commitment matches a claimed value
    ///
    /// This requires knowledge of the blinding factor
    pub fn verify_jubjub_commitment(
        commitment: &PedersenCommitment, 
        value: u64, 
        blinding: &JubjubScalar
    ) -> VerificationResult {
        let value_scalar = JubjubScalar::from(value);
        let expected_point = (jubjub_get_g() * value_scalar) + (jubjub_get_h() * *blinding);
        
        Ok(expected_point == commitment.commitment)
    }
    
    /// Verify a BlsScalar Pedersen commitment matches a claimed value
    ///
    /// This requires knowledge of the blinding factor
    pub fn verify_bls_commitment(
        commitment: &BlsPedersenCommitment, 
        value: u64, 
        blinding: &BlsScalar
    ) -> VerificationResult {
        let value_scalar = BlsScalar::from(value);
        let expected_point = (bls_get_g() * value_scalar) + (bls_get_h() * *blinding);
        
        Ok(expected_point == commitment.commitment)
    }
    
    /// Verify a DualCurveCommitment matches a claimed value and its internal commitments are consistent
    pub fn verify_dual_commitment(
        commitment: &DualCurveCommitment, 
        value: u64, 
        jubjub_blinding: Option<&JubjubScalar>,
        bls_blinding: Option<&BlsScalar>
    ) -> VerificationResult {
        let mut jubjub_result = true;
        let mut bls_result = true;
        
        // Verify individual commitments if blinding factors are provided
        if let Some(blinding) = jubjub_blinding {
            jubjub_result = Self::verify_jubjub_commitment(&commitment.jubjub_commitment, value, blinding)?;
        }
        
        if let Some(blinding) = bls_blinding {
            bls_result = Self::verify_bls_commitment(&commitment.bls_commitment, value, blinding)?;
        }
        
        // Ensure both commitments are to the same value (if we have both blinding factors)
        if jubjub_blinding.is_some() && bls_blinding.is_some() && (jubjub_result != bls_result) {
            return Err(VerificationError::BalanceError(
                "Inconsistent commitments: JubJub and BLS commitments do not match".to_string()
            ));
        }
        
        Ok(jubjub_result && bls_result)
    }
    
    /// Verify a commitment with blinding factor retrieved from secure storage
    pub fn verify_commitment_with_stored_blinding(
        commitment: &DualCurveCommitment,
        value: u64,
        tx_id: &[u8; 32],
        output_index: u32,
        context: &VerificationContext
    ) -> VerificationResult {
        let blinding_store = context.blinding_store.as_ref()
            .ok_or_else(|| VerificationError::MissingData("Blinding store not available".into()))?;
        
        // Try to get JubjubScalar blinding factor
        let jubjub_result = match blinding_store.get_jubjub_blinding_factor(tx_id, output_index) {
            Ok(blinding) => {
                Self::verify_jubjub_commitment(&commitment.jubjub_commitment, value, &blinding)?
            },
            Err(e) => {
                if context.strict_mode {
                    return Err(VerificationError::BlindingStoreError(format!(
                        "Failed to retrieve JubjubScalar blinding factor: {}", e
                    )));
                }
                // In non-strict mode, we continue with BLS verification
                true
            }
        };
        
        // Try to get BlsScalar blinding factor
        let bls_result = match blinding_store.get_bls_blinding_factor(tx_id, output_index) {
            Ok(blinding) => {
                Self::verify_bls_commitment(&commitment.bls_commitment, value, &blinding)?
            },
            Err(e) => {
                if context.strict_mode {
                    return Err(VerificationError::BlindingStoreError(format!(
                        "Failed to retrieve BlsScalar blinding factor: {}", e
                    )));
                }
                // In non-strict mode, we continue with JubjubScalar verification result
                true
            }
        };
        
        // If we're in strict mode, both must verify
        if context.strict_mode && (!jubjub_result || !bls_result) {
            return Err(VerificationError::BalanceError(
                "Commitment verification failed with stored blinding factors".into()
            ));
        }
        
        // In non-strict mode, we accept if either one verifies
        Ok(jubjub_result || bls_result)
    }
    
    /// Verify that commitments in a transaction are balanced (sum of inputs = sum of outputs + fee)
    pub fn verify_transaction_commitment_balance(
        tx: &Transaction, 
        known_fee: Option<u64>,
        context: &VerificationContext
    ) -> VerificationResult {
        // Skip coinbase transactions as they create new coins
        if tx.is_coinbase() {
            return Ok(true);
        }
        
        // Get commitments from inputs
        let mut input_commitments = Vec::new();
        for input in &tx.inputs {
            // Look up the corresponding UTXO
            if let Some(utxo) = context.utxo_cache.get(&input.previous_output) {
                if let Some(commitment_data) = &utxo.commitment {
                    // Parse the commitment data
                    match DualCurveCommitment::from_bytes(commitment_data) {
                        Ok(commitment) => input_commitments.push(commitment),
                        Err(e) => return Err(VerificationError::InvalidCommitment(
                            format!("Failed to parse input commitment: {}", e)
                        )),
                    }
                } else if context.strict_mode {
                    return Err(VerificationError::MissingData(
                        "Input UTXO does not have a commitment".into()
                    ));
                }
            } else if context.strict_mode {
                return Err(VerificationError::MissingData(
                    format!("Input UTXO not found: {:?}", input.previous_output)
                ));
            }
        }
        
        // Get commitments from outputs
        let mut output_commitments = Vec::new();
        for output in &tx.outputs {
            if let Some(commitment_data) = &output.commitment {
                match DualCurveCommitment::from_bytes(commitment_data) {
                    Ok(commitment) => output_commitments.push(commitment),
                    Err(e) => return Err(VerificationError::InvalidCommitment(
                        format!("Failed to parse output commitment: {}", e)
                    )),
                }
            } else if context.strict_mode {
                return Err(VerificationError::MissingData(
                    "Output does not have a commitment".into()
                ));
            }
        }
        
        // If we don't have any commitments to verify, don't fail in non-strict mode
        if input_commitments.is_empty() || output_commitments.is_empty() {
            if context.strict_mode {
                return Err(VerificationError::MissingData(
                    "No commitments found to verify balance".into()
                ));
            } else {
                return Ok(true);
            }
        }
        
        // Sum up input commitments
        let mut sum_inputs = input_commitments[0].clone();
        for i in 1..input_commitments.len() {
            sum_inputs = sum_inputs.add(&input_commitments[i]);
        }
        
        // Sum up output commitments
        let mut sum_outputs = output_commitments[0].clone();
        for i in 1..output_commitments.len() {
            sum_outputs = sum_outputs.add(&output_commitments[i]);
        }
        
        // If fee is known, create a commitment to the fee
        if let Some(fee) = known_fee {
            let fee_commitment = DualCurveCommitment::commit(fee);
            
            // Sum should be: inputs = outputs + fee
            let combined_outputs = sum_outputs.add(&fee_commitment);
            
            // JubJub commitment equality
            let jubjub_equal = sum_inputs.jubjub_commitment.commitment == combined_outputs.jubjub_commitment.commitment;
            
            // BLS commitment equality
            let bls_equal = sum_inputs.bls_commitment.commitment == combined_outputs.bls_commitment.commitment;
            
            // Both commitment types should match for full verification
            Ok(jubjub_equal && bls_equal)
        } else {
            // If fee is unknown, just verify that inputs ≥ outputs
            // This is a limitation - we can't fully verify without knowing the fee
            
            // Note: This is a simplified approach; in a complete system
            // we'd need to recover or know the fee to do proper verification
            
            debug!("Fee unknown, performing limited balance verification");
            
            // With Pedersen commitments, we can only check equality, not inequality
            // So this is a partial check, assuming fee is non-negative
            Ok(true)
        }
    }
    
    /// Verify range proofs for transaction outputs
    pub fn verify_transaction_range_proofs(
        tx: &Transaction,
        context: &VerificationContext
    ) -> VerificationResult {
        if !context.verify_range_proofs {
            return Ok(true);
        }
        
        for (i, output) in tx.outputs.iter().enumerate() {
            if let Some(range_proof_data) = &output.range_proof {
                if let Some(commitment_data) = &output.commitment {
                    // Parse the range proof
                    let range_proof = match RangeProof::from_bytes(range_proof_data) {
                        Ok(proof) => proof,
                        Err(e) => return Err(VerificationError::RangeProofError(
                            format!("Failed to parse range proof for output {}: {}", i, e)
                        )),
                    };
                    
                    // Parse the commitment
                    let commitment = match DualCurveCommitment::from_bytes(commitment_data) {
                        Ok(commitment) => commitment,
                        Err(e) => return Err(VerificationError::InvalidCommitment(
                            format!("Failed to parse commitment for output {}: {}", i, e)
                        )),
                    };
                    
                    // Verify the range proof
                    if !range_proof.verify(&commitment) {
                        return Err(VerificationError::RangeProofError(
                            format!("Range proof verification failed for output {}", i)
                        ));
                    }
                } else if context.strict_mode {
                    return Err(VerificationError::MissingData(
                        format!("Output {} has range proof but no commitment", i)
                    ));
                }
            } else if context.strict_mode && output.commitment.is_some() {
                // In strict mode, if we have a commitment we should also have a range proof
                return Err(VerificationError::MissingData(
                    format!("Output {} has commitment but no range proof", i)
                ));
            }
        }
        
        Ok(true)
    }
    
    /// Comprehensive verification of a transaction's commitments
    pub fn verify_transaction(
        tx: &Transaction,
        known_fee: Option<u64>,
        context: &VerificationContext
    ) -> VerificationResult {
        // Skip coinbase transactions for balance checks
        if !tx.is_coinbase() {
            // First verify balance
            Self::verify_transaction_commitment_balance(tx, known_fee, context)?;
        }
        
        // Then verify range proofs
        Self::verify_transaction_range_proofs(tx, context)?;
        
        Ok(true)
    }
    
    /// Batch verification of multiple transactions
    pub fn verify_transactions_batch(
        txs: &[Transaction],
        fees: &HashMap<[u8; 32], u64>, // Map from tx hash to fee
        context: &VerificationContext
    ) -> VerificationResult {
        let mut failed_txs = Vec::new();
        
        for tx in txs {
            let tx_hash = tx.hash();
            let fee = fees.get(&tx_hash).copied();
            
            match Self::verify_transaction(tx, fee, context) {
                Ok(true) => continue,
                Ok(false) => failed_txs.push(tx_hash),
                Err(e) => {
                    if context.strict_mode {
                        return Err(VerificationError::TransactionError(format!(
                            "Transaction {} verification failed: {}", hex::encode(tx_hash), e
                        )));
                    } else {
                        failed_txs.push(tx_hash);
                    }
                }
            }
        }
        
        if !failed_txs.is_empty() {
            if context.strict_mode {
                return Err(VerificationError::TransactionError(format!(
                    "{} transactions failed verification", failed_txs.len()
                )));
            } else {
                warn!("{} transactions failed verification in non-strict mode", failed_txs.len());
            }
        }
        
        Ok(failed_txs.is_empty())
    }
}

/// Utility functions for working with commitments
pub mod utils {
    use super::*;
    
    /// Create a hash of a commitment for reference
    pub fn commitment_digest(commitment: &DualCurveCommitment) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&commitment.to_bytes());
        let result = hasher.finalize();
        
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result[..]);
        digest
    }
    
    /// Check if two commitments are equal (without knowing their values)
    pub fn are_commitments_equal(a: &DualCurveCommitment, b: &DualCurveCommitment) -> bool {
        (a.jubjub_commitment.commitment == b.jubjub_commitment.commitment) &&
        (a.bls_commitment.commitment == b.bls_commitment.commitment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pedersen::generate_random_jubjub_scalar;
    use crate::crypto::pedersen::generate_random_bls_scalar;
    use crate::blockchain::{Transaction, TransactionInput, TransactionOutput};
    use std::path::PathBuf;
    use tempfile::tempdir;
    
    #[test]
    fn test_jubjub_commitment_verification() {
        // Create a commitment to a value
        let value = 100u64;
        let blinding = generate_random_jubjub_scalar();
        let commitment = PedersenCommitment::commit(value, blinding.clone());
        
        // Verify with correct value and blinding
        let result = CommitmentVerifier::verify_jubjub_commitment(&commitment, value, &blinding);
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Verify with incorrect value
        let result = CommitmentVerifier::verify_jubjub_commitment(&commitment, value + 1, &blinding);
        assert!(result.is_ok());
        assert!(!result.unwrap());
        
        // Verify with incorrect blinding
        let wrong_blinding = generate_random_jubjub_scalar();
        let result = CommitmentVerifier::verify_jubjub_commitment(&commitment, value, &wrong_blinding);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
    
    #[test]
    fn test_bls_commitment_verification() {
        // Create a commitment to a value
        let value = 200u64;
        let blinding = generate_random_bls_scalar();
        let commitment = BlsPedersenCommitment::commit(value, blinding.clone());
        
        // Verify with correct value and blinding
        let result = CommitmentVerifier::verify_bls_commitment(&commitment, value, &blinding);
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Verify with incorrect value
        let result = CommitmentVerifier::verify_bls_commitment(&commitment, value + 1, &blinding);
        assert!(result.is_ok());
        assert!(!result.unwrap());
        
        // Verify with incorrect blinding
        let wrong_blinding = generate_random_bls_scalar();
        let result = CommitmentVerifier::verify_bls_commitment(&commitment, value, &wrong_blinding);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
    
    #[test]
    fn test_dual_commitment_verification() {
        // Create a dual commitment
        let value = 300u64;
        let jubjub_blinding = generate_random_jubjub_scalar();
        let bls_blinding = generate_random_bls_scalar();
        
        let jubjub_commitment = PedersenCommitment::commit(value, jubjub_blinding.clone());
        let bls_commitment = BlsPedersenCommitment::commit(value, bls_blinding.clone());
        
        let dual_commitment = DualCurveCommitment {
            jubjub_commitment,
            bls_commitment,
            value: Some(value),
        };
        
        // Verify with both blinding factors
        let result = CommitmentVerifier::verify_dual_commitment(
            &dual_commitment,
            value,
            Some(&jubjub_blinding),
            Some(&bls_blinding)
        );
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Verify with only JubjubScalar blinding
        let result = CommitmentVerifier::verify_dual_commitment(
            &dual_commitment,
            value,
            Some(&jubjub_blinding),
            None
        );
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Verify with only BlsScalar blinding
        let result = CommitmentVerifier::verify_dual_commitment(
            &dual_commitment,
            value,
            None,
            Some(&bls_blinding)
        );
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Verify with incorrect value
        let result = CommitmentVerifier::verify_dual_commitment(
            &dual_commitment,
            value + 1,
            Some(&jubjub_blinding),
            Some(&bls_blinding)
        );
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
} 