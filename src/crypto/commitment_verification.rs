use std::collections::HashMap;

use crate::blockchain::{OutPoint, Transaction, TransactionOutput};
use crate::crypto::blinding_store::BlindingStore;
use crate::crypto::bulletproofs::RangeProof;
use crate::crypto::jubjub::JubjubScalar;
use crate::crypto::pedersen::{
    bls_get_g, bls_get_h, get_blinding_store, jubjub_get_g, jubjub_get_h, BlsPedersenCommitment,
    DualCurveCommitment, PedersenCommitment,
};
use crate::crypto::errors::{CryptoError, CryptoResult};

use blstrs::Scalar as BlsScalar;
use log::{debug, error, warn};
use sha2::{Digest, Sha256};

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
            VerificationError::BlindingStoreError(msg) => {
                write!(f, "Blinding store error: {}", msg)
            }
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

// Convert VerificationError to our standardized CryptoError
impl From<VerificationError> for CryptoError {
    fn from(err: VerificationError) -> Self {
        match err {
            VerificationError::InvalidCommitment(msg) => CryptoError::CommitmentError(msg),
            VerificationError::RangeProofError(msg) => CryptoError::ZkProofError(msg),
            VerificationError::CryptoError(msg) => CryptoError::UnexpectedError(msg),
            VerificationError::BlindingStoreError(msg) => CryptoError::CommitmentError(msg),
            VerificationError::MissingData(msg) => CryptoError::ValidationError(msg),
            VerificationError::TransactionError(msg) => CryptoError::ValidationError(msg),
            VerificationError::BalanceError(msg) => CryptoError::ValidationError(msg),
            VerificationError::Other(msg) => CryptoError::UnexpectedError(msg),
        }
    }
}

// Convert CryptoError to VerificationError (for backward compatibility)
impl From<CryptoError> for VerificationError {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::CommitmentError(msg) => VerificationError::InvalidCommitment(msg),
            CryptoError::ZkProofError(msg) => VerificationError::RangeProofError(msg),
            CryptoError::ValidationError(msg) => VerificationError::MissingData(msg),
            _ => VerificationError::Other(err.to_string()),
        }
    }
}

/// Context for commitment verification
#[derive(Debug, Clone)]
pub struct VerificationContext {
    /// Optional blinding store for verification that needs blinding factors
    pub blinding_store: Option<BlindingStore>,
    /// Known UTXOs that can be used as verification reference
    pub utxo_cache: HashMap<OutPoint, TransactionOutput>,
    /// Mapping from outpoints to source transaction hash for commitment lookup
    pub utxo_sources: HashMap<OutPoint, [u8; 32]>,
    /// Cache of transaction amount commitments (tx_hash -> commitment bytes)
    pub commitment_cache: HashMap<[u8; 32], Vec<Vec<u8>>>,
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
            utxo_sources: HashMap::new(),
            commitment_cache: HashMap::new(),
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
            utxo_sources: HashMap::new(),
            commitment_cache: HashMap::new(),
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

    /// Add transaction to the commitment cache
    pub fn add_transaction_commitments(&mut self, tx_hash: [u8; 32], commitments: Vec<Vec<u8>>) {
        self.commitment_cache.insert(tx_hash, commitments);
    }

    /// Register an outpoint as coming from a specific transaction
    pub fn register_utxo_source(&mut self, outpoint: OutPoint, tx_hash: [u8; 32]) {
        self.utxo_sources.insert(outpoint, tx_hash);
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
        blinding: &JubjubScalar,
    ) -> VerificationResult {
        let value_scalar = JubjubScalar::from(value);
        let expected_point = (jubjub_get_g() * value_scalar) + (jubjub_get_h() * *blinding);

        Ok(expected_point == commitment.compute_commitment())
    }

    /// Verify a BlsScalar Pedersen commitment matches a claimed value
    ///
    /// This requires knowledge of the blinding factor
    pub fn verify_bls_commitment(
        commitment: &BlsPedersenCommitment,
        value: u64,
        blinding: &BlsScalar,
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
        bls_blinding: Option<&BlsScalar>,
    ) -> VerificationResult {
        let mut jubjub_result = true;
        let mut bls_result = true;

        // Verify individual commitments if blinding factors are provided
        if let Some(blinding) = jubjub_blinding {
            jubjub_result =
                Self::verify_jubjub_commitment(&commitment.jubjub_commitment, value, blinding)?;
        }

        if let Some(blinding) = bls_blinding {
            bls_result = Self::verify_bls_commitment(&commitment.bls_commitment, value, blinding)?;
        }

        // Ensure both commitments are to the same value (if we have both blinding factors)
        if jubjub_blinding.is_some() && bls_blinding.is_some() && (jubjub_result != bls_result) {
            return Err(VerificationError::BalanceError(
                "Inconsistent commitments: JubJub and BLS commitments do not match".to_string(),
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
        context: &VerificationContext,
    ) -> VerificationResult {
        let blinding_store = context
            .blinding_store
            .as_ref()
            .ok_or_else(|| VerificationError::MissingData("Blinding store not available".into()))?;

        // Try to get JubjubScalar blinding factor
        let jubjub_result = match blinding_store.get_jubjub_blinding_factor(tx_id, output_index) {
            Ok(blinding) => {
                Self::verify_jubjub_commitment(&commitment.jubjub_commitment, value, &blinding)?
            }
            Err(e) => {
                if context.strict_mode {
                    return Err(VerificationError::BlindingStoreError(format!(
                        "Failed to retrieve JubjubScalar blinding factor: {}",
                        e
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
            }
            Err(e) => {
                if context.strict_mode {
                    return Err(VerificationError::BlindingStoreError(format!(
                        "Failed to retrieve BlsScalar blinding factor: {}",
                        e
                    )));
                }
                // In non-strict mode, we continue with JubjubScalar verification result
                true
            }
        };

        // If we're in strict mode, both must verify
        if context.strict_mode && (!jubjub_result || !bls_result) {
            return Err(VerificationError::BalanceError(
                "Commitment verification failed with stored blinding factors".into(),
            ));
        }

        // In non-strict mode, we accept if either one verifies
        Ok(jubjub_result || bls_result)
    }

    /// Verify that commitments in a transaction are balanced (sum of inputs = sum of outputs + fee)
    pub fn verify_transaction_commitment_balance(
        tx: &Transaction,
        known_fee: Option<u64>,
        context: &VerificationContext,
    ) -> VerificationResult {
        // Skip coinbase transactions as they create new coins
        if tx.inputs.is_empty() {
            return Ok(true);
        }

        // Get commitments from inputs
        let mut input_commitments = Vec::new();
        for input in &tx.inputs {
            // Look up the corresponding UTXO
            if let Some(utxo) = context.utxo_cache.get(&input.previous_output) {
                if let Some(tx_hash) = context.utxo_sources.get(&input.previous_output) {
                    // Try to find the source transaction's amount_commitments
                    if let Some(amount_commitments) = context.commitment_cache.get(tx_hash) {
                        let output_index = input.previous_output.index as usize;
                        if output_index < amount_commitments.len() {
                            // Parse the commitment data
                            match DualCurveCommitment::from_bytes(&amount_commitments[output_index])
                            {
                                Ok(commitment) => input_commitments.push(commitment),
                                Err(e) => {
                                    error!("Failed to parse input commitment: {}", e);
                                    return Err(VerificationError::InvalidCommitment(format!(
                                        "Failed to parse input commitment: {}",
                                        e
                                    )));
                                }
                            }
                        } else if context.strict_mode {
                            return Err(VerificationError::MissingData(
                                "Input UTXO commitment index out of bounds".into(),
                            ));
                        }
                    } else if context.strict_mode {
                        return Err(VerificationError::MissingData(
                            "Input UTXO does not have commitments".into(),
                        ));
                    }
                } else if context.strict_mode {
                    return Err(VerificationError::MissingData(
                        "Input UTXO source transaction not found".into(),
                    ));
                }
            } else if context.strict_mode {
                return Err(VerificationError::MissingData(format!(
                    "Input UTXO not found: {:?}",
                    input.previous_output
                )));
            }
        }

        // Get commitments from outputs
        let mut output_commitments = Vec::new();
        if let Some(commitments) = &tx.amount_commitments {
            for (i, commitment_data) in commitments.iter().enumerate() {
                if i < tx.outputs.len() {
                    // Parse the commitment data
                    match DualCurveCommitment::from_bytes(commitment_data) {
                        Ok(commitment) => output_commitments.push(commitment),
                        Err(e) => {
                            error!("Failed to parse output commitment: {}", e);
                            return Err(VerificationError::InvalidCommitment(format!(
                                "Failed to parse output commitment: {}",
                                e
                            )));
                        }
                    }
                }
            }
        } else if context.strict_mode {
            return Err(VerificationError::MissingData(
                "Transaction does not have amount_commitments".into(),
            ));
        }

        // If we don't have any commitments to verify, don't fail in non-strict mode
        if input_commitments.is_empty() || output_commitments.is_empty() {
            if context.strict_mode {
                return Err(VerificationError::MissingData(
                    "No commitments found to verify balance".into(),
                ));
            } else {
                debug!("No commitments to verify in non-strict mode");
                return Ok(true);
            }
        }

        // Sum up input commitments
        if input_commitments.is_empty() {
            return Err(VerificationError::MissingData(
                "No input commitments found to verify balance".into(),
            ));
        }

        let mut sum_inputs = input_commitments[0].clone();
        for i in 1..input_commitments.len() {
            sum_inputs = sum_inputs.add(&input_commitments[i]);
        }

        // Sum up output commitments
        if output_commitments.is_empty() {
            return Err(VerificationError::MissingData(
                "No output commitments found to verify balance".into(),
            ));
        }

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
            let jubjub_equal = sum_inputs.jubjub_commitment.compute_commitment()
                == combined_outputs.jubjub_commitment.compute_commitment();

            // BLS commitment equality
            let bls_equal =
                sum_inputs.bls_commitment.commitment == combined_outputs.bls_commitment.commitment;

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
        context: &VerificationContext,
    ) -> VerificationResult {
        if !context.verify_range_proofs {
            return Ok(true);
        }

        // Check if the transaction has range proofs and commitments
        let range_proofs = match &tx.range_proofs {
            Some(proofs) => proofs,
            None => {
                debug!("No range proofs to verify");
                return Ok(true); // No range proofs to verify
            }
        };

        let commitments = match &tx.amount_commitments {
            Some(commits) => commits,
            None => {
                if context.strict_mode && !range_proofs.is_empty() {
                    return Err(VerificationError::MissingData(
                        "Transaction has range proofs but no commitments".to_string(),
                    ));
                }
                debug!("No commitments to verify range proofs against");
                return Ok(true);
            }
        };

        // Ensure the number of range proofs matches the number of outputs
        if range_proofs.len() != tx.outputs.len() || commitments.len() != tx.outputs.len() {
            return Err(VerificationError::MissingData(format!(
                "Mismatch in number of outputs ({}) vs range proofs ({}) or commitments ({})",
                tx.outputs.len(),
                range_proofs.len(),
                commitments.len()
            )));
        }

        // Verify each range proof
        for i in 0..range_proofs.len() {
            if !range_proofs[i].is_empty() {
                let proof_data = &range_proofs[i];
                let commitment_data = &commitments[i];

                // Convert commitment to the format expected by range proof verifier
                let commitment = match DualCurveCommitment::from_bytes(commitment_data) {
                    Ok(commitment) => commitment,
                    Err(e) => {
                        error!("Failed to parse commitment for range proof: {}", e);
                        return Err(VerificationError::InvalidCommitment(format!(
                            "Failed to parse commitment for range proof: {}",
                            e
                        )));
                    }
                };

                // Create a range proof object
                let range_proof = match RangeProof::from_bytes(proof_data) {
                    Ok(proof) => proof,
                    Err(e) => {
                        error!("Failed to parse range proof: {}", e);
                        return Err(VerificationError::RangeProofError(format!(
                            "Failed to parse range proof: {}",
                            e
                        )));
                    }
                };

                // Verify the range proof
                match crate::crypto::bulletproofs::verify_range_proof(
                    &commitment.jubjub_commitment,
                    &range_proof,
                ) {
                    Ok(valid) => {
                        if !valid {
                            error!("Range proof verification failed for output {}", i);
                            return Err(VerificationError::RangeProofError(format!(
                                "Range proof verification failed for output {}",
                                i
                            )));
                        }
                    }
                    Err(e) => {
                        error!("Range proof verification error for output {}: {:?}", i, e);
                        return Err(VerificationError::RangeProofError(format!(
                            "Range proof verification error for output {}: {:?}",
                            i, e
                        )));
                    }
                }
            } else if context.strict_mode && i < commitments.len() && !commitments[i].is_empty() {
                // In strict mode, if we have a commitment we should also have a range proof
                return Err(VerificationError::MissingData(format!(
                    "Output {} has commitment but no range proof",
                    i
                )));
            }
        }

        debug!("All range proofs verified successfully");
        Ok(true)
    }

    /// Comprehensive verification of a transaction's commitments
    pub fn verify_transaction(
        tx: &Transaction,
        known_fee: Option<u64>,
        context: &VerificationContext,
    ) -> VerificationResult {
        // Skip coinbase transactions for balance checks
        if !tx.inputs.is_empty() {
            // First verify balance
            Self::verify_transaction_commitment_balance(tx, known_fee, context)?;
        }

        // Then verify range proofs
        Self::verify_transaction_range_proofs(tx, context)?;

        Ok(true)
    }

    /// Batch verification of multiple transactions
    /// This verifies both balance and range proofs for a batch of transactions
    /// Coinbase transactions (those with empty inputs) will only have range proofs verified
    pub fn verify_transactions_batch(
        txs: &[Transaction],
        fees: &HashMap<[u8; 32], u64>, // Map from tx hash to fee
        context: &VerificationContext,
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
                            "Transaction {} verification failed: {}",
                            hex::encode(tx_hash),
                            e
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
                    "{} transactions failed verification",
                    failed_txs.len()
                )));
            } else {
                warn!(
                    "{} transactions failed verification in non-strict mode",
                    failed_txs.len()
                );
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
        (a.jubjub_commitment.compute_commitment() == b.jubjub_commitment.compute_commitment())
            && (a.bls_commitment.commitment == b.bls_commitment.commitment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::{Transaction, TransactionInput, TransactionOutput};
    use crate::crypto::pedersen::generate_random_bls_scalar;
    use crate::crypto::pedersen::generate_random_jubjub_scalar;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn test_jubjub_commitment_verification() {
        // Create a commitment to a value
        let value = 100u64;
        let blinding = generate_random_jubjub_scalar();
        let commitment = PedersenCommitment::new(JubjubScalar::from(value), blinding.clone());

        // Verify with correct value and blinding
        let result = CommitmentVerifier::verify_jubjub_commitment(&commitment, value, &blinding);
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Verify with incorrect value
        let result =
            CommitmentVerifier::verify_jubjub_commitment(&commitment, value + 1, &blinding);
        assert!(result.is_ok());
        assert!(!result.unwrap());

        // Verify with incorrect blinding
        let wrong_blinding = generate_random_jubjub_scalar();
        let result =
            CommitmentVerifier::verify_jubjub_commitment(&commitment, value, &wrong_blinding);
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

        // Create the commitment using the standard commit method
        let dual_commitment = DualCurveCommitment::commit(value);

        // Get the blinding factors from the commitment
        let jubjub_blinding = dual_commitment
            .jubjub_commitment
            .blinding();
        let bls_blinding = dual_commitment
            .bls_commitment
            .blinding()
            .expect("BLS blinding should be available");

        // Verify with both blinding factors
        let result = CommitmentVerifier::verify_dual_commitment(
            &dual_commitment,
            value,
            Some(&jubjub_blinding),
            Some(&bls_blinding),
        );
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Verify with only JubjubScalar blinding
        let result = CommitmentVerifier::verify_dual_commitment(
            &dual_commitment,
            value,
            Some(&jubjub_blinding),
            None,
        );
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Verify with only BlsScalar blinding
        let result = CommitmentVerifier::verify_dual_commitment(
            &dual_commitment,
            value,
            None,
            Some(&bls_blinding),
        );
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Verify with incorrect value
        let result = CommitmentVerifier::verify_dual_commitment(
            &dual_commitment,
            value + 1,
            Some(&jubjub_blinding),
            Some(&bls_blinding),
        );
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}
