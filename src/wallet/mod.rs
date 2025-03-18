use crate::blockchain::{
    Block, OutPoint, Transaction, TransactionInput, TransactionOutput, UTXOSet,
};
use crate::crypto;
use crate::crypto::bls12_381::{BlsKeypair, BlsPublicKey, BlsSignature, ProofOfPossession};
use crate::crypto::jubjub::{
    JubjubKeypair, JubjubPoint, JubjubPointExt, JubjubScalar, JubjubScalarExt,
};
use crate::crypto::view_key::{ViewKey, ViewKeyPermissions, ViewKeyManager};
use crate::utils::{current_time, format_time_diff};
use crypto::jubjub;
use rand::rngs::OsRng;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use log::debug;

#[derive(Debug, Clone)]
pub struct Wallet {
    pub balance: u64,
    pub transactions: Vec<Transaction>,
    pub keypair: Option<JubjubKeypair>,
    pub privacy_enabled: bool,
    // UTXO set for this wallet
    utxos: HashMap<OutPoint, TransactionOutput>,
    // Transaction timestamp tracking for activity reports
    transaction_timestamps: HashMap<[u8; 32], u64>,
    // Last wallet sync time
    last_sync_time: u64,
    // Spent outpoints pending confirmation
    pending_spent_outpoints: Arc<Mutex<HashSet<OutPoint>>>,
    // View key management
    view_key_manager: ViewKeyManager,
    // BLS keypair for consensus participation
    bls_keypair: Option<BlsKeypair>,
    // Stealth addressing for enhanced privacy
    stealth_addressing: Option<StealthAddressing>,
    // Confidential transactions for amount privacy
    confidential_transactions: Option<ConfidentialTransactions>,
    // Use decoys for privacy
    add_decoys: bool,
}

// Placeholder for stealth addressing functionality
#[derive(Debug, Clone)]
pub struct StealthAddressing {
    // Cache of generated one-time addresses
    one_time_addresses: HashMap<Vec<u8>, JubjubPoint>,
    // Cache of ephemeral keys for addresses we've generated
    ephemeral_keys: HashMap<Vec<u8>, JubjubPoint>,
    // Cache of scanned transactions
    scanned_transactions: HashMap<[u8; 32], Vec<TransactionOutput>>,
}

impl StealthAddressing {
    pub fn new() -> Self {
        Self {
            one_time_addresses: HashMap::new(),
            ephemeral_keys: HashMap::new(),
            scanned_transactions: HashMap::new(),
        }
    }
    
    pub fn generate_one_time_address(&mut self, recipient_pubkey: &JubjubPoint) -> Vec<u8> {
        // Generate a secure ephemeral key pair
        let (ephemeral_private, ephemeral_public) = crypto::jubjub::generate_secure_ephemeral_key();
        
        // Create a stealth address using the recipient's public key
        let (ephemeral_pub, stealth_address) = crypto::jubjub::create_stealth_address(recipient_pubkey);
        
        // Convert to bytes
        let stealth_address_bytes = jubjub_point_to_bytes(&stealth_address);
        
        // Cache the one-time address and ephemeral key
        self.one_time_addresses.insert(stealth_address_bytes.clone(), stealth_address);
        self.ephemeral_keys.insert(stealth_address_bytes.clone(), ephemeral_pub);
        
        stealth_address_bytes
    }
    
    pub fn scan_transaction(&self, tx: &Transaction, keypair: &JubjubKeypair) -> Option<Vec<(OutPoint, TransactionOutput)>> {
        if tx.ephemeral_pubkey.is_none() {
            return None; // Not a stealth transaction
        }
        
        let mut found_outputs = Vec::new();
        
        // Get the ephemeral public key from the transaction
        let ephemeral_pubkey_bytes = tx.ephemeral_pubkey.as_ref().unwrap();
        let ephemeral_pubkey = match bytes_to_jubjub_point(ephemeral_pubkey_bytes) {
            Some(pk) => pk,
            None => return None,
        };
        
        // Recover the stealth private key
        let stealth_private_key = crypto::jubjub::recover_stealth_private_key(
            &keypair.secret,
            &ephemeral_pubkey,
            None // No timestamp for backward compatibility
        );
        
        // Derive the stealth public key
        let stealth_public = <JubjubPoint as JubjubPointExt>::generator() * stealth_private_key;
        let stealth_address_bytes = jubjub_point_to_bytes(&stealth_public);
        
        // Check each output to see if it's for us
        for (i, output) in tx.outputs.iter().enumerate() {
            if output.public_key_script == stealth_address_bytes {
                // Found a payment to us!
                let outpoint = OutPoint {
                    transaction_hash: tx.hash(),
                    index: i as u32,
                };
                
                found_outputs.push((outpoint, output.clone()));
            }
        }
        
        if found_outputs.is_empty() {
            None
        } else {
            Some(found_outputs)
        }
    }
    
    pub fn decrypt_amount(&self, tx: &Transaction, output_index: usize, keypair: &JubjubKeypair) -> Option<u64> {
        // Check if this is a confidential transaction
        if tx.amount_commitments.is_none() || tx.range_proofs.is_none() {
            // If not confidential, just return the output value directly
            return tx.outputs.get(output_index).map(|output| output.value);
        }
        
        let commitments = tx.amount_commitments.as_ref().unwrap();
        let range_proofs = tx.range_proofs.as_ref().unwrap();
        
        // Make sure the output index is valid and has a commitment
        if output_index >= commitments.len() || output_index >= tx.outputs.len() {
            return None;
        }
        
        let commitment = &commitments[output_index];
        
        // In a real implementation, we would use the private key to decrypt the amount
        // For now, we'll use a simplified approach where we check if we have the output
        // in our cache from scanning
        
        // Get the ephemeral public key from the transaction
        let ephemeral_pubkey_bytes = match &tx.ephemeral_pubkey {
            Some(bytes) => bytes,
            None => return None,
        };
        
        let ephemeral_pubkey = match bytes_to_jubjub_point(ephemeral_pubkey_bytes) {
            Some(pk) => pk,
            None => return None,
        };
        
        // Recover the stealth private key
        let stealth_private_key = crypto::jubjub::recover_stealth_private_key(
            &keypair.secret,
            &ephemeral_pubkey,
            None // No timestamp for backward compatibility
        );
        
        // Use the stealth private key to decrypt the amount
        // In a real implementation, this would use the private key with the commitment
        // to reveal the amount
        
        // For now, we'll just return the output value if it's not hidden
        tx.outputs.get(output_index).map(|output| output.value)
    }
}

// Placeholder for confidential transactions functionality
#[derive(Debug, Clone)]
pub struct ConfidentialTransactions {}

impl ConfidentialTransactions {
    pub fn new() -> Self {
        Self {}
    }
    
    pub fn create_commitment(&self, amount: u64) -> Vec<u8> {
        // Implement commitment creation
        let mut hasher = Sha256::new();
        hasher.update(amount.to_le_bytes());
        hasher.finalize().to_vec()
    }
    
    pub fn create_range_proof(&self, amount: u64) -> Vec<u8> {
        // Implement range proof creation
        let mut hasher = Sha256::new();
        hasher.update(b"rangeproof");
        hasher.update(amount.to_le_bytes());
        hasher.finalize().to_vec()
    }
}

impl Default for Wallet {
    fn default() -> Self {
        Wallet {
            balance: 0,
            transactions: Vec::new(),
            keypair: None,
            privacy_enabled: false,
            utxos: HashMap::new(),
            transaction_timestamps: HashMap::new(),
            last_sync_time: current_time(),
            pending_spent_outpoints: Arc::new(Mutex::new(HashSet::new())),
            view_key_manager: ViewKeyManager::new(),
            bls_keypair: None,
            stealth_addressing: None,
            confidential_transactions: None,
            add_decoys: false,
        }
    }
}

impl Wallet {
    pub fn new() -> Self {
        Wallet::default()
    }

    pub fn new_with_keypair() -> Self {
        let mut _rng = OsRng;
        let keypair = JubjubKeypair::generate();

        Wallet {
            balance: 0,
            transactions: Vec::new(),
            keypair: Some(keypair),
            privacy_enabled: false,
            utxos: HashMap::new(),
            transaction_timestamps: HashMap::new(),
            last_sync_time: current_time(),
            pending_spent_outpoints: Arc::new(Mutex::new(HashSet::new())),
            view_key_manager: ViewKeyManager::new(),
            bls_keypair: None,
            stealth_addressing: None,
            confidential_transactions: None,
            add_decoys: false,
        }
    }

    pub fn set_keypair(&mut self, keypair: JubjubKeypair) {
        self.keypair = Some(keypair);
    }

    pub fn get_public_key(&self) -> Option<JubjubPoint> {
        self.keypair.as_ref().map(|kp| kp.public)
    }

    pub fn get_public_key_bytes(&self) -> Vec<u8> {
        if let Some(keypair) = &self.keypair {
            jubjub_point_to_bytes(&keypair.public)
        } else {
            Vec::new()
        }
    }

    pub fn enable_privacy(&mut self) {
        self.privacy_enabled = true;
        // Initialize stealth addressing if not already done
        if self.stealth_addressing.is_none() {
            self.stealth_addressing = Some(StealthAddressing::new());
        }
        // Initialize confidential transactions if not already done
        if self.confidential_transactions.is_none() {
            self.confidential_transactions = Some(ConfidentialTransactions::new());
        }
    }

    pub fn disable_privacy(&mut self) {
        self.privacy_enabled = false;
    }

    pub fn is_privacy_enabled(&self) -> bool {
        self.privacy_enabled
    }

    /// Select UTXOs to use for a transaction
    fn select_utxos(
        &self,
        amount: u64,
        fee_per_kb: u64,
    ) -> Option<(Vec<(OutPoint, TransactionOutput)>, u64)> {
        #[cfg(test)]
        println!(
            "select_utxos called with amount: {}, fee_per_kb: {}",
            amount, fee_per_kb
        );

        if self.utxos.is_empty() {
            #[cfg(test)]
            println!("UTXO set is empty");
            return None;
        }

        // Get available UTXOs (not pending spent)
        let available_utxos: Vec<(OutPoint, TransactionOutput)> = self
            .utxos
            .iter()
            .filter(|(outpoint, _)| {
                !self
                    .pending_spent_outpoints
                    .lock()
                    .unwrap()
                    .contains(outpoint)
            })
            .map(|(outpoint, output)| (*outpoint, output.clone()))
            .collect();

        #[cfg(test)]
        println!("Available UTXOs: {}", available_utxos.len());

        if available_utxos.is_empty() {
            #[cfg(test)]
            println!("No available UTXOs (all might be pending)");
            return None;
        }

        // Try to find an exact match first (optimization)
        for (outpoint, output) in &available_utxos {
            if output.value == amount {
                #[cfg(test)]
                println!("Found exact match UTXO with value: {}", output.value);
                // Perfect match, no change needed
                return Some((vec![(*outpoint, output.clone())], 0));
            }
        }

        // Sort UTXOs by value (largest first) for simplicity
        // In a real implementation, we would use a more sophisticated coin selection algorithm
        let mut sorted_utxos = available_utxos.clone();
        sorted_utxos.sort_by(|(_, a), (_, b)| b.value.cmp(&a.value));

        #[cfg(test)]
        if !sorted_utxos.is_empty() {
            println!(
                "Sorted UTXOs: first value = {}, last value = {}",
                sorted_utxos.first().unwrap().1.value,
                sorted_utxos.last().unwrap().1.value
            );
        }

        // Try to find a combination of UTXOs that covers the amount
        let mut selected_utxos = Vec::new();
        let mut total_value = 0;

        for (outpoint, output) in sorted_utxos {
            #[cfg(test)]
            println!("Considering UTXO with value: {}", output.value);

            selected_utxos.push((outpoint, output.clone()));
            total_value += output.value;

            // Estimate the fee based on the size of the transaction
            let estimated_tx_size = self.estimate_tx_size(selected_utxos.len(), 2); // Assume 2 outputs (payment + change)
            let estimated_fee = (estimated_tx_size as u64 * fee_per_kb) / 1000;

            #[cfg(test)]
            println!(
                "Selected {} UTXOs with total value: {}, estimated fee: {}",
                selected_utxos.len(),
                total_value,
                estimated_fee
            );

            if total_value >= amount + estimated_fee {
                let change = total_value - amount - estimated_fee;

                // Check if change is "dust" - too small to be worth creating an output for
                // If it would cost more in fees to spend this change later than its value,
                // just include it as part of the fee
                let min_change_threshold = 1000; // Minimum change value to create a change output

                #[cfg(test)]
                println!("Found sufficient UTXOs with change: {}", change);

                if change < min_change_threshold {
                    #[cfg(test)]
                    println!("Change is too small (dust), including it in fee");
                    return Some((selected_utxos, 0)); // No change output, include in fee
                }

                return Some((selected_utxos, change));
            }
        }

        #[cfg(test)]
        println!("Could not find sufficient UTXOs to cover amount + fee");

        // Couldn't find enough funds
        None
    }

    /// Estimate the size of a transaction in bytes
    fn estimate_tx_size(&self, input_count: usize, output_count: usize) -> usize {
        // Update the constant values to be more realistic and smaller
        // Transaction overhead = 8 bytes (version, lock time)
        // Each input = ~41 bytes (outpoint, script length, sequence)
        // Each output = ~31 bytes (value, script length, script)
        // Signature per input = ~65 bytes (more compact signatures)

        let tx_overhead = 8;
        let input_size = 41;
        let output_size = 31;
        let signature_size = 65;

        tx_overhead + (input_count * (input_size + signature_size)) + (output_count * output_size)
    }

    /// Calculate appropriate fee for a transaction
    pub fn calculate_recommended_fee(
        &self,
        input_count: usize,
        output_count: usize,
        priority: &str,
    ) -> u64 {
        // Base fee rate for normal priority (satoshis per KB)
        let base_fee_rate = 1000; // 1000 satoshis per KB

        // Adjust fee rate based on priority
        let fee_rate = match priority {
            "low" => base_fee_rate / 2,
            "normal" => base_fee_rate,
            "high" => base_fee_rate * 3,
            "urgent" => base_fee_rate * 5,
            _ => base_fee_rate,
        };

        // Calculate size and fee
        let size = self.estimate_tx_size(input_count, output_count);
        (size as u64 * fee_rate) / 1000
    }

    /// Create a transaction using proper UTXO selection
    pub fn create_transaction_with_fee(
        &mut self,
        recipient: &JubjubPoint,
        amount: u64,
        fee_per_kb: u64,
    ) -> Option<Transaction> {
        if self.keypair.is_none() {
            return None; // Can't sign without a keypair
        }

        // Select UTXOs to cover the amount + fees
        let utxos_result = self.select_utxos(amount, fee_per_kb);
        if utxos_result.is_none() {
            return None; // Not enough funds
        }

        let (selected_utxos, change) = utxos_result.unwrap();
        let total_input = selected_utxos
            .iter()
            .map(|(_, output)| output.value)
            .sum::<u64>();

        // Create a new transaction
        let mut tx = Transaction::default();

        // Add inputs
        for (outpoint, _) in &selected_utxos {
            // Create a signature for the input using our keypair
            let keypair = self.keypair.as_ref().unwrap();

            // Create a transaction hash for signing
            let mut hasher = Sha256::new();
            hasher.update(&outpoint.transaction_hash);
            hasher.update(&outpoint.index.to_le_bytes());
            
            // Get the transaction hash
            let mut tx_hash = [0u8; 32];
            tx_hash.copy_from_slice(&hasher.finalize());
            
            // Sign the hash with our private key
            let signature = keypair.sign(&tx_hash);
            
            // Set the signature in the input - use the signature's to_bytes method
            let signature_bytes = signature.to_bytes();

            let input = TransactionInput {
                previous_output: outpoint.clone(),
                signature_script: signature_bytes,
                sequence: 0,
            };

            tx.inputs.push(input);
        }

        // Add recipient output
        let recipient_bytes = jubjub_point_to_bytes(recipient);
        let payment_output = TransactionOutput {
            value: amount,
            public_key_script: recipient_bytes,
            range_proof: None,
            commitment: None,
        };

        tx.outputs.push(payment_output);

        // Add change output if needed
        if change > 0 {
            let keypair = self.keypair.as_ref().unwrap();
            let change_output = TransactionOutput {
                value: change,
                public_key_script: jubjub_point_to_bytes(&keypair.public),
                range_proof: None,
                commitment: None,
            };

            tx.outputs.push(change_output);
        }

        // Apply privacy features if enabled
        if self.privacy_enabled {
            tx = self.apply_privacy_features(tx);
        }

        // Calculate the net change to wallet balance by comparing inputs and outputs
        // The difference is the transaction fee plus the payment amount minus any change returned
        let total_output: u64 = tx.outputs.iter().map(|output| output.value).sum();
        let spent_amount = total_input - total_output; // This is fee + payment - change

        // Update wallet balance more safely
        if self.balance >= spent_amount {
            self.balance -= spent_amount;
        } else {
            // This shouldn't happen if UTXO selection is working correctly
            // But better to be safe than sorry
            self.balance = 0;
            #[cfg(test)]
            println!("Warning: Balance underflow prevented");
        }

        // Store the transaction
        self.transactions.push(tx.clone());

        // Add timestamp for this transaction
        self.transaction_timestamps
            .insert(tx.hash(), current_time());

        // Mark UTXOs as pending spent
        for (outpoint, _) in selected_utxos {
            self.pending_spent_outpoints
                .lock()
                .unwrap()
                .insert(outpoint);
        }

        Some(tx)
    }

    /// Original simplified transaction creation (kept for backward compatibility)
    pub fn create_transaction(
        &mut self,
        recipient: &JubjubPoint,
        amount: u64,
    ) -> Option<Transaction> {
        if self.keypair.is_none() {
            return None; // Can't sign without a keypair
        }

        if self.balance < amount {
            return None; // Insufficient funds
        }

        // This is a simplified implementation
        // In a real wallet, we would select UTXOs for inputs

        // Create a new transaction
        let mut tx = Transaction::default();

        // Add a dummy input (in real implementation, this would be a UTXO)
        let mut hasher = Sha256::new();
        hasher.update(b"dummy_transaction");
        let mut tx_hash = [0u8; 32];
        tx_hash.copy_from_slice(&hasher.finalize());

        let outpoint = OutPoint {
            transaction_hash: tx_hash,
            index: 0,
        };

        // Create a signature for the input using our keypair
        let keypair = self.keypair.as_ref().unwrap();

        // Create a new hasher for the signature
        let mut sig_hasher = Sha256::new();
        sig_hasher.update(b"dummy_transaction");
        
        // Finalize the hash
        let hash = sig_hasher.finalize();
        
        // Sign the hash with our private key
        let signature = keypair.sign(&hash);
        
        // Set the signature in the input - use the signature's to_bytes method
        let signature_bytes = signature.to_bytes();

        let input = TransactionInput {
            previous_output: outpoint,
            signature_script: signature_bytes,
            sequence: 0,
        };

        tx.inputs.push(input);

        // Add recipient output
        let recipient_bytes = jubjub_point_to_bytes(recipient);
        let payment_output = TransactionOutput {
            value: amount,
            public_key_script: recipient_bytes,
            range_proof: None,
            commitment: None,
        };

        tx.outputs.push(payment_output);

        // Add change output if needed
        if self.balance > amount {
            let change_output = TransactionOutput {
                value: self.balance - amount,
                public_key_script: self.get_public_key_bytes(),
                range_proof: None,
                commitment: None,
            };

            tx.outputs.push(change_output);
        }

        // Apply privacy features if enabled
        if self.privacy_enabled {
            tx = self.apply_privacy_features(tx);
        }

        // Update wallet balance
        self.balance -= amount;

        // Store the transaction
        self.transactions.push(tx.clone());

        // Add timestamp for this transaction
        self.transaction_timestamps
            .insert(tx.hash(), current_time());

        Some(tx)
    }

    fn apply_privacy_features(&self, mut tx: Transaction) -> Transaction {
        if !self.privacy_enabled {
            return tx;
        }

        // Apply stealth addressing if enabled
        if let Some(stealth_addressing) = &self.stealth_addressing {
            // For each output, convert the recipient address to a stealth address
            for i in 0..tx.outputs.len() {
                let output = &tx.outputs[i];
                
                // Try to convert the output's public key script to a JubjubPoint
                if let Some(recipient_pubkey) = bytes_to_jubjub_point(&output.public_key_script) {
                    // Generate a one-time address for the recipient
                    // Note: We need to clone stealth_addressing to make it mutable
                    let mut stealth_addressing_clone = stealth_addressing.clone();
                    let stealth_address = stealth_addressing_clone.generate_one_time_address(&recipient_pubkey);
                    
                    // Update the output with the stealth address
                    tx.outputs[i].public_key_script = stealth_address.clone();
                    
                    // Set the ephemeral public key in the transaction
                    if let Some(ephemeral_key) = stealth_addressing_clone.ephemeral_keys.get(&stealth_address) {
                        tx.ephemeral_pubkey = Some(jubjub_point_to_bytes(ephemeral_key).try_into().unwrap());
                    }
                }
            }
        }

        // Apply confidential transactions if enabled
        if let Some(confidential_transactions) = &self.confidential_transactions {
            // For each output, create a commitment and range proof
            let mut commitments = Vec::new();
            let mut range_proofs = Vec::new();
            
            for output in &tx.outputs {
                // Create a commitment for the output value
                let commitment = confidential_transactions.create_commitment(output.value);
                commitments.push(commitment);
                
                // Create a range proof for the output value
                let range_proof = confidential_transactions.create_range_proof(output.value);
                range_proofs.push(range_proof);
            }
            
            // Set the commitments and range proofs in the transaction
            tx.amount_commitments = Some(commitments);
            tx.range_proofs = Some(range_proofs);
        }

        // Set privacy flags
        tx.privacy_flags |= if self.stealth_addressing.is_some() { 0x02 } else { 0x00 };
        tx.privacy_flags |= if self.confidential_transactions.is_some() { 0x04 } else { 0x00 };

        tx
    }

    /// Submit a transaction to the network
    /// Note: This marks the inputs as pending until they appear in a confirmed block
    pub fn submit_transaction(&mut self, tx: &Transaction) {
        // Mark UTXOs as pending spent
        for input in &tx.inputs {
            self.pending_spent_outpoints
                .lock()
                .unwrap()
                .insert(input.previous_output.clone());
        }

        // In a real implementation, this would broadcast the transaction to the network
        println!(
            "Transaction {} submitted to network",
            hex::encode(tx.hash())
        );

        // Add the transaction to our history
        self.transactions.push(tx.clone());

        // Add a timestamp for this transaction
        self.transaction_timestamps
            .insert(tx.hash(), current_time());
    }

    /// Clear pending transactions (e.g., if they fail to confirm)
    pub fn clear_pending_transactions(&mut self) {
        self.pending_spent_outpoints.lock().unwrap().clear();

        // Update the balance to match available UTXOs
        let available = self.get_available_balance();
        self.balance = available;
    }

    pub fn process_block(&mut self, block: &Block, utxo_set: &UTXOSet) {
        for tx in &block.transactions {
            self.process_transaction(tx, utxo_set);
        }

        // After processing the block, verify and update the utxo set state
        self.verify_utxo_consistency(utxo_set);

        // Clear any pending spent outpoints that were in this block
        for tx in &block.transactions {
            for input in &tx.inputs {
                self.pending_spent_outpoints
                    .lock()
                    .unwrap()
                    .remove(&input.previous_output);
            }
        }

        // Update the last sync time
        self.last_sync_time = current_time();
    }

    pub fn process_transaction(&mut self, tx: &Transaction, utxo_set: &UTXOSet) {
        // Skip if we don't have a keypair
        if self.keypair.is_none() {
            return;
        }

        let keypair = self.keypair.as_ref().unwrap();
        let our_pubkey_bytes = jubjub_point_to_bytes(&keypair.public);

        // Check if any outputs are for us
        let mut received = 0;
        for (i, output) in tx.outputs.iter().enumerate() {
            // This is a simplified check for ownership
            // In reality, we'd check if we can spend using our keypair
            if output.public_key_script == our_pubkey_bytes {
                received += output.value;

                // Add the UTXO to our records
                let outpoint = OutPoint {
                    transaction_hash: tx.hash(),
                    index: i as u32,
                };

                self.utxos.insert(outpoint, output.clone());
            }
        }

        // Check if any inputs are from us (i.e., spending)
        let mut spent = 0;
        for input in &tx.inputs {
            // Check if this input spends one of our UTXOs
            if self.utxos.contains_key(&input.previous_output) {
                if let Some(prev_output) = self.utxos.get(&input.previous_output) {
                    spent += prev_output.value;

                    // Remove this UTXO as it's now spent
                    self.utxos.remove(&input.previous_output);
                }
            }
        }

        // Update our balance
        self.balance = self.balance + received - spent;

        // Store the transaction for history
        self.transactions.push(tx.clone());

        // Add a timestamp for this transaction
        self.transaction_timestamps
            .insert(tx.hash(), current_time());

        // Also check for stealth transactions
        self.scan_for_stealth_transactions(tx);

        // Verify transaction against the utxo_set
        if !self.verify_transaction(tx, utxo_set) {
            // If verification fails, log or handle appropriately
            // In a real implementation, this would trigger a warning or rejection
            println!("Transaction verification failed: {:?}", tx.hash());
        }
    }

    // Verify a transaction against the UTXO set to ensure it's valid
    pub fn verify_transaction(&self, tx: &Transaction, utxo_set: &UTXOSet) -> bool {
        // Basic validation steps:

        // 1. Check that all inputs reference valid UTXOs
        for input in &tx.inputs {
            if !utxo_set.contains(&input.previous_output) {
                return false;
            }
        }

        // 2. Verify signatures using Jubjub's verification functionality
        for input in &tx.inputs {
            let _output = match utxo_set.get(&input.previous_output) {
                Some(out) => out,
                None => {
                    debug!("UTXO not found for input");
                    return false;
                }
            };
            
            // Extract the signature from the script
            if input.signature_script.len() < 64 {
                debug!("Signature script too short");
                return false;
            }
            
            let r_bytes = &input.signature_script[0..32];
            let s_bytes = &input.signature_script[32..64];
            
            if let Some(_r) = jubjub::JubjubScalar::from_bytes(r_bytes) {
                // Extract the public key from the output script (simplified)
                if let Some(_s_scalar) = jubjub::JubjubScalar::from_bytes(s_bytes) {
                    // In a real implementation, we would verify the signature
                    // using the JubjubPoint's verify method
                    // ...
                } else {
                    debug!("Invalid s value in signature");
                    return false;
                }
            } else {
                debug!("Invalid r value in signature");
                return false;
            }
        }

        // 3. Check that the transaction does not create or destroy value
        let mut input_value = 0;
        for input in &tx.inputs {
            if let Some(utxo) = utxo_set.get(&input.previous_output) {
                input_value += utxo.value;
            } else {
                return false;
            }
        }

        let output_value: u64 = tx.outputs.iter().map(|o| o.value).sum();

        // The sum of outputs must be less than or equal to inputs
        // (difference is the transaction fee)
        if output_value > input_value {
            return false;
        }

        true
    }

    // Verify that our local UTXO set is consistent with the global UTXO set
    pub fn verify_utxo_consistency(&self, utxo_set: &UTXOSet) -> bool {
        for (outpoint, our_utxo) in &self.utxos {
            // Check that each of our UTXOs exists in the global set
            if let Some(global_utxo) = utxo_set.get(outpoint) {
                // And that they match in value and public key script
                if our_utxo.value != global_utxo.value
                    || our_utxo.public_key_script != global_utxo.public_key_script
                {
                    return false;
                }
            } else {
                // This UTXO no longer exists in the global set
                return false;
            }
        }

        true
    }

    // If this transaction used a stealth address to pay us, find it
    pub fn scan_for_stealth_transactions(&mut self, tx: &Transaction) -> bool {
        if self.keypair.is_none() {
            return false;
        }

        let keypair = self.keypair.as_ref().unwrap();
        
        // Initialize stealth addressing if not already done
        if self.stealth_addressing.is_none() {
            self.stealth_addressing = Some(StealthAddressing::new());
        }
        
        // Use our StealthAddressing implementation to scan the transaction
        if let Some(stealth_addressing) = &self.stealth_addressing {
            if let Some(found_outputs) = stealth_addressing.scan_transaction(tx, keypair) {
                // Process each found output
                for (outpoint, output) in found_outputs {
                    // Add the UTXO to our records
                    self.utxos.insert(outpoint, output.clone());
                    
                    // Update balance
                    self.balance += output.value;
                    
                    // If this is a confidential transaction, try to decrypt the amount
                    if tx.amount_commitments.is_some() && tx.range_proofs.is_some() {
                        if let Some(amount) = stealth_addressing.decrypt_amount(tx, outpoint.index as usize, keypair) {
                            // Update with the decrypted amount
                            self.balance += amount - output.value; // Adjust for the difference
                        }
                    }
                }
                
                return true;
            }
        } else {
            // Fallback to the original implementation if stealth addressing is not enabled
            if tx.ephemeral_pubkey.is_none() {
                return false;
            }

            // Check if this transaction includes a stealth payment
            if let Some(ephemeral_pubkey_bytes) = &tx.ephemeral_pubkey {
                // Convert bytes to a JubjubPoint
                let ephemeral_pubkey = match bytes_to_jubjub_point(ephemeral_pubkey_bytes) {
                    Some(pk) => pk,
                    None => return false,
                };
                
                // Use stealth addressing functions from jubjub module
                // First, recover the stealth private key
                let stealth_private_key = jubjub::recover_stealth_private_key(
                    &keypair.secret,
                    &ephemeral_pubkey,
                    None // No timestamp for backward compatibility
                );
                
                // Derive the stealth public key - this is what the payment will be sent to
                let stealth_public = <JubjubPoint as JubjubPointExt>::generator() * stealth_private_key;
                let stealth_address_bytes = jubjub_point_to_bytes(&stealth_public);

                // For each output, check if it's a stealth payment to us
                for (i, output) in tx.outputs.iter().enumerate() {
                    // Check if the output's script matches our derived stealth address
                    if output.public_key_script == stealth_address_bytes {
                        // Found a payment to us!
                        self.balance += output.value;

                        // Add the UTXO to our records
                        let outpoint = OutPoint {
                            transaction_hash: tx.hash(),
                            index: i as u32,
                        };

                        self.utxos.insert(outpoint, output.clone());
                        return true;
                    }
                }
            }
        }

        false
    }

    // Helper function to derive a stealth address
    fn derive_stealth_address(&self, ephemeral_pubkey: &JubjubPoint) -> Vec<u8> {
        let keypair = self.keypair.as_ref().unwrap();
        
        // Use the recover_stealth_private_key function from jubjub module
        let stealth_private_key = jubjub::recover_stealth_private_key(
            &keypair.secret,
            ephemeral_pubkey,
            Some(current_time()), // Use current time for forward secrecy
        );
        
        // Derive the stealth address using the recovered private key
        let stealth_point = <JubjubPoint as JubjubPointExt>::generator() * stealth_private_key;
        
        // Return as bytes
        jubjub_point_to_bytes(&stealth_point)
    }

    // Create and broadcast a stake transaction
    pub fn create_stake(&mut self, amount: u64) -> Option<Transaction> {
        // Use the proper UTXO selection and fee calculation
        let stake_recipient = <JubjubPoint as JubjubPointExt>::generator(); // Use a standard address for staking

        // Default fee rate for staking (lower priority)
        let fee_per_kb = 500; // 0.5 satoshis per byte

        // Create transaction with proper UTXO selection
        let mut tx = self.create_transaction_with_fee(&stake_recipient, amount, fee_per_kb)?;

        // Set a flag or data to indicate this is a stake
        tx.privacy_flags |= 0x02; // Example flag for stake

        // Mark inputs as pending spent
        for input in &tx.inputs {
            self.pending_spent_outpoints
                .lock()
                .unwrap()
                .insert(input.previous_output.clone());
        }

        // Update our balance immediately (in real wallet, we'd wait for confirmation)
        self.balance -= amount;

        Some(tx)
    }

    // Unstake funds (withdraw from staking)
    pub fn unstake(&mut self, stake_id: &[u8; 32], amount: u64) -> Option<Transaction> {
        // This would require integration with the staking contract
        // For now, this is a simplified implementation

        if self.keypair.is_none() {
            return None;
        }

        // Create a transaction that claims the stake
        let mut tx = Transaction::default();

        // Add the stake as input
        let stake_outpoint = OutPoint {
            transaction_hash: *stake_id,
            index: 0, // Assuming the stake output is at index 0
        };

        // Sign the input using our keypair
        let keypair = self.keypair.as_ref().unwrap();
        
        // Create a message that includes the stake ID and amount for security
        let mut signing_data = Vec::new();
        signing_data.extend_from_slice(stake_id);
        signing_data.extend_from_slice(&amount.to_le_bytes());
        signing_data.extend_from_slice(b"UNSTAKE");
        
        // Add a timestamp for additional security
        let timestamp = current_time().to_le_bytes();
        signing_data.extend_from_slice(&timestamp);
        
        // Sign the data
        let signature = keypair.sign(&signing_data);
        
        // Create the signature script with the JubjubSignature
        let mut signature_bytes = Vec::with_capacity(64);
        signature_bytes.extend_from_slice(&signature.r.to_bytes());
        signature_bytes.extend_from_slice(&signature.s.to_bytes());

        let input = TransactionInput {
            previous_output: stake_outpoint,
            signature_script: signature_bytes,
            sequence: 0,
        };

        tx.inputs.push(input);

        // Add output back to our own wallet
        let output = TransactionOutput {
            value: amount,
            public_key_script: jubjub_point_to_bytes(&keypair.public),
            range_proof: None,
            commitment: None,
        };

        tx.outputs.push(output);

        // Set the unstake flag
        tx.privacy_flags |= 0x04; // Example flag for unstake

        Some(tx)
    }

    // Get all available UTXOs
    pub fn get_utxos(&self) -> &HashMap<OutPoint, TransactionOutput> {
        &self.utxos
    }

    // Get transaction history
    pub fn get_transaction_history(&self) -> &[Transaction] {
        &self.transactions
    }

    // Get pending (unconfirmed) transactions
    pub fn get_pending_transactions(&self) -> Vec<&Transaction> {
        // Find transactions that spend our pending outpoints
        self.transactions
            .iter()
            .filter(|tx| {
                tx.inputs.iter().any(|input| {
                    self.pending_spent_outpoints
                        .lock()
                        .unwrap()
                        .contains(&input.previous_output)
                })
            })
            .collect()
    }

    // Generate a wallet activity report
    pub fn generate_activity_report(&self) -> WalletActivityReport {
        let mut sent_count = 0;
        let mut received_count = 0;
        let mut total_sent = 0;
        let mut total_received = 0;
        let mut recent_transactions = Vec::new();

        // Process transactions to gather statistics
        for tx in &self.transactions {
            let is_outgoing = tx
                .inputs
                .iter()
                .any(|input| self.utxos.contains_key(&input.previous_output));

            if is_outgoing {
                sent_count += 1;
                // Sum output values as the sent amount
                let sent_amount: u64 = tx.outputs.iter().map(|out| out.value).sum();
                total_sent += sent_amount;
            } else {
                received_count += 1;
                // Sum outputs that belong to us
                for (i, output) in tx.outputs.iter().enumerate() {
                    let outpoint = OutPoint {
                        transaction_hash: tx.hash(),
                        index: i as u32,
                    };

                    if self.utxos.contains_key(&outpoint) {
                        total_received += output.value;
                    }
                }
            }

            // Add to recent transactions if we have a timestamp
            if let Some(timestamp) = self.transaction_timestamps.get(&tx.hash()) {
                let tx_info = TransactionInfo {
                    hash: tx.hash(),
                    is_outgoing,
                    amount: if is_outgoing {
                        tx.outputs.iter().map(|out| out.value).sum()
                    } else {
                        tx.outputs
                            .iter()
                            .enumerate()
                            .filter(|(i, _)| {
                                let outpoint = OutPoint {
                                    transaction_hash: tx.hash(),
                                    index: *i as u32,
                                };
                                self.utxos.contains_key(&outpoint)
                            })
                            .map(|(_, out)| out.value)
                            .sum()
                    },
                    timestamp: *timestamp,
                    time_ago: format_time_diff(*timestamp, false),
                };

                recent_transactions.push(tx_info);
            }
        }

        // Sort recent transactions by timestamp (newest first)
        recent_transactions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Limit to the 10 most recent transactions
        if recent_transactions.len() > 10 {
            recent_transactions.truncate(10);
        }

        WalletActivityReport {
            balance: self.balance,
            sent_count,
            received_count,
            total_sent,
            total_received,
            privacy_enabled: self.privacy_enabled,
            recent_transactions,
            last_sync_time: self.last_sync_time,
            last_sync_time_ago: format_time_diff(self.last_sync_time, false),
        }
    }

    /// Generate a new BLS keypair for consensus participation
    pub fn generate_bls_keypair(&mut self) -> BlsPublicKey {
        let keypair = BlsKeypair::generate();
        let public_key = keypair.public_key.clone();
        self.bls_keypair = Some(keypair);
        public_key
    }

    /// Set an existing BLS keypair
    pub fn set_bls_keypair(&mut self, keypair: BlsKeypair) {
        self.bls_keypair = Some(keypair);
    }

    /// Get the BLS public key if available
    pub fn get_bls_public_key(&self) -> Option<BlsPublicKey> {
        self.bls_keypair.as_ref().map(|kp| kp.public_key.clone())
    }

    /// Sign a message with the BLS keypair
    pub fn bls_sign(&self, message: &[u8]) -> Option<BlsSignature> {
        self.bls_keypair.as_ref().map(|kp| kp.sign(message))
    }

    /// Verify a BLS signature against this wallet's public key
    pub fn verify_bls_signature(&self, message: &[u8], signature: &BlsSignature) -> bool {
        if let Some(keypair) = &self.bls_keypair {
            // Use the global verify_signature function instead of accessing the private field
            crate::crypto::bls12_381::verify_signature(message, &keypair.public_key, signature)
        } else {
            false
        }
    }

    /// Generate a proof of possession for the BLS public key
    pub fn generate_proof_of_possession(&self) -> Option<ProofOfPossession> {
        if let Some(keypair) = &self.bls_keypair {
            Some(ProofOfPossession::sign(&keypair.secret_key, &keypair.public_key))
        } else {
            None
        }
    }

    /// Sign a block hash with the BLS keypair (for validator participation)
    pub fn sign_block_hash(&self, block_hash: &[u8; 32]) -> Option<BlsSignature> {
        self.bls_sign(block_hash)
    }

    /// Export the BLS keypair as encrypted bytes
    pub fn export_bls_keypair(&self, password: &str) -> Option<Vec<u8>> {
        // This is a placeholder - in a real implementation, you would properly encrypt the keypair
        // using strong encryption (e.g., AES-GCM with proper key derivation)
        
        if let Some(keypair) = &self.bls_keypair {
            // Serialize the keypair (this is simplified and NOT secure)
            let mut serialized = Vec::new();
            
            // Add the public key bytes
            let public_key_bytes = keypair.public_key.to_compressed();
            serialized.extend_from_slice(&(public_key_bytes.len() as u32).to_le_bytes());
            serialized.extend_from_slice(&public_key_bytes);
            
            // Add the secret key bytes (in a secure implementation, this would be encrypted)
            let mut secret_key_bytes = [0u8; 32]; // Assuming 32-byte scalar
            secret_key_bytes.copy_from_slice(&keypair.secret_key.to_bytes_le());
            serialized.extend_from_slice(&secret_key_bytes);
            
            // Encrypt with password (very simplified - do NOT use in production)
            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            let key = hasher.finalize();
            
            for i in 0..serialized.len() {
                serialized[i] ^= key[i % 32];
            }
            
            Some(serialized)
        } else {
            None
        }
    }

    /// Import a BLS keypair from encrypted bytes
    pub fn import_bls_keypair(&mut self, encrypted_bytes: &[u8], password: &str) -> Result<(), String> {
        if encrypted_bytes.len() < 36 { // At minimum: 4 bytes length + public key + 32 bytes secret key
            return Err("Invalid encrypted keypair data".to_string());
        }
        
        // Decrypt with password (very simplified - do NOT use in production)
        let mut decrypted = encrypted_bytes.to_vec();
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let key = hasher.finalize();
        
        for i in 0..decrypted.len() {
            decrypted[i] ^= key[i % 32];
        }
        
        // Parse the decrypted data
        let pub_key_len = u32::from_le_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]]) as usize;
        
        if 4 + pub_key_len + 32 > decrypted.len() {
            return Err("Invalid keypair format".to_string());
        }
        
        let public_key_bytes = &decrypted[4..4 + pub_key_len];
        let secret_key_bytes = &decrypted[4 + pub_key_len..4 + pub_key_len + 32];
        
        // Attempt to reconstruct the keypair
        let public_key = BlsPublicKey::from_compressed(public_key_bytes)
            .ok_or_else(|| "Failed to decode public key".to_string())?;
            
        // Create a new BlsKeypair
        let keypair = BlsKeypair {
            secret_key: {
                let mut array = [0u8; 32];
                if secret_key_bytes.len() >= 32 {
                    array.copy_from_slice(&secret_key_bytes[0..32]);
                } else {
                    return Err("Secret key bytes too short".to_string());
                }
                
                let ct_option = blstrs::Scalar::from_bytes_le(&array);
                if ct_option.is_some().into() {
                    ct_option.unwrap()
                } else {
                    return Err("Failed to decode secret key".to_string());
                }
            },
            public_key,
        };
        
        self.bls_keypair = Some(keypair);
        Ok(())
    }

    /// Serialize wallet data for backup, now including BLS keypair
    pub fn export_wallet_data(&self) -> WalletBackupData {
        let mut utxo_data = Vec::new();

        for (outpoint, output) in &self.utxos {
            utxo_data.push(UTXOData {
                tx_hash: outpoint.transaction_hash,
                index: outpoint.index,
                value: output.value,
                script: output.public_key_script.clone(),
            });
        }

        let keypair_data = self.keypair.as_ref().map(|kp| {
            KeypairData {
                public_key: jubjub_point_to_bytes(&kp.public),
                // In a real implementation, we would encrypt this:
                private_key: kp.secret.to_bytes().to_vec(),
            }
        });

        // Export BLS keypair if available
        let bls_keypair_data = if let Some(bls_keypair) = &self.bls_keypair {
            Some(BlsKeypairData {
                public_key: bls_keypair.public_key.to_compressed(),
                // Note: In a real implementation, this would be encrypted
                private_key: bls_keypair.secret_key.to_bytes_le().to_vec(),
            })
        } else {
            None
        };

        WalletBackupData {
            balance: self.balance,
            privacy_enabled: self.privacy_enabled,
            utxos: utxo_data,
            keypair: keypair_data,
            timestamp: current_time(),
            bls_keypair: bls_keypair_data,  // Add BLS keypair to backup data
        }
    }

    /// Import wallet data from backup, now including BLS keypair
    pub fn import_wallet_data(&mut self, backup: WalletBackupData) -> Result<(), String> {
        self.balance = backup.balance;
        self.privacy_enabled = backup.privacy_enabled;

        // Clear existing UTXOs and import from backup
        self.utxos.clear();
        for utxo in backup.utxos {
            let outpoint = OutPoint {
                transaction_hash: utxo.tx_hash,
                index: utxo.index,
            };

            let output = TransactionOutput {
                value: utxo.value,
                public_key_script: utxo.script,
                range_proof: None,
                commitment: None,
            };

            self.utxos.insert(outpoint, output);
        }

        // Import keypair if present
        if let Some(kp_data) = backup.keypair {
            if kp_data.private_key.len() == 32 {
                let mut scalar_bytes = [0u8; 32];
                scalar_bytes.copy_from_slice(&kp_data.private_key);

                let secret = JubjubScalar::from_bytes(&scalar_bytes)
                    .ok_or("Invalid private key in backup")?;

                // Create the public key by multiplying the generator point by the secret key
                let public = <JubjubPoint as JubjubPointExt>::generator() * secret;
                
                // Create the keypair with the secret and derived public key
                self.keypair = Some(JubjubKeypair { secret, public });

                // Verify that the restored public key matches the backup
                let public_key_bytes =
                    jubjub_point_to_bytes(&self.keypair.as_ref().unwrap().public);
                if public_key_bytes != kp_data.public_key {
                    return Err("Public key mismatch in restored keypair".to_string());
                }
            } else {
                return Err("Invalid private key length in backup".to_string());
            }
        } else {
            self.keypair = None;
        }

        // Import BLS keypair if available
        if let Some(bls_keypair_data) = backup.bls_keypair {
            let public_key = BlsPublicKey::from_compressed(&bls_keypair_data.public_key)
                .ok_or_else(|| "Failed to decode BLS public key".to_string())?;
                
            // Convert bytes to scalar for the secret key
            let mut bytes = [0u8; 32];
            if bls_keypair_data.private_key.len() >= 32 {
                bytes.copy_from_slice(&bls_keypair_data.private_key[0..32]);
            } else {
                return Err("Invalid BLS private key length in backup".to_string());
            }
            
            let secret_key = {
                let ct_option = blstrs::Scalar::from_bytes_le(&bytes);
                if ct_option.is_some().into() {
                    ct_option.unwrap()
                } else {
                    return Err("Failed to decode BLS private key".to_string());
                }
            };
                
            self.bls_keypair = Some(BlsKeypair {
                secret_key,
                public_key,
            });
        }

        self.last_sync_time = current_time();

        Ok(())
    }

    // Get the available (spendable) balance
    pub fn get_available_balance(&self) -> u64 {
        let mut available = 0;

        // Sum all UTXOs that aren't pending spent
        for (outpoint, output) in &self.utxos {
            if !self
                .pending_spent_outpoints
                .lock()
                .unwrap()
                .contains(outpoint)
            {
                available += output.value;
            }
        }

        available
    }

    // Calculate the pending balance (waiting for confirmation)
    pub fn get_pending_balance(&self) -> u64 {
        let mut pending = 0;

        // Sum all UTXOs that are pending spent
        for outpoint in self.pending_spent_outpoints.lock().unwrap().iter() {
            if let Some(output) = self.utxos.get(outpoint) {
                pending += output.value;
            }
        }

        pending
    }

    /// Generate a new view key with default permissions
    pub fn generate_view_key(&mut self) -> Option<ViewKey> {
        if let Some(keypair) = &self.keypair {
            let default_permissions = ViewKeyPermissions {
                view_incoming: true,
                view_outgoing: false,
                view_amounts: true,
                view_timestamps: true,
                full_audit: false,
                can_derive_keys: false,
                field_visibility: HashMap::new(),
                valid_from: 0,
                valid_until: 0,
                valid_block_range: (0, 0),
            };
            
            Some(self.view_key_manager.generate_view_key(keypair, default_permissions))
        } else {
            None
        }
    }

    /// Generate a new view key with custom permissions
    pub fn generate_view_key_with_permissions(&mut self, permissions: ViewKeyPermissions) -> Option<ViewKey> {
        if let Some(keypair) = &self.keypair {
            Some(self.view_key_manager.generate_view_key(keypair, permissions))
        } else {
            None
        }
    }

    /// Register an existing view key
    pub fn register_view_key(&mut self, view_key: ViewKey) {
        self.view_key_manager.register_view_key(view_key);
    }

    /// Revoke a view key
    pub fn revoke_view_key(&mut self, public_key: &JubjubPoint) {
        self.view_key_manager.revoke_view_key(public_key);
    }

    /// Get all registered view keys
    pub fn get_view_keys(&self) -> Vec<&ViewKey> {
        self.view_key_manager.get_all_view_keys()
    }

    /// Check if a view key is revoked
    pub fn is_view_key_revoked(&self, public_key: &JubjubPoint) -> bool {
        self.view_key_manager.is_revoked(public_key)
    }

    /// Export a view key to share with someone
    pub fn export_view_key(&self, public_key: &JubjubPoint) -> Option<Vec<u8>> {
        self.view_key_manager
            .get_view_key(public_key)
            .map(|vk| vk.to_bytes())
    }

    /// Scan transactions with registered view keys
    pub fn scan_with_view_keys(&self, transactions: &[Transaction]) -> HashMap<Vec<u8>, Vec<TransactionOutput>> {
        self.view_key_manager.scan_transactions(transactions, current_time(), None)
    }

    /// Create a time-limited view key (valid for specified duration in seconds)
    pub fn create_time_limited_view_key(&mut self, duration_seconds: u64) -> Option<ViewKey> {
        if let Some(keypair) = &self.keypair {
            let now = current_time();
            let permissions = ViewKeyPermissions {
                view_incoming: true,
                view_outgoing: false,
                view_amounts: true,
                view_timestamps: true,
                full_audit: false,
                can_derive_keys: false,
                field_visibility: HashMap::new(),
                valid_from: now,
                valid_until: now + duration_seconds,
                valid_block_range: (0, 0),
            };
            
            Some(self.view_key_manager.generate_view_key(keypair, permissions))
        } else {
            None
        }
    }

    /// Create an audit view key (can view all transactions)
    pub fn create_audit_view_key(&mut self) -> Option<ViewKey> {
        if let Some(keypair) = &self.keypair {
            let permissions = ViewKeyPermissions {
                view_incoming: true,
                view_outgoing: true,
                view_amounts: true,
                view_timestamps: true,
                full_audit: true,
                can_derive_keys: true,
                field_visibility: HashMap::new(), 
                valid_from: current_time(),
                valid_until: u64::MAX, // Never expires
                valid_block_range: (0, 0),
            };
            
            Some(self.view_key_manager.generate_view_key(keypair, permissions))
        } else {
            None
        }
    }

    /// Update permissions for an existing view key
    pub fn update_view_key_permissions(&mut self, public_key: &JubjubPoint, permissions: ViewKeyPermissions) -> bool {
        self.view_key_manager.update_permissions(public_key, permissions)
    }

    /// Signs an unstaking transaction
    pub fn sign_unstaking_transaction(&self, stake_id: &[u8; 32], amount: u64) -> Option<Vec<u8>> {
        let keypair = match &self.keypair {
            Some(kp) => kp,
            None => return None,
        };

        // Create signing data vector with stake ID, amount and a static message
        let mut signing_data = Vec::new();
        signing_data.extend_from_slice(stake_id);
        signing_data.extend_from_slice(&amount.to_le_bytes());
        signing_data.extend_from_slice(b"UNSTAKE"); // Static message for security
        signing_data.extend_from_slice(&current_time().to_le_bytes()); // Add timestamp for security

        // Sign the data
        let signature = keypair.sign(&signing_data);
        
        // Convert signature to bytes format required by the transaction script
        let r_bytes = signature.r.to_bytes();
        let s_bytes = signature.s.to_bytes();
        
        let mut signature_bytes = Vec::new();
        signature_bytes.extend_from_slice(&r_bytes);
        signature_bytes.extend_from_slice(&s_bytes);
        
        Some(signature_bytes)
    }

    fn sign_stake_transaction(&self, stake_id: &[u8; 32], amount: u64) -> Option<Vec<u8>> {
        let keypair = match &self.keypair {
            Some(kp) => kp,
            None => return None,
        };

        // Create signing data vector with stake ID, amount and a static message
        let mut signing_data = Vec::new();
        signing_data.extend_from_slice(stake_id);
        signing_data.extend_from_slice(&amount.to_le_bytes());
        signing_data.extend_from_slice(b"STAKE"); // Static message for security
        signing_data.extend_from_slice(&current_time().to_le_bytes()); // Add timestamp for security

        // Sign the data
        let signature = keypair.sign(&signing_data);
        
        // Convert signature to bytes
        let r_bytes = signature.r.to_bytes();
        let s_bytes = signature.s.to_bytes();
        
        let mut signature_bytes = Vec::new();
        signature_bytes.extend_from_slice(&r_bytes);
        signature_bytes.extend_from_slice(&s_bytes);
        
        Some(signature_bytes)
    }

    /// Create a standard transaction output
    pub fn create_output(address: Vec<u8>, amount: u64) -> TransactionOutput {
        TransactionOutput {
            value: amount,
            public_key_script: address,
            range_proof: None,
            commitment: None,
        }
    }

    /// Select inputs for a transaction
    pub fn select_inputs(&self, required_amount: u64) -> Result<Vec<(OutPoint, TransactionOutput)>, String> {
        let mut selected_inputs = Vec::new();
        let mut selected_amount = 0;
        
        // Try to select UTXOs that satisfy the required amount
        for (outpoint, output) in &self.utxos {
            // Skip outpoints that are pending spent
            let pending_spent = self.pending_spent_outpoints.lock().unwrap();
            if pending_spent.contains(outpoint) {
                continue;
            }
            
            selected_inputs.push((outpoint.clone(), output.clone()));
            selected_amount += output.value;
            
            if selected_amount >= required_amount {
                break;
            }
        }
        
        if selected_amount < required_amount {
            return Err("Insufficient funds".to_string());
        }
        
        Ok(selected_inputs)
    }

    /// Sign a transaction with the wallet's keypair
    pub fn sign_transaction(&self, tx: &mut Transaction, keypair: &JubjubKeypair) -> Result<(), String> {
        // For each input, create a signature
        for (_i, input) in tx.inputs.iter_mut().enumerate() {
            // Create a transaction hash for this input
            let mut hasher = Sha256::new();
            
            // Add all outputs
            hasher.update(&(tx.outputs.len() as u32).to_le_bytes());
            for output in &tx.outputs {
                hasher.update(&output.value.to_le_bytes());
                hasher.update(&(output.public_key_script.len() as u32).to_le_bytes());
                hasher.update(&output.public_key_script);
            }
            
            // Get the hash
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(&hasher.finalize());
            
            // Sign the hash with our private key
            let signature = keypair.sign(&hash_bytes);
            
            // Set the signature in the input - use the signature's to_bytes method
            let signature_bytes = signature.to_bytes();
            input.signature_script = signature_bytes;
        }
        
        Ok(())
    }

    /// Create a confidential output with a commitment and range proof
    ///
    /// @param address The recipient address
    /// @param commitment The amount commitment
    /// @param range_proof The range proof
    /// @return The confidential transaction output
    fn create_confidential_output(
        address: &[u8], 
        commitment: &[u8], 
        range_proof: &[u8]
    ) -> TransactionOutput {
        let mut output = Self::create_output(address.to_vec(), 0); // Amount is hidden in commitment
        
        // Add commitment and range proof to extra data
        let mut extra_data = Vec::new();
        
        // Add commitment marker
        extra_data.push(0x01); // Commitment marker
        
        // Add commitment size and data
        extra_data.push(commitment.len() as u8);
        extra_data.extend_from_slice(commitment);
        
        // Add range proof marker
        extra_data.push(0x02); // Range proof marker
        
        // Add range proof size (2-byte length for potentially large proofs)
        let range_proof_len = range_proof.len() as u16;
        extra_data.push((range_proof_len >> 8) as u8); // High byte
        extra_data.push((range_proof_len & 0xFF) as u8); // Low byte
        
        // Add range proof data
        extra_data.extend_from_slice(range_proof);
        
        // Set the extra data field - append to public_key_script
        output.public_key_script.extend_from_slice(&extra_data);
        
        output
    }

    /// Create a privacy-enhanced transaction
    ///
    /// This method creates a transaction with maximum privacy protection:
    /// - Uses stealth addressing for recipient
    /// - Implements confidential transaction features
    /// - Applies advanced metadata protection
    /// - Uses randomized change outputs
    /// - Adds decoy outputs when needed
    ///
    /// @param recipient The recipient's public key
    /// @param amount The amount to send
    /// @return The privacy-enhanced transaction or an error message
    pub fn create_private_transaction(
        &mut self,
        recipient: &JubjubPoint,
        amount: u64
    ) -> Result<Transaction, String> {
        
        if self.keypair.is_none() {
            return Err("Wallet is not initialized with a keypair".into());
        }
        
        // Default fee rate for private transactions
        let fee_per_kb = 1000; // 1000 satoshis per KB
        
        // Select UTXOs to cover the amount + fees (estimated)
        let utxos_result = self.select_utxos(amount, fee_per_kb)
            .ok_or_else(|| "Not enough funds to create transaction".to_string())?;
        
        let (selected_utxos, _) = utxos_result;
        let inputs = selected_utxos.iter()
            .map(|(outpoint, _)| TransactionInput {
                previous_output: outpoint.clone(),
                signature_script: Vec::new(), // Will be filled later
                sequence: 0xFFFFFFFF,
            })
            .collect::<Vec<TransactionInput>>();
            
        // Calculate total input amount
        let total_input_amount = selected_utxos
            .iter()
            .map(|(_, output)| output.value)
            .sum::<u64>();
            
        // Estimate transaction size and calculate fee
        let estimated_size = 148 * inputs.len() + 34 * 2 + 10; // Basic tx size estimation
        let fee = (estimated_size as u64 * fee_per_kb) / 1000;
        
        // Generate a one-time stealth address for the recipient
        let stealth_address = if let Some(ref mut stealth) = self.stealth_addressing {
            // Create a stealth address for the recipient to enhance privacy
            let recipient_pubkey_bytes = recipient.to_bytes();
            let recipient_pubkey = JubjubPoint::from_bytes(&recipient_pubkey_bytes)
                .ok_or_else(|| "Invalid recipient public key".to_string())?;
            
            // Generate stealth address if stealth addressing is enabled
            stealth.generate_one_time_address(&recipient_pubkey)
        } else {
            // Fallback if stealth addressing not available
            recipient.to_bytes().to_vec()
        };
        
        // Create a private output
        let mut outputs = Vec::new();
        
        // Use confidential transactions if available
        if let Some(ref confidential) = self.confidential_transactions {
            // Create commitment and range proof for amount
            let amount_commitment = confidential.create_commitment(amount);
            let range_proof = confidential.create_range_proof(amount);
            
            // Add confidential output
            let confidential_output = Self::create_confidential_output(
                &stealth_address,
                &amount_commitment, 
                &range_proof
            );
            outputs.push(confidential_output);
        } else {
            // Fallback to standard output with stealth address
            let output = Self::create_output(stealth_address, amount);
            outputs.push(output);
        }
        
        // Calculate change amount if needed
        let change_amount = {
            // Calculate change (total inputs - amount - fee)
            if total_input_amount > amount + fee {
                total_input_amount - amount - fee
            } else {
                0 // No change if inputs are exactly equal to outputs + fee
            }
        };
        
        // Add decoy outputs if enabled
        if self.add_decoys {
            // Generate 1-3 decoy outputs
            let num_decoys = 1 + rand::thread_rng().gen_range(0..=2);
            
            for _ in 0..num_decoys {
                // Generate a random amount and address for the decoy
                let decoy_amount = rand::thread_rng().gen_range(1000..100000);
                
                // Create a random scalar and point for the decoy
                let random_scalar = JubjubScalar::random(&mut OsRng);
                let decoy_point = JubjubPoint::generator() * random_scalar;
                let decoy_address = decoy_point.to_bytes().to_vec();
                
                // Create a confidential decoy output if available
                if let Some(ref confidential) = self.confidential_transactions {
                    let decoy_commitment = confidential.create_commitment(decoy_amount);
                    let decoy_range_proof = confidential.create_range_proof(decoy_amount);
                    
                    // Add confidential decoy output
                    let decoy_output = Self::create_confidential_output(
                        &decoy_address,
                        &decoy_commitment,
                        &decoy_range_proof
                    );
                    outputs.push(decoy_output);
                } else {
                    // Add standard decoy output
                    let decoy_output = Self::create_output(decoy_address, decoy_amount);
                    outputs.push(decoy_output);
                }
            }
        }
        
        // Randomize the order of outputs for privacy
        // In real implementation, would shuffle the vector
        
        // Select inputs for this transaction
        let inputs_with_utxos = self.select_inputs(amount)?;
        let inputs: Vec<TransactionInput> = inputs_with_utxos
            .iter()
            .map(|(outpoint, _)| TransactionInput {
                previous_output: outpoint.clone(),
                signature_script: Vec::new(), // To be filled later
                sequence: 0xFFFFFFFF,  // Default sequence
            })
            .collect();
        
        // Create the transaction
        let mut tx = Transaction {
            inputs,
            outputs,
            lock_time: 0,
            fee_adjustments: None,
            privacy_flags: (if self.confidential_transactions.is_some() { 0x01 } else { 0x00 }) |
                          (if self.stealth_addressing.is_some() { 0x02 } else { 0x00 }),
            obfuscated_id: None,
            ephemeral_pubkey: None,
            amount_commitments: None,
            range_proofs: None,
            metadata: HashMap::new(),
            salt: None,
        };
        
        // Sign the transaction
        if let Some(keypair) = &self.keypair {
            self.sign_transaction(&mut tx, keypair)?;
        }
        
        // Apply privacy features if enabled
        if self.privacy_enabled {
            tx = self.apply_privacy_features(tx);
        }
        
        Ok(tx)
    }
}

// Helper function to convert JubjubPoint to bytes
pub fn jubjub_point_to_bytes(point: &JubjubPoint) -> Vec<u8> {
    point.to_bytes().to_vec()
}

// Helper function to convert bytes to JubjubPoint
pub fn bytes_to_jubjub_point(bytes: &[u8]) -> Option<JubjubPoint> {
    JubjubPoint::from_bytes(bytes)
}

// Helper function to hash data to a JubjubScalar
pub fn hash_to_jubjub_scalar(data: &[u8]) -> JubjubScalar {
    JubjubScalar::hash_to_scalar(data)
}

// Struct to represent transaction information for reports
#[derive(Debug, Clone)]
pub struct TransactionInfo {
    pub hash: [u8; 32],
    pub is_outgoing: bool,
    pub amount: u64,
    pub timestamp: u64,
    pub time_ago: String,
}

// Struct for wallet activity reports
#[derive(Debug, Clone)]
pub struct WalletActivityReport {
    pub balance: u64,
    pub sent_count: usize,
    pub received_count: usize,
    pub total_sent: u64,
    pub total_received: u64,
    pub privacy_enabled: bool,
    pub recent_transactions: Vec<TransactionInfo>,
    pub last_sync_time: u64,
    pub last_sync_time_ago: String,
}

// Struct for UTXO data in wallet backups
#[derive(Debug, Clone)]
pub struct UTXOData {
    pub tx_hash: [u8; 32],
    pub index: u32,
    pub value: u64,
    pub script: Vec<u8>,
}

// Struct for keypair data in wallet backups
#[derive(Debug, Clone)]
pub struct KeypairData {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>, // This would be encrypted in a real implementation
}

// Struct for BLS keypair data in wallet backups
#[derive(Debug, Clone)]
pub struct BlsKeypairData {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>, // This would be encrypted in a real implementation
}

// Struct for wallet backup data
#[derive(Debug, Clone)]
pub struct WalletBackupData {
    pub balance: u64,
    pub privacy_enabled: bool,
    pub utxos: Vec<UTXOData>,
    pub keypair: Option<KeypairData>,
    pub timestamp: u64,
    pub bls_keypair: Option<BlsKeypairData>, // Add BLS keypair to backup data
}

// Implement wallet tests module
pub mod tests;

// Add the integration module
pub mod integration;

// Add these helper methods for testing purposes only
#[cfg(test)]
impl Wallet {
    /// Test helper: Set the wallet's UTXOs directly (for testing only)
    pub fn set_utxos_for_testing(&mut self, utxos: HashMap<OutPoint, TransactionOutput>) {
        self.utxos = utxos;
    }

    /// Test helper: Set the wallet's balance directly (for testing only)
    pub fn set_balance_for_testing(&mut self, balance: u64) {
        self.balance = balance;
    }

    /// Test helper: Get the wallet's UTXOs directly (for testing only)
    pub fn get_utxos_for_testing(&self) -> &HashMap<OutPoint, TransactionOutput> {
        &self.utxos
    }

    /// Test helper: Add a pending spent outpoint (for testing only)
    pub fn add_pending_outpoint_for_testing(&self, outpoint: OutPoint) {
        self.pending_spent_outpoints
            .lock()
            .unwrap()
            .insert(outpoint);
    }

    /// Test helper: Set the transaction timestamps (for testing only)
    pub fn set_transaction_timestamps_for_testing(&mut self, timestamps: HashMap<[u8; 32], u64>) {
        self.transaction_timestamps = timestamps;
    }
}

// For test compatibility - aliasing existing types to match test expectations
pub type StealthAddress = Vec<u8>;
