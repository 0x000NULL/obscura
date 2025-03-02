use crate::blockchain::{Block, Transaction, TransactionInput, TransactionOutput, OutPoint, UTXOSet};
use crate::crypto;
use crate::crypto::jubjub::{JubjubKeypair, JubjubPoint, JubjubScalar, JubjubPointExt, JubjubScalarExt};
use crypto::jubjub;
use sha2::{Sha256, Digest};
use std::collections::{HashMap, HashSet};
use rand::rngs::OsRng;
use crate::utils::{current_time, format_time_diff};

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
    pending_spent_outpoints: HashSet<OutPoint>,
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
            pending_spent_outpoints: HashSet::new(),
        }
    }
}

impl Wallet {
    pub fn new() -> Self {
        Wallet::default()
    }
    
    pub fn new_with_keypair() -> Self {
        let mut rng = OsRng;
        let keypair = JubjubKeypair::new(JubjubScalar::random(&mut rng));
        
        Wallet {
            balance: 0,
            transactions: Vec::new(),
            keypair: Some(keypair),
            privacy_enabled: false,
            utxos: HashMap::new(),
            transaction_timestamps: HashMap::new(),
            last_sync_time: current_time(),
            pending_spent_outpoints: HashSet::new(),
        }
    }
    
    pub fn set_keypair(&mut self, keypair: JubjubKeypair) {
        self.keypair = Some(keypair);
    }
    
    pub fn get_public_key(&self) -> Option<JubjubPoint> {
        self.keypair.as_ref().map(|kp| kp.public)
    }
    
    pub fn enable_privacy(&mut self) {
        self.privacy_enabled = true;
    }
    
    pub fn disable_privacy(&mut self) {
        self.privacy_enabled = false;
    }
    
    pub fn is_privacy_enabled(&self) -> bool {
        self.privacy_enabled
    }
    
    /// Select UTXOs to use for a transaction
    fn select_utxos(&self, amount: u64, fee_per_kb: u64) -> Option<(Vec<(OutPoint, TransactionOutput)>, u64)> {
        if self.utxos.is_empty() {
            return None;
        }
        
        // Get available UTXOs (not pending spent)
        let available_utxos: Vec<(OutPoint, TransactionOutput)> = self.utxos
            .iter()
            .filter(|(outpoint, _)| !self.pending_spent_outpoints.contains(outpoint))
            .map(|(outpoint, output)| (*outpoint, output.clone()))
            .collect();
        
        if available_utxos.is_empty() {
            return None;
        }
        
        // Try to find an exact match first (optimization)
        for (outpoint, output) in &available_utxos {
            if output.value == amount {
                // Perfect match, no change needed
                return Some((vec![(*outpoint, output.clone())], 0));
            }
        }
        
        // Sort UTXOs by value (largest first) for simplicity
        // In a real implementation, we would use a more sophisticated coin selection algorithm
        let mut sorted_utxos = available_utxos.clone();
        sorted_utxos.sort_by(|(_, a), (_, b)| b.value.cmp(&a.value));
        
        // Try to find a combination of UTXOs that covers the amount
        let mut selected_utxos = Vec::new();
        let mut total_value = 0;
        
        for (outpoint, output) in sorted_utxos {
            selected_utxos.push((outpoint, output.clone()));
            total_value += output.value;
            
            // Estimate the fee based on the size of the transaction
            let estimated_tx_size = self.estimate_tx_size(selected_utxos.len(), 2); // Assume 2 outputs (payment + change)
            let estimated_fee = (estimated_tx_size as u64 * fee_per_kb) / 1000;
            
            if total_value >= amount + estimated_fee {
                let change = total_value - amount - estimated_fee;
                return Some((selected_utxos, change));
            }
        }
        
        // Couldn't find enough funds
        None
    }
    
    /// Estimate the size of a transaction in bytes
    fn estimate_tx_size(&self, input_count: usize, output_count: usize) -> usize {
        // Fixed overhead: version(4) + locktime(4) + input count(1-9) + output count(1-9)
        let overhead = 20;
        
        // Input size: outpoint(36) + script length(1-9) + script(~108 for standard sig) + sequence(4)
        let input_size = input_count * 150;
        
        // Output size: value(8) + script length(1-9) + script(~35 for standard P2PK)
        let output_size = output_count * 50;
        
        overhead + input_size + output_size
    }
    
    /// Calculate appropriate fee for a transaction
    pub fn calculate_recommended_fee(&self, input_count: usize, output_count: usize, priority: &str) -> u64 {
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
    pub fn create_transaction_with_fee(&self, recipient: &JubjubPoint, amount: u64, fee_per_kb: u64) -> Option<Transaction> {
        if self.keypair.is_none() {
            return None; // Can't sign without a keypair
        }
        
        // Select UTXOs to spend
        let (selected_utxos, change) = self.select_utxos(amount, fee_per_kb)?;
        
        // Create a new transaction
        let mut tx = Transaction::default();
        
        // Add inputs from selected UTXOs
        for (outpoint, _) in &selected_utxos {
            // Create a signature for the input using our keypair
            let keypair = self.keypair.as_ref().unwrap();
            
            // In a real implementation, we would sign the transaction hash or a specific message derived from it
            let message = b"Authorize transaction";
            let signature = keypair.sign(message);
            let signature_bytes = signature.expect("Failed to sign transaction").to_bytes();
            
            let input = TransactionInput {
                previous_output: *outpoint,
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
        };
        
        tx.outputs.push(payment_output);
        
        // Add change output if needed
        if change > 0 {
            let keypair = self.keypair.as_ref().unwrap();
            let change_output = TransactionOutput {
                value: change,
                public_key_script: jubjub_point_to_bytes(&keypair.public),
            };
            
            tx.outputs.push(change_output);
        }
        
        // Apply privacy features if enabled
        if self.privacy_enabled {
            tx = self.apply_privacy_features(tx);
        }
        
        Some(tx)
    }
    
    /// Original simplified transaction creation (kept for backward compatibility)
    pub fn create_transaction(&self, recipient: &JubjubPoint, amount: u64) -> Option<Transaction> {
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
        
        // In a real implementation, we would sign the transaction hash
        let message = b"Authorize transaction";
        let signature = keypair.sign(message);
        let signature_bytes = signature.expect("Failed to sign transaction").to_bytes();
        
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
        };
        
        tx.outputs.push(payment_output);
        
        // Add change output if needed
        if self.balance > amount {
            let change_output = TransactionOutput {
                value: self.balance - amount,
                public_key_script: jubjub_point_to_bytes(&keypair.public),
            };
            
            tx.outputs.push(change_output);
        }
        
        // Apply privacy features if enabled
        if self.privacy_enabled {
            tx = self.apply_privacy_features(tx);
        }
        
        Some(tx)
    }
    
    fn apply_privacy_features(&self, mut tx: Transaction) -> Transaction {
        // Set privacy flags in the transaction
        tx.privacy_flags |= 0x01; // Basic privacy

        // Obfuscate the transaction ID
        let mut hasher = Sha256::new();
        hasher.update(b"obfuscated_tx");
        let mut tx_id = [0u8; 32];
        tx_id.copy_from_slice(&hasher.finalize());
        tx.obfuscated_id = Some(tx_id);
        
        // If we have a keypair, apply stealth addressing
        if let Some(keypair) = &self.keypair {
            // Use the keypair to enhance privacy with stealth addressing
            // Create a new ephemeral key for this transaction
            let ephemeral_keypair = jubjub::generate_keypair();
            let ephemeral_scalar = ephemeral_keypair.secret;
            
            let ephemeral_point = <JubjubPoint as JubjubPointExt>::generator() * ephemeral_scalar;
            let ephemeral_bytes = jubjub_point_to_bytes(&ephemeral_point);
            
            // Add the ephemeral key to the transaction
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&ephemeral_bytes[0..32]);
            tx.ephemeral_pubkey = Some(key_bytes);
            
            // Use diffie-hellman to create a shared secret for transaction privacy
            // For any outputs that aren't change outputs, convert them to stealth addresses
            for i in 0..tx.outputs.len() {
                // Skip if this is our change output
                if i == tx.outputs.len() - 1 && self.balance > tx.outputs[0].value {
                    continue;
                }
                
                // Try to parse the recipient's public key
                if let Some(recipient_point) = bytes_to_jubjub_point(&tx.outputs[i].public_key_script) {
                    // Create a stealth address for the recipient
                    let shared_secret = jubjub::diffie_hellman(&ephemeral_scalar, &recipient_point);
                    let hash_scalar = hash_to_jubjub_scalar(&jubjub_point_to_bytes(&shared_secret));
                    let stealth_point = recipient_point + (<JubjubPoint as JubjubPointExt>::generator() * hash_scalar);
                    
                    // Replace the original output with the stealth address
                    tx.outputs[i].public_key_script = jubjub_point_to_bytes(&stealth_point);
                }
            }
        }
        
        tx
    }
    
    /// Submit a transaction to the network 
    /// Note: This marks the inputs as pending until they appear in a confirmed block
    pub fn submit_transaction(&mut self, tx: &Transaction) {
        // Mark UTXOs as pending spent
        for input in &tx.inputs {
            self.pending_spent_outpoints.insert(input.previous_output);
        }
        
        // In a real implementation, this would broadcast the transaction to the network
        println!("Transaction {} submitted to network", hex::encode(tx.hash()));
        
        // Add the transaction to our history
        self.transactions.push(tx.clone());
        
        // Add a timestamp for this transaction
        self.transaction_timestamps.insert(tx.hash(), current_time());
    }
    
    /// Clear pending transactions (e.g., if they fail to confirm)
    pub fn clear_pending_transactions(&mut self) {
        self.pending_spent_outpoints.clear();
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
                self.pending_spent_outpoints.remove(&input.previous_output);
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
        self.transaction_timestamps.insert(tx.hash(), current_time());
        
        // Also check for stealth transactions
        if tx.ephemeral_pubkey.is_some() {
            self.scan_for_stealth_transactions(tx);
        }
        
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
        
        // 2. Verify signatures (simplified version)
        for input in &tx.inputs {
            // Get the UTXO that this input is spending
            if let Some(utxo) = utxo_set.get(&input.previous_output) {
                // Extract the public key from the UTXO script
                if let Some(pubkey) = bytes_to_jubjub_point(&utxo.public_key_script) {
                    // Verify the signature (this is highly simplified)
                    // In a real implementation, we would:
                    // 1. Create the message being signed (tx hash + other data)
                    // 2. Parse the signature from the input script
                    // 3. Use the JubjubKeypair verify function
                    
                    // Dummy verification for now
                    if input.signature_script.is_empty() {
                        return false;
                    }
                }
            } else {
                return false; // Input references a non-existent UTXO
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
                if our_utxo.value != global_utxo.value || 
                   our_utxo.public_key_script != global_utxo.public_key_script {
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
        if self.keypair.is_none() || tx.ephemeral_pubkey.is_none() {
            return false;
        }
        
        let keypair = self.keypair.as_ref().unwrap();
        
        // Check if this transaction includes a stealth payment
        if let Some(ephemeral_pubkey_bytes) = &tx.ephemeral_pubkey {
            // Convert bytes to a JubjubPoint
            let ephemeral_pubkey = match bytes_to_jubjub_point(ephemeral_pubkey_bytes) {
                Some(pk) => pk,
                None => return false,
            };
            
            // For each output, check if it's a stealth payment to us
            for (i, output) in tx.outputs.iter().enumerate() {
                // Derive the stealth address using the ephemeral key and our private key
                let derived_address = self.derive_stealth_address(&ephemeral_pubkey);
                
                // Check if the output's script matches our derived address
                if output.public_key_script == derived_address {
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
        
        false
    }
    
    // Helper function to derive a stealth address
    fn derive_stealth_address(&self, ephemeral_pubkey: &JubjubPoint) -> Vec<u8> {
        let keypair = self.keypair.as_ref().unwrap();
        
        // Compute shared secret using Diffie-Hellman
        let shared_secret = jubjub::diffie_hellman(&keypair.secret, ephemeral_pubkey);
        
        // Derive the stealth address using the shared secret
        let mut hasher = Sha256::new();
        hasher.update(&jubjub_point_to_bytes(&shared_secret));
        let hash = hasher.finalize();
        
        // Generate stealth address
        let hash_scalar = JubjubScalar::hash_to_scalar(&hash);
        let stealth_point = (<JubjubPoint as JubjubPointExt>::generator() * hash_scalar) + keypair.public;
        
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
            self.pending_spent_outpoints.insert(input.previous_output);
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
        
        // Sign the input
        let keypair = self.keypair.as_ref().unwrap();
        let message = b"Unstake transaction";
        let signature = keypair.sign(message);
        let signature_bytes = signature.expect("Failed to sign transaction").to_bytes();
        
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
        self.transactions.iter()
            .filter(|tx| {
                tx.inputs.iter().any(|input| {
                    self.pending_spent_outpoints.contains(&input.previous_output)
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
            let is_outgoing = tx.inputs.iter().any(|input| 
                self.utxos.contains_key(&input.previous_output)
            );
            
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
                        tx.outputs.iter().enumerate()
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
    
    // Export wallet data in a format suitable for backup
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
        
        WalletBackupData {
            balance: self.balance,
            privacy_enabled: self.privacy_enabled,
            utxos: utxo_data,
            keypair: keypair_data,
            timestamp: current_time(),
        }
    }
    
    // Import wallet data from a backup
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
                
                self.keypair = Some(JubjubKeypair::new(secret));
                
                // Verify that the restored public key matches the backup
                let public_key_bytes = jubjub_point_to_bytes(&self.keypair.as_ref().unwrap().public);
                if public_key_bytes != kp_data.public_key {
                    return Err("Public key mismatch in restored keypair".to_string());
                }
            } else {
                return Err("Invalid private key length in backup".to_string());
            }
        } else {
            self.keypair = None;
        }
        
        self.last_sync_time = current_time();
        
        Ok(())
    }
    
    // Get the available (spendable) balance
    pub fn get_available_balance(&self) -> u64 {
        let mut available = 0;
        
        // Sum all UTXOs that aren't pending spent
        for (outpoint, output) in &self.utxos {
            if !self.pending_spent_outpoints.contains(outpoint) {
                available += output.value;
            }
        }
        
        available
    }
    
    // Calculate the pending balance (waiting for confirmation)
    pub fn get_pending_balance(&self) -> u64 {
        let mut pending = 0;
        
        // Sum all UTXOs that are pending spent
        for outpoint in &self.pending_spent_outpoints {
            if let Some(output) = self.utxos.get(outpoint) {
                pending += output.value;
            }
        }
        
        pending
    }
}

// Helper function to convert JubjubPoint to bytes
fn jubjub_point_to_bytes(point: &JubjubPoint) -> Vec<u8> {
    point.to_bytes().to_vec()
}

// Helper function to convert bytes to JubjubPoint
fn bytes_to_jubjub_point(bytes: &[u8]) -> Option<JubjubPoint> {
    JubjubPoint::from_bytes(bytes)
}

// Helper function to hash data to a JubjubScalar
fn hash_to_jubjub_scalar(data: &[u8]) -> JubjubScalar {
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

// Struct for wallet backup data
#[derive(Debug, Clone)]
pub struct WalletBackupData {
    pub balance: u64,
    pub privacy_enabled: bool,
    pub utxos: Vec<UTXOData>,
    pub keypair: Option<KeypairData>,
    pub timestamp: u64,
}

// Implement wallet tests module
pub mod tests;

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
    pub fn add_pending_outpoint_for_testing(&mut self, outpoint: OutPoint) {
        self.pending_spent_outpoints.insert(outpoint);
    }
    
    /// Test helper: Set the transaction timestamps (for testing only)
    pub fn set_transaction_timestamps_for_testing(&mut self, timestamps: HashMap<[u8; 32], u64>) {
        self.transaction_timestamps = timestamps;
    }
}
