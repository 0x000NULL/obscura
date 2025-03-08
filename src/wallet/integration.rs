use std::sync::{Arc, Mutex};
use log::debug;

use crate::blockchain::{Block, Transaction, UTXOSet};
use crate::blockchain::mempool::Mempool;
use crate::networking::Node;
use crate::crypto::jubjub::JubjubPoint;
use crate::wallet::Wallet;

/// Responsible for integrating wallet functionality with the blockchain and network
pub struct WalletIntegration {
    wallet: Wallet,
    node: Arc<Mutex<Node>>,
    mempool: Arc<Mutex<Mempool>>,
    utxo_set: Arc<Mutex<UTXOSet>>,
}

impl WalletIntegration {
    /// Create a new wallet integration
    pub fn new(
        wallet: Wallet,
        node: Arc<Mutex<Node>>,
        mempool: Arc<Mutex<Mempool>>,
        utxo_set: Arc<Mutex<UTXOSet>>,
    ) -> Self {
        Self {
            wallet,
            node,
            mempool,
            utxo_set,
        }
    }

    /// Get a reference to the underlying wallet
    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }

    /// Get a mutable reference to the underlying wallet
    pub fn wallet_mut(&mut self) -> &mut Wallet {
        &mut self.wallet
    }

    /// Send funds to a recipient
    pub fn send_funds(&mut self, recipient: &JubjubPoint, amount: u64) -> Result<[u8; 32], String> {
        debug!("Creating transaction to send {} funds", amount);
        
        // Create the transaction
        let tx = match self.wallet.create_transaction(recipient, amount) {
            Some(tx) => tx,
            None => return Err("Failed to create transaction".to_string()),
        };
        
        // Hash for return value and logging
        let tx_hash = tx.hash();
        
        // Submit to network
        self.submit_transaction(tx)?;
        
        // Return transaction hash
        Ok(tx_hash)
    }

    /// Send funds with custom fee
    pub fn send_funds_with_fee(&mut self, recipient: &JubjubPoint, amount: u64, fee_per_kb: u64) -> Result<[u8; 32], String> {
        debug!("Creating transaction to send {} funds with custom fee", amount);
        
        // Create the transaction
        let tx = match self.wallet.create_transaction_with_fee(recipient, amount, fee_per_kb) {
            Some(tx) => tx,
            None => return Err("Failed to create transaction with custom fee".to_string()),
        };
        
        // Hash for return value and logging
        let tx_hash = tx.hash();
        
        // Submit to network
        self.submit_transaction(tx)?;
        
        // Return transaction hash
        Ok(tx_hash)
    }

    /// Create a stake
    pub fn create_stake(&mut self, amount: u64) -> Result<[u8; 32], String> {
        debug!("Creating staking transaction for {} funds", amount);
        
        // Create the staking transaction
        let tx = match self.wallet.create_stake(amount) {
            Some(tx) => tx,
            None => return Err("Failed to create staking transaction".to_string()),
        };
        
        // Hash for return value and logging
        let tx_hash = tx.hash();
        
        // Submit to network
        self.submit_transaction(tx)?;
        
        // Return transaction hash
        Ok(tx_hash)
    }

    /// Unstake funds
    pub fn unstake(&mut self, stake_id: &[u8; 32], amount: u64) -> Result<[u8; 32], String> {
        debug!("Creating unstaking transaction for stake ID: {:?}", stake_id);
        
        // Create the unstaking transaction
        let tx = match self.wallet.unstake(stake_id, amount) {
            Some(tx) => tx,
            None => return Err("Failed to create unstaking transaction".to_string()),
        };
        
        // Hash for return value and logging
        let tx_hash = tx.hash();
        
        // Submit to network
        self.submit_transaction(tx)?;
        
        // Return transaction hash
        Ok(tx_hash)
    }

    /// Submit a transaction to the network
    pub fn submit_transaction(&mut self, tx: Transaction) -> Result<(), String> {
        debug!("Submitting transaction to network");
        
        // First submit to the wallet
        self.wallet.submit_transaction(&tx);
        
        // Add to mempool
        {
            let mut mempool_lock = match self.mempool.lock() {
                Ok(lock) => lock,
                Err(_) => return Err("Failed to acquire mempool lock".to_string()),
            };
            
            if !mempool_lock.add_transaction(tx.clone()) {
                return Err("Transaction rejected by mempool".to_string());
            }
        }
        
        // Add to node for network propagation
        {
            let mut node_lock = match self.node.lock() {
                Ok(lock) => lock,
                Err(_) => return Err("Failed to acquire node lock".to_string()),
            };
            
            node_lock.add_transaction(tx);
        }
        
        Ok(())
    }

    /// Process new blocks 
    pub fn process_blocks(&mut self, blocks: &[Block]) -> Result<usize, String> {
        let mut processed = 0;
        
        // Process each block in the wallet
        let utxo_set = match self.utxo_set.lock() {
            Ok(lock) => lock,
            Err(_) => return Err("Failed to acquire UTXO lock".to_string()),
        };
        
        for block in blocks {
            debug!("Processing block: {:?}", block.hash());
            self.wallet.process_block(block, &utxo_set);
            processed += 1;
        }
        
        Ok(processed)
    }

    /// Scan for stealth transactions in the mempool
    pub fn scan_mempool_for_stealth_transactions(&mut self) -> Result<usize, String> {
        debug!("Scanning mempool for stealth transactions");
        
        let transactions = {
            let mempool_lock = match self.mempool.lock() {
                Ok(lock) => lock,
                Err(_) => return Err("Failed to acquire mempool lock".to_string()),
            };
            
            mempool_lock.get_transactions()
        };
        
        let mut found = 0;
        for tx in &transactions {
            if self.wallet.scan_for_stealth_transactions(tx) {
                found += 1;
            }
        }
        
        Ok(found)
    }

    /// Generate and export wallet backup data
    pub fn create_backup(&self) -> Result<String, String> {
        debug!("Creating wallet backup");
        
        let backup_data = self.wallet.export_wallet_data();
        // In a real implementation, we would properly serialize this to a secure format
        // For now, we'll just return a placeholder
        
        Ok(format!("Wallet backup created with {} UTXOs", backup_data.utxos.len()))
    }

    /// Get available wallet balance
    pub fn get_balance(&self) -> u64 {
        self.wallet.get_available_balance()
    }

    /// Get pending wallet balance
    pub fn get_pending_balance(&self) -> u64 {
        self.wallet.get_pending_balance()
    }

    /// Generate a view key for the wallet
    pub fn generate_view_key(&mut self) -> Result<Vec<u8>, String> {
        debug!("Generating view key");
        
        let view_key = match self.wallet.generate_view_key() {
            Some(key) => key,
            None => return Err("Failed to generate view key".to_string()),
        };
        
        // In a real implementation, you would properly serialize the view key
        // For now, we'll just use the public key component
        let pubkey = view_key.public_key();
        Ok(crate::wallet::jubjub_point_to_bytes(&pubkey))
    }

    /// Revoke a view key
    pub fn revoke_view_key(&mut self, view_key_pubkey: &[u8]) -> Result<(), String> {
        debug!("Revoking view key");
        
        let pubkey = match crate::wallet::bytes_to_jubjub_point(view_key_pubkey) {
            Some(key) => key,
            None => return Err("Invalid view key public key".to_string()),
        };
        
        self.wallet.revoke_view_key(&pubkey);
        Ok(())
    }

    /// Generate a wallet activity report
    pub fn generate_activity_report(&self) -> String {
        let report = self.wallet.generate_activity_report();
        
        format!(
            "Wallet Report:\n\
             Balance: {}\n\
             Privacy Enabled: {}\n\
             Sent Transactions: {}\n\
             Received Transactions: {}\n\
             Total Sent: {}\n\
             Total Received: {}\n\
             Recent Transactions: {}\n\
             Last Sync: {}",
            report.balance,
            report.privacy_enabled,
            report.sent_count,
            report.received_count,
            report.total_sent,
            report.total_received,
            report.recent_transactions.len(),
            report.last_sync_time_ago
        )
    }
} 