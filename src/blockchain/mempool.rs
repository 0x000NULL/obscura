use crate::blockchain::Transaction;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};

#[derive(Debug)]
pub struct Mempool {
    transactions: HashMap<[u8; 32], Transaction>,
    fee_ordered: BinaryHeap<TransactionWithFee>,
}

// Wrapper to order transactions by fee
#[derive(Debug, Eq, Clone)]
struct TransactionWithFee {
    hash: [u8; 32],
    fee: u64,
}

impl PartialEq for TransactionWithFee {
    fn eq(&self, other: &Self) -> bool {
        self.fee == other.fee
    }
}

impl PartialOrd for TransactionWithFee {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TransactionWithFee {
    fn cmp(&self, other: &Self) -> Ordering {
        // Order by fee (higher fee first), then by hash for deterministic ordering
        self.fee
            .cmp(&other.fee)
            .reverse()
            .then_with(|| self.hash.cmp(&other.hash))
    }
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            transactions: HashMap::new(),
            fee_ordered: BinaryHeap::new(),
        }
    }

    pub fn add_transaction(&mut self, tx: Transaction) -> bool {
        let hash = tx.hash();
        if self.transactions.contains_key(&hash) {
            return false;
        }

        // Calculate total fee (value of outputs)
        let fee = tx.outputs.iter().fold(0, |acc, output| acc + output.value);

        self.fee_ordered.push(TransactionWithFee { hash, fee });
        self.transactions.insert(hash, tx);
        true
    }

    pub fn remove_transaction(&mut self, hash: &[u8; 32]) {
        if let Some(_tx) = self.transactions.remove(hash) {
            // Rebuild fee_ordered without the removed transaction
            self.fee_ordered = self
                .fee_ordered
                .drain()
                .filter(|tx_fee| &tx_fee.hash != hash)
                .collect();
        }
    }

    pub fn contains(&self, tx: &Transaction) -> bool {
        self.transactions.contains_key(&tx.hash())
    }

    /// Get a transaction by its hash
    pub fn get_transaction(&self, hash: &[u8; 32]) -> Option<&Transaction> {
        self.transactions.get(hash)
    }

    /// Get all transactions in the mempool
    pub fn get_all_transactions(&self) -> impl Iterator<Item = (&[u8; 32], &Transaction)> {
        self.transactions.iter()
    }

    /// Get the number of transactions in the mempool
    pub fn size(&self) -> usize {
        self.transactions.len()
    }

    /// Check if the mempool is empty
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Get transactions that spend from a specific transaction
    pub fn get_descendants(&self, tx_hash: &[u8; 32]) -> Vec<&Transaction> {
        let mut descendants = Vec::new();
        
        for tx in self.transactions.values() {
            for input in &tx.inputs {
                if &input.previous_output.transaction_hash == tx_hash {
                    descendants.push(tx);
                    break;
                }
            }
        }
        
        descendants
    }

    pub fn get_transactions_by_fee(&self, limit: usize) -> Vec<Transaction> {
        let mut result = Vec::new();
        let mut fee_ordered = self.fee_ordered.clone();

        while result.len() < limit && !fee_ordered.is_empty() {
            if let Some(tx_fee) = fee_ordered.pop() {
                if let Some(tx) = self.transactions.get(&tx_fee.hash) {
                    result.push(tx.clone());
                }
            }
        }

        // Sort by fee (output value) in descending order
        result.sort_by(|a, b| {
            let a_fee = a.outputs.iter().map(|o| o.value).sum::<u64>();
            let b_fee = b.outputs.iter().map(|o| o.value).sum::<u64>();
            b_fee.cmp(&a_fee) // Reverse order for highest fees first
        });

        result
    }

    /// Get transactions ordered by effective fee rate (CPFP)
    /// This considers the combined fee rate of a transaction and its ancestors
    pub fn get_transactions_by_effective_fee_rate(
        &self,
        utxo_set: &crate::blockchain::UTXOSet,
        limit: usize,
    ) -> Vec<Transaction> {
        use crate::consensus::mining_reward::calculate_package_fee_rate;
        
        // Calculate package fee rate for each transaction
        let mut tx_with_package_rates: Vec<(&Transaction, u64)> = self
            .transactions
            .values()
            .map(|tx| (tx, calculate_package_fee_rate(tx, utxo_set, self)))
            .collect();
        
        // Sort by package fee rate (highest first)
        tx_with_package_rates.sort_by(|a, b| b.1.cmp(&a.1));
        
        // Select transactions up to the limit
        let mut result = Vec::new();
        let mut included_hashes = std::collections::HashSet::new();
        
        for (tx, _) in tx_with_package_rates {
            // Skip if we've reached the limit
            if result.len() >= limit {
                break;
            }
            
            // Skip if this transaction is already included
            if included_hashes.contains(&tx.hash()) {
                continue;
            }
            
            // Add this transaction and mark it as included
            result.push(tx.clone());
            included_hashes.insert(tx.hash());
            
            // Calculate and add ancestors that aren't already included
            let ancestors = crate::consensus::mining_reward::calculate_ancestor_set(tx, self);
            for ancestor_hash in ancestors {
                if !included_hashes.contains(&ancestor_hash) {
                    if let Some(ancestor_tx) = self.get_transaction(&ancestor_hash) {
                        result.push(ancestor_tx.clone());
                        included_hashes.insert(ancestor_hash);
                        
                        // Check if we've reached the limit
                        if result.len() >= limit {
                            break;
                        }
                    }
                }
            }
        }
        
        // Sort the result to ensure ancestors come before descendants
        result.sort_by(|a, b| {
            let a_ancestors = crate::consensus::mining_reward::calculate_ancestor_set(a, self).len();
            let b_ancestors = crate::consensus::mining_reward::calculate_ancestor_set(b, self).len();
            a_ancestors.cmp(&b_ancestors)
        });
        
        result
    }
}
