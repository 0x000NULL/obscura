use std::collections::{HashMap, BinaryHeap};
use std::cmp::Ordering;
use crate::blockchain::Transaction;

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
        self.fee.cmp(&other.fee).reverse()
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
        let fee = tx.outputs.iter()
            .fold(0, |acc, output| acc + output.value);

        self.fee_ordered.push(TransactionWithFee {
            hash,
            fee,
        });
        self.transactions.insert(hash, tx);
        true
    }

    pub fn remove_transaction(&mut self, hash: &[u8; 32]) {
        if let Some(_tx) = self.transactions.remove(hash) {
            // Rebuild fee_ordered without the removed transaction
            self.fee_ordered = self.fee_ordered.drain()
                .filter(|tx_fee| &tx_fee.hash != hash)
                .collect();
        }
    }

    pub fn contains(&self, tx: &Transaction) -> bool {
        self.transactions.contains_key(&tx.hash())
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
            b_fee.cmp(&a_fee)  // Reverse order for highest fees first
        });

        result
    }
} 