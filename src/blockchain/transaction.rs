use bincode::serialize;
use serde::{Serialize, Deserialize};
use crate::blockchain::{TransactionInput, TransactionOutput};

impl crate::blockchain::Transaction {
    pub fn to_bytes(&self) -> Vec<u8> {
        serialize(self).unwrap_or_default()
    }
    
    /// Determines if this transaction is a coinbase transaction
    /// A coinbase transaction is identified by having no inputs
    pub fn is_coinbase(&self) -> bool {
        self.inputs.is_empty()
    }
} 