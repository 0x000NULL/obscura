use bincode::serialize;
use serde::{Serialize, Deserialize};
use crate::blockchain::{TransactionInput, TransactionOutput};

impl crate::blockchain::Transaction {
    pub fn to_bytes(&self) -> Vec<u8> {
        serialize(self).unwrap_or_default()
    }
} 