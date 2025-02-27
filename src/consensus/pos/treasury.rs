use std::collections::HashMap;
use crate::consensus::pos::pos_structs::StakingError;

#[derive(Debug, Default)]
pub struct Treasury {
    pub balance: u64,
    pub allocations: HashMap<Vec<u8>, u64>,
    pub pending_allocations: HashMap<Vec<u8>, u64>,
    pub allocation_history: Vec<(Vec<u8>, u64, u64)>, // recipient, amount, timestamp
}

impl Treasury {
    pub fn new() -> Self {
        Self {
            balance: 0,
            allocations: HashMap::new(),
            pending_allocations: HashMap::new(),
            allocation_history: Vec::new(),
        }
    }

    pub fn allocate(&mut self, amount: u64, recipient: Vec<u8>) -> Result<(), StakingError> {
        if amount > self.balance {
            return Err(StakingError::InsufficientBalance);
        }

        self.balance -= amount;
        self.allocations.insert(recipient, amount);
        Ok(())
    }

    pub fn add_funds(&mut self, amount: u64) {
        self.balance += amount;
    }
} 