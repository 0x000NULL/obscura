use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct InsurancePool {
    pub balance: u64,
    pub coverage: HashMap<Vec<u8>, u64>,
    pub claims: Vec<(Vec<u8>, u64, String)>, // claimant, amount, reason
    pub premiums: HashMap<Vec<u8>, u64>,
}

impl InsurancePool {
    pub fn new() -> Self {
        InsurancePool {
            balance: 0,
            coverage: HashMap::new(),
            claims: Vec::new(),
            premiums: HashMap::new(),
        }
    }

    pub fn add_funds(&mut self, amount: u64) {
        self.balance += amount;
    }

    pub fn process_claim(&mut self, claimant: Vec<u8>, amount: u64) -> Result<(), String> {
        if amount > self.balance {
            return Err("Insufficient funds in insurance pool".to_string());
        }
        self.balance -= amount;
        self.claims.push((claimant, amount, String::new()));
        Ok(())
    }
} 