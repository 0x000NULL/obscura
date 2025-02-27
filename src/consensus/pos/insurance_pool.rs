pub struct InsurancePool {
    pub balance: u64,
    pub claims: Vec<(Vec<u8>, u64)>, // (claimant, amount)
}

impl InsurancePool {
    pub fn new() -> Self {
        Self {
            balance: 0,
            claims: Vec::new(),
        }
    }

    pub fn add_funds(&mut self, amount: u64) {
        self.balance += amount;
    }

    pub fn process_claim(&mut self, claimant: Vec<u8>, amount: u64) -> bool {
        if amount <= self.balance {
            self.balance -= amount;
            self.claims.push((claimant, amount));
            true
        } else {
            false
        }
    }
} 