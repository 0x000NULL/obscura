use ed25519_dalek::{Keypair, PublicKey, Signer};
use crate::blockchain::{Transaction, TransactionInput, TransactionOutput, OutPoint};
use crate::consensus::StakeProof;
use rand;

pub struct Wallet {
    pub keypair: Option<Keypair>,
    pub balance: u64,
    pub transactions: Vec<Transaction>,
    pub staked_amount: u64,
}

impl Wallet {
    pub fn new() -> Self {
        Wallet {
            keypair: None,
            balance: 0,
            transactions: Vec::new(),
            staked_amount: 0,
        }
    }

    pub fn new_with_keypair() -> Self {
        let mut wallet = Self::new();
        wallet.keypair = Some(Keypair::generate(&mut rand::thread_rng()));
        wallet
    }

    pub fn create_transaction(&mut self, recipient: PublicKey, amount: u64) -> Option<Transaction> {
        if amount > self.balance || self.keypair.is_none() {
            return None;
        }

        let keypair = self.keypair.as_ref().unwrap();
        
        // Create recipient output
        let recipient_output = TransactionOutput {
            value: amount,
            public_key_script: recipient.as_bytes().to_vec(),
        };

        // Create change output if necessary
        let mut outputs = vec![recipient_output];
        if amount < self.balance {
            let change_output = TransactionOutput {
                value: self.balance - amount,
                public_key_script: keypair.public.as_bytes().to_vec(),
            };
            outputs.push(change_output);
        }

        // Create a simple input (in reality, would reference actual UTXOs)
        let input = TransactionInput {
            previous_output: OutPoint {
                transaction_hash: [0u8; 32],
                index: 0,
            },
            signature_script: keypair.sign(&[0u8; 32]).to_bytes().to_vec(),
            sequence: 0,
        };

        self.balance -= amount;

        Some(Transaction {
            inputs: vec![input],
            outputs,
            lock_time: 0,
        })
    }

    pub fn create_stake(&mut self, amount: u64) -> Option<StakeProof> {
        Some(StakeProof {
            stake_amount: amount,
            stake_age: 24 * 60 * 60, // 24 hours
            signature: vec![0u8; 64], // In production, this would be a real signature
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    mod wallet_tests;
} 