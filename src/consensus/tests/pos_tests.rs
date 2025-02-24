use super::*;
use ed25519_dalek::{Keypair, Signer};
use crate::consensus::pos::{validate_stake, calculate_stake_reward};

#[test]
fn test_stake_validation() {
    let keypair = Keypair::generate(&mut rand::thread_rng());
    let stake_amount = 1000;
    let stake_age = 24 * 60 * 60; // 24 hours in seconds
    
    let stake_proof = StakeProof {
        public_key: keypair.public,
        signature: keypair.sign(b"test_message"),
        stake_amount,
        stake_age,
    };
    
    assert!(validate_stake(&stake_proof));
}

#[test]
fn test_stake_reward_calculation() {
    let stake_amount = 1000;
    let stake_time = 30 * 24 * 60 * 60; // 30 days in seconds
    
    let reward = calculate_stake_reward(stake_amount, stake_time);
    
    // 5% annual rate for 30 days
    let expected = (stake_amount as f64 * 0.05 * (30.0 / 365.0)) as u64;
    assert_eq!(reward, expected);
} 