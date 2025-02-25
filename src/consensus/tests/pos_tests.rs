use super::*;
use crate::consensus::pos::{calculate_stake_reward, ProofOfStake};

#[test]
fn test_stake_validation() {
    let pos = ProofOfStake::new();
    let proof = StakeProof {
        stake_amount: 2000,
        stake_age: 24 * 60 * 60,
        signature: vec![0u8; 64],
    };

    assert!(pos.validate_stake_proof(&proof, b"test_data"));
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
