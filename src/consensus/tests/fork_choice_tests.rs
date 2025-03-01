use crate::blockchain::{Block, BlockHeader};
use crate::consensus::pos::{
    Validator, ValidatorSet, ValidatorState, ValidatorRotation, 
    ForkChoiceRule, SlashingCondition, Stake
};
use crate::crypto::hash::Hash;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Helper function to create a test block
fn create_test_block(parent_hash: [u8; 32], height: u64) -> Block {
    let mut header = BlockHeader::default();
    header.previous_hash = parent_hash;
    header.height = height;
    header.timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    Block {
        header,
        transactions: Vec::new(),
    }
}

// Helper function to create a validator
fn create_test_validator(id: u64, stake_amount: u64) -> Validator {
    let mut validator = Validator::default();
    validator.id = id;
    validator.public_key = vec![id as u8; 32]; // Use ID as public key for simplicity
    validator.stake = Stake {
        amount: stake_amount,
        age: 24 * 60 * 60, // 1 day
    };
    validator.state = ValidatorState::Active;
    validator
}

#[test]
fn test_fork_choice_rule_highest_stake() {
    // Create competing fork chains
    let genesis_hash = [0u8; 32];
    
    // Create fork A (higher total stake)
    let mut fork_a = vec![create_test_block(genesis_hash, 1)];
    for i in 1..5 {
        let parent_hash = fork_a[i-1].hash();
        fork_a.push(create_test_block(parent_hash, i+1));
    }
    
    // Create fork B (lower total stake)
    let mut fork_b = vec![create_test_block(genesis_hash, 1)];
    for i in 1..4 {
        let parent_hash = fork_b[i-1].hash();
        fork_b.push(create_test_block(parent_hash, i+1));
    }
    
    // Create validator sets for each fork
    let mut validators_a = ValidatorSet::new();
    validators_a.add_validator(create_test_validator(1, 1_000_000));
    validators_a.add_validator(create_test_validator(2, 800_000));
    validators_a.add_validator(create_test_validator(3, 500_000));
    
    let mut validators_b = ValidatorSet::new();
    validators_b.add_validator(create_test_validator(4, 900_000));
    validators_b.add_validator(create_test_validator(5, 700_000));
    
    // Map blocks to validator sets
    let mut block_validators = HashMap::new();
    for block in &fork_a {
        block_validators.insert(block.hash(), validators_a.clone());
    }
    
    for block in &fork_b {
        block_validators.insert(block.hash(), validators_b.clone());
    }
    
    // Apply fork choice rule
    let fork_choice = ForkChoiceRule::new();
    let chosen_fork = fork_choice.choose_fork(&fork_a, &fork_b, &block_validators);
    
    // Fork A should be chosen (higher stake)
    assert_eq!(chosen_fork, &fork_a);
}

#[test]
fn test_fork_choice_rule_longest_chain() {
    // Create competing fork chains with same stake but different lengths
    let genesis_hash = [0u8; 32];
    
    // Create fork A (longer)
    let mut fork_a = vec![create_test_block(genesis_hash, 1)];
    for i in 1..6 {
        let parent_hash = fork_a[i-1].hash();
        fork_a.push(create_test_block(parent_hash, i+1));
    }
    
    // Create fork B (shorter)
    let mut fork_b = vec![create_test_block(genesis_hash, 1)];
    for i in 1..4 {
        let parent_hash = fork_b[i-1].hash();
        fork_b.push(create_test_block(parent_hash, i+1));
    }
    
    // Create identical validator sets for both forks
    let mut validators = ValidatorSet::new();
    validators.add_validator(create_test_validator(1, 1_000_000));
    validators.add_validator(create_test_validator(2, 800_000));
    
    // Map blocks to validator sets
    let mut block_validators = HashMap::new();
    for block in fork_a.iter().chain(fork_b.iter()) {
        block_validators.insert(block.hash(), validators.clone());
    }
    
    // Apply fork choice rule
    let fork_choice = ForkChoiceRule::new();
    let chosen_fork = fork_choice.choose_fork(&fork_a, &fork_b, &block_validators);
    
    // Fork A should be chosen (longer chain)
    assert_eq!(chosen_fork, &fork_a);
}

#[test]
fn test_validator_rotation() {
    // Create initial validator set
    let mut validator_rotation = ValidatorRotation::new(5); // Max 5 validators
    
    // Add initial validators
    for i in 1..=5 {
        validator_rotation.add_validator(create_test_validator(i, i * 100_000));
    }
    
    // Check initial validator count
    assert_eq!(validator_rotation.active_validators().len(), 5);
    
    // Add a new validator with higher stake
    let new_validator = create_test_validator(6, 600_000);
    validator_rotation.add_validator(new_validator.clone());
    
    // Should rotate out the lowest stake validator (validator 1)
    let active_validators = validator_rotation.active_validators();
    assert_eq!(active_validators.len(), 5);
    assert!(active_validators.iter().any(|v| v.id == 6));
    assert!(!active_validators.iter().any(|v| v.id == 1));
    
    // Check that validator 1 is now in standby
    let standby_validators = validator_rotation.standby_validators();
    assert!(standby_validators.iter().any(|v| v.id == 1));
}

#[test]
fn test_slashing_conditions_double_signing() {
    // Create a validator
    let mut validator = create_test_validator(1, 1_000_000);
    
    // Create a new slashing condition for double signing
    let slashing_condition = SlashingCondition::new();
    
    // Create two conflicting blocks at the same height
    let genesis_hash = [0u8; 32];
    let block1 = create_test_block(genesis_hash, 1);
    let block2 = create_test_block(genesis_hash, 1);
    
    // Simulate validator signing both blocks
    let signed_blocks = vec![block1.hash(), block2.hash()];
    
    // Apply slashing condition
    let slash_result = slashing_condition.check_double_signing(&validator, &signed_blocks);
    
    // Validator should be slashed
    assert!(slash_result);
    
    // Apply the slash
    slashing_condition.apply_slash(&mut validator, slash_result);
    
    // Verify stake is reduced by the slashing percentage (typically 50%)
    assert!(validator.stake.amount < 1_000_000);
    
    // Verify validator state is set to Slashed
    assert_eq!(validator.state, ValidatorState::Slashed);
}

#[test]
fn test_slashing_conditions_validator_inactivity() {
    // Create a validator
    let mut validator = create_test_validator(1, 1_000_000);
    
    // Create a new slashing condition
    let slashing_condition = SlashingCondition::new();
    
    // Set last active time to be a long time ago
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap();
    
    let inactivity_period = Duration::from_secs(7 * 24 * 60 * 60); // 7 days
    let last_active = now - inactivity_period;
    
    validator.last_active = last_active.as_secs();
    
    // Check inactivity slashing
    let slash_result = slashing_condition.check_inactivity(&validator, now.as_secs());
    
    // Should be slashed for inactivity
    assert!(slash_result);
    
    // Apply the slash
    slashing_condition.apply_slash(&mut validator, slash_result);
    
    // Verify validator is inactive with reduced stake
    assert!(validator.stake.amount < 1_000_000);
    assert_eq!(validator.state, ValidatorState::Inactive);
}

#[test]
fn test_adversarial_validator_behavior() {
    // Create a set of validators
    let mut validators = ValidatorSet::new();
    
    // Add legitimate validators
    validators.add_validator(create_test_validator(1, 1_000_000));
    validators.add_validator(create_test_validator(2, 900_000));
    validators.add_validator(create_test_validator(3, 800_000));
    
    // Add an adversarial validator that attempts to create multiple blocks
    let mut adversarial = create_test_validator(4, 700_000);
    validators.add_validator(adversarial.clone());
    
    // Create a fork choice rule
    let fork_choice = ForkChoiceRule::new();
    
    // Create slashing condition
    let slashing_condition = SlashingCondition::new();
    
    // Create legitimate chain
    let genesis_hash = [0u8; 32];
    let mut legitimate_chain = vec![create_test_block(genesis_hash, 1)];
    for i in 1..5 {
        let parent_hash = legitimate_chain[i-1].hash();
        legitimate_chain.push(create_test_block(parent_hash, i+1));
    }
    
    // Create adversarial fork
    let mut adversarial_chain = vec![legitimate_chain[0].clone()];
    for i in 1..5 {
        // Create a different block at each height
        let parent_hash = adversarial_chain[i-1].hash();
        adversarial_chain.push(create_test_block(parent_hash, i+1));
    }
    
    // Record that adversarial validator signed blocks on both chains
    let mut signed_blocks = HashMap::new();
    signed_blocks.insert(adversarial.id, vec![
        legitimate_chain[4].hash(), 
        adversarial_chain[4].hash()
    ]);
    
    // Check for double signing
    let slash_result = slashing_condition.check_double_signing(&adversarial, &signed_blocks[&adversarial.id]);
    assert!(slash_result);
    
    // Apply the slash
    slashing_condition.apply_slash(&mut adversarial, slash_result);
    
    // Update the validator set
    validators.update_validator(adversarial.clone());
    
    // Verify adversarial validator was slashed and removed from active validators
    assert_eq!(adversarial.state, ValidatorState::Slashed);
    assert!(!validators.active_validators().iter().any(|v| v.id == 4));
}

#[test]
fn test_consensus_finality() {
    // Create a validator set
    let mut validators = ValidatorSet::new();
    
    // Add validators with different stakes
    for i in 1..=5 {
        validators.add_validator(create_test_validator(i, i * 200_000));
    }
    
    // Create a chain of blocks
    let genesis_hash = [0u8; 32];
    let mut chain = vec![create_test_block(genesis_hash, 1)];
    for i in 1..10 {
        let parent_hash = chain[i-1].hash();
        chain.push(create_test_block(parent_hash, i+1));
    }
    
    // Map blocks to validator signatures (simplification: just count validators who signed)
    let mut block_signatures = HashMap::new();
    
    // All validators sign blocks 1-5
    for i in 0..5 {
        let block_hash = chain[i].hash();
        let signatures = validators.active_validators()
            .iter()
            .map(|v| v.id)
            .collect::<Vec<_>>();
        block_signatures.insert(block_hash, signatures);
    }
    
    // Only 3/5 validators sign blocks 6-8 (not enough for finality)
    for i in 5..8 {
        let block_hash = chain[i].hash();
        let signatures = validators.active_validators()
            .iter()
            .take(3)
            .map(|v| v.id)
            .collect::<Vec<_>>();
        block_signatures.insert(block_hash, signatures);
    }
    
    // Calculate finality threshold (2/3 of total stake)
    let total_stake: u64 = validators.active_validators()
        .iter()
        .map(|v| v.stake.amount)
        .sum();
    
    let finality_threshold = (total_stake * 2) / 3;
    
    // Check finality for each block
    for i in 0..chain.len() {
        let block_hash = chain[i].hash();
        
        // Skip if no signatures registered
        if !block_signatures.contains_key(&block_hash) {
            continue;
        }
        
        let signer_ids = &block_signatures[&block_hash];
        
        // Sum the stake of validators who signed this block
        let signed_stake: u64 = validators.active_validators()
            .iter()
            .filter(|v| signer_ids.contains(&v.id))
            .map(|v| v.stake.amount)
            .sum();
        
        // Check if the block has reached finality
        let is_final = signed_stake >= finality_threshold;
        
        // Blocks 1-5 should be final, blocks 6-8 should not be
        if i < 5 {
            assert!(is_final, "Block {} should be final", i+1);
        } else if i < 8 {
            assert!(!is_final, "Block {} should not be final", i+1);
        }
    }
} 