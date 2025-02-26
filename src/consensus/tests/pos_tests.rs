use super::*;
use crate::blockchain::{Block, BlockHeader};
use crate::consensus::threshold_sig::{ThresholdError, ValidatorAggregation};
use ed25519_dalek::{Keypair, Signer};
use crate::consensus::pos::{
    BftMessageType, ChainInfo, MAX_CONSECUTIVE_EPOCHS, ROTATION_INTERVAL,
    INSURANCE_POOL_FEE, INSURANCE_COVERAGE_PERCENTAGE
};
use crate::consensus::pos::{ProofOfStake, StakeProof, StakingContract, SlashingOffense};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_stake_validation() {
    let pos = ProofOfStake::new();
    let proof = StakeProof {
        stake_amount: 2000,
        stake_age: 24 * 60 * 60,
        public_key: vec![1, 2, 3, 4],
        signature: vec![0u8; 64],
    };

    // This will return false because we're not providing a valid signature
    // In a real test, we would need to generate a valid signature
    assert!(!pos.validate_stake_proof(&proof, b"test_data"));

    // But we can test the basic stake validation
    assert!(pos.validate_stake(proof.stake_amount, proof.stake_age));
}

#[test]
fn test_stake_reward_calculation() {
    let stake_amount = 1000;
    let stake_time = 30 * 24 * 60 * 60; // 30 days in seconds

    let reward = calculate_stake_reward(stake_amount, stake_time);

    // Expected reward should be approximately 0.41% for 30 days (5% annual rate)
    // 1000 * 0.0041 = 4.1
    assert!(reward >= 4 && reward <= 5);
}

#[test]
fn test_staking_contract_operations() {
    let mut contract = StakingContract::new(24 * 60 * 60); // 1 day epoch

    // Create stakes for multiple users
    let alice_key = vec![1, 2, 3, 4];
    let bob_key = vec![5, 6, 7, 8];
    let charlie_key = vec![9, 10, 11, 12];

    assert!(contract.create_stake(alice_key.clone(), 2000, true).is_ok());
    assert!(contract.create_stake(bob_key.clone(), 3000, true).is_ok());
    assert!(contract.create_stake(charlie_key.clone(), 1500, true).is_ok());

    // Register validators
    assert!(contract.register_validator(alice_key.clone(), 0.1, None).is_ok());
    assert!(contract.register_validator(bob_key.clone(), 0.05, None).is_ok());

    // Test delegation
    assert!(contract
        .delegate_stake(charlie_key.clone(), alice_key.clone())
        .is_ok());

    // Select validators
    let selected = contract.select_validators(2);
    assert_eq!(selected.len(), 2);

    // Both Alice and Bob should be selected as they have the highest stakes
    assert!(selected.contains(&alice_key));
    assert!(selected.contains(&bob_key));

    // Test reward distribution
    let rewards = contract.distribute_rewards();
    assert!(rewards.len() >= 2); // At least Alice and Bob should get rewards

    // Test undelegation
    assert!(contract.undelegate_stake(charlie_key.clone()).is_ok());

    // Test slashing
    let slash_result = contract
        .slash_validator(&alice_key, SlashingOffense::Downtime)
        .unwrap();
    assert!(slash_result > 0);

    // After slashing, only Bob should be selected
    let selected_after_slash = contract.select_validators(2);
    assert_eq!(selected_after_slash.len(), 1);
    assert_eq!(selected_after_slash[0], bob_key);
}

#[test]
fn test_enhanced_security_features() {
    // Create a staking contract
    let mut contract = StakingContract::new(24 * 60 * 60);

    // Create validators
    let mut csprng = OsRng;
    let keypair1 = Keypair::generate(&mut csprng);
    let keypair2 = Keypair::generate(&mut csprng);

    let public_key1 = keypair1.public.to_bytes().to_vec();
    let public_key2 = keypair2.public.to_bytes().to_vec();

    // Create stakes
    assert!(contract
        .create_stake(public_key1.clone(), 5000, false)
        .is_ok());
    assert!(contract
        .create_stake(public_key2.clone(), 3000, false)
        .is_ok());

    // Register validators
    assert!(contract
        .register_validator(public_key1.clone(), 0.1, None)
        .is_ok());
    assert!(contract
        .register_validator(public_key2.clone(), 0.05, None)
        .is_ok());

    // Select validators
    let selected = contract.select_validators(10);
    assert_eq!(selected.len(), 2);

    // Test tiered slashing
    let slash_result = contract.slash_validator(&public_key1, SlashingOffense::Downtime);
    assert!(slash_result.is_ok());
    let slashed_amount = slash_result.unwrap();

    // Verify that the validator was slashed by the correct percentage (5% for downtime)
    let validator = contract.validators.get(&public_key1).unwrap();
    assert_eq!(validator.offense_count, 1);
    assert!(!validator.slashed); // Downtime doesn't permanently slash

    // Test progressive slashing
    let slash_result2 = contract.slash_validator(&public_key1, SlashingOffense::Downtime);
    assert!(slash_result2.is_ok());
    let slashed_amount2 = slash_result2.unwrap();

    // Second offense should result in higher slashing due to progressive multiplier
    assert!(slashed_amount2 > slashed_amount);

    // Test severe slashing
    let slash_result3 = contract.slash_validator(&public_key2, SlashingOffense::DoubleSign);
    assert!(slash_result3.is_ok());

    // Verify that the validator was permanently slashed for double signing
    let validator2 = contract.validators.get(&public_key2).unwrap();
    assert!(validator2.slashed);
}

#[test]
fn test_performance_optimizations() {
    // Create a staking contract
    let mut contract = StakingContract::new(24 * 60 * 60);

    // Create validators
    let mut csprng = OsRng;
    let keypair1 = Keypair::generate(&mut csprng);
    let keypair2 = Keypair::generate(&mut csprng);

    let public_key1 = keypair1.public.to_bytes().to_vec();
    let public_key2 = keypair2.public.to_bytes().to_vec();

    // Create stakes
    assert!(contract
        .create_stake(public_key1.clone(), 5000, false)
        .is_ok());
    assert!(contract
        .create_stake(public_key2.clone(), 3000, false)
        .is_ok());

    // Register validators
    assert!(contract
        .register_validator(public_key1.clone(), 0.1, None)
        .is_ok());
    assert!(contract
        .register_validator(public_key2.clone(), 0.05, None)
        .is_ok());

    // Test validator selection caching
    let selected1 = contract.select_validators(10);
    let selected2 = contract.select_validators(10);

    // Both selections should be identical due to caching
    assert_eq!(selected1, selected2);

    // Test lazy reward calculation
    contract.calculate_rewards();
    let rewards = contract.unclaimed_rewards.clone();

    // Calling calculate_rewards again immediately shouldn't change anything
    contract.calculate_rewards();
    assert_eq!(rewards, contract.unclaimed_rewards);

    // Test reward claiming
    if !rewards.is_empty() {
        let staker = rewards.keys().next().unwrap();
        let reward_amount = rewards[staker];

        let claim_result = contract.claim_rewards(staker);
        assert!(claim_result.is_ok());
        assert_eq!(claim_result.unwrap(), reward_amount);
    }
}

#[test]
fn test_expanded_functionality() {
    // Create a staking contract
    let mut contract = StakingContract::new(24 * 60 * 60);

    // Create validators
    let mut csprng = OsRng;
    let keypair1 = Keypair::generate(&mut csprng);
    let keypair2 = Keypair::generate(&mut csprng);

    let public_key1 = keypair1.public.to_bytes().to_vec();
    let public_key2 = keypair2.public.to_bytes().to_vec();

    // Create stakes
    assert!(contract
        .create_stake(public_key1.clone(), 5000, false)
        .is_ok());
    assert!(contract
        .create_stake(public_key2.clone(), 3000, false)
        .is_ok());

    // Register validators with delegation caps
    assert!(contract
        .register_validator(public_key1.clone(), 0.1, Some(10000))
        .is_ok());
    assert!(contract
        .register_validator(public_key2.clone(), 0.05, Some(5000))
        .is_ok());

    // Test delegation cap
    let delegator_keypair = Keypair::generate(&mut csprng);
    let delegator_key = delegator_keypair.public.to_bytes().to_vec();

    // Create a large stake for the delegator
    assert!(contract
        .create_stake(delegator_key.clone(), 6000, false)
        .is_ok());

    // Try to delegate to validator2 (should fail due to cap)
    let delegation_result = contract.delegate_stake(delegator_key.clone(), public_key2.clone());
    assert!(delegation_result.is_err());

    // Delegate to validator1 (should succeed)
    let delegation_result = contract.delegate_stake(delegator_key.clone(), public_key1.clone());
    assert!(delegation_result.is_ok());

    // Test partial undelegation
    let undelegation_result = contract.partial_undelegate(delegator_key.clone(), 2000);
    assert!(undelegation_result.is_ok());

    // Verify validator's delegated stake was reduced
    let validator1 = contract.validators.get(&public_key1).unwrap();
    assert_eq!(validator1.delegated_stake, 4000);

    // Test validator reputation
    let reputation_result = contract.update_validator_reputation(&public_key1);
    assert!(reputation_result.is_ok());
    let reputation = reputation_result.unwrap();
    assert!(reputation >= 0.0 && reputation <= 1.0);
}

#[test]
fn test_advanced_staking_features() {
    // Create a staking contract
    let mut contract = StakingContract::new(24 * 60 * 60);

    // Create validators
    let mut csprng = OsRng;
    let keypair1 = Keypair::generate(&mut csprng);
    let keypair2 = Keypair::generate(&mut csprng);

    let public_key1 = keypair1.public.to_bytes().to_vec();
    let public_key2 = keypair2.public.to_bytes().to_vec();

    // Create stakes
    assert!(contract
        .create_stake(public_key1.clone(), 5000, false)
        .is_ok());
    assert!(contract
        .create_stake(public_key2.clone(), 3000, false)
        .is_ok());

    // Register validators
    assert!(contract
        .register_validator(public_key1.clone(), 0.1, None)
        .is_ok());
    assert!(contract
        .register_validator(public_key2.clone(), 0.05, None)
        .is_ok());

    // Select validators
    contract.select_validators(10);

    // Test liquid staking
    let staker_keypair = Keypair::generate(&mut csprng);
    let staker_key = staker_keypair.public.to_bytes().to_vec();

    let liquid_result = contract.add_to_liquid_pool(staker_key.clone(), 2000);
    assert!(liquid_result.is_ok());
    let liquid_tokens = liquid_result.unwrap();

    // Verify liquid tokens were issued
    assert!(liquid_tokens > 0);
    assert_eq!(contract.liquid_staking_pool.total_staked, 2000);

    // Test redeeming liquid tokens
    let redeem_result = contract.redeem_liquid_tokens(&staker_key, liquid_tokens / 2);
    assert!(redeem_result.is_ok());

    // Verify stake was returned
    assert!(redeem_result.unwrap() > 0);
    assert!(contract.liquid_staking_pool.total_staked < 2000);

    // Test cross-chain staking
    let origin_chain = "ethereum".to_string();
    let origin_address = vec![1, 2, 3, 4, 5];

    let cross_chain_result =
        contract.register_cross_chain_stake(origin_chain.clone(), origin_address.clone(), 3000);
    assert!(cross_chain_result.is_ok());
    let stake_id = cross_chain_result.unwrap();

    // Test governance
    let proposal_result = contract.create_proposal(
        public_key1.clone(),
        "Test Proposal".to_string(),
        "This is a test proposal".to_string(),
        ProposalAction::TreasuryAllocation(public_key2.clone(), 100, "Testing".to_string()),
    );
    assert!(proposal_result.is_ok());
    let proposal_id = proposal_result.unwrap();

    // Vote on the proposal
    let vote_result = contract.vote_on_proposal(public_key1.clone(), proposal_id, true);
    assert!(vote_result.is_ok());

    // Process proposals
    let executed = contract.process_proposals();

    // Treasury should have a balance from reward allocations
    contract.calculate_rewards();
    assert!(contract.treasury.balance >= 0);
}

#[test]
fn test_bft_finality_and_fork_choice() {
    // Create a staking contract
    let mut contract = StakingContract::new(24 * 60 * 60);

    // Create validators
    let mut csprng = OsRng;
    let keypair1 = Keypair::generate(&mut csprng);
    let keypair2 = Keypair::generate(&mut csprng);
    let keypair3 = Keypair::generate(&mut csprng);

    let public_key1 = keypair1.public.to_bytes().to_vec();
    let public_key2 = keypair2.public.to_bytes().to_vec();
    let public_key3 = keypair3.public.to_bytes().to_vec();

    // Create stakes
    assert!(contract
        .create_stake(public_key1.clone(), 5000, false)
        .is_ok());
    assert!(contract
        .create_stake(public_key2.clone(), 3000, false)
        .is_ok());
    assert!(contract
        .create_stake(public_key3.clone(), 2000, false)
        .is_ok());

    // Register validators
    assert!(contract
        .register_validator(public_key1.clone(), 0.1, None)
        .is_ok());
    assert!(contract
        .register_validator(public_key2.clone(), 0.05, None)
        .is_ok());
    assert!(contract
        .register_validator(public_key3.clone(), 0.07, None)
        .is_ok());

    // Select validators
    let selected = contract.select_validators(10);
    assert_eq!(selected.len(), 3);

    // Initialize BFT consensus
    let mut pos = ProofOfStake::new();
    let bft = pos.init_bft_consensus();
    pos.bft_consensus = Some(bft);

    // Create two competing chains
    let mut chain1 = ChainInfo {
        blocks: HashMap::new(),
        head: 0,
        total_stake: 0,
        total_validators: 0,
    };

    let mut chain2 = ChainInfo {
        blocks: HashMap::new(),
        head: 0,
        total_stake: 0,
        total_validators: 0,
    };

    // Create mock blocks for chain1
    for i in 0..5 {
        let block = create_mock_block(
            i,
            if i == 0 {
                [0; 32]
            } else {
                chain1.blocks[&(i - 1)].hash
            },
            public_key1.clone(),
        );
        assert!(pos.add_block_to_chain(&mut chain1, &block).is_ok());
    }

    // Create mock blocks for chain2 (fork at block 2)
    for i in 0..2 {
        let block = create_mock_block(
            i,
            if i == 0 {
                [0; 32]
            } else {
                chain2.blocks[&(i - 1)].hash
            },
            public_key1.clone(),
        );
        assert!(pos.add_block_to_chain(&mut chain2, &block).is_ok());
    }

    // Fork at block 2
    for i in 2..4 {
        let block = create_mock_block(
            i,
            if i == 2 {
                chain2.blocks[&1].hash
            } else {
                chain2.blocks[&(i - 1)].hash
            },
            public_key2.clone(),
        );
        assert!(pos.add_block_to_chain(&mut chain2, &block).is_ok());
    }

    // Test fork choice rule (chain1 should be chosen as it's longer)
    let chains = vec![chain1.clone(), chain2.clone()];
    let chosen = pos.choose_canonical_chain(&chains);
    assert_eq!(chosen, Some(0));

    // Test BFT finality
    if let Some(bft) = &mut pos.bft_consensus {
        // Create BFT messages for block 3 in chain1
        let block_hash = chain1.blocks[&3].hash;

        // Create prepare messages
        let prepare1 = pos
            .create_bft_message(&keypair1, BftMessageType::Prepare, block_hash, 0)
            .unwrap();
        let prepare2 = pos
            .create_bft_message(&keypair2, BftMessageType::Prepare, block_hash, 0)
            .unwrap();
        let prepare3 = pos
            .create_bft_message(&keypair3, BftMessageType::Prepare, block_hash, 0)
            .unwrap();

        // Process prepare messages
        assert!(pos.process_bft_message(bft, prepare1).is_ok());
        assert!(pos.process_bft_message(bft, prepare2).is_ok());
        let prepare_result = pos.process_bft_message(bft, prepare3);
        assert!(prepare_result.is_ok());
        assert!(prepare_result.unwrap()); // Should return true when prepared

        // Create commit messages
        let commit1 = pos
            .create_bft_message(&keypair1, BftMessageType::Commit, block_hash, 0)
            .unwrap();
        let commit2 = pos
            .create_bft_message(&keypair2, BftMessageType::Commit, block_hash, 0)
            .unwrap();
        let commit3 = pos
            .create_bft_message(&keypair3, BftMessageType::Commit, block_hash, 0)
            .unwrap();

        // Process commit messages
        assert!(pos.process_bft_message(bft, commit1).is_ok());
        assert!(pos.process_bft_message(bft, commit2).is_ok());
        let commit_result = pos.process_bft_message(bft, commit3);
        assert!(commit_result.is_ok());
        assert!(commit_result.unwrap()); // Should return true when committed

        // Verify block is finalized
        assert!(pos.is_block_finalized(bft, 3, &block_hash));

        // Test reorg prevention
        assert!(!pos.is_reorg_allowed(&chain1, &chain2));
    }

    // Test attack detection
    pos.record_reorg();
    pos.record_reorg();
    pos.record_reorg();
    pos.record_reorg();
    pos.record_reorg();
    pos.record_reorg();

    let attacks = pos.detect_attacks(&chains);
    assert!(!attacks.is_empty());
}

#[test]
fn test_validator_rotation() {
    // Create a staking contract
    let mut contract = StakingContract::new(24 * 60 * 60);

    // Create validators
    let mut csprng = OsRng;
    let mut validators = Vec::new();

    // Create 10 validators with different stakes
    for i in 0..10 {
        let keypair = Keypair::generate(&mut csprng);
        let public_key = keypair.public.to_bytes().to_vec();
        let stake_amount = 1000 + (i * 500); // Different stake amounts

        assert!(contract
            .create_stake(public_key.clone(), stake_amount, false)
            .is_ok());
        assert!(contract
            .register_validator(public_key.clone(), 0.1, None)
            .is_ok());

        validators.push(public_key);
    }

    // Select validators
    let selected = contract.select_validators(10);
    assert_eq!(selected.len(), 10);

    // All validators should be active
    for validator in &validators {
        assert!(contract.active_validators.contains(validator));
    }

    // Manually set consecutive epochs for some validators
    for i in 0..5 {
        if let Some(validator_info) = contract.validators.get_mut(&validators[i]) {
            validator_info.consecutive_epochs = MAX_CONSECUTIVE_EPOCHS - 1;
        }
    }

    // Set last rotation time to trigger rotation
    contract.last_rotation_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - ROTATION_INTERVAL
        - 1;

    // Perform rotation
    let rotated_out = contract.rotate_validators();

    // Should have rotated out some validators
    assert!(!rotated_out.is_empty());

    // Validators with high consecutive epochs should be rotated out
    for i in 0..5 {
        assert!(
            rotated_out.contains(&validators[i])
                || !contract.active_validators.contains(&validators[i])
        );
    }

    // Check that consecutive epochs were reset for rotated validators
    for validator in &rotated_out {
        if let Some(validator_info) = contract.validators.get(validator) {
            assert_eq!(validator_info.consecutive_epochs, 0);
        }
    }

    // Check that last rotation time was updated
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(contract.last_rotation_time >= current_time - 10);

    // Force a validator to exceed MAX_CONSECUTIVE_EPOCHS
    if let Some(validator_info) = contract.validators.get_mut(&validators[5]) {
        validator_info.consecutive_epochs = MAX_CONSECUTIVE_EPOCHS + 1;
    }

    // Set last rotation time to trigger rotation again
    contract.last_rotation_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - ROTATION_INTERVAL
        - 1;

    // Perform rotation again
    let rotated_out = contract.rotate_validators();

    // Validator 5 should be rotated out due to exceeding MAX_CONSECUTIVE_EPOCHS
    assert!(
        rotated_out.contains(&validators[5])
            || !contract.active_validators.contains(&validators[5])
    );
}

#[test]
fn test_validator_exit_queue() {
    // Create a new staking contract
    let mut contract = StakingContract::new(24 * 60 * 60); // 1 day duration

    // Create 5 validators with different stake amounts
    let validators = vec![
        (b"validator1".to_vec(), 1000),
        (b"validator2".to_vec(), 2000),
        (b"validator3".to_vec(), 3000),
        (b"validator4".to_vec(), 4000),
        (b"validator5".to_vec(), 5000),
    ];

    // Register validators and create stakes
    for (validator, amount) in &validators {
        let result = contract.create_stake(validator.to_vec(), *amount, true);
        assert!(result.is_ok());

        let result = contract.register_validator(validator.to_vec(), 10.0, None);
        assert!(result.is_ok());
    }

    // Verify all validators are active
    assert_eq!(contract.active_validators.len(), 5);

    // Request exit for validator1
    let wait_time = contract.request_validator_exit(&validators[0].0).unwrap();
    assert!(wait_time > 0, "Wait time should be positive");

    // Verify validator1 is marked as requesting exit
    let validator_info = contract.validators.get(&validators[0].0).unwrap();
    assert!(validator_info.exit_requested);

    // Check exit status
    let (completed, remaining_time) = contract.check_exit_status(&validators[0].0).unwrap();
    assert!(!completed, "Exit should not be completed yet");
    assert!(remaining_time > 0, "Remaining time should be positive");

    // Request exit for validator2 and validator3
    let _ = contract.request_validator_exit(&validators[1].0).unwrap();
    let _ = contract.request_validator_exit(&validators[2].0).unwrap();

    // Verify exit queue has 3 validators
    assert_eq!(contract.exit_queue.queue.len(), 3);

    // Verify queue is sorted by stake amount (smaller stakes first)
    assert_eq!(contract.exit_queue.queue[0].validator, validators[0].0);
    assert_eq!(contract.exit_queue.queue[1].validator, validators[1].0);
    assert_eq!(contract.exit_queue.queue[2].validator, validators[2].0);

    // Cancel exit request for validator2
    let result = contract.cancel_exit_request(&validators[1].0);
    assert!(result.is_ok());

    // Verify validator2 is no longer requesting exit
    let validator_info = contract.validators.get(&validators[1].0).unwrap();
    assert!(!validator_info.exit_requested);

    // Verify exit queue now has 2 validators
    assert_eq!(contract.exit_queue.queue.len(), 2);

    // Manually set last processed time to allow processing
    contract.exit_queue.last_processed = 0;

    // Manually set request time to pass minimum wait time
    for request in &mut contract.exit_queue.queue {
        request.request_time = 0;
    }

    // Process exit queue
    let processed = contract.process_exit_queue();
    assert_eq!(processed.len(), 2, "Two validators should be processed");

    // Verify validators were removed from active validators
    assert_eq!(contract.active_validators.len(), 3);

    // Try to deregister validator1 (should succeed as exit is complete)
    let result = contract.deregister_validator(&validators[0].0);
    assert!(result.is_ok());

    // Try to deregister validator4 (should fail as exit not requested)
    let result = contract.deregister_validator(&validators[3].0);
    assert!(result.is_err());

    // Request exit for validator4
    let _ = contract.request_validator_exit(&validators[3].0).unwrap();

    // Try to deregister validator4 (should fail as exit not complete)
    let result = contract.deregister_validator(&validators[3].0);
    assert!(result.is_err());

    // Verify remaining active validators
    assert_eq!(contract.active_validators.len(), 2);
}

#[test]
fn test_performance_based_rewards() {
    // Create a new staking contract
    let mut contract = StakingContract::new(24 * 60 * 60); // 1 day duration

    // Create 3 validators with equal stake amounts
    let validators = vec![
        (b"validator1".to_vec(), 1000), // Will have high performance
        (b"validator2".to_vec(), 1000), // Will have medium performance
        (b"validator3".to_vec(), 1000), // Will have low performance
    ];

    // Register validators and create stakes
    for (validator, amount) in &validators {
        let result = contract.create_stake(validator.to_vec(), *amount, true);
        assert!(result.is_ok());

        let result = contract.register_validator(validator.to_vec(), 10.0, None);
        assert!(result.is_ok());
    }

    // Create delegators
    let delegator1 = b"delegator1".to_vec();
    let delegator2 = b"delegator2".to_vec();

    // Create stakes for delegators
    let result = contract.create_stake(delegator1.clone(), 5000, false);
    assert!(result.is_ok());

    let result = contract.create_stake(delegator2.clone(), 5000, false);
    assert!(result.is_ok());

    // Delegate stakes
    let result = contract.delegate_stake(delegator1.clone(), validators[0].0.clone());
    assert!(result.is_ok());

    let result = contract.delegate_stake(delegator2.clone(), validators[2].0.clone());
    assert!(result.is_ok());

    // Set performance metrics for validators

    // High performance validator (validator1)
    // Record high uptime
    for _ in 0..100 {
        contract
            .validators
            .get_mut(&validators[0].0)
            .unwrap()
            .uptime_history
            .push(true);
    }

    // Record good block production
    contract
        .validators
        .get_mut(&validators[0].0)
        .unwrap()
        .blocks_proposed = 100;
    contract
        .validators
        .get_mut(&validators[0].0)
        .unwrap()
        .blocks_expected = 100;

    // Record low latency
    for _ in 0..100 {
        contract
            .record_block_latency(&validators[0].0, 100)
            .unwrap(); // 100ms latency
    }

    // Record high vote participation
    for _ in 0..100 {
        contract
            .record_vote_participation(&validators[0].0, true)
            .unwrap();
    }

    // Medium performance validator (validator2)
    // Record medium uptime
    for i in 0..100 {
        contract
            .validators
            .get_mut(&validators[1].0)
            .unwrap()
            .uptime_history
            .push(i % 5 != 0); // 80% uptime
    }

    // Record medium block production
    contract
        .validators
        .get_mut(&validators[1].0)
        .unwrap()
        .blocks_proposed = 80;
    contract
        .validators
        .get_mut(&validators[1].0)
        .unwrap()
        .blocks_expected = 100;

    // Record medium latency
    for _ in 0..100 {
        contract
            .record_block_latency(&validators[1].0, 300)
            .unwrap(); // 300ms latency
    }

    // Record medium vote participation
    for i in 0..100 {
        contract
            .record_vote_participation(&validators[1].0, i % 5 != 0)
            .unwrap(); // 80% participation
    }

    // Low performance validator (validator3)
    // Record low uptime
    for i in 0..100 {
        contract
            .validators
            .get_mut(&validators[2].0)
            .unwrap()
            .uptime_history
            .push(i % 2 == 0); // 50% uptime
    }

    // Record low block production
    contract
        .validators
        .get_mut(&validators[2].0)
        .unwrap()
        .blocks_proposed = 50;
    contract
        .validators
        .get_mut(&validators[2].0)
        .unwrap()
        .blocks_expected = 100;

    // Record high latency
    for _ in 0..100 {
        contract
            .record_block_latency(&validators[2].0, 800)
            .unwrap(); // 800ms latency
    }

    // Record low vote participation
    for i in 0..100 {
        contract
            .record_vote_participation(&validators[2].0, i % 2 == 0)
            .unwrap(); // 50% participation
    }

    // Set last performance assessment time to trigger recalculation
    for validator in &validators {
        contract
            .validators
            .get_mut(&validator.0)
            .unwrap()
            .last_performance_assessment = 0;
    }

    // Calculate performance scores
    let score1 = contract
        .calculate_validator_performance(&validators[0].0)
        .unwrap();
    let score2 = contract
        .calculate_validator_performance(&validators[1].0)
        .unwrap();
    let score3 = contract
        .calculate_validator_performance(&validators[2].0)
        .unwrap();

    // Verify performance scores
    assert!(
        score1 > 0.9,
        "High performance validator should have score > 0.9"
    );
    assert!(
        score2 > 0.7 && score2 < 0.9,
        "Medium performance validator should have score between 0.7 and 0.9"
    );
    assert!(
        score3 < 0.7,
        "Low performance validator should have score < 0.7"
    );

    // Apply performance multipliers
    let multiplier1 = contract
        .apply_performance_reward_multiplier(&validators[0].0, 100);
    let multiplier2 = contract
        .apply_performance_reward_multiplier(&validators[1].0, 100);
    let multiplier3 = contract
        .apply_performance_reward_multiplier(&validators[2].0, 100);

    // Verify multipliers
    assert!(
        multiplier1 > 100,
        "High performance validator should have multiplier > 100"
    );
    assert!(
        multiplier2 >= 100 && multiplier2 < multiplier1,
        "Medium performance validator should have multiplier between base and high"
    );
    assert!(
        multiplier3 < 100,
        "Low performance validator should have multiplier < 100"
    );

    // Set last reward time to trigger reward calculation
    contract.last_reward_time = 0;

    // Calculate rewards
    let rewards = contract.calculate_rewards();

    // Verify rewards distribution
    assert!(!rewards.is_empty(), "Rewards should not be empty");

    // Find rewards for each validator
    let reward1 = rewards
        .iter()
        .find(|r| r.validator == validators[0].0)
        .unwrap();
    let reward2 = rewards
        .iter()
        .find(|r| r.validator == validators[1].0)
        .unwrap();
    let reward3 = rewards
        .iter()
        .find(|r| r.validator == validators[2].0)
        .unwrap();

    // Verify high performance validator gets more rewards than medium and low
    assert!(
        reward1.amount > reward2.amount,
        "High performance validator should get more rewards than medium"
    );
    assert!(
        reward2.amount > reward3.amount,
        "Medium performance validator should get more rewards than low"
    );

    // Verify delegator rewards
    let delegator1_reward = rewards.iter().find(|r| r.staker == delegator1).unwrap();
    let delegator2_reward = rewards.iter().find(|r| r.staker == delegator2).unwrap();

    // Verify delegator to high performance validator gets more rewards
    assert!(
        delegator1_reward.amount > delegator2_reward.amount,
        "Delegator to high performance validator should get more rewards"
    );
}

#[test]
fn test_slashing_insurance_mechanism() {
    // Create a new staking contract
    let mut contract = StakingContract::new(24 * 60 * 60); // 1 day duration

    // Create 3 validators with different stake amounts
    let validators = vec![
        (b"validator1".to_vec(), 10000), // Will join insurance pool
        (b"validator2".to_vec(), 20000), // Will join insurance pool
        (b"validator3".to_vec(), 30000), // Will not join insurance pool
    ];

    // Register validators and create stakes
    for (validator, amount) in &validators {
        let result = contract.create_stake(validator.to_vec(), *amount, true);
        assert!(result.is_ok());

        let result = contract.register_validator(validator.to_vec(), 10.0, None);
        assert!(result.is_ok());
    }

    // Join insurance pool for validator1 and validator2
    let result = contract.join_insurance_pool(&validators[0].0);
    assert!(result.is_ok());

    let result = contract.join_insurance_pool(&validators[1].0);
    assert!(result.is_ok());

    // Verify insurance pool balance
    let fee1 = (validators[0].1 as f64 * INSURANCE_POOL_FEE) as u64;
    let fee2 = (validators[1].1 as f64 * INSURANCE_POOL_FEE) as u64;
    assert_eq!(contract.insurance_pool.balance, fee1 + fee2);

    // Verify validator insurance coverage
    let validator1_info = contract.validators.get(&validators[0].0).unwrap();
    let validator2_info = contract.validators.get(&validators[1].0).unwrap();
    let validator3_info = contract.validators.get(&validators[2].0).unwrap();

    assert!(validator1_info.insurance_coverage > 0);
    assert!(validator2_info.insurance_coverage > 0);
    assert_eq!(validator3_info.insurance_coverage, 0);

    // Calculate expected coverage
    let expected_coverage1 = (validators[0].1 as f64 * INSURANCE_COVERAGE_PERCENTAGE) as u64;
    let expected_coverage2 = (validators[1].1 as f64 * INSURANCE_COVERAGE_PERCENTAGE) as u64;

    assert_eq!(validator1_info.insurance_coverage, expected_coverage1);
    assert_eq!(validator2_info.insurance_coverage, expected_coverage2);

    // Slash validator1 for a minor offense (with insurance)
    let slashed_amount = contract
        .slash_validator(&validators[0].0, SlashingOffense::Downtime)
        .unwrap();

    // Verify slash amount is less than stake due to insurance
    let validator1_stake_after = contract.stakes.get(&validators[0].0).unwrap().amount;
    let expected_stake_after = validators[0].1 - slashed_amount;
    assert_eq!(validator1_stake_after, expected_stake_after);

    // Verify insurance claim was created
    assert!(!contract.insurance_pool.claims.is_empty());
    let claim = contract
        .insurance_pool
        .claims
        .iter()
        .find(|c| c.validator == validators[0].0)
        .unwrap();
    assert_eq!(claim.validator, validators[0].0);
    assert!(claim.amount > 0);
    assert!(!claim.processed);

    // Process insurance claims
    let processed_claims = contract.process_insurance_claims();
    assert_eq!(processed_claims.len(), 1);

    // Verify claim was processed
    let claim = contract
        .insurance_pool
        .claims
        .iter()
        .find(|c| c.validator == validators[0].0)
        .unwrap();
    assert!(claim.processed);

    // Slash validator3 for a major offense (without insurance)
    let slashed_amount = contract
        .slash_validator(&validators[2].0, SlashingOffense::DoubleSign)
        .unwrap();

    // Verify full slash amount was applied
    let validator3_stake_after = contract.stakes.get(&validators[2].0).unwrap().amount;
    let expected_stake_after = validators[2].1 - slashed_amount;
    assert_eq!(validator3_stake_after, expected_stake_after);

    // Verify no new insurance claim was created
    assert_eq!(contract.insurance_pool.claims.len(), 1);

    // File an insurance claim for validator1
    let claim_amount = 1000;
    let result = contract.file_insurance_claim(&validators[1].0, claim_amount, vec![1, 2, 3]);
    assert!(result.is_ok());

    // Verify claim was created
    assert_eq!(contract.insurance_pool.claims.len(), 2);
    let claim = contract
        .insurance_pool
        .claims
        .iter()
        .find(|c| c.validator == validators[1].0 && !c.processed)
        .unwrap();
    assert_eq!(claim.amount, claim_amount);

    // Process insurance claims again
    let processed_claims = contract.process_insurance_claims();
    assert_eq!(processed_claims.len(), 1);

    // Verify claim was processed
    let claim = contract
        .insurance_pool
        .claims
        .iter()
        .find(|c| c.validator == validators[1].0)
        .unwrap();
    assert!(claim.processed);

    // Try to file an excessive claim
    let excessive_claim = 100000; // More than coverage
    let result = contract.file_insurance_claim(&validators[1].0, excessive_claim, vec![1, 2, 3]);
    assert!(result.is_err());

    // Try to file a claim for a validator not in the insurance pool
    let result = contract.file_insurance_claim(&validators[2].0, 1000, vec![1, 2, 3]);
    assert!(result.is_err());

    // Verify insurance pool balance decreased after processing claims
    assert!(contract.insurance_pool.balance < fee1 + fee2);
}

#[test]
fn test_validator_enhancements_integration() {
    // Create a new staking contract
    let mut contract = StakingContract::new(24 * 60 * 60); // 1 day duration

    // Create 5 validators with different stake amounts
    let validators = vec![
        (b"validator1".to_vec(), 10000), // High performer, with insurance
        (b"validator2".to_vec(), 15000), // Medium performer, with insurance
        (b"validator3".to_vec(), 20000), // Low performer, with insurance
        (b"validator4".to_vec(), 25000), // High performer, no insurance
        (b"validator5".to_vec(), 30000), // Will request exit
    ];

    // Register validators and create stakes
    for (validator, amount) in &validators {
        let result = contract.create_stake(validator.to_vec(), *amount, true);
        assert!(result.is_ok());

        let result = contract.register_validator(validator.to_vec(), 10.0, None);
        assert!(result.is_ok());
    }

    // Create delegators
    let delegator1 = b"delegator1".to_vec();
    let delegator2 = b"delegator2".to_vec();

    // Create stakes for delegators
    let result = contract.create_stake(delegator1.clone(), 5000, false);
    assert!(result.is_ok());

    let result = contract.create_stake(delegator2.clone(), 5000, false);
    assert!(result.is_ok());

    // Delegate stakes
    let result = contract.delegate_stake(delegator1.clone(), validators[0].0.clone());
    assert!(result.is_ok());

    let result = contract.delegate_stake(delegator2.clone(), validators[2].0.clone());
    assert!(result.is_ok());

    // Join insurance pool for validators 0, 1, and 2
    for i in 0..3 {
        let result = contract.join_insurance_pool(&validators[i].0);
        assert!(result.is_ok());
    }

    // Verify insurance pool balance
    let expected_fee_total =
        (validators[0].1 + validators[1].1 + validators[2].1) as f64 * INSURANCE_POOL_FEE;
    assert_eq!(contract.insurance_pool.balance, expected_fee_total as u64);

    // Set performance metrics

    // High performers (validator1 and validator4)
    for i in [0, 3] {
        // Set high uptime
        for _ in 0..100 {
            contract
                .validators
                .get_mut(&validators[i].0)
                .unwrap()
                .uptime_history
                .push(true);
        }

        // Set high block production
        contract
            .validators
            .get_mut(&validators[i].0)
            .unwrap()
            .blocks_proposed = 100;
        contract
            .validators
            .get_mut(&validators[i].0)
            .unwrap()
            .blocks_expected = 100;

        // Set low latency
        for _ in 0..100 {
            contract
                .record_block_latency(&validators[i].0, 100)
                .unwrap();
        }

        // Set high vote participation
        for _ in 0..100 {
            contract
                .record_vote_participation(&validators[i].0, true)
                .unwrap();
        }
    }

    // Medium performer (validator2)
    // Set medium uptime
    for i in 0..100 {
        contract
            .validators
            .get_mut(&validators[1].0)
            .unwrap()
            .uptime_history
            .push(i % 5 != 0); // 80% uptime
    }

    // Set medium block production
    contract
        .validators
        .get_mut(&validators[1].0)
        .unwrap()
        .blocks_proposed = 80;
    contract
        .validators
        .get_mut(&validators[1].0)
        .unwrap()
        .blocks_expected = 100;

    // Set medium latency
    for _ in 0..100 {
        contract
            .record_block_latency(&validators[1].0, 300)
            .unwrap();
    }

    // Set medium vote participation
    for i in 0..100 {
        contract
            .record_vote_participation(&validators[1].0, i % 5 != 0)
            .unwrap();
    }

    // Low performer (validator3)
    // Set low uptime
    for i in 0..100 {
        contract
            .validators
            .get_mut(&validators[2].0)
            .unwrap()
            .uptime_history
            .push(i % 2 == 0); // 50% uptime
    }

    // Set low block production
    contract
        .validators
        .get_mut(&validators[2].0)
        .unwrap()
        .blocks_proposed = 50;
    contract
        .validators
        .get_mut(&validators[2].0)
        .unwrap()
        .blocks_expected = 100;

    // Set high latency
    for _ in 0..100 {
        contract
            .record_block_latency(&validators[2].0, 800)
            .unwrap();
    }

    // Set low vote participation
    for i in 0..100 {
        contract
            .record_vote_participation(&validators[2].0, i % 2 == 0)
            .unwrap();
    }

    // Request exit for validator5
    let wait_time = contract.request_validator_exit(&validators[4].0).unwrap();
    assert!(wait_time > 0);

    // Verify validator5 is marked as requesting exit
    let validator_info = contract.validators.get(&validators[4].0).unwrap();
    assert!(validator_info.exit_requested);

    // Set last performance assessment time to trigger recalculation
    for validator in &validators {
        contract
            .validators
            .get_mut(&validator.0)
            .unwrap()
            .last_performance_assessment = 0;
    }

    // Calculate performance scores
    let scores = validators
        .iter()
        .take(4)
        .map(|(v, _)| contract.calculate_validator_performance(v).unwrap())
        .collect::<Vec<_>>();

    // Verify performance scores
    assert!(scores[0] > 0.9, "High performer should have score > 0.9");
    assert!(
        scores[1] > 0.7 && scores[1] < 0.9,
        "Medium performer should have score between 0.7 and 0.9"
    );
    assert!(scores[2] < 0.7, "Low performer should have score < 0.7");
    assert!(scores[3] > 0.9, "High performer should have score > 0.9");

    // Set last reward time to trigger reward calculation
    contract.last_reward_time = 0;

    // Calculate rewards
    let rewards = contract.calculate_rewards();

    // Verify rewards distribution
    assert!(!rewards.is_empty());

    // Find rewards for validators
    let validator_rewards: Vec<_> = validators
        .iter()
        .take(4)
        .map(|(v, _)| rewards.iter().find(|r| r.validator == *v).unwrap().amount)
        .collect();

    // Verify high performers get more rewards than medium and low
    assert!(
        validator_rewards[0] > validator_rewards[1],
        "High performer should get more rewards than medium"
    );
    assert!(
        validator_rewards[1] > validator_rewards[2],
        "Medium performer should get more rewards than low"
    );
    assert!(
        validator_rewards[3] > validator_rewards[2],
        "High performer without insurance should get more rewards than low performer"
    );

    // Verify delegator rewards
    let delegator1_reward = rewards
        .iter()
        .find(|r| r.staker == delegator1)
        .unwrap()
        .amount;
    let delegator2_reward = rewards
        .iter()
        .find(|r| r.staker == delegator2)
        .unwrap()
        .amount;

    // Verify delegator to high performer gets more rewards
    assert!(
        delegator1_reward > delegator2_reward,
        "Delegator to high performer should get more rewards"
    );

    // Slash validator2 (medium performer with insurance)
    let slashed_amount = contract
        .slash_validator(&validators[1].0, SlashingOffense::Downtime)
        .unwrap();

    // Verify slash amount is less than stake due to insurance
    let validator2_stake_after = contract.stakes.get(&validators[1].0).unwrap().amount;
    let expected_stake_after = validators[1].1 - slashed_amount;
    assert_eq!(validator2_stake_after, expected_stake_after);

    // Verify insurance claim was created
    let claim = contract
        .insurance_pool
        .claims
        .iter()
        .find(|c| c.validator == validators[1].0)
        .unwrap();
    assert_eq!(claim.validator, validators[1].0);
    assert!(claim.amount > 0);
    assert!(!claim.processed);

    // Process insurance claims
    let processed_claims = contract.process_insurance_claims();
    assert_eq!(processed_claims.len(), 1);

    // Verify claim was processed
    let claim = contract
        .insurance_pool
        .claims
        .iter()
        .find(|c| c.validator == validators[1].0)
        .unwrap();
    assert!(claim.processed);

    // Slash validator4 (high performer without insurance)
    let slashed_amount = contract
        .slash_validator(&validators[3].0, SlashingOffense::Downtime)
        .unwrap();

    // Verify full slash amount was applied (no insurance)
    let validator4_stake_after = contract.stakes.get(&validators[3].0).unwrap().amount;
    let expected_stake_after = validators[3].1 - slashed_amount;
    assert_eq!(validator4_stake_after, expected_stake_after);

    // Verify no new insurance claim was created
    assert_eq!(contract.insurance_pool.claims.len(), 1);

    // Manually set last processed time to allow processing exit queue
    contract.exit_queue.last_processed = 0;

    // Manually set request time to pass minimum wait time
    for request in &mut contract.exit_queue.queue {
        request.request_time = 0;
    }

    // Process exit queue
    let processed = contract.process_exit_queue();
    assert_eq!(processed.len(), 1, "One validator should be processed");
    assert_eq!(
        processed[0], validators[4].0,
        "Validator5 should be processed"
    );

    // Verify validator5 was removed from active validators
    assert!(!contract.active_validators.contains(&validators[4].0));

    // Try to deregister validator5 (should succeed as exit is complete)
    let result = contract.deregister_validator(&validators[4].0);
    assert!(result.is_ok());

    // Verify validator5 is completely removed
    assert!(!contract.validators.contains_key(&validators[4].0));

    // Calculate rewards again after all changes
    contract.last_reward_time = 0;
    let rewards_after = contract.calculate_rewards();

    // Verify validator5 is not in rewards
    assert!(rewards_after
        .iter()
        .find(|r| r.validator == validators[4].0)
        .is_none());

    // Verify slashed validators get reduced rewards
    let validator2_reward_before = validator_rewards[1];
    let validator2_reward_after = rewards_after
        .iter()
        .find(|r| r.validator == validators[1].0)
        .unwrap()
        .amount;
    assert!(
        validator2_reward_after < validator2_reward_before,
        "Slashed validator should get reduced rewards"
    );

    // Verify high performers still get higher rewards
    let validator1_reward_after = rewards_after
        .iter()
        .find(|r| r.validator == validators[0].0)
        .unwrap()
        .amount;
    let validator3_reward_after = rewards_after
        .iter()
        .find(|r| r.validator == validators[2].0)
        .unwrap()
        .amount;
    assert!(
        validator1_reward_after > validator3_reward_after,
        "High performer should still get more rewards than low performer"
    );
}

#[test]
fn test_threshold_signature_integration() {
    use crate::consensus::threshold_sig::{ThresholdError, ValidatorAggregation};
    use ed25519_dalek::{Keypair, Signer};
    use rand::rngs::OsRng;

    // Create a staking contract
    let mut contract = StakingContract::new(24 * 60 * 60); // 1 day epoch

    // Create 5 validators with different stake amounts
    let mut keypairs = Vec::new();
    let mut validators = Vec::new();

    let mut csprng = OsRng;
    for i in 0..5 {
        let keypair = Keypair::generate(&mut csprng);
        let public_key = keypair.public.to_bytes().to_vec();
        let stake_amount = 1000 + (i as u64 * 500);

        contract
            .create_stake(public_key.clone(), stake_amount, false)
            .unwrap();
        contract
            .register_validator(public_key.clone(), 0.1, None)
            .unwrap();

        validators.push(public_key);
        keypairs.push(keypair);
    }

    // Select validators for the current epoch
    contract.select_validators(5);
    assert_eq!(contract.active_validators.len(), 5);

    // Create a block hash to sign
    let mut block_hash = [0u8; 32];
    for i in 0..32 {
        block_hash[i] = i as u8;
    }

    // Create a validator aggregation with 3-of-5 threshold
    let threshold = 3;
    let validator_keys = validators
        .iter()
        .map(|v| ed25519_dalek::PublicKey::from_bytes(v).unwrap())
        .collect::<Vec<_>>();

    let mut aggregation = ValidatorAggregation::new(threshold, validator_keys, block_hash).unwrap();

    // Add signatures from validators 0, 2, and 4
    let sig0 = keypairs[0].sign(&block_hash.to_vec());
    let result = aggregation.add_validator_signature(0, sig0);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false); // Threshold not met yet

    let sig2 = keypairs[2].sign(&block_hash.to_vec());
    let result = aggregation.add_validator_signature(2, sig2);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false); // Threshold not met yet

    let sig4 = keypairs[4].sign(&block_hash.to_vec());
    let result = aggregation.add_validator_signature(4, sig4);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), true); // Threshold met

    // Verify the aggregation is complete
    assert!(aggregation.is_complete);

    // Verify the aggregated signature
    let result = aggregation.verify();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), true);

    // Get the aggregated signature
    let agg_sig = aggregation.get_aggregated_signature();
    assert!(agg_sig.is_ok());
    assert_eq!(agg_sig.unwrap().len(), 32); // SHA-256 output

    // Try to add another signature after completion
    let sig1 = keypairs[1].sign(&block_hash.to_vec());
    let result = aggregation.add_validator_signature(1, sig1);
    assert!(matches!(result, Err(ThresholdError::ThresholdAlreadyMet)));
}

// Helper function to create a mock block for testing
fn create_mock_block(
    height: u64,
    previous_hash: [u8; 32],
    miner: Vec<u8>,
) -> crate::blockchain::Block {
    use crate::blockchain::{Block, BlockHeader, Transaction};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut header = BlockHeader {
        version: 1,
        previous_hash,
        merkle_root: [0; 32],
        timestamp,
        height,
        nonce: 0,
        difficulty_target: 1,
        miner: Some(miner),
    };

    // Create a unique hash for this block
    let mut hasher = Sha256::new();
    hasher.update(height.to_le_bytes());
    hasher.update(previous_hash);
    hasher.update(timestamp.to_le_bytes());
    let hash_result = hasher.finalize();

    let mut hash = [0; 32];
    hash.copy_from_slice(&hash_result);
    header.merkle_root = hash;

    Block {
        header,
        transactions: Vec::<Transaction>::new(),
    }
}
