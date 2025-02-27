use crate::consensus::pos::*;
use crate::consensus::pos_fixes::*;
use crate::consensus::pos::pos_structs::*;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_register_asset() {
    let mut contract = StakingContract::new_with_multi_asset_support(24 * 60 * 60);
    
    // The native token (OBX) should already be registered
    assert_eq!(contract.supported_assets.len(), 1);
    assert!(contract.supported_assets.contains_key("OBX"));
    
    // Register a new asset
    let new_asset = AssetInfo {
        asset_id: "ETH".to_string(),
        name: "Ethereum".to_string(),
        symbol: "ETH".to_string(),
        decimals: 18,
        min_stake: 100,
        weight: 1.0,
        exchange_rate: 10.0, // 1 ETH = 10 OBX
        last_rate_update: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        total_staked: 0,
        is_native: false,
    };
    
    let result = contract.register_asset(new_asset);
    assert!(result.is_ok());
    
    // Now we should have 2 assets
    assert_eq!(contract.supported_assets.len(), 2);
    assert!(contract.supported_assets.contains_key("ETH"));
    
    // Try to register the same asset again (should fail)
    let duplicate_asset = AssetInfo {
        asset_id: "ETH".to_string(),
        name: "Ethereum".to_string(),
        symbol: "ETH".to_string(),
        decimals: 18,
        min_stake: 100,
        weight: 1.0,
        exchange_rate: 10.0,
        last_rate_update: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        total_staked: 0,
        is_native: false,
    };
    
    let result = contract.register_asset(duplicate_asset);
    assert!(result.is_err());
}

#[test]
fn test_create_multi_asset_stake() {
    let mut contract = StakingContract::new_with_multi_asset_support(24 * 60 * 60);
    
    // Register a secondary asset
    let eth_asset = AssetInfo {
        asset_id: "ETH".to_string(),
        name: "Ethereum".to_string(),
        symbol: "ETH".to_string(),
        decimals: 18,
        min_stake: 100,
        weight: 1.0,
        exchange_rate: 10.0, // 1 ETH = 10 OBX
        last_rate_update: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        total_staked: 0,
        is_native: false,
    };
    
    contract.register_asset(eth_asset).unwrap();
    
    // Create a staker
    let staker = vec![1, 2, 3, 4];
    
    // Create a multi-asset stake with both OBX and ETH
    let mut assets = HashMap::new();
    assets.insert("OBX".to_string(), 2000); // 2000 OBX
    assets.insert("ETH".to_string(), 150);  // 150 ETH
    
    let result = contract.create_multi_asset_stake(staker.clone(), assets, true);
    assert!(result.is_ok());
    
    // Check that the stake was created
    let stakes = contract.multi_asset_stakes.get(&staker).unwrap();
    assert_eq!(stakes.len(), 1);
    
    // Check that the assets were recorded correctly
    let stake = &stakes[0];
    assert_eq!(stake.assets.get("OBX").unwrap(), &2000);
    assert_eq!(stake.assets.get("ETH").unwrap(), &150);
    
    // Check that the total staked amounts were updated
    assert_eq!(contract.supported_assets.get("OBX").unwrap().total_staked, 2000);
    assert_eq!(contract.supported_assets.get("ETH").unwrap().total_staked, 150);
    
    // Try to create a stake with insufficient native token (should fail)
    let mut bad_assets = HashMap::new();
    bad_assets.insert("OBX".to_string(), 100); // Only 100 OBX (less than 20% of value)
    bad_assets.insert("ETH".to_string(), 500); // 500 ETH (worth 5000 OBX)
    
    let result = contract.create_multi_asset_stake(staker.clone(), bad_assets, true);
    assert!(result.is_err());
    
    // Try to create a stake without native token (should fail)
    let mut no_native_assets = HashMap::new();
    no_native_assets.insert("ETH".to_string(), 200);
    
    let result = contract.create_multi_asset_stake(staker.clone(), no_native_assets, true);
    assert!(result.is_err());
}

#[test]
fn test_get_effective_stake_value() {
    let mut contract = StakingContract::new_with_multi_asset_support(24 * 60 * 60);
    
    // Register a secondary asset
    let eth_asset = AssetInfo {
        asset_id: "ETH".to_string(),
        name: "Ethereum".to_string(),
        symbol: "ETH".to_string(),
        decimals: 18,
        min_stake: 100,
        weight: 1.0,
        exchange_rate: 10.0, // 1 ETH = 10 OBX
        last_rate_update: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        total_staked: 0,
        is_native: false,
    };
    
    contract.register_asset(eth_asset).unwrap();
    
    // Create a staker
    let staker = vec![1, 2, 3, 4];
    
    // Create a multi-asset stake with both OBX and ETH
    let mut assets = HashMap::new();
    assets.insert("OBX".to_string(), 2000); // 2000 OBX
    assets.insert("ETH".to_string(), 150);  // 150 ETH (worth 1500 OBX)
    
    contract.create_multi_asset_stake(staker.clone(), assets, true).unwrap();
    
    // Calculate effective stake value
    // OBX: 2000 * 1.0 (exchange rate) * 1.5 (weight) = 3000
    // ETH: 150 * 10.0 (exchange rate) * 1.0 (weight) = 1500
    // Total: 4500
    let effective_value = contract.get_effective_stake_value(&staker).unwrap();
    assert_eq!(effective_value, 4500);
}

#[test]
fn test_withdrawal_flow() {
    let mut contract = StakingContract::new_with_multi_asset_support(24 * 60 * 60);
    
    // Register a secondary asset
    let eth_asset = AssetInfo {
        asset_id: "ETH".to_string(),
        name: "Ethereum".to_string(),
        symbol: "ETH".to_string(),
        decimals: 18,
        min_stake: 100,
        weight: 1.0,
        exchange_rate: 10.0,
        last_rate_update: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        total_staked: 0,
        is_native: false,
    };
    
    contract.register_asset(eth_asset).unwrap();
    
    // Create a staker
    let staker = vec![1, 2, 3, 4];
    
    // Create a multi-asset stake
    let mut assets = HashMap::new();
    assets.insert("OBX".to_string(), 2000);
    assets.insert("ETH".to_string(), 150);
    
    contract.create_multi_asset_stake(staker.clone(), assets, true).unwrap();
    
    // Try to withdraw before lock period (should fail)
    let result = contract.request_multi_asset_withdrawal(&staker, 0);
    assert!(result.is_err());
    
    // Manually set the lock_until to a past time to simulate lock period ending
    if let Some(stakes) = contract.multi_asset_stakes.get_mut(&staker) {
        stakes[0].lock_until = 0;
    }
    
    // Now request withdrawal
    let result = contract.request_multi_asset_withdrawal(&staker, 0);
    assert!(result.is_ok());
    
    // Try to complete withdrawal before delay period (should fail)
    let result = contract.complete_multi_asset_withdrawal(&staker, 0);
    assert!(result.is_err());
    
    // Manually set the timestamp to a past time to simulate delay period ending
    if let Some(stakes) = contract.multi_asset_stakes.get_mut(&staker) {
        stakes[0].timestamp = 0;
    }
    
    // Now complete withdrawal
    let result = contract.complete_multi_asset_withdrawal(&staker, 0);
    assert!(result.is_ok());
    
    // Check that the assets were returned correctly
    let returned_assets = result.unwrap();
    assert_eq!(returned_assets.get("OBX").unwrap(), &2000);
    assert_eq!(returned_assets.get("ETH").unwrap(), &150);
    
    // Check that the stake was removed
    assert!(contract.multi_asset_stakes.get(&staker).unwrap().is_empty());
    
    // Check that the total staked amounts were updated
    assert_eq!(contract.supported_assets.get("OBX").unwrap().total_staked, 0);
    assert_eq!(contract.supported_assets.get("ETH").unwrap().total_staked, 0);
}

#[test]
fn test_rewards_and_compounding() {
    let mut contract = StakingContract::new_with_multi_asset_support(24 * 60 * 60);
    
    // Create a staker
    let staker = vec![1, 2, 3, 4];
    
    // Create a stake with auto-compounding enabled
    let mut assets = HashMap::new();
    assets.insert("OBX".to_string(), 10000);
    
    contract.create_multi_asset_stake(staker.clone(), assets.clone(), true).unwrap();
    
    // Create another stake with auto-compounding disabled
    let staker2 = vec![5, 6, 7, 8];
    contract.create_multi_asset_stake(staker2.clone(), assets.clone(), false).unwrap();
    
    // Manually set the last_compound_time to simulate time passing
    if let Some(stakes) = contract.multi_asset_stakes.get_mut(&staker) {
        stakes[0].last_compound_time = 0; // A long time ago
    }
    
    if let Some(stakes) = contract.multi_asset_stakes.get_mut(&staker2) {
        stakes[0].last_compound_time = 0; // A long time ago
    }
    
    // Calculate rewards
    let rewards = contract.calculate_multi_asset_rewards();
    
    // Both stakers should have rewards
    assert!(rewards.contains_key(&staker));
    assert!(rewards.contains_key(&staker2));
    
    // For the auto-compounding stake, the rewards should be added to the stake
    let auto_compound_stake = &contract.multi_asset_stakes.get(&staker).unwrap()[0];
    assert!(auto_compound_stake.assets.get("OBX").unwrap() > &10000);
    
    // For the non-auto-compounding stake, the stake amount should remain the same
    let non_auto_compound_stake = &contract.multi_asset_stakes.get(&staker2).unwrap()[0];
    assert_eq!(non_auto_compound_stake.assets.get("OBX").unwrap(), &10000);
    
    // Claim rewards for the non-auto-compounding stake
    let claimed_rewards = contract.claim_multi_asset_rewards(&staker2).unwrap();
    assert!(claimed_rewards.contains_key("OBX"));
    assert!(claimed_rewards.get("OBX").unwrap() > &0);
}

#[test]
fn test_oracle_integration() {
    let mut contract = StakingContract::new_with_multi_asset_support(24 * 60 * 60);
    
    // Register a secondary asset
    let eth_asset = AssetInfo {
        asset_id: "ETH".to_string(),
        name: "Ethereum".to_string(),
        symbol: "ETH".to_string(),
        decimals: 18,
        min_stake: 100,
        weight: 1.0,
        exchange_rate: 10.0, // 1 ETH = 10 OBX
        last_rate_update: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        total_staked: 0,
        is_native: false,
    };
    
    contract.register_asset(eth_asset).unwrap();
    
    // Manually set the last exchange rate update to a past time
    contract.last_exchange_rate_update = 0;
    
    // Generate simulated oracle price feeds
    let price_feeds = contract.simulate_oracle_price_feeds();
    
    // Update exchange rates
    let result = contract.update_exchange_rates_from_oracle(price_feeds);
    assert!(result.is_ok());
    
    // Check that rates were updated
    let updated_rates = result.unwrap();
    assert!(updated_rates.contains_key("ETH"));
    
    // Check that the rate is close to the original (within the allowed change percentage)
    let new_rate = updated_rates.get("ETH").unwrap();
    let original_rate = 10.0;
    let max_change = original_rate * MAX_RATE_CHANGE_PERCENTAGE;
    
    assert!((*new_rate - original_rate).abs() <= max_change);
    
    // Try to update again too soon (should fail)
    let price_feeds = contract.simulate_oracle_price_feeds();
    let result = contract.update_exchange_rates_from_oracle(price_feeds);
    assert!(result.is_err());
}

#[test]
fn test_validator_selection_with_multi_assets() {
    let mut contract = StakingContract::new_with_multi_asset_support(24 * 60 * 60);
    
    // Register a secondary asset
    let eth_asset = AssetInfo {
        asset_id: "ETH".to_string(),
        name: "Ethereum".to_string(),
        symbol: "ETH".to_string(),
        decimals: 18,
        min_stake: 100,
        weight: 1.0,
        exchange_rate: 10.0, // 1 ETH = 10 OBX
        last_rate_update: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        total_staked: 0,
        is_native: false,
    };
    
    contract.register_asset(eth_asset).unwrap();
    
    // Create validators with different stake configurations
    
    // Validator 1: Traditional stake only
    let validator1 = vec![1, 1, 1, 1];
    let validator_info1 = ValidatorInfo {
        public_key: validator1.clone(),
        total_stake: 5000,
        commission_rate: 0.05,
        uptime: 0.99,
        blocks_proposed: 100,
        blocks_expected: 100,
        last_proposed_block: 0,
        last_performance_assessment: 0,
        performance_score: 0.95,
        exit_requested: false,
        exit_request_time: 0,
        consecutive_epochs: 0,
        last_rotation: 0,
        block_latency: Vec::new(),
        vote_participation: Vec::new(),
        uptime_history: Vec::new(),
        slashing_history: Vec::new(),
    };
    contract.validators.insert(validator1.clone(), validator_info1);
    
    // Validator 2: Multi-asset stake only
    let validator2 = vec![2, 2, 2, 2];
    let validator_info2 = ValidatorInfo {
        public_key: validator2.clone(),
        total_stake: 0, // No traditional stake
        commission_rate: 0.05,
        uptime: 0.99,
        blocks_proposed: 100,
        blocks_expected: 100,
        last_proposed_block: 0,
        last_performance_assessment: 0,
        performance_score: 0.95,
        exit_requested: false,
        exit_request_time: 0,
        consecutive_epochs: 0,
        last_rotation: 0,
        block_latency: Vec::new(),
        vote_participation: Vec::new(),
        uptime_history: Vec::new(),
        slashing_history: Vec::new(),
    };
    contract.validators.insert(validator2.clone(), validator_info2);
    
    // Create multi-asset stake for validator 2
    let mut assets = HashMap::new();
    assets.insert("OBX".to_string(), 2000); // 2000 OBX
    assets.insert("ETH".to_string(), 300);  // 300 ETH (worth 3000 OBX)
    // Total effective value: 2000 * 1.5 + 300 * 10 * 1.0 = 6000
    
    contract.create_multi_asset_stake(validator2.clone(), assets, true).unwrap();
    
    // Validator 3: Both traditional and multi-asset stake
    let validator3 = vec![3, 3, 3, 3];
    let validator_info3 = ValidatorInfo {
        public_key: validator3.clone(),
        total_stake: 3000,
        commission_rate: 0.05,
        uptime: 0.99,
        blocks_proposed: 100,
        blocks_expected: 100,
        last_proposed_block: 0,
        last_performance_assessment: 0,
        performance_score: 0.95,
        exit_requested: false,
        exit_request_time: 0,
        consecutive_epochs: 0,
        last_rotation: 0,
        block_latency: Vec::new(),
        vote_participation: Vec::new(),
        uptime_history: Vec::new(),
        slashing_history: Vec::new(),
    };
    contract.validators.insert(validator3.clone(), validator_info3);
    
    // Create multi-asset stake for validator 3
    let mut assets = HashMap::new();
    assets.insert("OBX".to_string(), 1000); // 1000 OBX
    assets.insert("ETH".to_string(), 100);  // 100 ETH (worth 1000 OBX)
    // Total effective value: 1000 * 1.5 + 100 * 10 * 1.0 = 2500
    // But traditional stake is higher at 3000, so that should be used
    
    contract.create_multi_asset_stake(validator3.clone(), assets, true).unwrap();
    
    // Select validators
    let selected = contract.select_validators_with_multi_assets(2);
    
    // We should have 2 validators selected
    assert_eq!(selected.len(), 2);
    
    // Validator 2 should be first (highest effective stake at 6000)
    assert_eq!(selected[0], validator2);
    
    // Validator 3 should be second (effective stake 3000)
    assert_eq!(selected[1], validator3);
    
    // Validator 1 should not be selected (lowest effective stake at 5000)
    assert!(!selected.contains(&validator1));
}

#[test]
fn test_slash_multi_asset_stakes() {
    let mut contract = StakingContract::new_with_multi_asset_support(24 * 60 * 60);
    
    // Register a secondary asset
    let eth_asset = AssetInfo {
        asset_id: "ETH".to_string(),
        name: "Ethereum".to_string(),
        symbol: "ETH".to_string(),
        decimals: 18,
        min_stake: 100,
        weight: 1.0,
        exchange_rate: 10.0, // 1 ETH = 10 OBX
        last_rate_update: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        total_staked: 0,
        is_native: false,
    };
    
    contract.register_asset(eth_asset).unwrap();
    
    // Create a validator
    let validator = vec![1, 1, 1, 1];
    let validator_info = ValidatorInfo {
        public_key: validator.clone(),
        total_stake: 5000,
        commission_rate: 0.05,
        uptime: 0.99,
        blocks_proposed: 100,
        blocks_expected: 100,
        last_proposed_block: 0,
        last_performance_assessment: 0,
        performance_score: 0.95,
        exit_requested: false,
        exit_request_time: 0,
        consecutive_epochs: 0,
        last_rotation: 0,
        block_latency: Vec::new(),
        vote_participation: Vec::new(),
        uptime_history: Vec::new(),
        slashing_history: Vec::new(),
    };
    contract.validators.insert(validator.clone(), validator_info);
    
    // Create multi-asset stake for the validator
    let mut assets = HashMap::new();
    assets.insert("OBX".to_string(), 2000); // 2000 OBX
    assets.insert("ETH".to_string(), 300);  // 300 ETH (worth 3000 OBX)
    
    contract.create_multi_asset_stake(validator.clone(), assets, true).unwrap();
    
    // Check initial stake amounts
    let initial_obx_staked = contract.supported_assets.get("OBX").unwrap().total_staked;
    let initial_eth_staked = contract.supported_assets.get("ETH").unwrap().total_staked;
    
    assert_eq!(initial_obx_staked, 2000);
    assert_eq!(initial_eth_staked, 300);
    
    // Slash the validator's stakes by 50%
    let slash_percentage = 0.5;
    let result = contract.slash_multi_asset_stakes(&validator, slash_percentage, "Downtime");
    assert!(result.is_ok());
    
    // Check slashed amounts
    let slashed_amounts = result.unwrap();
    assert_eq!(*slashed_amounts.get("OBX").unwrap(), 1000); // 50% of 2000
    assert_eq!(*slashed_amounts.get("ETH").unwrap(), 150);  // 50% of 300
    
    // Check updated stake amounts
    let updated_obx_staked = contract.supported_assets.get("OBX").unwrap().total_staked;
    let updated_eth_staked = contract.supported_assets.get("ETH").unwrap().total_staked;
    
    assert_eq!(updated_obx_staked, 1000); // 2000 - 1000
    assert_eq!(updated_eth_staked, 150);  // 300 - 150
    
    // Check validator's updated total stake
    let validator_info = contract.validators.get(&validator).unwrap();
    
    // The validator's total stake should be reduced by the equivalent value in OBX
    // 1000 OBX + 150 ETH (worth 1500 OBX) = 2500 OBX equivalent
    assert_eq!(validator_info.total_stake, 2500);
    
    // Check that slashing history was recorded
    assert_eq!(validator_info.slashing_history.len(), 1);
    assert_eq!(validator_info.slashing_history[0].2, "Downtime");
    
    // Check the stake itself
    let stakes = contract.multi_asset_stakes.get(&validator).unwrap();
    assert_eq!(stakes.len(), 1);
    
    let stake = &stakes[0];
    assert_eq!(*stake.assets.get("OBX").unwrap(), 1000);
    assert_eq!(*stake.assets.get("ETH").unwrap(), 150);
}