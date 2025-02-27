# Multi-Asset Staking

This document describes the multi-asset staking functionality implemented in the Obscura blockchain.

## Overview

Multi-asset staking allows validators and delegators to stake multiple types of assets in the Obscura network, not just the native OBX token. This feature enhances capital efficiency, increases network security, and provides more flexibility for participants.

## Key Features

1. **Support for Multiple Assets**: Stake using OBX (native token) and other supported assets.
2. **Weighted Stake Calculation**: Different assets have different weights in stake calculations.
3. **Exchange Rate Management**: Assets are valued relative to OBX using exchange rates.
4. **Auto-compounding**: Automatically reinvest staking rewards.
5. **Minimum Native Token Requirement**: At least 20% of stake value must be in native OBX tokens.

## Supported Assets

Each supported asset has the following properties:

- **Asset ID**: Unique identifier for the asset
- **Name**: Human-readable name
- **Symbol**: Trading symbol
- **Decimals**: Number of decimal places
- **Minimum Stake**: Minimum amount required to stake
- **Weight**: Influence in validator selection (higher weight = more influence)
- **Exchange Rate**: Value relative to the native token
- **Is Native**: Whether this is the native blockchain token

## Implementation Details

### Key Structures

- `AssetInfo`: Contains information about a stakable asset
- `MultiAssetStake`: Represents a stake consisting of multiple assets
- `OraclePriceFeed`: Represents a price feed from an oracle

### Key Methods

- `register_asset`: Register a new asset for staking
- `create_multi_asset_stake`: Create a new multi-asset stake
- `get_effective_stake_value`: Calculate the effective value of a multi-asset stake
- `request_multi_asset_withdrawal`: Request withdrawal of a multi-asset stake
- `complete_multi_asset_withdrawal`: Complete the withdrawal process
- `calculate_multi_asset_rewards`: Calculate rewards for multi-asset stakes
- `claim_multi_asset_rewards`: Claim rewards for multi-asset stakes
- `update_exchange_rates_from_oracle`: Update exchange rates using oracle price feeds
- `select_validators_with_multi_assets`: Select validators based on effective stake values
- `slash_multi_asset_stakes`: Slash a validator's multi-asset stakes

### Constants

- `STAKE_LOCK_PERIOD`: Duration for which stakes are locked (14 days)
- `WITHDRAWAL_DELAY`: Delay between requesting and completing withdrawal (2 days)
- `MINIMUM_STAKE`: Minimum stake amount for the native token
- `MAX_ASSETS_PER_VALIDATOR`: Maximum number of different assets a validator can stake
- `ORACLE_UPDATE_INTERVAL`: Interval between oracle updates (1 hour)
- `MAX_RATE_CHANGE_PERCENTAGE`: Maximum allowed change in exchange rates (10%)
- `MIN_ORACLE_CONFIRMATIONS`: Minimum number of oracle confirmations required (3)

## Usage Examples

### Registering a New Asset

```rust
let eth_asset = AssetInfo {
    asset_id: "ETH".to_string(),
    name: "Ethereum".to_string(),
    symbol: "ETH".to_string(),
    decimals: 18,
    min_stake: 100,
    weight: 1.0,
    exchange_rate: 10.0, // 1 ETH = 10 OBX
    last_rate_update: current_time,
    total_staked: 0,
    is_native: false,
};

contract.register_asset(eth_asset).unwrap();
```

### Creating a Multi-Asset Stake

```rust
let mut assets = HashMap::new();
assets.insert("OBX".to_string(), 2000); // 2000 OBX
assets.insert("ETH".to_string(), 150);  // 150 ETH

contract.create_multi_asset_stake(staker, assets, true).unwrap();
```

### Calculating Effective Stake Value

```rust
let effective_value = contract.get_effective_stake_value(&staker).unwrap();
```

### Requesting Withdrawal

```rust
let withdrawal_time = contract.request_multi_asset_withdrawal(&staker, 0).unwrap();
```

### Completing Withdrawal

```rust
let returned_assets = contract.complete_multi_asset_withdrawal(&staker, 0).unwrap();
```

### Selecting Validators with Multi-Asset Stakes

```rust
let selected_validators = contract.select_validators_with_multi_assets(10);
```

### Slashing Multi-Asset Stakes

```rust
let slashed_amounts = contract.slash_multi_asset_stakes(&validator, 0.5, "Downtime").unwrap();
```

### Updating Exchange Rates from Oracle

```rust
let price_feeds = get_oracle_price_feeds();
let updated_rates = contract.update_exchange_rates_from_oracle(price_feeds).unwrap();
```

## Testing

The multi-asset staking functionality is thoroughly tested in `src/consensus/tests/multi_asset_staking_tests.rs`. The tests cover:

1. Asset registration
2. Creating multi-asset stakes
3. Calculating effective stake values
4. Withdrawal flow
5. Rewards and auto-compounding
6. Oracle integration
7. Validator selection with multi-asset stakes
8. Slashing multi-asset stakes

## Implementation Progress

The following tasks have been completed:

- ✅ Basic multi-asset staking functionality
- ✅ Validator selection with multi-asset stakes
- ✅ Slashing for multi-asset stakes
- ✅ Oracle integration for exchange rate updates

## TODO List

The following tasks still need to be completed:

1. **Add Validator Asset Constraints**:
   - Enforce the `MAX_ASSETS_PER_VALIDATOR` limit in the validator registration process
   - Add methods to manage a validator's asset portfolio

2. **Implement Governance for Asset Addition**:
   - Create a governance proposal type for adding new assets
   - Implement voting mechanism for asset addition
   - Add security checks for new assets

3. **Performance Optimization**:
   - Optimize the calculation of effective stake values for large numbers of validators
   - Add caching mechanisms for frequently accessed values

4. **Risk Management**:
   - Implement circuit breakers for extreme exchange rate fluctuations
   - Add mechanisms to gradually adjust weights based on market conditions

5. **UI/API Integration**:
   - Create API endpoints for multi-asset staking operations
   - Design UI components for managing multi-asset stakes

## Future Improvements

1. **Dynamic Weights**: Adjust asset weights based on market conditions and risk profiles
2. **Liquid Staking Integration**: Integrate with liquid staking for multi-asset stakes
3. **Cross-Chain Asset Support**: Support for assets from other blockchains
4. **Advanced Reward Distribution**: More sophisticated reward distribution mechanisms
5. **Validator Specialization**: Allow validators to specialize in certain assets 