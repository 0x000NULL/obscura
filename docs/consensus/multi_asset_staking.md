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

## Implementation Status

The multi-asset staking functionality has been implemented with the following components:

- ✅ Basic multi-asset staking functionality
- ✅ Validator selection with multi-asset stakes
- ✅ Slashing for multi-asset stakes
- ✅ Oracle integration for exchange rates

Remaining tasks:
- Add validator asset constraints
- Implement governance for asset addition
- Performance optimization for large validator sets
- Risk management for exchange rate fluctuations
- UI/API integration for multi-asset staking

## Technical Details

### Asset Information

Each supported asset has the following properties:

```rust
pub struct AssetInfo {
    /// Unique identifier for the asset
    pub asset_id: String,
    /// Human-readable name of the asset
    pub name: String,
    /// Symbol/ticker of the asset
    pub symbol: String,
    /// Number of decimal places for the asset
    pub decimals: u8,
    /// Minimum amount required to stake this asset
    pub min_stake: u64,
    /// Weight of this asset in validator selection (higher weight = more influence)
    pub weight: f64,
    /// Exchange rate to the native token
    pub exchange_rate: f64,
    /// Timestamp of the last exchange rate update
    pub last_rate_update: u64,
    /// Total amount of this asset currently staked
    pub total_staked: u64,
    /// Whether this is the native token of the blockchain
    pub is_native: bool,
}
```

### Multi-Asset Stake

A multi-asset stake is represented as:

```rust
pub struct MultiAssetStake {
    /// Public key of the staker
    pub staker: Vec<u8>,
    /// Map of asset ID to staked amount
    pub assets: HashMap<String, u64>,
    /// Timestamp when the stake was created
    pub timestamp: u64,
    /// Timestamp until which the stake is locked
    pub lock_until: u64,
    /// Whether rewards should be automatically compounded
    pub auto_compound: bool,
    /// Timestamp of the last compounding operation
    pub last_compound_time: u64,
}
```

### Oracle Price Feed

Exchange rates are updated using oracle price feeds:

```rust
pub struct OraclePriceFeed {
    pub asset_id: String,
    pub price: f64,
    pub timestamp: u64,
    pub source: String,
    pub signature: Vec<u8>,
}
```

## Key Constants

- `STAKE_LOCK_PERIOD`: Duration for which stakes are locked (14 days)
- `WITHDRAWAL_DELAY`: Delay between requesting and completing withdrawal (2 days)
- `MINIMUM_STAKE`: Minimum stake amount for the native token
- `MAX_ASSETS_PER_VALIDATOR`: Maximum number of different assets a validator can stake
- `ORACLE_UPDATE_INTERVAL`: Interval between oracle updates (1 hour)
- `MAX_RATE_CHANGE_PERCENTAGE`: Maximum allowed change in exchange rates (10%)
- `MIN_ORACLE_CONFIRMATIONS`: Minimum number of oracle confirmations required (3)

## Key Methods

### Asset Registration

```rust
pub fn register_asset(&mut self, asset_info: AssetInfo) -> Result<(), String>
```

Registers a new asset for staking. The asset must have a unique ID and cannot be already registered.

### Creating a Multi-Asset Stake

```rust
pub fn create_multi_asset_stake(
    &mut self,
    staker: Vec<u8>,
    assets: HashMap<String, u64>,
    auto_compound: bool,
) -> Result<(), &'static str>
```

Creates a new multi-asset stake. At least 20% of the total value must be in the native OBX token.

### Calculating Effective Stake Value

```rust
pub fn get_effective_stake_value(&self, staker: &[u8]) -> Result<u64, &'static str>
```

Calculates the effective value of a multi-asset stake, taking into account the exchange rates and weights of each asset.

### Validator Selection

```rust
pub fn select_validators_with_multi_assets(&self, count: usize) -> Vec<Vec<u8>>
```

Selects validators based on their effective stake values, considering both traditional and multi-asset stakes.

### Slashing

```rust
pub fn slash_multi_asset_stakes(
    &mut self,
    validator: &[u8],
    percentage: f64,
    reason: &str,
) -> Result<HashMap<String, u64>, &'static str>
```

Slashes a validator's multi-asset stakes by the specified percentage. Returns the slashed amounts for each asset.

### Oracle Integration

```rust
pub fn update_exchange_rates_from_oracle(
    &mut self,
    price_feeds: Vec<OraclePriceFeed>,
) -> Result<HashMap<String, f64>, &'static str>
```

Updates exchange rates using oracle price feeds. Includes safeguards against manipulation:
- Minimum number of confirmations required
- Maximum rate change percentage
- Minimum time between updates
- Median price calculation to filter outliers

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

## Future Improvements

1. **Dynamic Weights**: Adjust asset weights based on market conditions and risk profiles
2. **Liquid Staking Integration**: Integrate with liquid staking for multi-asset stakes
3. **Cross-Chain Asset Support**: Support for assets from other blockchains
4. **Advanced Reward Distribution**: More sophisticated reward distribution mechanisms
5. **Validator Specialization**: Allow validators to specialize in certain assets 