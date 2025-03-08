# Wallet Interface Documentation

## Overview
Wallet functionality and integration points for the Obscura network.

## Features

### Basic Operations
- Key management
- Balance tracking
- Transaction creation
- History viewing
- Stealth transaction scanning

### Staking Operations
- Stake creation
- Reward tracking
- Stake withdrawal
- Compound settings

### Privacy Features
- View key management
- Stealth addresses
- Transaction privacy
- Secure backup/restore

## Implementation

### Wallet Types
- CLI wallet
- Integrated wallet service
- Thread-safe wallet access
- Background processing

### Integration Points
- **Node Integration**: Connects wallet to the network layer
- **Mempool Integration**: Scans mempool for stealth transactions
- **Blockchain Integration**: Processes blocks and updates wallet state
- **UTXO Integration**: Manages UTXO set and consistency validation

### Security Features
- Encrypted storage
- Backup functionality
- Recovery phrases
- Multi-signature support
- Thread-safe operations

## Interfaces

### WalletIntegration API
```rust
// Primary integration interface
struct WalletIntegration {
    // Core wallet functionality
    fn wallet(&self) -> &Wallet;
    fn wallet_mut(&mut self) -> &mut Wallet;
    
    // Transaction operations
    fn send_funds(&mut self, recipient: &JubjubPoint, amount: u64) -> Result<[u8; 32], String>;
    fn send_funds_with_fee(&mut self, recipient: &JubjubPoint, amount: u64, fee_per_kb: u64) -> Result<[u8; 32], String>;
    fn submit_transaction(&mut self, tx: Transaction) -> Result<(), String>;
    
    // Staking operations
    fn create_stake(&mut self, amount: u64) -> Result<[u8; 32], String>;
    fn unstake(&mut self, stake_id: &[u8; 32], amount: u64) -> Result<[u8; 32], String>;
    
    // Blockchain integration
    fn process_blocks(&mut self, blocks: &[Block]) -> Result<usize, String>;
    fn scan_mempool_for_stealth_transactions(&mut self) -> Result<usize, String>;
    
    // Wallet management
    fn create_backup(&self) -> Result<String, String>;
    fn get_balance(&self) -> u64;
    fn get_pending_balance(&self) -> u64;
    
    // View key operations
    fn generate_view_key(&mut self) -> Result<Vec<u8>, String>;
    fn revoke_view_key(&mut self, view_key_pubkey: &[u8]) -> Result<(), String>;
    
    // Reporting
    fn generate_activity_report(&self) -> String;
}
```

### Background Services
- Periodic transaction scanning
- Automatic block processing
- Regular activity reporting
- Scheduled wallet maintenance

### Thread Safety
All wallet integration operations are designed for thread-safe access, using:
- Proper mutex locking
- Error handling for lock acquisition failures
- Minimal lock durations to prevent deadlocks
- Clean API for cross-component interaction 