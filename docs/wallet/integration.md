# Wallet Integration

## Overview

The Wallet Integration module bridges the wallet functionality with the rest of the Obscura blockchain components, providing thread-safe access and proper synchronization between components. This document covers the architecture, design, and implementation details of this integration.

## Architecture

The wallet integration architecture connects the wallet with several other components:

```
┌───────────────┐      ┌───────────────┐
│     Node      │◄────►│    Mempool    │
└───────┬───────┘      └───────┬───────┘
        │                      │
        │      ┌───────────────┼───────┐
        └──────►  WalletIntegration    │
               │                       │
┌───────────────┐    │                │
│   Blockchain  │◄───┘                │
└───────┬───────┘    │                │
        │            │                │
        └────────────►    Wallet      │
                     │                │
                     └────────────────┘
```

### Components

#### WalletIntegration
The central component that manages access to the wallet and facilitates communication with other blockchain components.

```rust
pub struct WalletIntegration {
    wallet: Wallet,
    node: Arc<Mutex<Node>>,
    mempool: Arc<Mutex<Mempool>>,
    utxo_set: Arc<Mutex<UTXOSet>>,
}
```

#### Thread-Safe Access
All component interactions are managed through thread-safe mechanisms:
- `Arc<Mutex<T>>` for shared access with exclusive locking
- Proper error handling for lock acquisition failures
- Short lock durations to prevent deadlocks

## Functionality

### Transaction Submission Flow

1. The wallet creates a transaction
2. The integration layer submits it to the wallet's internal state
3. The transaction is added to the mempool
4. The transaction is sent to the node for network propagation

```rust
pub fn send_funds(&mut self, recipient: &JubjubPoint, amount: u64) -> Result<[u8; 32], String> {
    // Create the transaction
    let tx = match self.wallet.create_transaction(recipient, amount) {
        Some(tx) => tx,
        None => return Err("Failed to create transaction".to_string()),
    };
    
    // Hash for return value and logging
    let tx_hash = tx.hash();
    
    // Submit to network
    self.submit_transaction(tx)?;
    
    // Return transaction hash
    Ok(tx_hash)
}
```

### Stealth Transaction Scanning

The integration periodically scans the mempool for transactions that may belong to the wallet:

```rust
pub fn scan_mempool_for_stealth_transactions(&mut self) -> Result<usize, String> {
    // Get transactions from mempool
    let transactions = {
        let mempool_lock = match self.mempool.lock() {
            Ok(lock) => lock,
            Err(_) => return Err("Failed to acquire mempool lock".to_string()),
        };
        
        mempool_lock.get_transactions()
    };
    
    // Scan each transaction
    let mut found = 0;
    for tx in &transactions {
        if self.wallet.scan_for_stealth_transactions(tx) {
            found += 1;
        }
    }
    
    Ok(found)
}
```

### Block Processing

When new blocks are received, the integration ensures they are properly processed by the wallet:

```rust
pub fn process_blocks(&mut self, blocks: &[Block]) -> Result<usize, String> {
    // Process each block in the wallet
    let utxo_set = match self.utxo_set.lock() {
        Ok(lock) => lock,
        Err(_) => return Err("Failed to acquire UTXO lock".to_string()),
    };
    
    let mut processed = 0;
    for block in blocks {
        self.wallet.process_block(block, &utxo_set);
        processed += 1;
    }
    
    Ok(processed)
}
```

### Background Services

The wallet integration provides background services for:

1. **Transaction Scanning**: Periodically scans the mempool for stealth transactions
2. **Activity Reporting**: Generates regular wallet activity reports
3. **Maintenance**: Performs wallet maintenance tasks at scheduled intervals
4. **Backups**: Creates periodic backups of wallet data

These services run in separate threads and interact with the main application loop:

```rust
fn start_wallet_services(wallet_integration: Arc<Mutex<WalletIntegration>>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        loop {
            // Periodic operations with proper error handling
            thread::sleep(Duration::from_secs(30));
            
            // Example: Scanning for transactions
            if let Ok(mut integration) = wallet_integration.lock() {
                if let Err(e) = integration.scan_mempool_for_stealth_transactions() {
                    error!("Error scanning mempool: {}", e);
                }
            }
            
            // Other periodic operations...
        }
    })
}
```

## Error Handling

The integration layer implements comprehensive error handling:

1. **Detailed Error Messages**: All errors include meaningful descriptions
2. **Propagation Strategy**: Errors are properly propagated to the caller
3. **Resource Management**: Resources are properly released even on error paths
4. **Fallback Mechanisms**: Critical operations have fallback strategies

Example of error handling:

```rust
pub fn submit_transaction(&mut self, tx: Transaction) -> Result<(), String> {
    // First submit to the wallet
    self.wallet.submit_transaction(&tx);
    
    // Add to mempool with error handling
    {
        let mut mempool_lock = match self.mempool.lock() {
            Ok(lock) => lock,
            Err(_) => return Err("Failed to acquire mempool lock".to_string()),
        };
        
        if !mempool_lock.add_transaction(tx.clone()) {
            return Err("Transaction rejected by mempool".to_string());
        }
    }
    
    // Add to node with error handling
    {
        let mut node_lock = match self.node.lock() {
            Ok(lock) => lock,
            Err(_) => return Err("Failed to acquire node lock".to_string()),
        };
        
        node_lock.add_transaction(tx);
    }
    
    Ok(())
}
```

## Security Considerations

The wallet integration addresses several security concerns:

1. **Thread Safety**: Proper synchronization prevents race conditions
2. **Error Handling**: Comprehensive error handling prevents state corruption
3. **Resource Management**: Resources are properly released to prevent leaks
4. **Input Validation**: All inputs are validated before processing
5. **State Consistency**: Transactions are validated for consistency

## Performance Optimization

The integration is optimized for performance:

1. **Minimal Locking**: Lock durations are kept as short as possible
2. **Efficient Resource Usage**: Resources are acquired only when needed
3. **Batched Operations**: Operations are batched when possible
4. **Background Processing**: Heavy operations run in background threads

## Integration Points

### 1. Node Integration

Connects wallet functionality to network operations:
- Transaction submission to the network
- Block reception and processing
- Network state monitoring
- Peer connections management

### 2. Mempool Integration

Provides transaction management:
- Transaction submission to mempool
- Stealth transaction scanning
- Transaction verification
- Fee estimation and management

### 3. Blockchain Integration

Manages blockchain state:
- Block processing
- UTXO set validation
- Chain reorganization handling
- Transaction confirmation tracking

### 4. UTXO Integration

Handles unspent transaction outputs:
- UTXO consistency validation
- Balance calculation
- Transaction input selection
- Spending verification

## API Reference

The wallet integration provides a comprehensive API for wallet operations:

| Method | Description |
|--------|-------------|
| `send_funds` | Sends funds to a recipient |
| `send_funds_with_fee` | Sends funds with a custom fee |
| `create_stake` | Creates a new stake |
| `unstake` | Unstakes funds |
| `submit_transaction` | Submits a transaction to the network |
| `process_blocks` | Processes blocks and updates wallet state |
| `scan_mempool_for_stealth_transactions` | Scans mempool for stealth transactions |
| `create_backup` | Creates a wallet backup |
| `get_balance` | Gets available balance |
| `get_pending_balance` | Gets pending balance |
| `generate_view_key` | Generates a view key |
| `revoke_view_key` | Revokes a view key |
| `generate_activity_report` | Generates a wallet activity report |

## Usage Examples

### Basic Transaction Flow

```rust
// Create and submit a transaction
let tx_hash = wallet_integration.send_funds(&recipient, 100)?;
println!("Transaction submitted with hash: {:?}", tx_hash);

// Check balance after transaction
let balance = wallet_integration.get_balance();
println!("Available balance: {}", balance);
```

### Stealth Transaction Scanning

```rust
// Scan mempool for stealth transactions
let found = wallet_integration.scan_mempool_for_stealth_transactions()?;
if found > 0 {
    println!("Found {} stealth transactions", found);
}

// Check for pending balance
let pending = wallet_integration.get_pending_balance();
println!("Pending balance: {}", pending);
```

### Background Processing

```rust
// Start wallet services
let wallet_handle = start_wallet_services(Arc::clone(&wallet_integration_arc));

// In main loop
run_main_loop(mempool, utxo_set, node_arc, wallet_integration_arc);

// Clean shutdown
wallet_handle.join().unwrap();
```

## Best Practices

1. **Lock Management**: 
   - Keep lock durations short
   - Always handle lock acquisition failures
   - Never nest locks to prevent deadlocks

2. **Error Handling**:
   - Provide detailed error messages
   - Properly propagate errors to callers
   - Ensure resources are released on error paths

3. **Resource Management**:
   - Properly initialize all resources
   - Release resources in the reverse order of acquisition
   - Use RAII (Resource Acquisition Is Initialization) patterns

4. **Testing**:
   - Test with multiple threads to ensure thread safety
   - Test error conditions and recovery mechanisms
   - Test resource exhaustion scenarios 