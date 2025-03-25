# Module Integration for Profiling

The Obscura profiling system includes specialized integration modules for key components of the codebase. These integrations provide tailored profiling capabilities for specific subsystems, making it easier to profile and optimize these critical areas. This guide explains how to use these module-specific integrations and how to create your own.

## Available Module Integrations

The profiling system currently includes integrations for these key modules:

1. **Crypto Module**: Profiling cryptographic operations (`src/crypto/profile_integration.rs`)
2. **Consensus Module**: Profiling consensus operations (`src/consensus/profile_integration.rs`)

These integrations provide wrapper functions that automatically profile critical operations within each module, allowing for specialized analysis of these components.

## Using the Crypto Module Integration

### Overview

The crypto module integration provides profiling wrappers for cryptographic operations, including:

- BLS signature verification
- Scalar multiplication
- Hash operations
- Commitment schemes
- Key generation and management

### Basic Usage

To use the crypto profiling integration:

```rust
use obscura::crypto::profile_integration;

// Instead of directly calling crypto::verify_signature
// use the profiled version:
let is_valid = profile_integration::verify_signature(
    &public_key, 
    &message, 
    &signature
);

// The operation is automatically profiled under the "crypto.signatures" category
```

### Available Wrapper Functions

The crypto integration includes these key wrapper functions:

```rust
// BLS operations
pub fn verify_signature(pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool;
pub fn batch_verify_signatures(pks: &[PublicKey], msgs: &[&[u8]], sigs: &[Signature]) -> bool;
pub fn aggregate_signatures(signatures: &[Signature]) -> Result<Signature, CryptoError>;

// Scalar multiplication
pub fn scalar_multiply(point: &JubjubPoint, scalar: &JubjubScalar) -> JubjubPoint;
pub fn multi_scalar_multiply(points: &[JubjubPoint], scalars: &[JubjubScalar]) -> JubjubPoint;

// Hash operations
pub fn hash_to_scalar(data: &[u8]) -> JubjubScalar;
pub fn hash_to_point(data: &[u8]) -> JubjubPoint;

// Commitment operations
pub fn create_commitment(value: u64, blinding: &JubjubScalar) -> Commitment;
pub fn verify_commitment(comm: &Commitment, value: u64, blinding: &JubjubScalar) -> bool;

// Key operations
pub fn generate_keypair() -> (SecretKey, PublicKey);
pub fn derive_key(base_key: &SecretKey, path: &[u8]) -> SecretKey;
```

### Profiling Categories

The crypto integration uses these profiling categories:

- `crypto.bls`: BLS signature operations
- `crypto.jubjub`: Jubjub curve operations
- `crypto.hash`: Hashing operations
- `crypto.commitments`: Pedersen commitment operations
- `crypto.keys`: Key generation and management

### Custom Profiling Level Control

The crypto integration includes functions for operation-specific profiling level control:

```rust
use obscura::crypto::profile_integration;
use obscura::utils::ProfilingLevel;

// Set profiling level for a specific crypto category
profile_integration::set_category_profiling_level(
    "crypto.bls", 
    ProfilingLevel::Detailed
);

// Reset to global default
profile_integration::reset_category_profiling_level("crypto.bls");
```

## Using the Consensus Module Integration

### Overview

The consensus module integration provides profiling wrappers for consensus operations, including:

- Block validation
- Transaction processing
- State transitions
- Proof verification
- Consensus protocol messages

### Basic Usage

To use the consensus profiling integration:

```rust
use obscura::consensus::profile_integration;

// Instead of directly calling consensus functions
// use the profiled version:
let is_valid = profile_integration::validate_block(
    &block, 
    &state, 
    validation_options
);

// The operation is automatically profiled under the "consensus.validation" category
```

### Available Wrapper Functions

The consensus integration includes these key wrapper functions:

```rust
// Block operations
pub fn validate_block(block: &Block, state: &State, options: ValidationOptions) -> Result<(), ConsensusError>;
pub fn process_block(block: &Block, state: &mut State) -> Result<(), ConsensusError>;
pub fn validate_block_header(header: &BlockHeader, prev_header: &BlockHeader) -> Result<(), ConsensusError>;

// Transaction operations
pub fn validate_transaction(tx: &Transaction, state: &State) -> Result<(), ConsensusError>;
pub fn process_transaction(tx: &Transaction, state: &mut State) -> Result<(), ConsensusError>;
pub fn validate_tx_inputs(tx: &Transaction, state: &State) -> Result<(), ConsensusError>;

// State operations
pub fn apply_state_transition(state: &mut State, transition: &StateTransition) -> Result<(), ConsensusError>;
pub fn calculate_state_root(state: &State) -> Hash;
pub fn verify_state_proof(root: &Hash, key: &[u8], value: &[u8], proof: &Proof) -> bool;

// Consensus protocol
pub fn process_consensus_message(msg: &ConsensusMessage, state: &mut ConsensusState) -> Result<(), ConsensusError>;
pub fn generate_vote(block_hash: &Hash, vote_data: &VoteData) -> Vote;
pub fn validate_vote(vote: &Vote, signer: &PublicKey) -> bool;
```

### Profiling Categories

The consensus integration uses these profiling categories:

- `consensus.validation`: Block and transaction validation
- `consensus.processing`: Block and transaction processing
- `consensus.state`: State management and transitions
- `consensus.voting`: Consensus voting and message handling
- `consensus.proofs`: State and validity proof operations

### Time-Series Analysis

The consensus integration includes special support for time-series performance analysis:

```rust
use obscura::consensus::profile_integration;

// Start tracking block processing times
profile_integration::start_block_processing_tracking();

// Process several blocks...

// Generate a block processing time report
let report = profile_integration::generate_block_processing_report();
println!("{}", report);

// Export data for external analysis
profile_integration::export_block_processing_data("block_times.csv");
```

This functionality helps identify trends in block processing performance over time.

## Creating Your Own Module Integration

You can create custom integrations for other modules following these steps:

### Step 1: Create an Integration File

Create a new file in your module directory, e.g., `your_module/profile_integration.rs`:

```rust
//! Profiling integration for YourModule
//!
//! This module provides profiling wrappers for YourModule operations.

use crate::utils::{profile, profile_with_level, ProfilingLevel};

// Wrapper for a module function
pub fn your_function(param1: Type1, param2: Type2) -> ReturnType {
    // Create a profiling span
    let _span = profile("function_name", "your_module.category");
    
    // Call the actual implementation
    crate::your_module::your_function(param1, param2)
}

// Wrapper with custom profiling level
pub fn expensive_function(param: Type) -> ReturnType {
    // Only profile with Detailed level or higher
    let _span = profile_with_level(
        "expensive_function", 
        "your_module.expensive", 
        ProfilingLevel::Detailed
    );
    
    crate::your_module::expensive_function(param)
}
```

### Step 2: Add Module Exports

Update your module's `mod.rs` to include the integration:

```rust
pub mod your_feature;
pub mod another_feature;
pub mod profile_integration;  // Add this line

// Re-export if desired
pub use profile_integration::your_function;
```

### Step 3: Add Category Constants

For consistency, define category constants:

```rust
// In profile_integration.rs
/// Category for general operations
pub const CATEGORY_GENERAL: &str = "your_module.general";

/// Category for expensive operations
pub const CATEGORY_EXPENSIVE: &str = "your_module.expensive";

// Then use these in your wrappers
pub fn your_function(param: Type) -> ReturnType {
    let _span = profile("function_name", CATEGORY_GENERAL);
    // ...
}
```

### Step 4: Add Specialized Features

Consider adding module-specific profiling features:

```rust
/// Track operation counts for this module
pub fn start_operation_tracking() {
    // Implementation
}

/// Generate a specialized report for this module
pub fn generate_module_report() -> String {
    // Implementation
}
```

## Best Practices for Module Integration

1. **Consistent Naming**: Use a consistent naming pattern for wrapper functions
2. **Category Hierarchy**: Organize categories hierarchically (e.g., `module.subcategory`)
3. **Appropriate Detail Level**: Use appropriate profiling levels for different operations
4. **Performance Impact**: Be mindful of the overhead introduced by profiling
5. **Complete Coverage**: Create wrappers for all performance-critical operations
6. **Documentation**: Document categories and special features in your integration

## Example: Database Module Integration

Here's a complete example for a hypothetical database module:

```rust
//! Profiling integration for Database module
//!
//! This module provides profiling wrappers for database operations.

use crate::utils::{profile, profile_with_level, ProfilingLevel};
use crate::database::{Query, Record, Database, QueryOptions, DatabaseError};

/// Category for read operations
pub const CATEGORY_READ: &str = "database.read";

/// Category for write operations
pub const CATEGORY_WRITE: &str = "database.write";

/// Category for query operations
pub const CATEGORY_QUERY: &str = "database.query";

/// Category for maintenance operations
pub const CATEGORY_MAINTENANCE: &str = "database.maintenance";

/// Profiled wrapper for database get operation
pub fn get(db: &Database, key: &[u8]) -> Result<Option<Record>, DatabaseError> {
    let _span = profile("get", CATEGORY_READ);
    db.get(key)
}

/// Profiled wrapper for database put operation
pub fn put(db: &mut Database, key: &[u8], value: &Record) -> Result<(), DatabaseError> {
    let _span = profile("put", CATEGORY_WRITE);
    db.put(key, value)
}

/// Profiled wrapper for database delete operation
pub fn delete(db: &mut Database, key: &[u8]) -> Result<(), DatabaseError> {
    let _span = profile("delete", CATEGORY_WRITE);
    db.delete(key)
}

/// Profiled wrapper for database query operation
pub fn query(db: &Database, query: &Query, options: &QueryOptions) -> Result<Vec<Record>, DatabaseError> {
    // Queries can be expensive, so use detailed level
    let _span = profile_with_level("query", CATEGORY_QUERY, ProfilingLevel::Detailed);
    db.query(query, options)
}

/// Profiled wrapper for database compact operation
pub fn compact(db: &mut Database) -> Result<(), DatabaseError> {
    // Maintenance operations are typically rare but expensive
    let _span = profile("compact", CATEGORY_MAINTENANCE);
    db.compact()
}

/// Start tracking query statistics
pub fn start_query_tracking() {
    // Implementation
}

/// Generate a query performance report
pub fn generate_query_report() -> String {
    // Implementation
}
```

## Next Steps

- Learn about [visualization tools](profiler_visualization.md) to better analyze profiling data
- Explore [benchmarking capabilities](critical_path_benchmarking.md) for measuring performance
- Review the [profiler usage guide](profiling_guide.md) for general profiling techniques 