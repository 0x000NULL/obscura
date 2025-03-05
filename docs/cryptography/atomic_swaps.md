# Cross-Curve Atomic Swaps

## Overview

The Obscura blockchain implements atomic swaps using both BLS12-381 and Jubjub curves to enable secure cross-chain transactions. This document describes the implementation details and usage of the cross-curve atomic swap functionality.

## Architecture

The atomic swap implementation uses the following components:

1. **CrossCurveSwap**: Core structure managing the atomic swap lifecycle
2. **DualCurveCommitment**: Handles commitments on both BLS12-381 and Jubjub curves
3. **SwapState**: Enum tracking the swap's current state
4. **Cryptographic Primitives**: BLS signatures, hash locks, and dual-curve commitments

## Swap Lifecycle

1. **Initialization**
   - Initiator creates a secret and generates its hash lock
   - Creates dual-curve commitments for the swap amount
   - Sets timeout and generates unique swap ID

2. **Participant Commitment**
   - Participant verifies the commitments
   - Signs the swap details
   - State changes to Committed

3. **Secret Revelation**
   - Initiator reveals the secret
   - Participant verifies the secret matches the hash lock
   - State changes to Revealed

4. **Completion**
   - Swap is completed after successful secret verification
   - Generates completion proof
   - State changes to Completed

5. **Refund (if needed)**
   - Available only after timeout
   - Returns funds to original parties
   - State changes to Refunded

## Security Features

### Timeouts
- Default timeout: 1 hour
- Configurable through `SWAP_TIMEOUT_SECONDS`
- Prevents indefinite fund locking

### Dual-Curve Commitments
- Uses both BLS12-381 and Jubjub curves
- Provides cross-chain compatibility
- Ensures commitment consistency

### Cryptographic Verification
- Hash lock verification
- BLS signature verification
- Dual-curve commitment verification

## Usage Example

```rust
// Initialize a swap
let secret = generate_random_secret();
let initiator_keypair = BlsKeypair::generate();
let swap = CrossCurveSwap::initialize(amount, &secret, &initiator_keypair)?;

// Participant commits
let participant_keypair = BlsKeypair::generate();
let signature = swap.participant_commit(&participant_keypair)?;

// Reveal secret
swap.reveal_secret(&secret, &signature)?;

// Complete swap
swap.complete_swap()?;

// Generate proof
let completion_proof = swap.generate_completion_proof()?;
```

## Error Handling

The implementation includes comprehensive error handling for:
- Invalid state transitions
- Timeout conditions
- Invalid secrets or signatures
- Commitment verification failures

## Testing

The implementation includes unit tests covering:
- Complete swap lifecycle
- Timeout handling
- Invalid secret attempts
- Commitment verification

## Integration Considerations

When integrating with other chains:
1. Ensure compatible timeout periods
2. Verify cross-chain commitment schemes
3. Implement appropriate signature verification
4. Handle network-specific transaction formats

## Future Enhancements

Planned improvements include:
1. Multi-party atomic swaps
2. Batch swap operations
3. Privacy-preserving swap protocols
4. Extended timeout mechanisms
5. Additional curve support 