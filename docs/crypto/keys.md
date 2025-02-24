# Key Management Documentation

## Overview
Obscura uses multiple key types for different purposes within the system.

## Key Types

### Stake Keys
- Ed25519 key pairs
- Used for stake validation
- Generates stake proofs
- Signs stake transactions

### Transaction Keys
- Future: Stealth address keys
- Future: View keys
- Future: zk-SNARK proving keys
- Future: zk-SNARK verification keys

## Key Generation

### Stake Key Generation
1. Random entropy collection
2. Key derivation
3. Public key extraction
4. Key storage

### Security Measures
- Secure entropy sources
- Memory protection
- Key deletion
- Backup procedures 