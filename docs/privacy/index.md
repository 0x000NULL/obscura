# Privacy Features

This section provides comprehensive documentation on Obscura's privacy features, which span multiple layers of the protocol stack.

## Overview

Obscura implements a comprehensive set of privacy features at the network, transaction, and consensus levels. These features work together to provide robust privacy protections for users while maintaining the security and integrity of the blockchain.

## Network Privacy

- [Client Fingerprinting Countermeasures](../networking/fingerprinting_protection.md): Prevents identification based on network behavior patterns
- [Protocol Morphing](../networking/protocol_morphing.md): Disguises network traffic as common protocols
- [I2P Network Support](../networking/i2p_proxy.md): Routes traffic through the I2P anonymity network
- [DNS-over-HTTPS for Seed Discovery](../networking/dns_over_https.md): Prevents DNS leakage and monitoring
- [Traffic Pattern Obfuscation](../networking/traffic_pattern_obfuscation.md): Prevents analysis based on traffic patterns
- [Dandelion Protocol](dandelion_protocol.md): Privacy-preserving transaction propagation

## Transaction Privacy

- [Stealth Addressing](../cryptography/stealth_addressing.md): One-time addresses for enhanced transaction privacy
- [Confidential Transactions](../cryptography/confidential_transactions.md): Hides transaction amounts
- [Zero-Knowledge Proofs](../cryptography/zero_knowledge_proofs.md): Proves transaction validity without revealing details
- [Fee Obfuscation](../cryptography/fee_obfuscation.md): Prevents transaction linking based on fees

## Cryptographic Foundations

- [BLS12-381 and Jubjub Curves](../cryptography/curves.md): Advanced cryptographic curves
- [Bulletproofs](../cryptography/bulletproofs.md): Compact range proofs without trusted setup
- [Pedersen Commitments](../cryptography/pedersen_commitments.md): Homomorphic commitments for confidential values

## Privacy Design Documents

- [Peer Reputation Privacy Design](../peer_reputation_privacy_design.md): Design of privacy-preserving peer reputation system
- [Peer Reputation Privacy Specification](../peer_reputation_privacy_spec.md): Technical specification of peer reputation privacy

## Comprehensive Privacy Documentation

For a comprehensive overview of all privacy features, see the [Privacy Features](../privacy_features.md) document.

## Privacy Best Practices

- [Node Operation Security](../security/node_operation.md): Best practices for operating nodes securely
- [User Privacy Best Practices](../security/user_privacy.md): Recommendations for users to maximize privacy
- [Privacy-Enhancing Configuration](../security/privacy_config.md): Configuration options for enhanced privacy 