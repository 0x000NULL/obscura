# Keypair Encryption Implementation

## Overview

This document details the implementation of secure, authenticated encryption for cryptographic keypairs in the Obscura project. This implementation replaces the previous XOR-based encryption method with a more secure approach that follows cryptographic best practices.

## Security Features

The following security features have been implemented:

1. **Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations
2. **Authenticated Encryption**: ChaCha20-Poly1305 for confidentiality and integrity
3. **Salt**: Unique random 16-byte salt generated for each encryption operation
4. **Nonce**: Unique random 12-byte nonce generated for each encryption operation

## Implementation Details

### Encryption Process

1. The keypair is first serialized into a binary format (64 bytes total)
2. A random 16-byte salt is generated
3. A random 12-byte nonce is generated for the ChaCha20Poly1305 cipher
4. The encryption key is derived using PBKDF2 with the provided password and salt
5. The serialized keypair is encrypted using ChaCha20Poly1305 with the derived key and nonce
6. The salt, nonce, and encrypted data are concatenated to form the final result

### Data Format

The encrypted data has the following format:

```
+----------------+----------------+--------------------+
| Salt (16 bytes)| Nonce (12 bytes)| Ciphertext + Tag  |
+----------------+----------------+--------------------+
```

### Decryption Process

1. The salt and nonce are extracted from the encrypted data
2. The encryption key is derived using PBKDF2 with the provided password and extracted salt
3. The ciphertext is decrypted using ChaCha20Poly1305 with the derived key and extracted nonce
4. The decrypted data is deserialized back into a keypair

### Security Considerations

1. **Authentication**: The Poly1305 MAC ensures the integrity and authenticity of the encrypted keypair. Any tampering with the ciphertext will cause the decryption to fail.

2. **Salt**: Each encryption operation uses a unique random salt, preventing precomputation attacks like rainbow tables.

3. **Nonce**: A unique nonce for each encryption ensures that the same plaintext will not produce the same ciphertext even with the same password.

4. **Key Derivation**: PBKDF2 with 100,000 iterations increases the computational cost of brute-force attacks against the password.

## Usage Example

```rust
// Generate a keypair
let keypair = generate_keypair();
let keypair_tuple = (keypair.secret, keypair.public);

// Encrypt with a password
let password = "secure_password";
let encrypted = encrypt_keypair(&keypair_tuple, password);

// Later, decrypt with the same password
let decrypted = decrypt_keypair(&encrypted, password).unwrap();

// Verify decryption was successful
assert_eq!(keypair.secret.to_bytes(), decrypted.0.to_bytes());
assert_eq!(keypair.public.to_bytes(), decrypted.1.to_bytes());
```

## Future Enhancements

While the current implementation significantly improves security over the previous XOR-based approach, future enhancements could include:

1. Migration to Argon2id for key derivation for increased resistance to specialized hardware attacks
2. Configurable parameters for iteration count based on security requirements
3. Support for key rotation and version information in the encrypted format
4. Hardware-backed key storage integration where available 