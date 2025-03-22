# Error Handling Guidelines

This document outlines the standardized error handling approach for the Obscura project. Following these guidelines ensures consistent error handling throughout the codebase.

## Core Error Types

### 1. `ObscuraError`

The root error type for the entire application, defined in `src/errors.rs`. This error type represents high-level errors across all subsystems.

### 2. `CryptoError`

A specialized error type for the crypto module, defined in `src/crypto/errors.rs`. This error type provides detailed error categorization for cryptographic operations.

## Error Handling Principles

1. **Use typed errors**: Always use the appropriate error type (`CryptoError` for crypto operations) rather than generic strings or static error messages.

2. **Provide context**: Include sufficient details in error messages to help diagnose issues.

3. **Propagate errors appropriately**: Use `?` operator with proper conversion between error types.

4. **Avoid panics**: Use proper error handling instead of `unwrap()`, `expect()`, or `panic!()` in production code.

5. **Use error conversion**: Implement `From` traits for converting between error types.

## Using `CryptoError`

### Creating Errors

```rust
// Creating a validation error
return Err(CryptoError::ValidationError("Amount must be greater than 0".to_string()));

// Creating an encryption error
return Err(CryptoError::EncryptionError("Failed to decrypt data".to_string()));

// Creating a key error
return Err(CryptoError::KeyError("Invalid key format".to_string()));
```

### Helper Methods

```rust
// Using helper methods
return Err(CryptoError::to_validation_error("Invalid parameter"));
return Err(CryptoError::to_key_error("Key generation failed"));
```

### Using `CryptoResult`

```rust
// Define a function that returns a CryptoResult
pub fn encrypt_data(data: &[u8], key: &Key) -> CryptoResult<Vec<u8>> {
    // Implementation...
}

// Use the function with the ? operator
fn process_data(data: &[u8], key: &Key) -> CryptoResult<()> {
    let encrypted = encrypt_data(data, key)?;
    // Further processing...
    Ok(())
}
```

## Error Conversion Flow

1. Low-level errors (e.g., `io::Error`) → `CryptoError` → `ObscuraError`
2. Custom module errors (e.g., `VerificationError`) → `CryptoError` → `ObscuraError`

## Migration Guidelines

When migrating existing error handling to the standardized approach:

1. Replace `Result<T, &'static str>` or `Result<T, String>` with `CryptoResult<T>`
2. Convert string error messages to appropriate `CryptoError` variants
3. Implement `From` traits for any custom error types
4. Update error propagation using the `?` operator

## Error Logging

When reporting errors:

1. Use the appropriate log level:
   - `error!` - For errors that affect system operation
   - `warn!` - For issues that might need attention but don't prevent operation
   - `info!` - For normal informational events
   - `debug!` - For detailed diagnostic information

2. Include relevant context but avoid exposing sensitive information

Example:
```rust
match decrypt_sensitive_data(encrypted) {
    Ok(data) => process_data(data),
    Err(err) => {
        error!("Failed to decrypt data: {}", err);
        // Don't log the encrypted data itself
        return Err(err);
    }
}
```

## Testing Error Conditions

Always include tests for error conditions:

```rust
#[test]
fn test_validate_input_errors() {
    // Test validation errors
    match validate_input(invalid_data) {
        Err(CryptoError::ValidationError(_)) => (), // Expected
        other => panic!("Expected ValidationError, got {:?}", other),
    }
}
``` 