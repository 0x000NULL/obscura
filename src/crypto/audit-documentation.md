# Cryptographic Auditing and Logging System

This document describes the cryptographic auditing and logging system implemented in the Obscura cryptocurrency codebase.

## Overview

The cryptographic auditing system provides a comprehensive framework for logging, tracking, and analyzing security-relevant events throughout the cryptographic operations in the Obscura system. It supports the following key features:

- Detailed logging of all cryptographic operations
- Fine-grained audit levels (Info, Warning, Critical, Fatal)
- Sanitization of sensitive parameters to avoid exposure
- File-based and in-memory audit storage
- Log rotation and management
- Operation tracking with timing metrics
- Classification of operations by type
- Search and filtering capabilities

## Components

### Core Types

- `AuditEntry`: Represents a single auditable event with metadata
- `CryptoAudit`: Main implementation of the audit system
- `OperationTracker`: Helper for tracking an operation from start to finish
- `AuditConfig`: Configuration for the audit system

### Enumerations

- `AuditLevel`: Severity levels for audit events (Info, Warning, Critical, Fatal)
- `CryptoOperationType`: Types of cryptographic operations that can be audited
- `OperationStatus`: Status of operations (Started, Success, Failed, Denied, Expired)

## Usage Patterns

### Basic Auditing

To log a simple audit event:

```rust
let audit = CryptoAudit::new(AuditConfig::default())?;
let entry = AuditEntry::new(
    CryptoOperationType::KeyGeneration,
    OperationStatus::Success,
    AuditLevel::Info,
    "module_name",
    "Generated a new key",
);
audit.record(entry)?;
```

### Operation Tracking

To track an operation from start to finish:

```rust
let tracker = audit.track_operation(
    CryptoOperationType::Encryption,
    AuditLevel::Info,
    "module_name",
    "Encrypting sensitive data"
)
.with_algorithm("AES-256-GCM");

// Perform operation...

// On success:
tracker.complete_success()?;

// Or on failure:
tracker.complete_failure("Encryption failed: invalid key")?;
```

### Wrapper Function

To automatically audit any operation:

```rust
let result = audit_crypto_operation(
    &audit,
    CryptoOperationType::Signing,
    AuditLevel::Info,
    "module_name",
    "Signing transaction",
    || {
        // Actual operation implementation
        sign_transaction(transaction, key)
    }
);
```

## Integration with Security Systems

The audit system is designed to integrate with other security systems:

1. **Memory Protection**: Logs memory protection events like guard page triggers
2. **Side-Channel Protection**: Tracks operations that use constant-time algorithms 
3. **Key Management**: Audits all key lifecycle events
4. **Cryptographic Operations**: Records parameters and timings of operations

## Configuration Options

The audit system can be configured with various options:

```rust
let config = AuditConfig {
    enabled: true,
    min_level: AuditLevel::Info,
    log_output: true,
    in_memory_limit: 1000,
    log_file_path: Some(PathBuf::from("audit.log")),
    rotate_logs: true,
    max_log_size: 10 * 1024 * 1024,  // 10 MB
    max_backup_count: 5,
    redact_sensitive_params: true,
    redacted_fields: vec!["private_key".to_string(), "password".to_string()],
};
```

## Security Considerations

The audit system is designed with security in mind:

1. **Sensitive Data Protection**: Parameters are automatically redacted
2. **Log File Security**: Consider securing the log files with appropriate permissions
3. **Performance Impact**: The audit system is designed for minimal performance impact
4. **Memory Usage**: In-memory limits prevent excessive memory consumption
5. **Thread Safety**: The system is thread-safe for use in concurrent environments

## Examples

See the following examples for practical usage:

- `src/crypto/examples/audit_example.rs`: Basic usage
- `src/crypto/examples/audit_integration.rs`: Integration with other systems

## Testing

Comprehensive tests for the audit system are available in:

- `src/crypto/audit_tests.rs`

The tests demonstrate all the major features and ensure proper functionality.

## Future Improvements

Potential enhancements for the audit system:

1. **Remote Logging**: Support for sending audit events to remote servers
2. **Structured Outputs**: Additional output formats (JSON, CSV)
3. **Aggregation and Analysis**: Built-in tools for analyzing audit data
4. **Real-time Alerting**: Trigger alerts on critical security events
5. **Compliance Reporting**: Generate compliance reports from audit data 