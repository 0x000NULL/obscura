use crate::crypto::{
    AuditConfig, AuditLevel, CryptoAudit, CryptoError, CryptoOperationType, 
    CryptoResult, OperationStatus, JubjubKeypair, audit_crypto_operation
};
use crate::crypto::memory_protection::{MemoryProtection, MemoryProtectionConfig, SecurityProfile};
use crate::crypto::side_channel_protection::{SideChannelProtection, SideChannelProtectionConfig};
use crate::crypto::jubjub::{self, JubjubPoint, JubjubScalar};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use serde_json::json;

/// Comprehensive example demonstrating integration of the audit system
/// with various cryptographic operations, creating a complete security 
/// solution that performs both operations and audit logging.
pub fn run_audit_integration_example() -> CryptoResult<()> {
    println!("Cryptographic Audit Integration Example");
    println!("--------------------------------------");
    
    // Step 1: Create and configure audit system
    println!("\n1. Initializing Cryptographic Audit System");
    let audit_config = create_audit_config()?;
    let audit = Arc::new(CryptoAudit::new(audit_config)?);
    println!("   - Audit system initialized with file logging");
    
    // Step 2: Configure protection systems with auditing
    println!("\n2. Setting up Protection Systems");
    let memory_protection = create_memory_protection(Arc::clone(&audit))?;
    let side_channel_protection = create_side_channel_protection(Arc::clone(&audit))?;
    println!("   - Memory protection configured with Medium security profile");
    println!("   - Side-channel protection configured with constant-time operations");
    
    // Step 3: Generate and manage keys with auditing
    println!("\n3. Key Generation and Management (with audit logging)");
    let keypair = generate_audited_keypair(&audit, &side_channel_protection)?;
    println!("   - Generated keypair with comprehensive audit trail");
    
    // Step 4: Secure memory operations with auditing
    println!("\n4. Secure Memory Operations (with audit logging)");
    let secure_keypair = store_keypair_securely(&audit, &memory_protection, &keypair)?;
    println!("   - Stored keypair in secure memory with audit trail");
    
    // Step 5: Encryption operations with auditing
    println!("\n5. Encryption Operations (with audit logging)");
    let message = b"This is a sensitive message that needs encryption";
    let (ciphertext, nonce) = encrypt_with_audit(&audit, message, &keypair)?;
    println!("   - Encrypted message with authenticated encryption");
    
    // Step 6: Decryption operations with auditing
    println!("\n6. Decryption Operations (with audit logging)");
    let decrypted = decrypt_with_audit(&audit, &ciphertext, &nonce, &keypair)?;
    println!("   - Decrypted message successfully: {}", String::from_utf8_lossy(&decrypted));
    
    // Step 7: Simulate security event detection
    println!("\n7. Security Event Detection and Logging");
    record_security_event(&audit)?;
    println!("   - Recorded critical security event");
    
    // Step 8: Generate audit report
    println!("\n8. Generating Audit Report");
    generate_audit_report(&audit)?;
    
    println!("\nAudit Integration Example Completed Successfully!");
    println!("Check the audit.log file for detailed audit records.");
    
    Ok(())
}

/// Creates a comprehensive audit configuration
fn create_audit_config() -> CryptoResult<AuditConfig> {
    let mut config = AuditConfig::default();
    config.log_file_path = Some(PathBuf::from("audit.log"));
    config.min_level = AuditLevel::Info;
    config.in_memory_limit = 1000;
    config.rotate_logs = true;
    config.max_log_size = 5 * 1024 * 1024; // 5 MB
    config.max_backup_count = 3;
    config.redact_sensitive_params = true;
    
    Ok(config)
}

/// Creates a memory protection system with audit integration
fn create_memory_protection(audit: Arc<CryptoAudit>) -> CryptoResult<Arc<MemoryProtection>> {
    // Record the operation in the audit log
    let tracker = audit.track_operation(
        CryptoOperationType::MemoryProtection,
        AuditLevel::Info,
        "audit_integration",
        "Initialize memory protection with Medium security profile"
    )
    .with_parameters(json!({
        "security_profile": "Medium",
        "guard_pages_enabled": true
    }));
    
    // Create the memory protection configuration
    let config = MemoryProtectionConfig::medium();
    
    // Create the memory protection system
    let side_channel = Some(Arc::new(SideChannelProtection::default()));
    let protection = Arc::new(MemoryProtection::new(config, side_channel));
    
    // Record successful completion
    tracker.complete_success()?;
    
    Ok(protection)
}

/// Creates a side-channel protection system with audit integration
fn create_side_channel_protection(audit: Arc<CryptoAudit>) -> CryptoResult<Arc<SideChannelProtection>> {
    // Record the operation in the audit log
    let tracker = audit.track_operation(
        CryptoOperationType::SideChannelProtection,
        AuditLevel::Info,
        "audit_integration",
        "Initialize side-channel protection with default configuration"
    )
    .with_parameters(json!({
        "constant_time_enabled": true,
        "blinding_enabled": true
    }));
    
    // Create the side-channel protection configuration
    let config = SideChannelProtectionConfig::default();
    
    // Create the side-channel protection system
    let protection = Arc::new(SideChannelProtection::new(config));
    
    // Record successful completion
    tracker.complete_success()?;
    
    Ok(protection)
}

/// Generates a keypair with comprehensive audit logging
fn generate_audited_keypair(
    audit: &CryptoAudit,
    side_channel: &SideChannelProtection
) -> CryptoResult<JubjubKeypair> {
    audit_crypto_operation(
        audit,
        CryptoOperationType::KeyGeneration,
        AuditLevel::Info,
        "audit_integration",
        "Generate JubJub keypair with side-channel protection",
        || {
            // Use side-channel protection for key generation
            let keypair = side_channel.protected_operation(|| {
                jubjub::generate_keypair()
            });
            
            Ok(keypair)
        }
    )
}

/// Stores a keypair in secure memory with audit logging
fn store_keypair_securely(
    audit: &CryptoAudit,
    memory_protection: &MemoryProtection,
    keypair: &JubjubKeypair
) -> CryptoResult<Arc<SecureMemory<JubjubKeypair>>> {
    audit_crypto_operation(
        audit,
        CryptoOperationType::MemoryProtection,
        AuditLevel::Info,
        "audit_integration",
        "Store keypair in secure memory",
        || {
            // Clone the keypair to store it
            let keypair_clone = keypair.clone();
            
            // Use secure memory allocation to protect the keypair
            let secure_mem = memory_protection.secure_alloc(keypair_clone)?;
            
            Ok(Arc::new(secure_mem))
        }
    )
}

/// Performs encryption with comprehensive audit logging
fn encrypt_with_audit(
    audit: &CryptoAudit,
    message: &[u8],
    keypair: &JubjubKeypair
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    // Create a more detailed tracker for the complex operation
    let tracker = audit.track_operation(
        CryptoOperationType::Encryption,
        AuditLevel::Info,
        "audit_integration",
        "Encrypt message with authenticated encryption"
    )
    .with_algorithm("ChaCha20-Poly1305")
    .with_parameters(json!({
        "message_length": message.len(),
        "public_key_type": "JubjubPoint"
    }));
    
    // Start timing the operation
    let start = Instant::now();
    
    // Generate a random key based on keypair
    // In a real implementation, we would derive this properly
    let mut rng = rand::thread_rng();
    
    // Generate a nonce for encryption
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    
    // For this example, we'll use chacha20poly1305 from the project dependencies
    let key_bytes = keypair.0.to_bytes();
    let key = chacha20poly1305::Key::from_slice(&key_bytes);
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(key);
    let nonce_slice = chacha20poly1305::Nonce::from_slice(&nonce);
    
    // Encrypt the message
    let ciphertext = cipher
        .encrypt(nonce_slice, message)
        .map_err(|_| CryptoError::EncryptionError("Encryption failed".to_string()))?;
    
    // Calculate duration
    let duration = start.elapsed().as_millis() as u64;
    
    // Complete the operation tracking
    tracker.with_duration(duration).complete_success()?;
    
    Ok((ciphertext, nonce.to_vec()))
}

/// Performs decryption with comprehensive audit logging
fn decrypt_with_audit(
    audit: &CryptoAudit,
    ciphertext: &[u8],
    nonce: &[u8],
    keypair: &JubjubKeypair
) -> CryptoResult<Vec<u8>> {
    audit_crypto_operation(
        audit,
        CryptoOperationType::Decryption,
        AuditLevel::Info,
        "audit_integration",
        "Decrypt message with authenticated encryption",
        || {
            // Create key from keypair
            let key_bytes = keypair.0.to_bytes();
            let key = chacha20poly1305::Key::from_slice(&key_bytes);
            let cipher = chacha20poly1305::ChaCha20Poly1305::new(key);
            
            // Check nonce length
            if nonce.len() != 12 {
                return Err(CryptoError::ValidationError("Invalid nonce length".to_string()));
            }
            
            let nonce_slice = chacha20poly1305::Nonce::from_slice(nonce);
            
            // Decrypt the message
            cipher
                .decrypt(nonce_slice, ciphertext)
                .map_err(|_| CryptoError::EncryptionError("Decryption failed (authentication failed)".to_string()))
        }
    )
}

/// Records a simulated security event in the audit log
fn record_security_event(audit: &CryptoAudit) -> CryptoResult<()> {
    // Create a critical level audit entry
    let entry = audit.track_operation(
        CryptoOperationType::General,
        AuditLevel::Critical,
        "audit_integration",
        "Detected potential key compromise attempt"
    )
    .with_parameters(json!({
        "detection_source": "memory_guard_page",
        "access_pattern": "unauthorized",
        "location": "sensitive_key_area"
    }))
    .with_caller_context("memory_protection::guard_page_handler");
    
    // Complete with failure status to indicate security event
    entry.complete_failure("Memory access violation detected in guarded key storage region")?;
    
    Ok(())
}

/// Generates a simple audit report from collected entries
fn generate_audit_report(audit: &CryptoAudit) -> CryptoResult<()> {
    let entries = audit.get_entries(None, None, None, None)?;
    
    println!("   - Found {} audit entries", entries.len());
    println!("   - Summary by operation type:");
    
    // Count operations by type
    let mut operation_counts = std::collections::HashMap::new();
    for entry in &entries {
        *operation_counts.entry(entry.operation_type).or_insert(0) += 1;
    }
    
    for (op_type, count) in operation_counts {
        println!("     * {}: {} operations", op_type, count);
    }
    
    // Count by status
    let mut status_counts = std::collections::HashMap::new();
    for entry in &entries {
        *status_counts.entry(entry.status).or_insert(0) += 1;
    }
    
    println!("   - Summary by status:");
    for (status, count) in status_counts {
        println!("     * {}: {} operations", status, count);
    }
    
    // Count by severity
    let critical_count = entries.iter().filter(|e| e.level == AuditLevel::Critical).count();
    let warning_count = entries.iter().filter(|e| e.level == AuditLevel::Warning).count();
    
    println!("   - Found {} critical events", critical_count);
    println!("   - Found {} warning events", warning_count);
    
    Ok(())
} 