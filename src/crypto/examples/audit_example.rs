use crate::crypto::{
    audit_crypto_operation, AuditConfig, AuditLevel, CryptoAudit, 
    CryptoError, CryptoOperationType, CryptoResult, 
    JubjubKeypair, OperationStatus
};
use std::path::PathBuf;
use std::sync::Arc;

/// This example demonstrates how to use the cryptographic auditing system.
pub fn run_audit_example() -> CryptoResult<()> {
    // Create a basic audit configuration with file logging enabled
    let mut config = AuditConfig::default();
    config.log_file_path = Some(PathBuf::from("crypto_audit.log"));
    
    // Create the audit system
    let audit = Arc::new(CryptoAudit::new(config)?);
    
    println!("Cryptographic Auditing Example");
    println!("------------------------------");
    
    // Example 1: Simple key generation with auditing
    println!("\n1. Generating a keypair with auditing:");
    let keypair = generate_keypair_with_audit(&audit)?;
    println!("    Key generated successfully!");
    
    // Example 2: Using operation tracker directly
    println!("\n2. Using an operation tracker for manual control:");
    let tracker = audit.track_operation(
        CryptoOperationType::KeyManagement,
        AuditLevel::Info,
        "examples::audit_example",
        "Manual key verification operation"
    );
    
    // Simulate a verification operation
    println!("    Verifying keypair...");
    let is_valid = verify_keypair(&keypair);
    
    if is_valid {
        println!("    Keypair verification successful!");
        tracker.complete_success()?;
    } else {
        println!("    Keypair verification failed!");
        tracker.complete_failure("Invalid keypair structure")?;
    }
    
    // Example 3: Handling errors with auditing
    println!("\n3. Demonstrating error handling with auditing:");
    let result = audit_crypto_operation(
        &audit,
        CryptoOperationType::Encryption,
        AuditLevel::Warning,
        "examples::audit_example",
        "Intentionally failing encryption operation",
        || {
            println!("    Attempting to encrypt with invalid parameters...");
            Err(CryptoError::ValidationError("Invalid encryption parameters".to_string()))
        }
    );
    
    match result {
        Ok(_) => println!("    Encryption succeeded (not expected)"),
        Err(e) => println!("    Encryption failed as expected: {}", e),
    }
    
    // Example 4: Retrieving audit records
    println!("\n4. Retrieving recent audit records:");
    let entries = audit.get_entries(None, None, None, Some(10))?;
    
    println!("    Found {} audit entries:", entries.len());
    for (i, entry) in entries.iter().enumerate() {
        println!("    {}. [{}] {} - {}", 
            i + 1,
            entry.operation_type,
            entry.status,
            entry.description
        );
    }
    
    println!("\nAll operations completed successfully!");
    Ok(())
}

/// Example function that generates a keypair with auditing
fn generate_keypair_with_audit(audit: &CryptoAudit) -> CryptoResult<JubjubKeypair> {
    audit_crypto_operation(
        audit,
        CryptoOperationType::KeyGeneration,
        AuditLevel::Info,
        "examples::audit_example",
        "Generate JubJub keypair",
        || {
            // Simulate work
            std::thread::sleep(std::time::Duration::from_millis(50));
            
            // Use the actual key generation function
            Ok(crate::crypto::jubjub_generate_keypair())
        }
    )
}

/// Example function to verify a keypair
fn verify_keypair(_keypair: &JubjubKeypair) -> bool {
    // In a real implementation, this would verify the keypair structure
    // For this example, we just return true
    true
} 