use obscura_core::crypto::{
    jubjub::{JubjubPoint, JubjubScalar},
    view_key::ViewKey,
};
use obscura_core::crypto::{
    ViewKeyPermissions, ViewKeyManager, ViewKeyLevel, ViewKeyContext
};
use obscura_core::blockchain::{Transaction, TransactionOutput};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use obscura_core::crypto::{
    jubjub::{JubjubKeypair, JubjubSignature},
};
use rand::{thread_rng, Rng};
use colored::*;

/// DEVELOPER GUIDE: USING THE ADVANCED VIEW KEY SYSTEM
/// 
/// This demo showcases how to use the comprehensive view key system
/// in the Obscura blockchain. View keys are a powerful privacy feature
/// that allow selective disclosure of transaction data to third parties.
/// 
/// INTEGRATING WITH YOUR APPLICATION:
/// 
/// 1. Import the necessary types:
///    ```
///    use obscura_core::crypto::{
///        JubjubKeypair, ViewKey, ViewKeyPermissions, ViewKeyManager, 
///        ViewKeyLevel, ViewKeyContext, MultiSigViewKey
///    };
///    ```
/// 
/// 2. Create a view key manager in your application:
///    ```
///    let mut manager = ViewKeyManager::new();
///    ```
/// 
/// 3. Generate and manage view keys:
///    ```
///    // Create a basic view key
///    let view_key = manager.generate_view_key(&wallet_keypair, ViewKeyPermissions::default());
///    
///    // Create a hierarchical structure
///    let root_key = manager.generate_hierarchical_key(
///        &wallet_keypair, permissions, ViewKeyLevel::Root
///    );
///    
///    // Derive child keys
///    let child_key = manager.derive_child_key(
///        root_key.public_key(), index, permissions
///    );
///    ```
/// 
/// 4. Scan transactions with view keys:
///    ```
///    // Scan transactions with context filtering
///    let results = manager.scan_transactions(
///        &transactions, current_time, context
///    );
///    ```
/// 
/// 5. Apply field visibility to control what data is revealed:
///    ```
///    let filtered_tx = view_key.apply_field_visibility(&transaction);
///    ```
/// 
/// 6. Create multi-signature view keys for enhanced security:
///    ```
///    let multi_sig_key = manager.create_multi_sig_key(
///        &wallet_keypair, permissions, signers, threshold, expiry
///    );
///    ```
/// 
/// 7. Handle revocation:
///    ```
///    manager.revoke_view_key(view_key.public_key());
///    ```
/// 
/// 8. Monitor view key usage with audit logs:
///    ```
///    let log = manager.get_audit_log();
///    ```
/// 
/// BEST PRACTICES:
/// 
/// - Use time-bound keys for temporary access
/// - Implement multi-signature authorization for sensitive data
/// - Always check context compatibility when using view keys
/// - Revoke keys when they are no longer needed
/// - Regularly audit view key usage
/// - Use the most restrictive permissions possible
/// - Implement proper UI to clearly show what information is being shared

fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// Create a dummy transaction for testing
fn create_test_transaction() -> Transaction {
    let mut tx = Transaction::default();
    
    // Add a dummy output
    tx.outputs.push(TransactionOutput {
        value: 1000,
        public_key_script: vec![1, 2, 3, 4, 5], // Dummy public key script
        range_proof: None,
        commitment: None,
    });
    
    tx
}

fn main() {
    println!("======================================");
    println!("Obscura Advanced View Key System Demo");
    println!("======================================");
    
    println!("\n[1] Basic View Key Creation\n");
    
    // Create wallet keypair
    let wallet_keypair = obscura_core::crypto::jubjub::generate_keypair();
    println!("Generated wallet keypair");
    
    // Create view key manager
    let mut manager = ViewKeyManager::new();
    println!("Created view key manager");
    
    // Create basic view key
    let basic_key = manager.generate_view_key(&wallet_keypair, ViewKeyPermissions::default());
    println!("Generated basic view key: {:?}", basic_key.public_key());
    
    println!("\n[2] Hierarchical View Key Structure\n");
    
    // Create root key
    let mut root_permissions = ViewKeyPermissions::default();
    root_permissions.can_derive_keys = true;
    root_permissions.view_amounts = true;
    
    let root_key = manager.generate_hierarchical_key(
        &wallet_keypair,
        root_permissions.clone(),
        ViewKeyLevel::Root
    );
    println!("Created root key: {:?}", root_key.public_key());
    
    // Create department key
    let dept_key = manager.derive_child_key(
        root_key.public_key(),
        1, // Department ID
        root_permissions.clone()
    ).unwrap();
    println!("Created department key: {:?}", dept_key.public_key());
    
    // Create employee key
    let mut employee_permissions = ViewKeyPermissions::default();
    employee_permissions.view_incoming = true;
    
    let employee_key = manager.derive_child_key(
        dept_key.public_key(),
        101, // Employee ID
        employee_permissions
    ).unwrap();
    println!("Created employee key: {:?}", employee_key.public_key());
    
    // Show hierarchy
    println!("\nView Key Hierarchy:");
    println!("- Root: {:?}", root_key.public_key());
    
    let children = manager.get_child_keys(root_key.public_key());
    for child in children {
        println!("  └── Department: {:?}", child.public_key());
        
        let grandchildren = manager.get_child_keys(child.public_key());
        for grandchild in grandchildren {
            println!("      └── Employee: {:?}", grandchild.public_key());
        }
    }
    
    println!("\n[3] Granular Disclosure Controls\n");
    
    // Create a transaction
    let tx = create_test_transaction();
    println!("Created test transaction with amount: {}", tx.outputs[0].value);
    
    // Create different visibility permissions
    let mut field_visibility = HashMap::new();
    field_visibility.insert("amounts".to_string(), false);
    
    let mut permissions = ViewKeyPermissions::default();
    permissions = permissions.with_field_visibility(field_visibility);
    
    let visibility_key = manager.generate_view_key(&wallet_keypair, permissions);
    println!("Created view key with custom field visibility");
    
    // Apply visibility
    let filtered_tx = visibility_key.apply_field_visibility(&tx);
    println!("Original transaction amount: {}", tx.outputs[0].value);
    println!("Filtered transaction amount: {}", filtered_tx.outputs[0].value);
    
    println!("\n[4] Context-Restricted View Keys\n");
    
    // Create key with context restrictions
    let context_key = manager.generate_view_key(&wallet_keypair, ViewKeyPermissions::default());
    
    // Add context
    let context = ViewKeyContext {
        networks: vec!["mainnet".to_string()],
        applications: vec!["wallet".to_string()],
        ip_restrictions: Vec::new(),
        custom_context: HashMap::new(),
    };
    
    manager.update_context(context_key.public_key(), context.clone());
    println!("Updated view key with context restrictions");
    
    // Scan with matching context
    let results = manager.scan_transactions(
        &[tx.clone()],
        current_time(),
        Some(&context)
    );
    println!("Scanned with matching context: {} results", results.len());
    
    // Scan with non-matching context
    let non_matching_context = ViewKeyContext {
        networks: vec!["testnet".to_string()],
        applications: vec!["wallet".to_string()],
        ip_restrictions: Vec::new(),
        custom_context: HashMap::new(),
    };
    
    let results = manager.scan_transactions(
        &[tx.clone()],
        current_time(),
        Some(&non_matching_context)
    );
    println!("Scanned with non-matching context: {} results", results.len());
    
    println!("\n[5] Time-Bound View Keys\n");
    
    // Create time-bound key
    let mut time_permissions = ViewKeyPermissions::default();
    time_permissions.valid_from = current_time() + 3600; // Valid 1 hour from now
    
    let _time_key = manager.generate_view_key(&wallet_keypair, time_permissions);
    println!("Created time-bound view key valid from 1 hour in the future");
    
    // Try to use key now (should fail)
    let results = manager.scan_transactions(
        &[tx.clone()],
        current_time(),
        None
    );
    println!("Scanning with time-bound key before valid time: {} results", 
        results.values().filter(|v| !v.is_empty()).count());
    
    // Try in the future
    let future_time = current_time() + 7200; // 2 hours from now
    let results = manager.scan_transactions(
        &[tx.clone()],
        future_time,
        None
    );
    println!("Scanning with time-bound key after valid time: {} results", 
        results.values().filter(|v| !v.is_empty()).count());
    
    println!("\n[6] Multi-Signature View Keys\n");
    
    // Create signers
    let signer1 = obscura_core::crypto::jubjub::generate_keypair();
    let signer2 = obscura_core::crypto::jubjub::generate_keypair();
    let signer3 = obscura_core::crypto::jubjub::generate_keypair();
    
    println!("Created signers:");
    println!("- Signer 1: {:?}", signer1.public);
    println!("- Signer 2: {:?}", signer2.public);
    println!("- Signer 3: {:?}", signer3.public);
    
    let signers = vec![signer1.public.clone(), signer2.public.clone(), signer3.public.clone()];
    
    // Create multi-sig key (2 of 3)
    let mut multi_sig_key = manager.create_multi_sig_key(
        &wallet_keypair,
        ViewKeyPermissions::default(),
        signers,
        2, // Threshold
        current_time() + 3600 // Expire in 1 hour
    );
    println!("Created multi-signature view key (2 of 3)");
    
    println!("Initial authorization status: {:?}", multi_sig_key.is_authorized(current_time()));
    
    // Add authorizations
    println!("Adding authorization from Signer 1...");
    multi_sig_key.add_authorization(&signer1.public, &[0; 64], b"authorize");
    
    println!("Authorization status after 1 signature: {:?}", 
        multi_sig_key.is_authorized(current_time()));
    
    println!("Adding authorization from Signer 2...");
    multi_sig_key.add_authorization(&signer2.public, &[0; 64], b"authorize");
    
    println!("Authorization status after 2 signatures: {:?}", 
        multi_sig_key.is_authorized(current_time()));
    
    // Convert to view key
    if let Some(view_key) = multi_sig_key.to_view_key(current_time()) {
        println!("Successfully converted multi-sig key to view key: {:?}", view_key.public_key());
    }
    
    println!("\n[7] Audit Logging\n");
    
    // Get audit log
    let log = manager.get_audit_log();
    println!("Audit log has {} entries", log.len());
    
    println!("Last 5 audit entries:");
    for entry in log.iter().rev().take(5) {
        println!("- {} : {:?} for key {}", 
            entry.timestamp, 
            entry.operation,
            hex::encode(&entry.public_key[0..4]));
    }
    
    println!("\n[8] Revocation\n");
    
    // Revoke the root key
    println!("Revoking root key and all derived keys...");
    manager.revoke_view_key(root_key.public_key());
    
    // Check if keys are revoked
    println!("Root key revoked: {}", manager.is_revoked(root_key.public_key()));
    println!("Department key revoked: {}", manager.is_revoked(dept_key.public_key()));
    println!("Employee key revoked: {}", manager.is_revoked(employee_key.public_key()));
    
    println!("\nDemo completed successfully!");
} 