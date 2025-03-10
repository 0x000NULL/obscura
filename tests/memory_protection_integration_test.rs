use obscura::crypto::memory_protection::{MemoryProtection, MemoryProtectionConfig};
use obscura::crypto::side_channel_protection::SideChannelProtection;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn test_memory_protection_integration() {
    // Create a memory protection instance with safe configuration for testing
    let mut config = MemoryProtectionConfig::default();
    // Disable guard pages and ASLR to avoid access violations in testing
    config.guard_pages_enabled = false;
    config.aslr_integration_enabled = false;
    
    let mp = MemoryProtection::new(config, None);
    
    // Test with different types of sensitive data
    let sensitive_string = "sensitive password data".to_string();
    let sensitive_bytes = vec![0x73, 0x65, 0x63, 0x72, 0x65, 0x74];  // "secret" in ASCII
    let sensitive_number = 42u64;
    
    // Store in protected memory
    let mut protected_string = mp.secure_alloc(sensitive_string).unwrap();
    let mut protected_bytes = mp.secure_alloc(sensitive_bytes).unwrap();
    let mut protected_number = mp.secure_alloc(sensitive_number).unwrap();
    
    // Verify we can retrieve the data
    assert_eq!(*protected_string.get().unwrap(), "sensitive password data");
    assert_eq!(*protected_bytes.get().unwrap(), vec![0x73, 0x65, 0x63, 0x72, 0x65, 0x74]);
    assert_eq!(*protected_number.get().unwrap(), 42u64);
    
    // Test modification
    protected_string.get_mut().unwrap().push_str(" modified");
    protected_bytes.get_mut().unwrap().push(0x21);  // '!' in ASCII
    *protected_number.get_mut().unwrap() = 100;
    
    // Verify modifications
    assert_eq!(*protected_string.get().unwrap(), "sensitive password data modified");
    assert_eq!(*protected_bytes.get().unwrap(), vec![0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x21]);
    assert_eq!(*protected_number.get().unwrap(), 100u64);
    
    // Test encryption/decryption
    protected_string.encrypt().unwrap();
    
    // Should be automatically decrypted on access
    assert_eq!(*protected_string.get().unwrap(), "sensitive password data modified");
    
    println!("Memory protection integration test passed successfully");
}

#[test]
fn test_integration_with_side_channel_protection() {
    // Create side-channel protection
    let scp = Arc::new(SideChannelProtection::default());
    
    // Create memory protection with side-channel protection and safe configuration for testing
    let mut config = MemoryProtectionConfig::default();
    // Disable guard pages and ASLR to avoid access violations in testing
    config.guard_pages_enabled = false;
    config.aslr_integration_enabled = false;
    
    let mp = MemoryProtection::new(config, Some(scp.clone()));
    
    // Create sensitive data
    let sensitive_data = "sensitive data that needs both memory and side-channel protection".to_string();
    
    // Store in protected memory
    let mut protected_data = mp.secure_alloc(sensitive_data).unwrap();
    
    // Use the data with side-channel protection
    let result = scp.protected_operation(|| {
        // This should be protected from side-channel attacks during access
        let data = protected_data.get().unwrap();
        data.len()
    });
    
    // Verify the result
    assert_eq!(result, 63);
    
    println!("Integration with side-channel protection test passed successfully");
}

#[test]
fn test_auto_encryption() {
    // Create config with short auto-encrypt time for testing
    let mut config = MemoryProtectionConfig::default();
    config.auto_encrypt_after_ms = 100;  // 100ms
    // Disable guard pages and ASLR to avoid access violations in testing
    config.guard_pages_enabled = false;
    config.aslr_integration_enabled = false;
    
    let mp = MemoryProtection::new(config, None);
    
    // Create sensitive data
    let sensitive_data = "auto-encrypt this data".to_string();
    
    // Store in protected memory
    let mut protected_data = mp.secure_alloc(sensitive_data).unwrap();
    
    // Access once to set the last access time
    let _ = protected_data.get().unwrap();
    
    // Wait for the auto-encrypt timeout
    thread::sleep(Duration::from_millis(150));
    
    // Check if it should be auto-encrypted
    protected_data.check_auto_encrypt().unwrap();
    
    // Should still be accessible (auto-decryption on access)
    assert_eq!(*protected_data.get().unwrap(), "auto-encrypt this data");
    
    println!("Auto-encryption test passed successfully");
}

#[test]
fn test_complex_data_structure() {
    // Define a complex data structure
    #[derive(Debug, PartialEq)]
    struct SensitiveUserData {
        username: String,
        password_hash: Vec<u8>,
        private_key: Vec<u8>,
        personal_data: PersonalInfo,
    }
    
    #[derive(Debug, PartialEq)]
    struct PersonalInfo {
        name: String,
        address: String,
        ssn: String,
    }
    
    // Create memory protection with safe configuration for testing
    let mut config = MemoryProtectionConfig::default();
    // Disable guard pages and ASLR to avoid access violations in testing
    config.guard_pages_enabled = false;
    config.aslr_integration_enabled = false;
    
    let mp = MemoryProtection::new(config, None);
    
    // Create sensitive data
    let user_data = SensitiveUserData {
        username: "johndoe".to_string(),
        password_hash: vec![1, 2, 3, 4, 5],
        private_key: vec![10, 20, 30, 40, 50],
        personal_data: PersonalInfo {
            name: "John Doe".to_string(),
            address: "123 Main St".to_string(),
            ssn: "123-45-6789".to_string(),
        },
    };
    
    // Store in protected memory
    let mut protected_data = mp.secure_alloc(user_data).unwrap();
    
    // Access and modify
    protected_data.get_mut().unwrap().username = "johndoe2".to_string();
    protected_data.get_mut().unwrap().personal_data.address = "456 Oak Ave".to_string();
    
    // Verify
    assert_eq!(protected_data.get().unwrap().username, "johndoe2");
    assert_eq!(protected_data.get().unwrap().personal_data.address, "456 Oak Ave");
    
    // Encrypt the data
    protected_data.encrypt().unwrap();
    
    // Should still be accessible
    assert_eq!(protected_data.get().unwrap().username, "johndoe2");
    assert_eq!(protected_data.get().unwrap().personal_data.ssn, "123-45-6789");
    
    println!("Complex data structure test passed successfully");
}

#[test]
fn test_multithreaded_usage() {
    // Create shared memory protection with safe configuration for testing
    let mut config = MemoryProtectionConfig::default();
    // Disable guard pages and ASLR to avoid access violations in testing
    config.guard_pages_enabled = false;
    config.aslr_integration_enabled = false;
    
    let mp = Arc::new(MemoryProtection::new(config, None));
    
    // Create some test data
    let data = "shared protected data".to_string();
    let protected_data = mp.secure_alloc(data).unwrap();
    let protected_data = Arc::new(std::sync::Mutex::new(protected_data));
    
    // Create multiple threads
    let mut handles = vec![];
    
    for i in 0..5 {
        let mp_clone = Arc::clone(&mp);
        let data_clone = Arc::clone(&protected_data);
        
        let handle = thread::spawn(move || {
            // Each thread creates its own protected data
            let thread_data = format!("thread {} data", i);
            let mut thread_protected = mp_clone.secure_alloc(thread_data).unwrap();
            
            // And accesses the shared data
            let mut shared = data_clone.lock().unwrap();
            let shared_value = shared.get().unwrap();
            
            // Return both values
            (thread_protected.get().unwrap().clone(), shared_value.clone())
        });
        
        handles.push(handle);
    }
    
    // Collect results
    for (i, handle) in handles.into_iter().enumerate() {
        let (thread_value, shared_value) = handle.join().unwrap();
        
        assert_eq!(thread_value, format!("thread {} data", i));
        assert_eq!(shared_value, "shared protected data");
    }
    
    println!("Multithreaded usage test passed successfully");
} 