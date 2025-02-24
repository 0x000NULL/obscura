use super::*;
use std::sync::Arc;

#[test]
fn test_randomx_context_creation() {
    let context = RandomXContext::new("test_key").expect("Failed to create RandomX context");
    assert!(!context.vm.is_null());
    assert!(!context.cache.is_null());
}

#[test]
fn test_hash_computation() {
    let context = Arc::new(RandomXContext::new("test_key").unwrap());
    let input = b"test block header";
    let mut output = [0u8; 32];
    
    context.calculate_hash(input, &mut output).expect("Hash calculation failed");
    assert_ne!(output, [0u8; 32]);
}

#[test]
fn test_difficulty_verification() {
    let context = Arc::new(RandomXContext::new("test_key").unwrap());
    let input = b"test block header";
    let mut hash = [0u8; 32];
    
    context.calculate_hash(input, &mut hash).unwrap();
    
    // Test against easy difficulty
    assert!(verify_difficulty(&hash, 0x207fffff));
    // Test against impossible difficulty
    assert!(!verify_difficulty(&hash, 0x00000001));
} 