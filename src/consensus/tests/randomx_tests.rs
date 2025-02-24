use crate::RandomXContext;
use crate::consensus::randomx::verify_difficulty;
use std::sync::Arc;

#[test]
fn test_randomx_context_creation() {
    let context = RandomXContext::new(b"test_key");
    assert!(context.is_valid());
}

#[test]
fn test_hash_computation() {
    let context = Arc::new(RandomXContext::new(b"test_key"));
    let input = b"test block header";
    let mut output = [0u8; 32];
    
    context.calculate_hash(input, &mut output).expect("Hash calculation failed");
    assert_ne!(output, [0u8; 32]);
}

#[test]
fn test_difficulty_verification() {
    let context = Arc::new(RandomXContext::new(b"test_key"));
    let input = b"test block header";
    let mut hash = [0u8; 32];
    
    context.calculate_hash(input, &mut hash).expect("Hash calculation failed");
    
    // Test against easy difficulty
    assert!(verify_difficulty(&hash, 0x207fffff));
    // Test against impossible difficulty
    assert!(!verify_difficulty(&hash, 0x00000001));
} 