use crate::consensus::randomx::RandomXContext;
use crate::blockchain::tests::create_test_block;
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
    let mut hash = [0u8; 32];
    
    // Try multiple times to get a hash that meets the target
    // This is a realistic mining simulation
    let target = 0x207fffff;
    let mut input = b"test block header".to_vec();
    let mut nonce = 0u32;
    
    while nonce < 1000 {  // Limit attempts to avoid infinite loop in test
        input.extend_from_slice(&nonce.to_le_bytes());
        context.calculate_hash(&input, &mut hash).expect("Hash calculation failed");
        
        if verify_difficulty(&hash, target) {
            // Found a valid hash
            assert!(verify_difficulty(&hash, target));
            return;
        }
        
        nonce += 1;
        input.truncate(input.len() - 4);  // Remove previous nonce
    }
    
    // If we reach here, we couldn't find a valid hash
    // This is unlikely but possible - you might want to adjust the target
    // or increase the number of attempts for more reliable tests
    panic!("Could not find valid hash within {} attempts", nonce);
} 