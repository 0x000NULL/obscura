use obscura_lib::crypto::privacy::{PrivacyPrimitive, TransactionObfuscationPrimitive};
use obscura_lib::crypto::pedersen::PedersenCommitment;
use obscura_lib::crypto::bulletproofs::RangeProof;
use std::sync::Arc;

#[test]
fn test_privacy_primitive_clone() {
    // Create a privacy primitive
    let primitive: Box<dyn PrivacyPrimitive> = Box::new(TransactionObfuscationPrimitive::new());
    
    // Clone the privacy primitive
    let cloned_primitive = primitive.clone();
    
    // Verify that the clone works correctly
    assert_eq!(primitive.name(), cloned_primitive.name());
    assert_eq!(primitive.description(), cloned_primitive.description());
    assert_eq!(primitive.feature_flag(), cloned_primitive.feature_flag());
    assert_eq!(primitive.computational_cost(), cloned_primitive.computational_cost());
    assert_eq!(primitive.privacy_level(), cloned_primitive.privacy_level());
} 