use super::*;
use crate::tests::common::create_test_transaction;
use std::time::Duration;

#[test]
fn test_stem_phase() {
    let mut node = Node::new();
    let tx = create_test_transaction();
    
    // Test stem phase routing
    let _next_node = node.get_stem_successor();
    node.route_transaction_stem(&tx);
    
    assert_eq!(node.stem_transactions.len(), 1);
    assert!(node.fluff_queue.is_empty());
}

#[test]
fn test_fluff_phase_transition() {
    let mut node = Node::new();
    let tx = create_test_transaction();
    
    // Add to stem phase
    node.route_transaction_stem(&tx);
    
    // Wait for fluff transition
    std::thread::sleep(Duration::from_secs(10));
    node.process_fluff_queue();
    
    assert!(node.stem_transactions.is_empty());
    assert_eq!(node.broadcast_transactions.len(), 1);
} 