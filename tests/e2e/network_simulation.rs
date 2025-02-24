use obscura::networking::Node;
use obscura::wallet::Wallet;
use std::time::Duration;

#[test]
fn test_transaction_propagation() {
    let mut network = TestNetwork::new(10); // Create 10 node network
    let wallet = Wallet::new_random();
    
    // Create and broadcast transaction
    let tx = wallet.create_test_transaction();
    network.broadcast_transaction(&tx);
    
    // Wait for propagation
    std::thread::sleep(Duration::from_secs(2));
    
    // Verify all nodes received the transaction
    for node in network.nodes() {
        assert!(node.mempool().contains(&tx));
    }
}

#[test]
fn test_block_propagation() {
    let mut network = TestNetwork::new(5);
    let miner_node = network.add_mining_node();
    
    // Mine a block
    let block = miner_node.mine_block().unwrap();
    network.broadcast_block(&block);
    
    // Verify all nodes accepted the block
    for node in network.nodes() {
        assert_eq!(node.best_block_hash(), block.hash());
    }
} 