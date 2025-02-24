use obscura::blockchain::{Block, BlockHeader, Transaction};
use obscura::consensus::StakeProof;
use obscura::networking::Node;
use ed25519_dalek::Keypair;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::thread_rng;

pub fn create_test_block(nonce: u64) -> Block {
    Block::new([0u8; 32])
}

pub fn create_test_stake_proof() -> StakeProof {
    let keypair = Keypair::generate(&mut rand::thread_rng());
    StakeProof {
        public_key: keypair.public,
        signature: keypair.sign(b"test_block"),
        stake_amount: 1000,
        stake_age: 24 * 60 * 60,
    }
}

pub struct TestNetwork {
    nodes: Vec<Node>,
}

impl TestNetwork {
    pub fn new(node_count: usize) -> Self {
        let mut nodes = Vec::with_capacity(node_count);
        for _ in 0..node_count {
            nodes.push(Node::new());
        }
        TestNetwork { nodes }
    }
    
    pub fn add_mining_node(&mut self) -> &mut Node {
        let mut node = Node::new();
        node.enable_mining();
        self.nodes.push(node);
        self.nodes.last_mut().unwrap()
    }
    
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    pub fn broadcast_transaction(&self, tx: &Transaction) {
        for node in &self.nodes {
            // In a real implementation, this would use networking
            // For tests, we can directly add to mempool
            let mempool = node.mempool();
            if !mempool.contains(&tx) {
                node.add_transaction(tx.clone());
            }
        }
    }

    pub fn broadcast_block(&self, block: &Block) {
        for node in &self.nodes {
            // In a real implementation, this would use networking
            // For tests, we directly add the block
            node.process_block(block.clone());
        }
    }
}

pub fn create_test_transaction() -> Transaction {
    let keypair = Keypair::generate(&mut thread_rng());
    let output = TransactionOutput {
        value: 50,
        public_key_script: keypair.public.as_bytes().to_vec(),
    };
    
    Transaction {
        inputs: vec![],
        outputs: vec![output],
        lock_time: 0,
    }
} 