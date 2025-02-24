use obscura::blockchain::{Block, Transaction};
use obscura::consensus::StakeProof;
use ed25519_dalek::Keypair;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn create_test_block(nonce: u64) -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            previous_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            difficulty_target: 0x207fffff,
            nonce,
        },
        transactions: Vec::new(),
    }
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
} 