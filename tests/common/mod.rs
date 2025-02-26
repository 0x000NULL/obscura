use ed25519_dalek::{Keypair, Signer};
use obscura::blockchain::{Block, OutPoint, Transaction, TransactionInput, TransactionOutput};
use obscura::consensus::randomx::RandomXContext;
use obscura::consensus::StakeProof;
use obscura::networking::Node;
use rand::rngs::OsRng;
use rand::thread_rng;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn create_test_block(nonce: u64) -> Block {
    let mut block = Block::new([0u8; 32]);
    block.header.nonce = nonce;
    block.header.difficulty_target = 0x207fffff;
    block
}

pub fn create_test_transaction() -> Transaction {
    let mut csprng = OsRng;
    let keypair = Keypair::generate(&mut csprng);

    Transaction {
        inputs: vec![TransactionInput {
            previous_output: OutPoint {
                transaction_hash: [0u8; 32],
                index: 0,
            },
            signature_script: keypair.sign(b"test_block").to_bytes().to_vec(),
            sequence: 0,
        }],
        outputs: vec![TransactionOutput {
            value: 100,
            public_key_script: vec![],
        }],
        lock_time: 0,
        fee_adjustments: None,
    }
}

pub fn create_test_stake_proof() -> StakeProof {
    StakeProof {
        stake_amount: 1_000_000,
        stake_age: 24 * 60 * 60,  // 24 hours
        signature: vec![0u8; 64], // Dummy signature for testing
    }
}

pub fn create_transaction_with_fee(fee: u64) -> Transaction {
    let mut tx = create_test_transaction();
    tx.outputs[0].value = fee;
    tx
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

    pub fn broadcast_transaction(&mut self, tx: &Transaction) {
        for node in &mut self.nodes {
            node.add_transaction(tx.clone());
        }
    }

    pub fn broadcast_block(&mut self, block: &Block) {
        for node in &mut self.nodes {
            node.process_block(block.clone());
        }
    }
}
