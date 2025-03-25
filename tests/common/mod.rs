use obscura_core::blockchain::{Block, OutPoint, Transaction, TransactionInput, TransactionOutput};
use obscura_core::consensus::StakeProof;
use obscura_core::crypto::jubjub::generate_keypair;
use obscura_core::networking::{Node, NetworkConfig};

pub fn create_test_block(nonce: u64) -> Block {
    let mut block = Block::new([0u8; 32]);
    block.header.nonce = nonce;
    block.header.difficulty_target = 0x207fffff;
    block
}

pub fn create_test_transaction() -> Transaction {
    let keypair = generate_keypair();
    let message = b"test_block";
    let signature = keypair.sign(message);

    Transaction {
        inputs: vec![TransactionInput {
            previous_output: OutPoint {
                transaction_hash: [0u8; 32],
                index: 0,
            },
            signature_script: signature.to_bytes(),
            sequence: 0,
        }],
        outputs: vec![TransactionOutput {
            value: 100,
            public_key_script: vec![],
            commitment: None,
            range_proof: None,
        }],
        lock_time: 0,
        fee_adjustments: None,
        privacy_flags: 0,
        obfuscated_id: None,
        ephemeral_pubkey: None,
        amount_commitments: None,
        range_proofs: None,
        metadata: std::collections::HashMap::new(),
        salt: Some(vec![0u8; 32]),
    }
}

pub fn create_test_stake_proof() -> StakeProof {
    StakeProof {
        stake_amount: 1_000_000,
        stake_age: 24 * 60 * 60,      // 24 hours
        public_key: vec![1, 2, 3, 4], // Dummy public key for testing
        signature: vec![0u8; 64],     // Dummy signature for testing
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
            nodes.push(Node::new_with_config(NetworkConfig::default()));
        }
        TestNetwork { nodes }
    }

    pub fn add_mining_node(&mut self) -> &mut Node {
        let mut node = Node::new_with_config(NetworkConfig::default());
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
