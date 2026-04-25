use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::broadcast;

use crate::blockchain::mempool::Mempool;
use crate::blockchain::{Block, Transaction, calculate_merkle_root, create_coinbase_transaction};
use crate::consensus::mining_reward::calculate_block_reward;

#[derive(Default)]
pub struct Blockchain {
    pub tip_hash: [u8; 32],
    pub tip_height: u64,
}

impl Blockchain {
    pub fn tip(&self) -> ([u8; 32], u64) {
        (self.tip_hash, self.tip_height)
    }
}

pub struct BlockTemplate {
    pub previous_hash: [u8; 32],
    pub height: u64,
    pub merkle_root: [u8; 32],
    pub timestamp: u64,
    pub difficulty_target: u32,
    pub transactions: Vec<Transaction>,
}

#[derive(Debug)]
pub enum MiningError {
    ChainLockPoisoned,
}

impl fmt::Display for MiningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MiningError::ChainLockPoisoned => write!(f, "chain RwLock is poisoned"),
        }
    }
}

impl std::error::Error for MiningError {}

pub struct MiningLoop {
    pub mempool: Arc<Mempool>,
    pub chain: Arc<RwLock<Blockchain>>,
    pub tx_blocks: broadcast::Sender<Block>,
    pub running: Arc<AtomicBool>,
}

impl MiningLoop {
    pub fn new(
        mempool: Arc<Mempool>,
        chain: Arc<RwLock<Blockchain>>,
        tx_blocks: broadcast::Sender<Block>,
    ) -> Self {
        Self {
            mempool,
            chain,
            tx_blocks,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub async fn start(self: Arc<Self>) {
        while self.running.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub fn build_template(&self) -> Result<BlockTemplate, MiningError> {
        let (previous_hash, parent_height) = {
            let guard = self
                .chain
                .read()
                .map_err(|_| MiningError::ChainLockPoisoned)?;
            guard.tip()
        };

        let height = parent_height + 1;

        let mempool_txs = self.mempool.get_transactions_by_fee(2000);
        let total_fees: u64 = 0;

        let reward = calculate_block_reward(height) + total_fees;
        let coinbase = create_coinbase_transaction(reward);

        let mut transactions = Vec::with_capacity(mempool_txs.len() + 1);
        transactions.push(coinbase);
        transactions.extend(mempool_txs);

        let merkle_root = calculate_merkle_root(&transactions);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(BlockTemplate {
            previous_hash,
            height,
            merkle_root,
            timestamp,
            difficulty_target: 0,
            transactions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_loop() -> MiningLoop {
        let mempool = Arc::new(Mempool::new());
        let chain = Arc::new(RwLock::new(Blockchain::default()));
        let (tx_blocks, _rx) = broadcast::channel::<Block>(16);
        MiningLoop::new(mempool, chain, tx_blocks)
    }

    #[test]
    fn new_starts_with_running_false() {
        let m = make_loop();
        assert_eq!(m.running.load(Ordering::SeqCst), false);
    }

    #[test]
    fn stop_is_idempotent() {
        let m = make_loop();
        assert_eq!(m.running.load(Ordering::SeqCst), false);

        let initial_strong = Arc::strong_count(&m.running);

        m.stop();
        assert_eq!(m.running.load(Ordering::SeqCst), false);
        assert_eq!(Arc::strong_count(&m.running), initial_strong);

        m.stop();
        assert_eq!(m.running.load(Ordering::SeqCst), false);
        assert_eq!(Arc::strong_count(&m.running), initial_strong);

        m.stop();
        assert_eq!(m.running.load(Ordering::SeqCst), false);
        assert_eq!(Arc::strong_count(&m.running), initial_strong);

        m.running.store(true, Ordering::SeqCst);
        m.stop();
        assert_eq!(m.running.load(Ordering::SeqCst), false);
        m.stop();
        assert_eq!(m.running.load(Ordering::SeqCst), false);
    }

    #[test]
    fn build_template_well_formed() {
        let mempool = Arc::new(Mempool::new());
        let chain = Arc::new(RwLock::new(Blockchain {
            tip_hash: [7u8; 32],
            tip_height: 41,
        }));
        let (tx_blocks, _rx) = broadcast::channel::<Block>(16);
        let m = MiningLoop::new(mempool, chain, tx_blocks);

        let template = m.build_template().expect("build_template should succeed");

        assert_eq!(template.previous_hash, [7u8; 32]);
        assert_eq!(template.height, 42);
        assert_eq!(template.transactions.len(), 1);
        assert!(template.transactions[0].inputs.is_empty());
        assert_eq!(
            template.transactions[0].outputs[0].value,
            calculate_block_reward(42)
        );
        assert_eq!(
            template.merkle_root,
            calculate_merkle_root(&template.transactions)
        );
    }
}
