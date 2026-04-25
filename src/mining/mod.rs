use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::broadcast;

use crate::blockchain::Block;
use crate::blockchain::mempool::Mempool;

#[derive(Default)]
pub struct Blockchain;

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
}
