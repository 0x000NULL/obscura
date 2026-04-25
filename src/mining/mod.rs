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
}
