use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tokio::sync::broadcast;

use obscura_core::Block;
use obscura_core::blockchain::Mempool;
use obscura_core::consensus::randomx::RandomXContext;
use obscura_core::crypto::jubjub::JubjubKeypair;
use obscura_core::mining::{Blockchain, MiningLoop};
use obscura_core::networking::Node;
use obscura_core::wallet::Wallet;

#[tokio::test(flavor = "multi_thread")]
async fn block_contains_broadcast_tx() {
    let mut wallet = Wallet::new();
    wallet.set_keypair(JubjubKeypair::generate());

    let recipient_keypair = JubjubKeypair::generate();
    let recipient = recipient_keypair.public;

    wallet.balance = 1000;

    let tx = wallet
        .create_transaction(&recipient, 500)
        .expect("create_transaction should produce a Transaction when balance covers amount");

    let mut node_a = Node::new_with_test_config();
    let _node_b = Node::new_with_test_config();

    let mut mempool_b = Mempool::new();

    node_a.add_transaction(tx.clone());

    let mut received = false;
    for _ in 0..200 {
        let _ = node_a.maintain_dandelion();
        let _ = node_a.process_fluff_queue();

        let mut drained: Vec<_> = node_a.broadcast_transactions.drain(..).collect();
        drained.extend(node_a.stem_transactions.drain(..));
        drained.extend(node_a.fluff_queue.lock().unwrap().drain(..));

        for t in drained {
            mempool_b.add_transaction(t);
        }

        if mempool_b.contains(&tx) {
            received = true;
            break;
        }

        tokio::task::yield_now().await;
    }

    assert!(received, "node B's mempool must observe the relayed tx within the yield-loop budget");

    let mempool_b = Arc::new(Mutex::new(mempool_b));
    let chain = Arc::new(RwLock::new(Blockchain::default()));
    let (tx_blocks, mut rx) = broadcast::channel::<Block>(16);
    let randomx = Arc::new(RandomXContext::new_for_testing(b"obx-test"));
    let miner = Arc::new(MiningLoop::new(mempool_b.clone(), chain, tx_blocks, randomx));

    let runner = miner.clone();
    let stopper = miner.clone();

    let block: Block = tokio::time::timeout(Duration::from_secs(15), async move {
        let mut captured: Option<Block> = None;
        let driver = async {
            let b = tokio::time::timeout(Duration::from_secs(10), rx.recv())
                .await
                .expect("block within 10s")
                .expect("channel open");
            captured = Some(b);
            stopper.stop();
        };

        tokio::join!(runner.start(), driver);
        captured.expect("driver must capture a block before stopping the miner")
    })
    .await
    .expect("mining loop must emit a block and stop within 15s");

    assert_eq!(block.header.height, 1);
    assert!(
        block.transactions.iter().any(|t| t.hash() == tx.hash()),
        "mined block must include the relayed tx by hash",
    );
    assert!(
        block.transactions.len() >= 2,
        "block must include at least the coinbase plus the relayed tx",
    );
}
