use obscura_core::blockchain::Mempool;
use obscura_core::crypto::jubjub::JubjubKeypair;
use obscura_core::networking::Node;
use obscura_core::wallet::Wallet;

#[tokio::test(flavor = "current_thread")]
async fn peer_b_receives_tx() {
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
    // Drain stem_transactions directly alongside fluff/broadcast: stem→fluff
    // is timeout-driven (10–30s), which would exceed the test budget.
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
    assert_eq!(mempool_b.size(), 1, "mempool size must reflect the single relayed tx");

    let tx_hash = tx.hash();
    let txs = mempool_b.get_transactions();
    assert!(
        txs.iter().any(|t| t.hash() == tx_hash),
        "get_transactions must include the relayed tx by hash",
    );
}
