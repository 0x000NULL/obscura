use obscura_core::blockchain::Mempool;
use obscura_core::crypto::jubjub::JubjubKeypair;
use obscura_core::wallet::Wallet;

struct MockBroadcastSink {
    received: Vec<[u8; 32]>,
}

impl MockBroadcastSink {
    fn new() -> Self {
        Self { received: Vec::new() }
    }

    fn push(&mut self, hash: [u8; 32]) {
        self.received.push(hash);
    }

    fn received(&self) -> &[[u8; 32]] {
        &self.received
    }
}

#[test]
fn mempool_emits_to_broadcast() {
    let mut wallet = Wallet::new();
    wallet.set_keypair(JubjubKeypair::generate());

    let recipient_keypair = JubjubKeypair::generate();
    let recipient = recipient_keypair.public;

    wallet.balance = 1000;

    let tx = wallet
        .create_transaction(&recipient, 500)
        .expect("create_transaction should produce a Transaction when balance covers amount");

    let mut mempool = Mempool::new();
    assert!(
        mempool.add_transaction(tx.clone()),
        "fresh mempool must accept a wallet-signed transaction",
    );

    let mut sink = MockBroadcastSink::new();
    for t in mempool.get_transactions() {
        sink.push(t.hash());
    }

    let tx_hash = tx.hash();
    assert!(!sink.received().is_empty(), "sink must observe at least one tx");
    assert_eq!(
        sink.received().iter().filter(|h| **h == tx_hash).count(),
        1,
        "sink must observe the signed tx hash exactly once",
    );
}
