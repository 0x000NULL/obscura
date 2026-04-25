use obscura_core::blockchain::Mempool;
use obscura_core::crypto::jubjub::JubjubKeypair;
use obscura_core::wallet::Wallet;

#[test]
fn mempool_accepts_signed_tx() {
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
    assert!(mempool.contains(&tx), "mempool must report the added tx via contains");
    assert_eq!(mempool.size(), 1, "mempool size must reflect the single accepted tx");

    let tx_hash = tx.hash();
    let txs = mempool.get_transactions();
    assert!(
        txs.iter().any(|t| t.hash() == tx_hash),
        "get_transactions must include the accepted tx by hash",
    );
}
