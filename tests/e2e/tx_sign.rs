use obscura_core::crypto::jubjub::JubjubKeypair;
use obscura_core::wallet::Wallet;

#[test]
fn create_transaction_populates_input_signature() {
    let mut wallet = Wallet::new();
    wallet.set_keypair(JubjubKeypair::generate());

    let recipient_keypair = JubjubKeypair::generate();
    let recipient = recipient_keypair.public;

    wallet.balance = 1000;

    let tx = wallet
        .create_transaction(&recipient, 500)
        .expect("create_transaction should produce a Transaction when balance covers amount");

    assert_eq!(tx.inputs.len(), 1, "wallet must populate exactly one input");
    assert!(
        !tx.inputs[0].signature_script.is_empty(),
        "input signature_script must be non-empty after signing",
    );
}

#[test]
fn create_transaction_signatures_are_randomized_per_call() {
    let mut wallet = Wallet::new();
    wallet.set_keypair(JubjubKeypair::generate());

    let recipient_keypair = JubjubKeypair::generate();
    let recipient = recipient_keypair.public;

    wallet.balance = 10_000;

    let tx_a = wallet
        .create_transaction(&recipient, 500)
        .expect("first create_transaction call must succeed");
    let tx_b = wallet
        .create_transaction(&recipient, 500)
        .expect("second create_transaction call must succeed");

    assert_ne!(
        tx_a.inputs[0].signature_script, tx_b.inputs[0].signature_script,
        "two consecutive signings of the same payload must differ (randomized nonce)",
    );
}

#[test]
fn create_transaction_without_keypair_returns_none() {
    let mut wallet = Wallet::new();
    let recipient_keypair = JubjubKeypair::generate();
    let recipient = recipient_keypair.public;

    wallet.balance = 1000;

    assert!(
        wallet.create_transaction(&recipient, 500).is_none(),
        "create_transaction must refuse to sign without a keypair",
    );
}
