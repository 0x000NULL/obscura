use obscura_core::crypto::jubjub::JubjubKeypair;
use obscura_core::wallet::Wallet;

#[test]
fn create_transaction_populates_outputs() {
    let mut wallet = Wallet::new();
    wallet.set_keypair(JubjubKeypair::generate());

    let recipient_keypair = JubjubKeypair::generate();
    let recipient = recipient_keypair.public;

    wallet.balance = 1000;

    let tx = wallet
        .create_transaction(&recipient, 500)
        .expect("create_transaction should produce a Transaction when balance covers amount");

    assert!(!tx.inputs.is_empty(), "transaction must have at least one populated input");
    assert_eq!(tx.outputs.len(), 2, "transaction must have payment + change outputs");
    assert_eq!(tx.outputs[0].value, 500, "payment output value must equal amount");
    assert_eq!(tx.outputs[1].value, 500, "change output value must equal balance - amount");
    assert!(
        !tx.inputs[0].signature_script.is_empty(),
        "input must carry a non-empty signature script",
    );
}
