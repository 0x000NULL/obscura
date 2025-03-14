use obscura::wallet::Wallet;
use obscura::crypto::jubjub;
use obscura::Node;
use obscura::blockchain::UTXOSet;
use obscura::blockchain::mempool::Mempool;
use obscura::wallet::integration::WalletIntegration;
use obscura::networking::NetworkConfig;
use std::sync::{Arc, Mutex, RwLock};

fn main() {
    println!("Testing Obscura Wallet Integration");
    
    // Create a node with proper configuration
    let network_config = NetworkConfig::default();
    let node = Arc::new(Mutex::new(Node::new_with_config(network_config)));
    
    // Create a wallet with privacy features enabled
    let mut wallet = Wallet::new();
    wallet.enable_privacy();
    
    // Generate a keypair using the generate_keypair function instead of JubjubKeypair::generate
    let keypair = jubjub::generate_keypair();
    wallet.set_keypair(keypair);
    
    // Wrap the wallet in an Arc<RwLock> for thread-safe access
    let wallet_arc = Arc::new(RwLock::new(wallet));
    
    // Create empty UTXO set and mempool
    let utxo_set = Arc::new(Mutex::new(UTXOSet::new()));
    let mempool = Arc::new(Mutex::new(Mempool::new()));
    
    // Create the wallet integration to connect the wallet to the node
    let wallet_integration = WalletIntegration::new(
        wallet_arc,
        node.clone(),
        mempool,
        utxo_set
    );
    
    // Initialize connections and perform test operations
    println!("Wallet setup complete!");
    
    // Generate an activity report
    let report = wallet_integration.generate_activity_report();
    println!("Wallet Activity Report: {}", report);
} 