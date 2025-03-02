mod blockchain;
mod consensus;
mod crypto;
mod networking;
mod wallet;
mod utils;
#[cfg(test)]
mod tests;

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use log::{info, error, debug};
use crate::consensus::HybridConsensus;
use crate::networking::Node;
use crate::crypto::jubjub::JubjubKeypair;

// Initialize cryptographic components
fn init_crypto() -> Option<JubjubKeypair> {
    info!("Initializing cryptographic components...");
    let keypair = crypto::generate_keypair();
    
    // For JubjubKeypair, we wrap it in Some since it doesn't return an Option
    Some(keypair)
}

// Initialize wallet components
fn init_wallet(keypair: Option<JubjubKeypair>) -> wallet::Wallet {
    info!("Initializing wallet...");
    let mut wallet = wallet::Wallet::new();
    if keypair.is_some() {
        // In a real implementation, would pass the keypair to the wallet
        // wallet.set_keypair(keypair.unwrap());
    }
    wallet.enable_privacy();
    wallet
}

// Initialize blockchain components
fn init_blockchain() -> (Arc<Mutex<blockchain::mempool::Mempool>>, Arc<Mutex<blockchain::UTXOSet>>) {
    info!("Initializing blockchain components...");
    let mempool = Arc::new(Mutex::new(blockchain::mempool::Mempool::new()));
    let utxo_set = Arc::new(Mutex::new(blockchain::UTXOSet::new()));
    (mempool, utxo_set)
}

// Initialize consensus engine
fn init_consensus() -> HybridConsensus {
    info!("Initializing consensus engine...");
    HybridConsensus::new()
}

// Initialize networking components
fn init_networking() -> Node {
    info!("Initializing networking components...");
    Node::new()
}

// Start network services
fn start_network_services(mempool: Arc<Mutex<blockchain::mempool::Mempool>>) -> thread::JoinHandle<()> {
    info!("Starting network services...");
    let _mempool_clone = Arc::clone(&mempool);
    thread::spawn(move || {
        debug!("Network service thread started");
        // Simulate network activity
        loop {
            thread::sleep(Duration::from_secs(10));
            debug!("Network heartbeat: checking for new peers and messages");
            // Here we would normally handle incoming connections, sync with peers, etc.
        }
    })
}

// Process mempool transactions
fn process_mempool(mempool: &Arc<Mutex<blockchain::mempool::Mempool>>) -> usize {
    let mempool_size = mempool.lock().unwrap().size();
    if mempool_size > 0 {
        info!("Processing {} transactions in mempool", mempool_size);
        // Here we would process transactions and potentially create a new block
    }
    mempool_size
}

// Main loop
fn run_main_loop(mempool: Arc<Mutex<blockchain::mempool::Mempool>>) {
    info!("Node is running. Press Ctrl+C to stop.");
    let running = true;
    while running {
        // Process any pending transactions in the mempool
        process_mempool(&mempool);
        
        // Sleep to avoid high CPU usage
        thread::sleep(Duration::from_secs(1));
        
        // In a real implementation, we would check for interrupt signals here
        // if interrupt_received() { running = false; }
    }
}

fn main() {
    // Initialize logging
    env_logger::init();
    info!("Obscura OBX Node Starting...");
    
    // Initialize components
    let keypair = match init_crypto() {
        Some(kp) => kp,
        None => return,
    };
    
    let wallet = init_wallet(Some(keypair));
    let (mempool, utxo_set) = init_blockchain();
    let consensus_engine = init_consensus();
    let node = init_networking();
    
    // Start network services
    let network_handle = start_network_services(Arc::clone(&mempool));
    
    // Run main loop
    run_main_loop(mempool);
    
    info!("Obscura OBX Node shutting down...");
}
