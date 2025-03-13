#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(private_interfaces)]
#![allow(unused_mut)]
#![allow(non_snake_case)]
#![allow(unused_assignments)]
#![allow(unused_attributes)]
mod blockchain;
mod consensus;
mod crypto;
mod networking;
#[cfg(test)]
mod tests;
mod utils;
mod wallet;

use crate::consensus::HybridConsensus;
use crate::crypto::jubjub::JubjubKeypair;
use crate::networking::Node;
use crate::utils::{current_time, format_time_diff, is_timestamp_valid, time_since};
use crate::wallet::integration::WalletIntegration;
use log::{debug, error, info, warn};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

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
    if let Some(kp) = keypair {
        // In a real implementation, would pass the keypair to the wallet
        wallet.set_keypair(kp);
    }
    wallet.enable_privacy();
    wallet
}

// Initialize blockchain components
fn init_blockchain() -> (
    Arc<Mutex<blockchain::mempool::Mempool>>,
    Arc<Mutex<blockchain::UTXOSet>>,
) {
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
    let config = networking::NetworkConfig::default();
    Node::new_with_config(config)
}

// Test-specific networking initialization that disables background tasks
#[cfg(test)]
fn init_networking_for_tests() -> Node {
    info!("Initializing networking components for testing...");
    let mut config = networking::NetworkConfig::default();
    
    // Disable features that might start background tasks
    if let Some(ref mut doh_config) = config.doh_config {
        doh_config.enabled = false;
        doh_config.rotate_resolvers = false;
        doh_config.verify_with_multiple_resolvers = false;
    }
    
    // Disable any other long-running tasks or background services
    if let Some(ref mut fps_config) = config.fingerprinting_protection_config {
        fps_config.enabled = false;
    }
    
    // Create a Node with the test-specific configuration
    Node::new_with_config(config)
}

// Start network services
fn start_network_services(
    mempool: Arc<Mutex<blockchain::mempool::Mempool>>,
) -> thread::JoinHandle<()> {
    info!("Starting network services...");
    // Would normally initialize P2P server and client here

    // Simulate network activity in a background thread
    let handle = thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(5));
            // This is where we would process network messages

            // Log timing information using our utility functions
            let start_time = current_time();
            process_mempool(&mempool);
            let elapsed = time_since(start_time);

            // Only log if processing took longer than 1 second
            if elapsed > 1 {
                info!("Mempool processing took {} seconds", elapsed);
            }
        }
    });

    handle
}

// Process transactions in the mempool
fn process_mempool(mempool: &Arc<Mutex<blockchain::mempool::Mempool>>) -> usize {
    let lock = mempool.lock().unwrap();
    // In a real implementation, we would:
    // 1. Get a list of transactions from the mempool
    // 2. Validate each transaction
    // 3. Create a new block with valid transactions
    // 4. Submit the block to the consensus engine

    // For now, just return a placeholder count
    lock.size()
}

// Main application loop
fn run_main_loop(
    mempool: Arc<Mutex<blockchain::mempool::Mempool>>,
    utxo_set: Arc<Mutex<blockchain::UTXOSet>>,
    node: Arc<Mutex<Node>>,
    wallet_integration: Arc<Mutex<WalletIntegration>>,
) {
    info!("Entering main application loop...");

    let start_time = current_time();

    loop {
        // Process any pending tasks
        thread::sleep(Duration::from_secs(1));

        // Periodically process transactions in the mempool
        if time_since(start_time) % 5 == 0 {
            let processed = process_mempool(&mempool);
            if processed > 0 {
                debug!("Processed {} transactions from mempool", processed);
            }
        }

        // Log uptime every minute using our time formatting utility
        let uptime = time_since(start_time);
        if uptime % 60 == 0 && uptime > 0 {
            info!(
                "Node has been running for {}",
                format_time_diff(start_time, false)
            );
            
            // Log mempool size
            info!("Current mempool size: {}", mempool.lock().unwrap().size());
            
            // Log available balance
            if let Ok(integration) = wallet_integration.lock() {
                info!("Available balance: {}", integration.get_balance());
                info!("Pending balance: {}", integration.get_pending_balance());
            }
        }

        // Check if we need to perform hourly maintenance tasks
        if uptime % 3600 == 0 && uptime > 0 {
            perform_maintenance_tasks(&wallet_integration, &node);
        }
    }
}

// Perform periodic maintenance tasks
fn perform_maintenance_tasks(
    wallet_integration: &Arc<Mutex<WalletIntegration>>,
    node: &Arc<Mutex<Node>>,
) {
    debug!("Performing maintenance tasks...");

    // Record the timestamp for this maintenance run
    let maintenance_timestamp = current_time();

    // Validate that the maintenance timestamp is reasonable
    // This could help detect system clock issues
    if !is_timestamp_valid(maintenance_timestamp, 60, 60) {
        error!("System clock may have changed unexpectedly!");
    }
    
    // Wallet maintenance tasks
    debug!("Performing wallet maintenance");
    
    // Create a backup of the wallet
    if let Ok(mut integration) = wallet_integration.lock() {
        match integration.create_backup() {
            Ok(message) => debug!("{}", message),
            Err(e) => error!("Error creating wallet backup: {}", e),
        }
    }
    
    // Node maintenance
    debug!("Performing node maintenance");
    if let Ok(mut node_lock) = node.lock() {
        if let Err(e) = node_lock.maintain_dandelion() {
            error!("Error maintaining Dandelion: {:?}", e);
        }
        
        if let Err(e) = node_lock.process_fluff_queue() {
            error!("Error processing fluff queue: {:?}", e);
        }
    }

    debug!("Maintenance tasks completed");
}

fn main() {
    // Initialize cryptographic components
    let keypair = init_crypto();
    
    // Initialize wallet components
    let wallet = init_wallet(keypair);
    let wallet_arc = Arc::new(RwLock::new(wallet));
    
    // Initialize blockchain components
    let (mempool, utxo_set) = init_blockchain();
    
    // Initialize consensus engine
    let consensus = init_consensus();
    
    // Initialize networking components
    let mut node = init_networking();
    let node_arc = Arc::new(Mutex::new(node));
    
    // Initialize wallet integration
    let mut wallet_integration = WalletIntegration::new(
        wallet_arc.clone(),
        node_arc.clone(),
        mempool.clone(),
        utxo_set.clone(),
    );

    // Create and set up the AdvancedMetadataProtection
    let metadata_protection = Arc::new(RwLock::new(crypto::metadata_protection::AdvancedMetadataProtection::new()));

    // Set metadata protection for wallet integration
    wallet_integration.set_metadata_protection(metadata_protection.clone());

    // Set metadata protection for node
    {
        let mut node = node_arc.lock().unwrap();
        node.set_metadata_protection(metadata_protection.clone());
    }

    // Create a shared wallet integration
    let wallet_integration_arc = Arc::new(Mutex::new(wallet_integration));
    
    // Start network services
    let network_handle = start_network_services(mempool.clone());
    
    // Start wallet services
    let wallet_handle = start_wallet_services(wallet_integration_arc.clone());
    
    // Run the main application loop
    run_main_loop(mempool, utxo_set, node_arc, wallet_integration_arc);
    
    // Wait for services to complete (they won't in practice)
    let _ = network_handle.join();
    let _ = wallet_handle.join();
}

// Start wallet services
fn start_wallet_services(
    wallet_integration: Arc<Mutex<WalletIntegration>>,
) -> thread::JoinHandle<()> {
    info!("Starting wallet services...");
    
    let handle = thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(30));
            
            // Scan for transactions periodically
            let scan_result = {
                let mut integration = wallet_integration.lock().unwrap();
                match integration.scan_mempool_for_stealth_transactions() {
                    Ok(count) => {
                        if count > 0 {
                            info!("Found {} new transactions belonging to this wallet", count);
                        }
                        true
                    },
                    Err(e) => {
                        error!("Error scanning mempool: {}", e);
                        false
                    }
                }
            };
            
            // Generate a report every hour
            let current_time = current_time();
            if current_time % 3600 == 0 {
                if let Ok(integration) = wallet_integration.lock() {
                    let report = integration.generate_activity_report();
                    info!("Wallet Activity Report:\n{}", report);
                }
            }
        }
    });
    
    handle
}
