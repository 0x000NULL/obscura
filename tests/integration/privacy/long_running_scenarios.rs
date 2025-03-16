use obscura::{
    blockchain::transaction::Transaction,
    config::{presets::PrivacyLevel, privacy_registry::PrivacyRegistry},
    crypto::{
        bulletproofs::RangeProof,
        pedersen::PedersenCommitment,
        privacy::{SenderPrivacy, ReceiverPrivacy},
        view_key::ViewKey,
    },
    networking::{
        dandelion::DandelionRouter,
        circuit::CircuitRouter,
        timing_obfuscation::TimingObfuscator,
    },
    wallet::stealth_address::StealthAddress,
};

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Test fixture for long-running scenario tests
struct LongRunningTest {
    privacy_config: PrivacyRegistry,
    dandelion_router: DandelionRouter,
    circuit_router: CircuitRouter,
    timing_obfuscator: TimingObfuscator,
}

impl LongRunningTest {
    fn new(privacy_level: PrivacyLevel) -> Self {
        let privacy_config = PrivacyRegistry::from_preset(privacy_level);
        
        let dandelion_router = DandelionRouter::new(
            privacy_config.get_dandelion_config().clone(),
        );
        
        let circuit_router = CircuitRouter::new(
            privacy_config.get_circuit_config().clone(),
        );
        
        let timing_obfuscator = TimingObfuscator::new(
            privacy_config.get_timing_config().clone(),
        );
        
        Self {
            privacy_config,
            dandelion_router,
            circuit_router,
            timing_obfuscator,
        }
    }
    
    fn create_private_transaction(&self, amount: u64) -> Transaction {
        // Create a transaction with default privacy settings
        let mut tx = Transaction::new();
        
        // Apply sender privacy features
        tx.apply_sender_privacy(SenderPrivacy::default());
        
        // Apply receiver privacy features
        tx.apply_receiver_privacy(ReceiverPrivacy::default());
        
        // Create Pedersen commitment for the amount
        let (commitment, blinding_factor) = PedersenCommitment::commit(amount);
        tx.set_amount_commitment(commitment);
        
        // Create range proof to prove amount is positive without revealing it
        let range_proof = RangeProof::prove(amount, blinding_factor);
        tx.set_range_proof(range_proof);
        
        tx
    }
    
    fn propagate_transaction(&self, tx: Transaction) -> bool {
        // Apply timing obfuscation
        let delayed_tx = self.timing_obfuscator.apply_delay(tx);
        
        // Route through Dandelion++ stem phase
        let stem_routed_tx = self.dandelion_router.route_stem_phase(delayed_tx);
        
        // Route through circuit for additional network privacy
        let circuit_routed_tx = self.circuit_router.route_through_circuit(stem_routed_tx);
        
        // Simulate fluff phase broadcast
        self.dandelion_router.broadcast_fluff_phase(circuit_routed_tx)
    }
    
    fn create_and_propagate_transactions(&self, count: usize) -> (usize, Duration) {
        let start_time = Instant::now();
        let mut successful_count = 0;
        
        for i in 0..count {
            let amount = (i as u64 + 1) * 100;
            let tx = self.create_private_transaction(amount);
            
            if self.propagate_transaction(tx) {
                successful_count += 1;
            }
        }
        
        let elapsed = start_time.elapsed();
        (successful_count, elapsed)
    }
    
    fn create_and_propagate_transactions_concurrent(&self, count: usize, threads: usize) -> (usize, Duration) {
        let start_time = Instant::now();
        let successful_count = Arc::new(Mutex::new(0));
        
        let transactions_per_thread = count / threads;
        let mut handles = vec![];
        
        for thread_id in 0..threads {
            let successful_count_clone = Arc::clone(&successful_count);
            let test_clone = self.clone();
            
            let handle = thread::spawn(move || {
                let start = thread_id * transactions_per_thread;
                let end = start + transactions_per_thread;
                
                let mut thread_successful = 0;
                
                for i in start..end {
                    let amount = (i as u64 + 1) * 100;
                    let tx = test_clone.create_private_transaction(amount);
                    
                    if test_clone.propagate_transaction(tx) {
                        thread_successful += 1;
                    }
                }
                
                let mut total_successful = successful_count_clone.lock().unwrap();
                *total_successful += thread_successful;
            });
            
            handles.push(handle);
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        let elapsed = start_time.elapsed();
        let final_count = *successful_count.lock().unwrap();
        
        (final_count, elapsed)
    }
}

// Implement Clone for LongRunningTest to support concurrent testing
impl Clone for LongRunningTest {
    fn clone(&self) -> Self {
        let privacy_config = self.privacy_config.clone();
        
        let dandelion_router = DandelionRouter::new(
            privacy_config.get_dandelion_config().clone(),
        );
        
        let circuit_router = CircuitRouter::new(
            privacy_config.get_circuit_config().clone(),
        );
        
        let timing_obfuscator = TimingObfuscator::new(
            privacy_config.get_timing_config().clone(),
        );
        
        Self {
            privacy_config,
            dandelion_router,
            circuit_router,
            timing_obfuscator,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    #[ignore] // Long-running test, run explicitly
    fn test_many_transactions_sequential() {
        let test = LongRunningTest::new(PrivacyLevel::Medium);
        
        // Create and propagate 100 transactions
        let (successful_count, elapsed) = test.create_and_propagate_transactions(100);
        
        // Verify all transactions were successful
        assert_eq!(successful_count, 100);
        
        // Log performance metrics
        println!("Sequential processing of 100 transactions took: {:?}", elapsed);
        println!("Average time per transaction: {:?}", elapsed / 100);
    }
    
    #[test]
    #[ignore] // Long-running test, run explicitly
    fn test_many_transactions_concurrent() {
        let test = LongRunningTest::new(PrivacyLevel::Medium);
        
        // Create and propagate 100 transactions using 4 threads
        let (successful_count, elapsed) = test.create_and_propagate_transactions_concurrent(100, 4);
        
        // Verify all transactions were successful
        assert_eq!(successful_count, 100);
        
        // Log performance metrics
        println!("Concurrent processing of 100 transactions took: {:?}", elapsed);
        println!("Average time per transaction: {:?}", elapsed / 100);
    }
    
    #[test]
    #[ignore] // Long-running test, run explicitly
    fn test_privacy_level_performance_comparison() {
        // Test with Low privacy level
        let low_test = LongRunningTest::new(PrivacyLevel::Low);
        let (low_count, low_elapsed) = low_test.create_and_propagate_transactions(50);
        
        // Test with Medium privacy level
        let medium_test = LongRunningTest::new(PrivacyLevel::Medium);
        let (medium_count, medium_elapsed) = medium_test.create_and_propagate_transactions(50);
        
        // Test with High privacy level
        let high_test = LongRunningTest::new(PrivacyLevel::High);
        let (high_count, high_elapsed) = high_test.create_and_propagate_transactions(50);
        
        // Verify all transactions were successful
        assert_eq!(low_count, 50);
        assert_eq!(medium_count, 50);
        assert_eq!(high_count, 50);
        
        // Log performance metrics
        println!("Low privacy level: {:?} for 50 transactions", low_elapsed);
        println!("Medium privacy level: {:?} for 50 transactions", medium_elapsed);
        println!("High privacy level: {:?} for 50 transactions", high_elapsed);
        
        // Calculate performance impact of privacy levels
        let medium_overhead = (medium_elapsed.as_millis() as f64 / low_elapsed.as_millis() as f64) - 1.0;
        let high_overhead = (high_elapsed.as_millis() as f64 / low_elapsed.as_millis() as f64) - 1.0;
        
        println!("Medium privacy overhead: {:.2}%", medium_overhead * 100.0);
        println!("High privacy overhead: {:.2}%", high_overhead * 100.0);
    }
    
    #[test]
    #[ignore] // Long-running test, run explicitly
    fn test_continuous_transaction_stream() {
        let test = LongRunningTest::new(PrivacyLevel::Medium);
        let duration = Duration::from_secs(30); // Run for 30 seconds
        
        let start_time = Instant::now();
        let mut transaction_count = 0;
        
        // Create and propagate transactions continuously for the specified duration
        while start_time.elapsed() < duration {
            let tx = test.create_private_transaction(100);
            if test.propagate_transaction(tx) {
                transaction_count += 1;
            }
            
            // Small delay to prevent overwhelming the system
            thread::sleep(Duration::from_millis(50));
        }
        
        let elapsed = start_time.elapsed();
        let transactions_per_second = transaction_count as f64 / elapsed.as_secs_f64();
        
        println!("Processed {} transactions in {:?}", transaction_count, elapsed);
        println!("Transactions per second: {:.2}", transactions_per_second);
        
        // Verify we processed a reasonable number of transactions
        assert!(transaction_count > 0);
    }
    
    #[test]
    #[ignore] // Long-running test, run explicitly
    fn test_view_key_performance_with_many_transactions() {
        let test = LongRunningTest::new(PrivacyLevel::Medium);
        let transaction_count = 100;
        
        // Create transactions
        let mut transactions = Vec::with_capacity(transaction_count);
        let mut view_keys = Vec::with_capacity(transaction_count);
        
        for i in 0..transaction_count {
            let amount = (i as u64 + 1) * 100;
            let tx = test.create_private_transaction(amount);
            let view_key = ViewKey::create_for_transaction(&tx);
            
            transactions.push(tx);
            view_keys.push(view_key);
        }
        
        // Measure view key decryption performance
        let start_time = Instant::now();
        
        for i in 0..transaction_count {
            let decrypted_amount = view_keys[i].decrypt_amount(&transactions[i]);
            assert_eq!(decrypted_amount, (i as u64 + 1) * 100);
        }
        
        let elapsed = start_time.elapsed();
        
        println!("Decrypted {} transactions in {:?}", transaction_count, elapsed);
        println!("Average decryption time: {:?}", elapsed / transaction_count as u32);
    }
    
    #[test]
    #[ignore] // Long-running test, run explicitly
    fn test_stealth_address_scanning_performance() {
        let test = LongRunningTest::new(PrivacyLevel::High);
        let transaction_count = 100;
        
        // Create stealth address
        let stealth_address = StealthAddress::generate();
        
        // Create transactions, with every 5th transaction sent to the stealth address
        let mut transactions = Vec::with_capacity(transaction_count);
        let mut expected_matches = Vec::with_capacity(transaction_count / 5);
        
        for i in 0..transaction_count {
            let amount = (i as u64 + 1) * 100;
            let mut tx = test.create_private_transaction(amount);
            
            if i % 5 == 0 {
                // Set stealth address as recipient for every 5th transaction
                tx.set_stealth_recipient(stealth_address.clone());
                expected_matches.push(i);
            }
            
            transactions.push(tx);
        }
        
        // Measure stealth address scanning performance
        let start_time = Instant::now();
        let mut found_matches = Vec::new();
        
        for i in 0..transaction_count {
            if stealth_address.scan_for_transaction(&transactions[i]) {
                found_matches.push(i);
            }
        }
        
        let elapsed = start_time.elapsed();
        
        // Verify correct transactions were found
        assert_eq!(found_matches, expected_matches);
        
        println!("Scanned {} transactions in {:?}", transaction_count, elapsed);
        println!("Found {} matching transactions", found_matches.len());
        println!("Average scanning time: {:?}", elapsed / transaction_count as u32);
    }
}