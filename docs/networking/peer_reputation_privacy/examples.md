# Peer Reputation Privacy System - Examples and Usage

## 1. Basic Usage Examples

### 1.1 Creating and Managing a Connection Pool

```rust
// Initialize a connection pool with privacy features
let local_features = FeatureFlag::BasicTransactions as u32 | 
                    FeatureFlag::Dandelion as u32;
let privacy_features = PrivacyFeatureFlag::TransactionObfuscation as u32 | 
                      PrivacyFeatureFlag::StealthAddressing as u32;

let pool = ConnectionPool::new(local_features, privacy_features);

// Configure pool settings for testing
#[cfg(test)]
let pool = pool.with_rotation_interval(Duration::from_secs(60))
              .with_max_connections_per_network(3);
```

### 1.2 Managing Peer Reputation

```rust
// Update a peer's reputation with privacy
let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333);

// Record successful connection
pool.record_successful_connection(&peer_addr, Duration::from_millis(100));

// Update reputation with privacy
let new_score = 0.85;
match pool.update_peer_reputation(peer_addr, new_score) {
    Ok(_) => println!("Reputation updated successfully"),
    Err(e) => eprintln!("Failed to update reputation: {}", e),
}

// Get anonymized network statistics
let (mean, std_dev, count) = pool.get_anonymized_reputation_stats();
println!("Network Stats - Mean: {:.2}, StdDev: {:.2}, Count: {}", mean, std_dev, count);
```

## 2. Advanced Usage Scenarios

### 2.1 Privacy-Preserving Peer Selection

```rust
// Select peers with privacy considerations
let mut selected_peers = Vec::new();

// Get a random subset for privacy operations
let peers = pool.select_random_peers(5);
for peer in peers {
    if let Some(score) = pool.get_peer_reputation(peer) {
        // Add noise to selection threshold
        let mut rng = rand::thread_rng();
        let noise = rng.gen_range(-0.05, 0.05);
        let threshold = 0.7 + noise;
        
        if score > threshold {
            selected_peers.push(peer);
        }
    }
}
```

### 2.2 Implementing Custom Privacy Rules

```rust
impl ConnectionPool {
    pub fn apply_privacy_rules(&self, peer: &PeerScore) -> bool {
        // Check minimum peer count for privacy
        let (_, _, count) = self.get_anonymized_reputation_stats();
        if count < MIN_PEERS_FOR_PRIVACY {
            return false;
        }

        // Verify network diversity
        let diversity_score = self.get_network_diversity_score();
        if diversity_score < MIN_DIVERSITY_SCORE {
            return false;
        }

        // Check privacy feature support
        let privacy_features = peer.privacy_features;
        if privacy_features & PrivacyFeatureFlag::TransactionObfuscation as u32 == 0 {
            return false;
        }

        true
    }
}
```

## 3. Testing Scenarios

### 3.1 Testing Reputation Privacy

```rust
#[test]
fn test_reputation_privacy_guarantees() {
    let pool = create_test_connection_pool();
    
    // Add test peers
    let peers: Vec<_> = (0..5).map(|i| create_test_peer(8333 + i)).collect();
    for peer in &peers {
        pool.add_connection(peer.clone(), ConnectionType::Outbound).unwrap();
    }
    
    // Update reputation for first peer
    let test_score = 0.75;
    pool.update_peer_reputation(peers[0].addr, test_score).unwrap();
    
    // Verify privacy guarantees
    let retrieved_score = pool.get_peer_reputation(peers[0].addr).unwrap();
    
    // Score should be within noise bounds
    assert!((retrieved_score - test_score).abs() <= 0.05);
    
    // Verify share distribution
    let shares = pool.get_reputation_shares(peers[0].addr).unwrap();
    assert_eq!(shares.len(), peers.len() - 1);
    
    // Verify statistical privacy
    let (mean, std_dev, count) = pool.get_anonymized_reputation_stats();
    assert!(count >= MIN_PEERS_FOR_STATS);
}
```

### 3.2 Testing Network Diversity

```rust
#[test]
fn test_network_diversity_privacy() {
    let pool = create_test_connection_pool();
    
    // Add peers from different networks
    let ipv4_peer = create_test_peer_ipv4(8333);
    let ipv6_peer = create_test_peer_ipv6(8334);
    let tor_peer = create_test_peer_tor(8335);
    
    pool.add_connection(ipv4_peer.clone(), ConnectionType::Outbound).unwrap();
    pool.add_connection(ipv6_peer.clone(), ConnectionType::Outbound).unwrap();
    pool.add_connection(tor_peer.clone(), ConnectionType::Outbound).unwrap();
    
    // Calculate diversity score
    let diversity_score = pool.get_network_diversity_score();
    assert!(diversity_score >= MIN_DIVERSITY_SCORE);
    
    // Test privacy-preserving peer selection
    let selected = pool.select_outbound_peer().unwrap();
    assert!(pool.is_privacy_preserving_connection(&selected));
}
```

## 4. Error Handling Examples

### 4.1 Handling Privacy-Related Errors

```rust
pub fn handle_reputation_update(
    pool: &ConnectionPool,
    peer: SocketAddr,
    score: f64
) -> Result<(), ReputationError> {
    // Validate input
    if score < 0.0 || score > 1.0 {
        return Err(ReputationError::InvalidScore);
    }
    
    // Check minimum peer requirements
    let (_, _, count) = pool.get_anonymized_reputation_stats();
    if count < MIN_PEERS_FOR_SHARING {
        return Err(ReputationError::InsufficientPeers);
    }
    
    // Try to update with privacy
    match pool.update_peer_reputation(peer, score) {
        Ok(_) => Ok(()),
        Err(e) => {
            log::error!("Failed to update reputation: {}", e);
            Err(ReputationError::UpdateFailed)
        }
    }
}
```

### 4.2 Privacy-Aware Error Messages

```rust
pub enum ReputationError {
    InvalidScore,
    InsufficientPeers,
    UpdateFailed,
    PrivacyViolation,
}

impl fmt::Display for ReputationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidScore => write!(f, "Score out of valid range"),
            Self::InsufficientPeers => write!(f, "Not enough peers for privacy"),
            Self::UpdateFailed => write!(f, "Update operation failed"),
            Self::PrivacyViolation => write!(f, "Operation would violate privacy guarantees"),
        }
    }
}
```

## 5. Performance Optimization Examples

### 5.1 Batch Processing with Privacy

```rust
impl ConnectionPool {
    pub fn batch_update_reputations(
        &self,
        updates: Vec<(SocketAddr, f64)>
    ) -> Result<(), ReputationError> {
        // Ensure minimum peer count
        if updates.len() < MIN_PEERS_FOR_BATCH {
            return Err(ReputationError::InsufficientPeers);
        }
        
        // Process in random order for privacy
        let mut rng = rand::thread_rng();
        let mut shuffled = updates.clone();
        shuffled.shuffle(&mut rng);
        
        // Add timing jitter
        for (peer, score) in shuffled {
            thread::sleep(Duration::from_millis(rng.gen_range(10, 50)));
            self.update_peer_reputation(peer, score)?;
        }
        
        Ok(())
    }
}
```

### 5.2 Caching with Privacy Considerations

```rust
impl ConnectionPool {
    pub fn cache_reputation_stats(&self) -> Result<(), ReputationError> {
        let stats = self.calculate_stats_with_privacy()?;
        
        // Add noise to cache duration
        let mut rng = rand::thread_rng();
        let noise = Duration::from_secs(rng.gen_range(0, 60));
        let cache_duration = Duration::from_secs(300) + noise;
        
        if let Ok(mut cache) = self.stats_cache.write() {
            *cache = (stats, Instant::now() + cache_duration);
        }
        
        Ok(())
    }
}
``` 