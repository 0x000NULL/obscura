use std::time::{SystemTime, UNIX_EPOCH};

/// Get the current time in seconds since the Unix epoch
pub fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
} 