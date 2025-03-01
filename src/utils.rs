use std::time::{SystemTime, UNIX_EPOCH};

/// Get the current time in seconds since the Unix epoch
pub fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

// Add a simple test to ensure the utility functions are covered
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_time() {
        let time = current_time();
        assert!(time > 0, "Current time should be positive");
    }
} 