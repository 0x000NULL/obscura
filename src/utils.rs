use std::time::{SystemTime, UNIX_EPOCH};

/// Get the current time in seconds since the Unix epoch
pub fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

/// Check if a timestamp is within a specific range of the current time
/// 
/// # Arguments
/// * `timestamp` - The timestamp to validate
/// * `max_future_seconds` - The maximum number of seconds the timestamp can be in the future
/// * `max_past_seconds` - The maximum number of seconds the timestamp can be in the past
/// 
/// # Returns
/// `true` if the timestamp is within the acceptable range, `false` otherwise
pub fn is_timestamp_valid(timestamp: u64, max_future_seconds: u64, max_past_seconds: u64) -> bool {
    let now = current_time();
    
    // Check if timestamp is too far in the future
    if timestamp > now + max_future_seconds {
        return false;
    }
    
    // Check if timestamp is too far in the past
    if now > timestamp && now - timestamp > max_past_seconds {
        return false;
    }
    
    true
}

/// Calculate the time elapsed since a given timestamp
/// 
/// # Arguments
/// * `timestamp` - The reference timestamp
/// 
/// # Returns
/// The number of seconds elapsed since the timestamp, or 0 if the timestamp is in the future
pub fn time_since(timestamp: u64) -> u64 {
    let now = current_time();
    if now > timestamp {
        now - timestamp
    } else {
        0
    }
}

/// Format a timestamp for display purposes
/// 
/// # Arguments
/// * `timestamp` - The Unix timestamp to format
/// * `include_seconds` - Whether to include seconds in the formatted string
/// 
/// # Returns
/// A string representing the time difference in a human-readable format
pub fn format_time_diff(timestamp: u64, include_seconds: bool) -> String {
    let diff = time_since(timestamp);
    
    if diff < 60 {
        if include_seconds {
            format!("{} seconds ago", diff)
        } else {
            "just now".to_string()
        }
    } else if diff < 3600 {
        format!("{} minutes ago", diff / 60)
    } else if diff < 86400 {
        format!("{} hours ago", diff / 3600)
    } else {
        format!("{} days ago", diff / 86400)
    }
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
    
    #[test]
    fn test_timestamp_validation() {
        let now = current_time();
        
        // Valid timestamp (current time)
        assert!(is_timestamp_valid(now, 60, 60));
        
        // Invalid timestamp (too far in future)
        assert!(!is_timestamp_valid(now + 120, 60, 60));
        
        // Invalid timestamp (too far in past)
        assert!(!is_timestamp_valid(now - 120, 60, 60));
    }
    
    #[test]
    fn test_time_since() {
        let past_time = current_time() - 100;
        let future_time = current_time() + 100;
        
        assert!(time_since(past_time) > 0);
        assert_eq!(time_since(future_time), 0);
    }
    
    #[test]
    fn test_format_time_diff() {
        let now = current_time();
        
        assert_eq!(format_time_diff(now, false), "just now");
        
        // These tests are simplified since we can't easily test time-based functions
        // In a real test, we might use mocking to control the current time
    }
} 