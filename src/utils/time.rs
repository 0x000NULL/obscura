use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current time in seconds since the Unix epoch
pub fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

/// Check if a timestamp is within an acceptable range
/// 
/// Returns `true` if the timestamp is within the acceptable range, `false` otherwise
pub fn is_timestamp_valid(timestamp: u64, max_future_seconds: u64, max_past_seconds: u64) -> bool {
    let now = current_time();

    // Check if timestamp is too far in the future
    if timestamp > now && timestamp - now > max_future_seconds {
        return false;
    }

    // Check if timestamp is too far in the past
    if now > timestamp && now - timestamp > max_past_seconds {
        return false;
    }

    true
}

/// Calculate seconds since a given timestamp
/// 
/// Returns 0 if the timestamp is in the future
pub fn time_since(timestamp: u64) -> u64 {
    let now = current_time();
    if now > timestamp {
        now - timestamp
    } else {
        0
    }
}

/// Format a time difference in a human-readable format
pub fn format_time_diff(timestamp: u64, include_seconds: bool) -> String {
    let diff = time_since(timestamp);

    if diff < 60 {
        if include_seconds {
            format!("{} seconds ago", diff)
        } else {
            String::from("just now")
        }
    } else if diff < 3600 {
        format!("{} minutes ago", diff / 60)
    } else if diff < 86400 {
        format!("{} hours ago", diff / 3600)
    } else {
        format!("{} days ago", diff / 86400)
    }
} 