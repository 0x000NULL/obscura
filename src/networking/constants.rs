//! Canonical networking constants shared across the networking layer.

use std::time::Duration;

/// Minimum time spent in the stem phase.
pub const STEM_PHASE_MIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time spent in the stem phase.
pub const STEM_PHASE_MAX_TIMEOUT: Duration = Duration::from_secs(30);
