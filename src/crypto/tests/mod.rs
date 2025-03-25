// Register test modules
pub mod hash_tests;
pub mod key_tests;
pub mod privacy_tests;
pub mod pedersen_tests;
pub mod curve_vectors;
mod metadata_protection_test;
mod zk_key_management_tests;
pub mod vss_test;
pub mod privacy_primitives_tests;
pub mod pedersen_commitment_tests;
pub mod side_channel_protection_tests;
pub mod memory_protection_tests;
pub mod improved_side_channel_tests;
pub mod audit_integration_tests;
pub mod audit_tests;
pub mod audit_external_tests;

#[cfg(test)]
mod bullet_proofs_tests;

#[cfg(test)]
mod constant_time_tests;

#[cfg(test)]
mod jubjub_tests;

#[cfg(test)]
mod hardware_accel_tests;

// Re-export test utilities
pub mod test_utils; 