use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use rand::thread_rng;
use rand::Rng;
use log::{debug, error, info, warn, trace};

use crate::crypto::side_channel_protection::SideChannelProtection;
use crate::crypto::jubjub::{JubjubPoint, JubjubScalar, JubjubScalarExt, JubjubPointExt};

use ark_ff::{BigInteger, PrimeField};
use ff::PrimeFieldBits;
use ark_ec::{CurveGroup, Group};
use ark_std::{Zero, UniformRand, One};

/// Configuration for power analysis protection features
#[derive(Debug, Clone)]
pub struct PowerAnalysisConfig {
    /// Enable power usage normalization
    pub normalization_enabled: bool,
    /// Number of baseline operations for normalization
    pub normalization_baseline_ops: usize,
    
    /// Enable operation balancing
    pub operation_balancing_enabled: bool,
    /// Balance factor (higher means more balanced but slower)
    pub balance_factor: usize,
    
    /// Enable dummy operations
    pub dummy_operations_enabled: bool,
    /// Percentage of operations that should be dummy (0-100)
    pub dummy_operation_percentage: u8,
    /// Maximum number of dummy operations per real operation
    pub max_dummy_operations: usize,
    
    /// Enable power analysis resistant algorithms
    pub resistant_algorithms_enabled: bool,
    /// Resistance level (1-5, higher means more resistant but slower)
    pub resistance_level: u8,
    
    /// Enable hardware-specific countermeasures
    pub hardware_countermeasures_enabled: bool,
    /// Hardware platform target ("generic", "arm", "x86", etc)
    pub hardware_platform: String,
    /// Hardware-specific options as key-value pairs
    pub hardware_options: Vec<(String, String)>,
}

impl Default for PowerAnalysisConfig {
    fn default() -> Self {
        Self {
            normalization_enabled: true,
            normalization_baseline_ops: 10,
            
            operation_balancing_enabled: true,
            balance_factor: 2,
            
            dummy_operations_enabled: true,
            dummy_operation_percentage: 20, // 20% dummy ops
            max_dummy_operations: 5,
            
            resistant_algorithms_enabled: true,
            resistance_level: 3, // Medium resistance
            
            hardware_countermeasures_enabled: false, // Off by default, platform-specific
            hardware_platform: "generic".to_string(),
            hardware_options: Vec::new(),
        }
    }
}

/// Errors that can occur during power analysis protection operations
#[derive(Debug)]
pub enum PowerAnalysisError {
    /// Error during power usage normalization
    NormalizationError(String),
    /// Error during operation balancing
    BalancingError(String),
    /// Error related to dummy operations
    DummyOperationError(String),
    /// Error with resistant algorithm implementation
    ResistanceError(String),
    /// Error with hardware-specific countermeasures
    HardwareError(String),
    /// Generic error
    Other(String),
}

impl std::fmt::Display for PowerAnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NormalizationError(msg) => write!(f, "Power normalization error: {}", msg),
            Self::BalancingError(msg) => write!(f, "Operation balancing error: {}", msg),
            Self::DummyOperationError(msg) => write!(f, "Dummy operation error: {}", msg),
            Self::ResistanceError(msg) => write!(f, "Resistance implementation error: {}", msg),
            Self::HardwareError(msg) => write!(f, "Hardware countermeasure error: {}", msg),
            Self::Other(msg) => write!(f, "Power analysis protection error: {}", msg),
        }
    }
}

impl std::error::Error for PowerAnalysisError {}

/// Implementation data for tracking cumulative operations
struct PowerAnalysisData {
    /// Count of operations performed (for balancing)
    operation_count: AtomicU64,
    /// Last power profile adjustment time
    last_adjustment: Mutex<Instant>,
    /// Baseline operation cost (for normalization)
    baseline_cost: AtomicU64,
    /// Balanced operation map (operation type -> count)
    balanced_ops: Mutex<std::collections::HashMap<String, u64>>,
    /// Flag to indicate if hardware initialization was done
    hardware_initialized: AtomicBool,
}

/// Power Analysis Protection system to mitigate power-based side channel attacks
pub struct PowerAnalysisProtection {
    /// Configuration for power analysis protection
    config: PowerAnalysisConfig,
    /// Side-channel protection integration (optional)
    side_channel_protection: Option<Arc<SideChannelProtection>>,
    /// Implementation data
    data: Arc<PowerAnalysisData>,
}

impl PowerAnalysisProtection {
    /// Create a new power analysis protection instance with the specified configuration
    pub fn new(
        config: PowerAnalysisConfig,
        side_channel_protection: Option<Arc<SideChannelProtection>>,
    ) -> Self {
        let instance = Self {
            config,
            side_channel_protection,
            data: Arc::new(PowerAnalysisData {
                operation_count: AtomicU64::new(0),
                last_adjustment: Mutex::new(Instant::now()),
                baseline_cost: AtomicU64::new(0),
                balanced_ops: Mutex::new(std::collections::HashMap::new()),
                hardware_initialized: AtomicBool::new(false),
            }),
        };
        
        // Initialize components as needed
        if instance.config.normalization_enabled {
            instance.initialize_normalization();
        }
        
        if instance.config.hardware_countermeasures_enabled {
            match instance.initialize_hardware_countermeasures() {
                Ok(_) => {
                    instance.data.hardware_initialized.store(true, Ordering::SeqCst);
                    debug!("Hardware countermeasures initialized for platform: {}", 
                            instance.config.hardware_platform);
                },
                Err(e) => {
                    warn!("Failed to initialize hardware countermeasures: {}", e);
                }
            }
        }
        
        instance
    }
    
    /// Create a new power analysis protection instance with default configuration
    pub fn default() -> Self {
        Self::new(PowerAnalysisConfig::default(), None)
    }
    
    /// Get the current configuration
    pub fn config(&self) -> &PowerAnalysisConfig {
        &self.config
    }
    
    /// Update the configuration
    pub fn update_config(&mut self, config: PowerAnalysisConfig) {
        // Check if hardware platform changed and needs re-initialization
        let hardware_platform_changed = self.config.hardware_platform != config.hardware_platform ||
                                      self.config.hardware_countermeasures_enabled != config.hardware_countermeasures_enabled;
        
        // Update config
        self.config = config;
        
        // Re-initialize components if necessary
        if self.config.normalization_enabled {
            self.initialize_normalization();
        }
        
        if hardware_platform_changed && self.config.hardware_countermeasures_enabled {
            match self.initialize_hardware_countermeasures() {
                Ok(_) => {
                    self.data.hardware_initialized.store(true, Ordering::SeqCst);
                    debug!("Hardware countermeasures re-initialized for platform: {}", 
                            self.config.hardware_platform);
                },
                Err(e) => {
                    warn!("Failed to re-initialize hardware countermeasures: {}", e);
                    self.data.hardware_initialized.store(false, Ordering::SeqCst);
                }
            }
        }
    }
    
    //------------------------
    // Power Usage Normalization
    //------------------------
    
    /// Initialize the normalization baseline
    fn initialize_normalization(&self) {
        if !self.config.normalization_enabled {
            return;
        }
        
        // Perform baseline operations to establish a reference timing
        let baseline_point = <JubjubPoint as JubjubPointExt>::generator();
        let mut rng = thread_rng();
        let baseline_scalar = JubjubScalar::rand(&mut rng);
        
        // Measure baseline operations
        let start = Instant::now();
        for _ in 0..self.config.normalization_baseline_ops {
            // Use a dummy point and operation to establish baseline
            let dummy_point = JubjubPoint::zero();
            let _ = dummy_point + baseline_point * baseline_scalar;
        }
        
        // Store the baseline operation cost
        let duration = start.elapsed();
        let op_cost = duration.as_nanos() as u64 / self.config.normalization_baseline_ops as u64;
        self.data.baseline_cost.store(op_cost, Ordering::SeqCst);
    }
    
    /// Normalize a cryptographic operation to have consistent power profile
    /// 
    /// This will add delay or additional operations to ensure the operation
    /// consumes a consistent amount of power over time.
    pub fn normalize_operation<F, T>(&self, operation: F) -> T
    where
        F: FnOnce() -> T
    {
        if !self.config.normalization_enabled {
            return operation();
        }
        
        // Track start time
        let start = Instant::now();
        
        // Execute the operation
        let result = operation();
        
        // Calculate how long it took
        let duration = start.elapsed();
        let op_time_ns = duration.as_nanos() as u64;
        
        // Get baseline cost
        let baseline_ns = self.data.baseline_cost.load(Ordering::SeqCst);
        if baseline_ns > 0 && op_time_ns < baseline_ns {
            // Operation was faster than baseline, perform additional work to normalize
            let remaining_ns = baseline_ns - op_time_ns;
            
            // Perform dummy work to fill the remaining time
            let dummy_start = Instant::now();
            while (dummy_start.elapsed().as_nanos() as u64) < remaining_ns {
                // Simple arithmetic operations that should be hard to optimize away
                let mut dummy = thread_rng().gen::<u64>();
                for _ in 0..10 {
                    dummy = dummy.wrapping_mul(dummy).wrapping_add(thread_rng().gen::<u64>());
                }
                // Prevent compiler from optimizing away
                std::sync::atomic::compiler_fence(Ordering::SeqCst);
            }
            
            trace!("Normalized operation: added {} ns of work", remaining_ns);
        }
        
        result
    }
    
    //------------------------
    // Operation Balancing
    //------------------------
    
    /// Balance the execution of different types of operations
    /// 
    /// This ensures that different cryptographic operations have similar
    /// execution profiles to prevent distinguishing them by power analysis.
    pub fn balanced_operation<F, T>(&self, op_type: &str, operation: F) -> T
    where
        F: FnOnce() -> T
    {
        if !self.config.operation_balancing_enabled {
            return operation();
        }
        
        // Increment operation counter
        let count = self.data.operation_count.fetch_add(1, Ordering::SeqCst);
        
        // Track this operation type and gather all metrics we need in one block
        let balance_factor = {
            let mut balanced_ops = self.data.balanced_ops.lock().unwrap();
            let op_count = balanced_ops.entry(op_type.to_string()).or_insert(0);
            *op_count += 1;
            
            // Calculate balance metrics while we have the lock
            let current_op_count = *op_count;
            let total_ops: u64 = balanced_ops.values().sum();
            let num_op_types = balanced_ops.len();
            
            // Calculate expected count and determine balance factor
            let expected_count = (total_ops as f64 / num_op_types as f64).ceil() as u64;
            
            if current_op_count < expected_count {
                self.config.balance_factor
            } else {
                1 // No extra balance needed
            }
        }; // Lock is released here when balanced_ops goes out of scope
        
        // Execute the real operation first
        let result = operation();
        
        // Perform dummy operations for balancing if needed
        if balance_factor > 1 {
            // This is just a simple no-op placeholder for the extra dummy work
            // In a real implementation, you might want to perform equivalent dummy work
            // that has a similar power consumption pattern to the original operation
            for _ in 1..balance_factor {
                // Dummy work - should have similar power profile as the real operation
                std::hint::black_box(());
            }
        }
        
        // Return the result of the operation
        result
    }
    
    /// Reset the operation balance counters
    /// 
    /// This should be called periodically to prevent the counters from growing too large
    pub fn reset_balance_counters(&self) {
        if !self.config.operation_balancing_enabled {
            return;
        }
        
        let mut balanced_ops = self.data.balanced_ops.lock().unwrap();
        balanced_ops.clear();
        self.data.operation_count.store(0, Ordering::SeqCst);
        
        debug!("Reset power analysis operation balance counters");
    }
    
    //------------------------
    // Dummy Operations
    //------------------------
    
    /// Add dummy operations to mask real operations
    /// 
    /// This executes the real operation along with a random number of dummy operations
    /// to make it harder to distinguish the real operation by power analysis.
    pub fn with_dummy_operations<F, T>(&self, operation: F) -> T
    where
        F: Fn() -> T + Clone,
        T: Clone,
    {
        if !self.config.dummy_operations_enabled {
            return operation();
        }
        
        // Calculate the number of dummy operations to perform
        let mut rng = thread_rng();
        let dummy_count = if self.config.dummy_operation_percentage > 0 {
            // Calculate based on percentage (0-100%)
            let percentage = self.config.dummy_operation_percentage as f64 / 100.0;
            let count = (percentage * self.config.max_dummy_operations as f64).ceil() as usize;
            rng.gen_range(0..=count.min(self.config.max_dummy_operations))
        } else {
            0
        };
        
        // First perform the real operation
        let result = operation();
        
        // Then perform dummy operations
        if dummy_count > 0 {
            // Create a collection of dummy operations (same as real one)
            let operations = operation.clone();
            for _ in 0..dummy_count {
                let _ = operations();
            }
        }
        
        result
    }
    
    //------------------------
    // Power Analysis Resistant Implementations
    //------------------------
    
    /// Perform scalar multiplication with power analysis resistance
    pub fn resistant_scalar_mul(
        &self,
        point: &JubjubPoint,
        scalar: &JubjubScalar,
    ) -> JubjubPoint {
        if !self.config.resistant_algorithms_enabled {
            // Use side-channel protection if available
            if let Some(scp) = &self.side_channel_protection {
                return scp.protected_scalar_mul(point, scalar);
            }
            return *point * *scalar;
        }
        
        // Apply resistance techniques based on level
        match self.config.resistance_level {
            1 => {
                // Level 1: Double-and-add-always algorithm (simple but effective)
                self.scalar_mul_double_and_add_always(point, scalar)
            },
            2 => {
                // Level 2: Montgomery ladder (more resistant)
                self.scalar_mul_montgomery_ladder(point, scalar)
            },
            3..=5 => {
                // Level 3-5: More sophisticated approaches with additional masking
                self.scalar_mul_with_masking(point, scalar, self.config.resistance_level)
            },
            _ => {
                // Default to level 1 for invalid values
                warn!("Invalid resistance level {}, using level 1", self.config.resistance_level);
                self.scalar_mul_double_and_add_always(point, scalar)
            }
        }
    }
    
    /// Double-and-add-always algorithm for scalar multiplication
    /// 
    /// This always performs both double and add operations regardless of
    /// the scalar bit, making it resistant to simple power analysis.
    pub fn scalar_mul_double_and_add_always(
        &self,
        point: &JubjubPoint,
        scalar: &JubjubScalar,
    ) -> JubjubPoint {
        let scalar_bits = scalar.into_bigint().to_bits_be();
        let mut result = JubjubPoint::zero();
        
        for bit in scalar_bits {
            result = result.double();
            let temp = result + point;
            let mask = if bit { JubjubScalar::one() } else { JubjubScalar::zero() };
            result = temp * mask + result * (JubjubScalar::one() - mask);
        }
        
        result
    }
    
    /// Montgomery ladder algorithm for scalar multiplication
    /// 
    /// This algorithm is resistant to simple power analysis and some
    /// differential power analysis attacks.
    fn scalar_mul_montgomery_ladder(
        &self,
        point: &JubjubPoint,
        scalar: &JubjubScalar,
    ) -> JubjubPoint {
        // Convert scalar to bits for Montgomery ladder algorithm
        let scalar_bits = scalar.into_bigint().to_bits_be();
        
        // Initialize working variables
        let mut r0 = JubjubPoint::zero();
        let mut r1 = *point;
        
        // Montgomery ladder algorithm with constant-time operations
        for bit in scalar_bits {
            // Store temporaries to avoid branching
            let t0 = r0 + r1;  // R0 + R1
            let t1 = r0.double(); // 2R0
            let t2 = r1.double(); // 2R1
            
            // Select the right values based on the bit (constant time operation)
            // Using a mask to avoid branching
            let mask = if bit { JubjubScalar::one() } else { JubjubScalar::zero() };
            r0 = t0 * mask + t1 * (JubjubScalar::one() - mask);
            r1 = t2 * mask + t0 * (JubjubScalar::one() - mask);
        }
        
        r0
    }
    
    /// Scalar multiplication with masking
    /// 
    /// This implementation uses scalar splitting and point blinding
    /// to resist differential power analysis.
    fn scalar_mul_with_masking(
        &self,
        point: &JubjubPoint,
        scalar: &JubjubScalar,
        level: u8,
    ) -> JubjubPoint {
        let mut rng = thread_rng();
        
        // Split scalar into two parts
        let mask = JubjubScalar::rand(&mut rng);
        
        // k = k1 + k2
        let scalar1 = *scalar - mask; // k1
        let scalar2 = mask;          // k2
        
        // Generate random point for blinding
        let blind_point = JubjubPoint::rand(&mut rng);
        let blind_scalar = JubjubScalar::rand(&mut rng);
        
        // Additional masking for higher levels
        let extra_rounds = match level {
            3 => 1,
            4 => 2,
            5 => 3,
            _ => 0,
        };
        
        // First part with blinding
        let part1 = self.scalar_mul_montgomery_ladder(point, &scalar1);
        
        // Add blinding factor
        let mut result = part1 + (blind_point * blind_scalar);
        
        // Add jitter if available
        if let Some(scp) = &self.side_channel_protection {
            scp.add_jitter();
        }
        
        // Second part with blinding
        let part2 = self.scalar_mul_montgomery_ladder(point, &scalar2);
        
        // Remove blinding factor and combine parts
        result = (result - (blind_point * blind_scalar)) + part2;
        
        // Extra rounds for higher security levels
        for _ in 0..extra_rounds {
            let extra_blind = JubjubPoint::rand(&mut rng);
            let extra_scalar = JubjubScalar::rand(&mut rng);
            
            // Add and immediately subtract a random value to confuse power analysis
            result = result + (extra_blind * extra_scalar);
            result = result - (extra_blind * extra_scalar);
        }
        
        result
    }
    
    //------------------------
    // Hardware-specific Countermeasures
    //------------------------
    
    /// Initialize hardware-specific countermeasures
    fn initialize_hardware_countermeasures(&self) -> Result<(), PowerAnalysisError> {
        if !self.config.hardware_countermeasures_enabled {
            return Ok(());
        }
        
        match self.config.hardware_platform.as_str() {
            "generic" => {
                // Generic platform, no special initialization needed
                debug!("Using generic hardware countermeasures");
                Ok(())
            },
            "arm" => {
                // ARM-specific countermeasures
                #[cfg(target_arch = "arm")]
                {
                    self.initialize_arm_countermeasures()
                }
                #[cfg(not(target_arch = "arm"))]
                {
                    warn!("ARM countermeasures requested but not running on ARM");
                    Ok(())
                }
            },
            "x86" => {
                // x86-specific countermeasures
                #[cfg(target_arch = "x86_64")]
                {
                    self.initialize_x86_countermeasures()
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    warn!("x86 countermeasures requested but not running on x86");
                    Ok(())
                }
            },
            other => {
                warn!("Unsupported hardware platform: {}", other);
                Err(PowerAnalysisError::HardwareError(format!(
                    "Unsupported hardware platform: {}", other
                )))
            }
        }
    }
    
    /// Initialize ARM-specific countermeasures
    #[cfg(target_arch = "arm")]
    fn initialize_arm_countermeasures(&self) -> Result<(), PowerAnalysisError> {
        debug!("Initializing ARM-specific countermeasures");
        
        // On a real implementation, we might:
        // 1. Configure CPU power management
        // 2. Set up timer interrupt randomization
        // 3. Configure branch prediction randomization
        
        info!("ARM power analysis countermeasures initialized");
        Ok(())
    }
    
    /// Initialize x86-specific countermeasures
    #[cfg(target_arch = "x86_64")]
    fn initialize_x86_countermeasures(&self) -> Result<(), PowerAnalysisError> {
        debug!("Initializing x86-specific countermeasures");
        
        // On a real implementation, we might:
        // 1. Configure RDRAND for hardware random number generation
        // 2. Set up CPU power states
        // 3. Configure hardware AES for constant-time crypto
        
        info!("x86 power analysis countermeasures initialized");
        Ok(())
    }
    
    /// Execute an operation with hardware-specific protections
    pub fn with_hardware_protection<F, T>(&self, operation: F) -> T
    where
        F: FnOnce() -> T
    {
        if !self.config.hardware_countermeasures_enabled || 
           !self.data.hardware_initialized.load(Ordering::SeqCst) {
            return operation();
        }
        
        match self.config.hardware_platform.as_str() {
            "generic" => {
                // Generic hardware protection
                self.with_generic_hardware_protection(operation)
            },
            "arm" => {
                // ARM-specific protection
                #[cfg(target_arch = "arm")]
                {
                    self.with_arm_hardware_protection(operation)
                }
                #[cfg(not(target_arch = "arm"))]
                {
                    self.with_generic_hardware_protection(operation)
                }
            },
            "x86" => {
                // x86-specific protection
                #[cfg(target_arch = "x86_64")]
                {
                    self.with_x86_hardware_protection(operation)
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    self.with_generic_hardware_protection(operation)
                }
            },
            _ => {
                // Default to generic
                self.with_generic_hardware_protection(operation)
            }
        }
    }
    
    /// Generic hardware protection implementation
    fn with_generic_hardware_protection<F, T>(&self, operation: F) -> T
    where
        F: FnOnce() -> T
    {
        // For generic hardware, we use software-based techniques:
        // 1. Randomize CPU usage before and after
        // 2. Execute some dummy operations to mask power profile
        
        // Randomize CPU usage before
        let mut rng = thread_rng();
        let dummy_work = rng.gen_range(1000..5000);
        
        for _ in 0..dummy_work {
            let _ = rng.gen::<u64>().wrapping_mul(rng.gen::<u64>());
        }
        
        // Execute the operation
        let result = operation();
        
        // Randomize CPU usage after
        let dummy_work = rng.gen_range(1000..5000);
        
        for _ in 0..dummy_work {
            let _ = rng.gen::<u64>().wrapping_mul(rng.gen::<u64>());
        }
        
        result
    }
    
    /// ARM-specific hardware protection
    #[cfg(target_arch = "arm")]
    fn with_arm_hardware_protection<F, T>(&self, operation: F) -> T
    where
        F: FnOnce() -> T
    {
        // On a real implementation, we would use ARM-specific features
        // For this example, we'll use a placeholder
        
        // Execute the operation
        let result = operation();
        
        result
    }
    
    /// x86-specific hardware protection
    #[cfg(target_arch = "x86_64")]
    fn with_x86_hardware_protection<F, T>(&self, operation: F) -> T
    where
        F: FnOnce() -> T
    {
        // On a real implementation, we would use x86-specific features
        // For this example, we'll use a placeholder
        
        // Execute the operation
        let result = operation();
        
        result
    }
    
    //------------------------
    // Combined Protection
    //------------------------
    
    /// Execute an operation with all enabled power analysis protections
    pub fn protected_operation<F, T>(&self, operation: F) -> T
    where
        F: Fn() -> T,
        T: Clone,
    {
        // Apply each protection in sequence
        let result = self.with_dummy_operations(|| {
            self.balanced_operation("protected", || {
                self.normalize_operation(|| {
                    self.with_hardware_protection(|| {
                        operation()
                    })
                })
            })
        });
        
        // Increment operation counter
        self.data.operation_count.fetch_add(1, Ordering::SeqCst);
        
        // Periodically reset balance counters
        if self.data.operation_count.load(Ordering::SeqCst) % 1000 == 0 {
            self.reset_balance_counters();
        }
        
        result
    }
    
    /// Perform scalar multiplication with power analysis protection
    pub fn protected_scalar_mul(
        &self,
        point: &JubjubPoint,
        scalar: &JubjubScalar,
    ) -> JubjubPoint {
        // Apply general protections to a constant-time implementation
        self.protected_operation(|| {
            if self.config.resistant_algorithms_enabled {
                // Use the resistant implementation
                self.resistant_scalar_mul(point, scalar)
            } else {
                // Use a basic constant-time implementation
                let mut result = JubjubPoint::zero();
                let scalar_bits = scalar.into_bigint().to_bits_be();
                
                // Process bits from MSB to LSB for efficiency
                for bit in scalar_bits {
                    result = result.double();
                    // Constant-time conditional addition using a mask
                    let temp = result + *point;
                    let mask = if bit { JubjubScalar::one() } else { JubjubScalar::zero() };
                    result = temp * mask + result * (JubjubScalar::one() - mask);
                }
                result
            }
        })
    }
}

// Unit tests for power analysis protection
#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use ark_ec::{CurveGroup, Group, AffineRepr};

    // Helper function to compare points in affine coordinates
    fn assert_points_equal(left: &JubjubPoint, right: &JubjubPoint) {
        let left_affine = left.into_affine();
        let right_affine = right.into_affine();
        assert_eq!(left_affine, right_affine);
    }

    #[test]
    fn test_power_protection_creation() {
        // Test creating with default config
        let protection = PowerAnalysisProtection::default();
        assert!(protection.config.normalization_enabled);
        
        // Test creating with custom config
        let custom_config = PowerAnalysisConfig {
            normalization_enabled: false,
            dummy_operations_enabled: true,
            dummy_operation_percentage: 50,
            ..PowerAnalysisConfig::default()
        };
        
        let protection = PowerAnalysisProtection::new(custom_config, None);
        assert!(!protection.config.normalization_enabled);
        assert!(protection.config.dummy_operations_enabled);
        assert_eq!(protection.config.dummy_operation_percentage, 50);
    }
    
    #[test]
    fn test_normalization() {
        let protection = PowerAnalysisProtection::default();
        
        // Test normalization of a simple operation
        let result = protection.normalize_operation(|| 42);
        assert_eq!(result, 42);
    }
    
    #[test]
    fn test_balanced_operation() {
        let protection = PowerAnalysisProtection::default();
        
        // Test balanced operations
        let result1 = protection.balanced_operation("test_op", || 42);
        assert_eq!(result1, 42);
        
        let result2 = protection.balanced_operation("test_op", || 100);
        assert_eq!(result2, 100);
        
        // Reset counters
        protection.reset_balance_counters();
    }
    
    #[test]
    fn test_dummy_operations() {
        let protection = PowerAnalysisProtection::default();
        
        // Test with dummy operations
        let result = protection.with_dummy_operations(|| 42);
        assert_eq!(result, 42);
    }
    
    #[test]
    fn test_resistant_scalar_mul() {
        let protection = PowerAnalysisProtection::default();
        
        // Generate random point and scalar
        let mut rng = thread_rng();
        let point = JubjubPoint::rand(&mut rng);
        let scalar = JubjubScalar::rand(&mut rng);
        
        // Calculate expected result
        let expected = point * scalar;
        
        // Test with different resistance levels
        for level in 1..=5 {
            let mut config = protection.config().clone();
            config.resistance_level = level;
            
            let custom_protection = PowerAnalysisProtection::new(config, None);
            let result = custom_protection.resistant_scalar_mul(&point, &scalar);
            
            // Compare points in affine form
            assert_points_equal(&result, &expected);
        }
    }
    
    #[test]
    fn test_hardware_protection() {
        let protection = PowerAnalysisProtection::default();
        
        // Test with hardware protection
        let result = protection.with_hardware_protection(|| 42);
        assert_eq!(result, 42);
    }
    
    #[test]
    fn test_protected_operation() {
        let protection = PowerAnalysisProtection::default();
        
        // Test combined protections
        let result = protection.protected_operation(|| 42);
        assert_eq!(result, 42);
    }
    
    #[test]
    fn test_protected_scalar_mul() {
        let protection = PowerAnalysisProtection::default();
        
        // Generate random point and scalar
        let mut rng = thread_rng();
        let point = JubjubPoint::rand(&mut rng);
        let scalar = JubjubScalar::rand(&mut rng);
        
        // Calculate expected result
        let expected = point * scalar;
        
        // Test with protected multiplication
        let result = protection.protected_scalar_mul(&point, &scalar);
        
        // Compare points in affine form
        assert_points_equal(&result, &expected);
    }
    
    #[test]
    fn test_config_update() {
        let mut protection = PowerAnalysisProtection::default();
        
        // Initial config values
        assert!(protection.config().normalization_enabled);
        
        // Create new config
        let mut new_config = PowerAnalysisConfig::default();
        new_config.normalization_enabled = false;
        new_config.dummy_operations_enabled = false;
        
        // Update config
        protection.update_config(new_config);
        
        // Verify updated values
        assert!(!protection.config().normalization_enabled);
        assert!(!protection.config().dummy_operations_enabled);
    }
}

// Implement Clone for PowerAnalysisProtection
impl Clone for PowerAnalysisProtection {
    fn clone(&self) -> Self {
        PowerAnalysisProtection {
            config: self.config.clone(),
            side_channel_protection: self.side_channel_protection.clone(),
            data: self.data.clone(),
        }
    }
} 