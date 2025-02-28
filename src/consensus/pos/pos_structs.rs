use std::collections::{HashMap, HashSet, VecDeque};
use crate::consensus::pos_old::{
    Treasury, Governance, CrossChainStake, InsurancePool, ExitQueue, BftConsensus,
    Stake, ValidatorUpdate, LiquidStakingPool
};
use crate::consensus::sharding::{Shard, CrossShardCommittee, ShardManager};

// Multi-asset staking structures
/// Represents information about a stakable asset in the system
#[derive(Clone, Default)]
pub struct AssetInfo {
    /// Unique identifier for the asset
    pub asset_id: String,
    /// Human-readable name of the asset
    pub name: String,
    /// Symbol/ticker of the asset
    pub symbol: String,
    /// Number of decimal places for the asset
    pub decimals: u8,
    /// Minimum amount required to stake this asset
    pub min_stake: u64,
    /// Weight of this asset in validator selection (higher weight = more influence)
    pub weight: f64,
    /// Exchange rate to the native token
    pub exchange_rate: f64,
    /// Timestamp of the last exchange rate update
    pub last_rate_update: u64,
    /// Total amount of this asset currently staked
    pub total_staked: u64,
    /// Whether this is the native token of the blockchain
    pub is_native: bool,
}

/// Represents a stake consisting of multiple assets
#[derive(Clone, Default)]
pub struct MultiAssetStake {
    /// Public key of the staker
    pub staker: Vec<u8>,
    /// Map of asset ID to staked amount
    pub assets: HashMap<String, u64>,
    /// Timestamp when the stake was created
    pub timestamp: u64,
    /// Timestamp until which the stake is locked
    pub lock_until: u64,
    /// Whether rewards should be automatically compounded
    pub auto_compound: bool,
    /// Timestamp of the last compounding operation
    pub last_compound_time: u64,
}

// Delegation marketplace structures
/// Represents a listing in the delegation marketplace
#[derive(Clone, Debug)]
pub struct MarketplaceListing {
    /// Unique identifier for the listing
    pub id: String,
    /// Public key of the validator offering delegation
    pub validator_id: String,
    /// Amount of delegation available
    pub amount: u64,
    /// Minimum delegation amount accepted
    pub min_delegation: u64,
    /// Commission rate charged by the validator
    pub commission_rate: f64,
    /// Current status of the listing
    pub status: MarketplaceListingStatus,
    /// Timestamp when the listing was created
    pub created_at: u64,
}

/// Status of a marketplace listing
#[derive(Clone, Debug)]
pub enum MarketplaceListingStatus {
    /// Listing is active and accepting delegations
    Active,
    /// Listing has been filled to capacity
    Filled,
    /// Listing has expired
    Expired,
    /// Listing was cancelled by the validator
    Cancelled,
}

/// Represents an offer made by a delegator in response to a listing
#[derive(Clone, Debug)]
pub struct MarketplaceOffer {
    /// Unique identifier for the offer
    pub id: String,
    /// ID of the listing this offer is for
    pub listing_id: String,
    /// Public key of the delegator making the offer
    pub delegator_id: String,
    /// Amount being offered for delegation
    pub amount: u64,
    /// Timestamp when the offer was created
    pub created_at: u64,
    /// Current status of the offer
    pub status: MarketplaceOfferStatus,
}

/// Status of a marketplace offer
#[derive(Clone, Debug)]
pub enum MarketplaceOfferStatus {
    /// Offer is pending validator approval
    Pending,
    /// Offer has been accepted by the validator
    Accepted,
    /// Offer has been rejected by the validator
    Rejected,
    /// Offer has expired
    Expired,
}

/// Represents a completed transaction in the delegation marketplace
#[derive(Clone, Debug)]
pub struct MarketplaceTransaction {
    /// Unique identifier for the transaction
    pub id: String,
    /// ID of the offer that led to this transaction
    pub offer_id: String,
    /// Current status of the transaction
    pub status: MarketplaceTransactionStatus,
    /// Timestamp when the transaction was completed
    pub completed_at: u64,
}

/// Status of a marketplace transaction
#[derive(Clone, Debug)]
pub enum MarketplaceTransactionStatus {
    /// Transaction has been completed
    Completed,
    /// Transaction failed
    Failed,
    /// Transaction is under dispute
    Disputed,
}

/// Represents a dispute in the delegation marketplace
#[derive(Clone, Debug)]
pub struct MarketplaceDispute {
    /// Unique identifier for the dispute
    pub id: String,
    /// ID of the transaction under dispute
    pub transaction_id: String,
    /// Reason for the dispute
    pub reason: String,
    /// Current status of the dispute
    pub status: MarketplaceDisputeStatus,
    /// Timestamp when the dispute was created
    pub created_at: u64,
}

/// Status of a marketplace dispute
#[derive(Clone, Debug)]
pub enum MarketplaceDisputeStatus {
    /// Dispute is open and awaiting review
    Open,
    /// Dispute has been resolved
    Resolved,
    /// Dispute was rejected
    Rejected,
}

// Validator reputation oracle structures
/// Manages the reputation scores of validators
#[derive(Clone, Debug)]
pub struct ReputationOracle {
    /// Unique identifier for the reputation oracle
    pub id: String,
    /// Name of the reputation oracle
    pub name: String,
    /// Weight of this reputation oracle in the overall reputation calculation
    pub weight: f64,
    /// Timestamp of the last update
    pub last_update: u64,
}

/// Represents a validator's reputation score
#[derive(Clone, Debug, Default)]
pub struct ReputationScore {
    /// Total reputation score (0.0-1.0)
    pub total_score: f64,
    /// Number of updates
    pub update_count: u64,
    /// Timestamp of the last update
    pub last_update: u64,
}

impl ReputationScore {
    pub fn update_with_assessment(&mut self, assessment: &ReputationAssessment) {
        self.total_score = (self.total_score * self.update_count as f64 + assessment.score) / (self.update_count + 1) as f64;
        self.update_count += 1;
        self.last_update = assessment.timestamp;
    }
}

/// Represents an assessment of a validator's reputation
#[derive(Clone, Debug)]
pub struct ReputationAssessment {
    /// Public key of the validator being assessed
    pub validator_id: String,
    /// Score based on validator performance (0.0-1.0)
    pub score: f64,
    /// Timestamp of the assessment
    pub timestamp: u64,
    /// ID of the reputation oracle making the assessment
    pub oracle_id: String,
}

/// Represents an external data source for reputation information
pub struct ExternalDataSource {
    /// Unique identifier for the data source
    pub id: String,
    /// Name of the data source
    pub name: String,
    /// URL of the data source API
    pub url: String,
    /// API key for accessing the data source
    pub api_key: Option<String>,
    /// Weight of this data source in the overall reputation calculation
    pub weight: f64,
    /// Timestamp of the last data update
    pub last_update: u64,
    /// Categories of data provided by this source
    pub categories: Vec<String>,
    /// Whether this data source is currently active
    pub active: bool,
}

// Stake compounding automation structures
/// Configuration for automatic compounding of staking rewards
#[derive(Clone, Debug)]
pub struct CompoundingConfig {
    /// Public key of the staker
    pub validator_id: String,
    /// Minimum reward amount to trigger compounding
    pub threshold_amount: u64,
    /// Frequency of compounding operations in seconds
    pub frequency: u64,
    /// Whether auto-compounding is enabled
    pub enabled: bool,
}

/// Represents a compounding operation
#[derive(Clone, Debug)]
pub struct CompoundingOperation {
    /// Unique identifier for the operation
    pub id: String,
    /// Public key of the staker
    pub validator_id: String,
    /// Amount of rewards before compounding
    pub amount: u64,
    /// Timestamp of the operation
    pub timestamp: u64,
}

/// Status of a compounding operation
#[derive(Clone, Debug)]
pub struct CompoundingStatus {
    /// Unique identifier for the operation
    pub operation_id: String,
    /// Whether the operation succeeded
    pub success: bool,
    /// Message associated with the operation
    pub message: String,
    /// Timestamp of the operation
    pub timestamp: u64,
}

// Validator set diversity metrics structures
/// Metrics for measuring the diversity of the validator set
#[derive(Clone, Debug, Default)]
pub struct DiversityMetrics {
    /// Timestamp when the metrics were calculated
    pub last_update: u64,
    /// Score for entity diversity (0.0-1.0)
    pub entity_diversity: f64,
    /// Score for geographic diversity (0.0-1.0)
    pub geographic_diversity: f64,
    /// Score for client implementation diversity (0.0-1.0)
    pub client_diversity: f64,
}

/// Information about an entity operating validators
#[derive(Clone, Debug)]
pub struct EntityInfo {
    /// Unique identifier for the entity
    pub id: String,
    /// Name of the entity
    pub name: String,
    /// Number of validators operated by this entity
    pub validator_count: u64,
    /// Total stake controlled by this entity
    pub total_stake: u64,
}

/// Information about a client implementation used by validators
#[derive(Clone, Debug)]
pub struct ClientImplementation {
    /// Name of the client implementation
    pub name: String,
    /// Version of the client implementation
    pub version: String,
    /// Number of validators using this client implementation
    pub validator_count: u64,
}

// Geographic distribution structures
/// Represents a geographic region for validator distribution
#[derive(Clone, Debug)]
pub struct GeoRegion {
    /// Unique identifier for the region
    pub id: usize,
    /// Name of the region
    pub name: String,
    /// Set of validators in this region
    pub validators: HashSet<Vec<u8>>,
    /// Total stake in this region
    pub total_stake: u64,
    /// Percentage of total stake in this region
    pub stake_percentage: f64,
    /// Target percentage for optimal distribution
    pub target_percentage: f64,
    /// Whether this region is eligible for distribution bonuses
    pub bonus_eligible: bool,
}

/// Report on the geographic distribution of validators
#[derive(Clone, Debug)]
pub struct GeoDistributionReport {
    /// Timestamp when the report was generated
    pub timestamp: u64,
    /// Metrics for measuring the diversity of the validator set
    pub metrics: DiversityMetrics,
    /// Number of validators in the set
    pub validator_count: u64,
    /// Number of entities in the set
    pub entity_count: u64,
}

/// Geographic information for a validator
#[derive(Clone, Debug)]
pub struct ValidatorGeoInfo {
    /// Country where the validator is located
    pub country_code: String,
    /// Region where the validator is located
    pub region: String,
    /// Latitude coordinate
    pub latitude: f64,
    /// Longitude coordinate
    pub longitude: f64,
}

// Hardware security structures
/// Information about a validator's hardware security setup
#[derive(Clone, Debug)]
pub struct HardwareSecurityInfo {
    /// Security level (0-3)
    pub security_level: u32,
    /// TPM version
    pub tpm_version: String,
    /// Whether the validator is in a secure enclave
    pub secure_enclave: bool,
    /// Timestamp of the last attestation
    pub last_attestation: u64,
}

/// Represents an attestation of hardware security
#[derive(Clone, Debug)]
pub struct SecurityAttestation {
    /// Unique identifier for the attestation
    pub id: String,
    /// Public key of the validator
    pub validator_id: String,
    /// Attestation data
    pub attestation_data: String,
    /// Timestamp of the attestation
    pub timestamp: u64,
}

// Formal verification structures
/// Represents a formal verification of a contract
#[derive(Clone, Debug)]
pub struct FormalVerification {
    /// ID of the contract being verified
    pub contract_id: String,
    /// Proof system used for verification
    pub proof_system: String,
    /// Result of the verification
    pub verification_result: bool,
    /// Timestamp of the verification
    pub timestamp: u64,
}

/// Represents a contract that has undergone formal verification
#[derive(Clone, Debug)]
pub struct VerifiedContract {
    /// Unique identifier for the contract
    pub id: String,
    /// Hash of the contract code
    pub code_hash: String,
    /// Whether the contract is verified
    pub is_verified: bool,
    /// Timestamp of the verification
    pub verification_time: u64,
}

/// Status of a contract's verification
#[derive(Clone, Debug)]
pub struct VerificationStatus {
    /// ID of the contract
    pub contract_id: String,
    /// Verification status
    pub status: bool,
    /// Message associated with the verification
    pub message: String,
    /// Timestamp of the verification
    pub timestamp: u64,
}

// Quantum resistance structures
/// Represents a quantum-resistant key pair
pub struct QuantumKeyPair {
    /// Algorithm used for the key pair
    pub algorithm: String,
    /// Public key
    pub public_key: Vec<u8>,
    /// Encrypted private key
    pub encrypted_private_key: Vec<u8>,
    /// Timestamp when the key pair was created
    pub creation_time: u64,
    /// Timestamp when the key pair expires
    pub expiration_time: u64,
    /// Timestamp of the last key rotation
    pub last_rotation: u64,
    /// Number of signatures created with this key pair
    pub signature_count: u64,
}

/// Represents a quantum-resistant signature
pub struct QuantumSignature {
    /// Algorithm used for the signature
    pub algorithm: String,
    /// Public key that created the signature
    pub public_key: Vec<u8>,
    /// The signature itself
    pub signature: Vec<u8>,
    /// Message that was signed
    pub message: Vec<u8>,
    /// Timestamp when the signature was created
    pub timestamp: u64,
}

/// Represents a hybrid signature using both classical and quantum-resistant algorithms
pub struct HybridSignature {
    /// Classical signature component
    pub classical_signature: Vec<u8>,
    /// Quantum-resistant signature component
    pub quantum_signature: Vec<u8>,
    /// Message that was signed
    pub message: Vec<u8>,
    /// Timestamp when the signature was created
    pub timestamp: u64,
}

// Implementation of new() methods for structs that need them
impl ReputationOracle {
    pub fn new() -> Self {
        ReputationOracle {
            id: String::new(),
            name: String::new(),
            weight: 0.0,
            last_update: 0,
        }
    }
}

impl DiversityMetrics {
    pub fn new() -> Self {
        DiversityMetrics {
            last_update: 0,
            entity_diversity: 0.0,
            geographic_diversity: 0.0,
            client_diversity: 0.0,
        }
    }
}

#[derive(Clone, Default)]
pub struct StakingContract {
    // Map of staker public key to their stake
    pub stakes: HashMap<Vec<u8>, Stake>,
    // Map of validator public key to their validator info
    pub validators: HashMap<Vec<u8>, ValidatorInfo>,
    // Set of validators selected for the current epoch
    pub active_validators: HashSet<Vec<u8>>,
    // Current epoch number
    pub current_epoch: u64,
    // Epoch duration in seconds
    pub epoch_duration: u64,
    // Random beacon for validator selection
    pub random_beacon: [u8; 32],
    pub shard_manager: Option<ShardManager>,
    // Performance optimization fields
    pub validator_selection_cache: Option<(Vec<Vec<u8>>, u64)>, // (selected validators, timestamp)
    pub pending_validator_updates: Vec<ValidatorUpdate>,
    pub unclaimed_rewards: HashMap<Vec<u8>, u64>,
    pub last_reward_calculation: u64,
    // Advanced staking fields
    pub liquid_staking_pool: LiquidStakingPool,
    pub treasury: Treasury,
    pub governance: Governance,
    pub cross_chain_stakes: HashMap<Vec<u8>, CrossChainStake>,
    // Validator rotation tracking
    pub last_rotation_time: u64,
    // Fields for performance-based rewards, insurance, and exit queue
    pub insurance_pool: InsurancePool,
    pub exit_queue: ExitQueue,
    pub last_reward_time: u64,
    // Sharded validator sets
    pub shards: Vec<Shard>,
    pub cross_shard_committees: HashMap<(usize, usize), CrossShardCommittee>, // (shard1, shard2) -> committee
    pub last_shard_rotation: u64,
    // Performance metrics tracking
    pub performance_metrics: HashMap<Vec<u8>, Vec<(u64, f64)>>, // Validator -> [(timestamp, score)]
    // BFT consensus fields
    pub bft_consensus: Option<BftConsensus>,
    pub recent_reorgs: VecDeque<u64>, // Timestamps of recent reorgs
    pub known_blocks: HashSet<[u8; 32]>, // Set of known block hashes
    pub highest_finalized_block: u64, // Height of highest finalized block
    
    // Multi-asset staking fields
    pub supported_assets: HashMap<String, AssetInfo>,
    pub multi_asset_stakes: HashMap<Vec<u8>, Vec<MultiAssetStake>>,
    pub asset_exchange_rates: HashMap<String, f64>,
    pub last_exchange_rate_update: u64,
}

#[derive(Clone, Debug)]
pub struct ValidatorInfo {
    pub id: String,
    pub stake: u64,
    pub commission: f64,
    pub uptime: f64,
    pub performance: f64,
    pub last_update: u64,
} 