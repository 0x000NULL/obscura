use std::collections::{HashMap, HashSet, VecDeque};

// Multi-asset staking structures
/// Represents information about a stakable asset in the system
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
pub struct MarketplaceListing {
    /// Unique identifier for the listing
    pub id: String,
    /// Public key of the validator offering delegation
    pub validator: Vec<u8>,
    /// Amount of delegation available
    pub available_delegation: u64,
    /// Minimum delegation amount accepted
    pub min_delegation: u64,
    /// Commission rate charged by the validator
    pub commission_rate: f64,
    /// Duration for which delegations will be locked
    pub lock_period: u64,
    /// Timestamp when the listing was created
    pub creation_time: u64,
    /// Timestamp when the listing expires
    pub expiration_time: u64,
    /// Current status of the listing
    pub status: MarketplaceListingStatus,
    /// Terms and conditions for the delegation
    pub terms: String,
    /// Historical performance data for the validator
    pub performance_history: Vec<(u64, f64)>,  // (timestamp, performance)
}

/// Status of a marketplace listing
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
pub struct MarketplaceOffer {
    /// Unique identifier for the offer
    pub id: String,
    /// ID of the listing this offer is for
    pub listing_id: String,
    /// Public key of the delegator making the offer
    pub delegator: Vec<u8>,
    /// Amount being offered for delegation
    pub amount: u64,
    /// Timestamp when the offer was created
    pub creation_time: u64,
    /// Timestamp when the offer expires
    pub expiration_time: u64,
    /// Current status of the offer
    pub status: MarketplaceOfferStatus,
    /// Whether the delegator has accepted the terms
    pub terms_accepted: bool,
}

/// Status of a marketplace offer
pub enum MarketplaceOfferStatus {
    /// Offer is pending validator approval
    Pending,
    /// Offer has been accepted by the validator
    Accepted,
    /// Offer has been rejected by the validator
    Rejected,
    /// Offer has expired
    Expired,
    /// Offer is under dispute
    Disputed,
    /// Offer has been completed successfully
    Completed,
}

/// Represents a completed transaction in the delegation marketplace
pub struct MarketplaceTransaction {
    /// Unique identifier for the transaction
    pub id: String,
    /// ID of the listing this transaction is for
    pub listing_id: String,
    /// ID of the offer that led to this transaction
    pub offer_id: String,
    /// Public key of the validator
    pub validator: Vec<u8>,
    /// Public key of the delegator
    pub delegator: Vec<u8>,
    /// Amount delegated
    pub amount: u64,
    /// Commission rate agreed upon
    pub commission_rate: f64,
    /// Duration for which the delegation is locked
    pub lock_period: u64,
    /// Timestamp when the transaction was created
    pub creation_time: u64,
    /// Timestamp when the transaction was completed
    pub completion_time: Option<u64>,
    /// Current status of the transaction
    pub status: MarketplaceTransactionStatus,
    /// Amount held in escrow for dispute resolution
    pub escrow_amount: u64,
    /// Timestamp when the escrow will be released
    pub escrow_release_time: Option<u64>,
}

/// Status of a marketplace transaction
pub enum MarketplaceTransactionStatus {
    /// Transaction is active
    Active,
    /// Transaction has been completed
    Completed,
    /// Transaction is under dispute
    Disputed,
    /// Transaction was refunded
    Refunded,
}

/// Represents a dispute in the delegation marketplace
pub struct MarketplaceDispute {
    /// Unique identifier for the dispute
    pub id: String,
    /// ID of the transaction under dispute
    pub transaction_id: String,
    /// Public key of the party initiating the dispute
    pub initiator: Vec<u8>,
    /// Reason for the dispute
    pub reason: String,
    /// Evidence supporting the dispute claim
    pub evidence: Vec<u8>,
    /// Timestamp when the dispute was created
    pub creation_time: u64,
    /// Timestamp when the dispute was resolved
    pub resolution_time: Option<u64>,
    /// Current status of the dispute
    pub status: MarketplaceDisputeStatus,
    /// Resolution details if the dispute has been resolved
    pub resolution: Option<String>,
}

/// Status of a marketplace dispute
pub enum MarketplaceDisputeStatus {
    /// Dispute is open and awaiting review
    Open,
    /// Dispute is being reviewed
    UnderReview,
    /// Dispute has been resolved
    Resolved,
    /// Dispute was dismissed
    Dismissed,
}

// Validator reputation oracle structures
/// Manages the reputation scores of validators
pub struct ReputationOracle {
    /// Committee members responsible for reputation assessments
    pub committee: Vec<Vec<u8>>,
    /// Timestamp of the last committee rotation
    pub last_rotation: u64,
    /// Current reputation scores for validators
    pub reputation_scores: HashMap<Vec<u8>, ReputationScore>,
    /// Pending reputation assessments
    pub pending_assessments: Vec<ReputationAssessment>,
    /// External data sources for reputation information
    pub external_data_sources: Vec<ExternalDataSource>,
    /// Historical reputation scores
    pub reputation_history: HashMap<Vec<u8>, VecDeque<(u64, f64)>>,
}

/// Represents a validator's reputation score
pub struct ReputationScore {
    /// Public key of the validator
    pub validator: Vec<u8>,
    /// Overall reputation score (0.0-1.0)
    pub overall_score: f64,
    /// Score based on validator uptime (0.0-1.0)
    pub uptime_score: f64,
    /// Score based on validator performance (0.0-1.0)
    pub performance_score: f64,
    /// Score based on community feedback (0.0-1.0)
    pub community_score: f64,
    /// Score based on security practices (0.0-1.0)
    pub security_score: f64,
    /// Timestamp of the last score update
    pub last_update: u64,
    /// Confidence level in the score (0.0-1.0)
    pub confidence: f64,
}

/// Represents an assessment of a validator's reputation
pub struct ReputationAssessment {
    /// Public key of the validator being assessed
    pub validator: Vec<u8>,
    /// Public key of the committee member making the assessment
    pub assessor: Vec<u8>,
    /// Category-specific scores
    pub scores: HashMap<String, f64>,
    /// Evidence supporting the assessment
    pub evidence: HashMap<String, Vec<u8>>,
    /// Timestamp of the assessment
    pub timestamp: u64,
    /// Signature of the assessor
    pub signature: Vec<u8>,
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
pub struct CompoundingConfig {
    /// Public key of the staker
    pub staker: Vec<u8>,
    /// Whether auto-compounding is enabled
    pub enabled: bool,
    /// Frequency of compounding operations in seconds
    pub frequency: u64,
    /// Minimum reward amount to trigger compounding
    pub threshold: u64,
    /// Maximum percentage of stake to compound
    pub max_percentage: f64,
    /// Timestamp of the last compounding operation
    pub last_compound_time: u64,
    /// Whether to auto-delegate compounded stake
    pub auto_delegation: bool,
    /// Preferred validator for auto-delegation
    pub preferred_validator: Option<Vec<u8>>,
}

/// Represents a compounding operation
pub struct CompoundingOperation {
    /// Unique identifier for the operation
    pub id: String,
    /// Public key of the staker
    pub staker: Vec<u8>,
    /// Amount of rewards before compounding
    pub reward_amount: u64,
    /// Amount actually compounded
    pub compounded_amount: u64,
    /// Fee charged for the compounding service
    pub fee_amount: u64,
    /// Timestamp of the operation
    pub timestamp: u64,
    /// Status of the operation
    pub status: CompoundingStatus,
    /// Hash of the transaction that executed the compounding
    pub transaction_hash: Option<Vec<u8>>,
}

/// Status of a compounding operation
pub enum CompoundingStatus {
    /// Operation is pending execution
    Pending,
    /// Operation has been completed
    Completed,
    /// Operation failed
    Failed,
}

// Validator set diversity metrics structures
/// Metrics for measuring the diversity of the validator set
pub struct DiversityMetrics {
    /// Timestamp when the metrics were calculated
    pub timestamp: u64,
    /// Score for entity diversity (0.0-1.0)
    pub entity_diversity_score: f64,
    /// Score for geographic diversity (0.0-1.0)
    pub geographic_diversity_score: f64,
    /// Score for stake distribution (0.0-1.0)
    pub stake_distribution_score: f64,
    /// Score for client implementation diversity (0.0-1.0)
    pub client_diversity_score: f64,
    /// Overall diversity score (0.0-1.0)
    pub overall_diversity_score: f64,
    /// Number of validators in the set
    pub validator_count: usize,
    /// Total active stake
    pub active_stake: u64,
    /// Recommendations for improving diversity
    pub recommendations: Vec<String>,
}

/// Information about an entity operating validators
pub struct EntityInfo {
    /// Unique identifier for the entity
    pub id: String,
    /// Name of the entity
    pub name: String,
    /// Set of validators operated by this entity
    pub validators: HashSet<Vec<u8>>,
    /// Total stake controlled by this entity
    pub total_stake: u64,
    /// Percentage of total stake controlled by this entity
    pub stake_percentage: f64,
}

/// Information about a client implementation used by validators
pub struct ClientImplementation {
    /// Unique identifier for the client implementation
    pub id: String,
    /// Name of the client implementation
    pub name: String,
    /// Version of the client implementation
    pub version: String,
    /// Set of validators using this client implementation
    pub validators: HashSet<Vec<u8>>,
    /// Percentage of total stake using this client implementation
    pub stake_percentage: f64,
}

// Geographic distribution structures
/// Represents a geographic region for validator distribution
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
pub struct GeoDistributionReport {
    /// Timestamp when the report was generated
    pub timestamp: u64,
    /// Information about each region
    pub regions: Vec<GeoRegion>,
    /// Overall distribution score (0.0-1.0)
    pub distribution_score: f64,
    /// Whether the minimum number of regions requirement is met
    pub min_regions_met: bool,
    /// Whether the distribution is eligible for bonuses
    pub bonus_eligible: bool,
    /// Recommendations for improving distribution
    pub recommendations: Vec<String>,
}

/// Geographic information for a validator
pub struct ValidatorGeoInfo {
    /// Public key of the validator
    pub validator: Vec<u8>,
    /// ID of the region where the validator is located
    pub region_id: usize,
    /// Country where the validator is located
    pub country: String,
    /// Latitude coordinate
    pub latitude: f64,
    /// Longitude coordinate
    pub longitude: f64,
    /// Timestamp of the last update
    pub last_update: u64,
    /// Whether the location has been verified
    pub verified: bool,
}

// Hardware security structures
/// Information about a validator's hardware security setup
pub struct HardwareSecurityInfo {
    /// Public key of the validator
    pub validator: Vec<u8>,
    /// Security level (0-3)
    pub security_level: u8,
    /// Description of the security setup
    pub description: String,
    /// Method used for attestation
    pub attestation_method: String,
    /// Timestamp of the last attestation
    pub last_attestation: u64,
    /// Timestamp when the next attestation is due
    pub next_attestation_due: u64,
    /// History of attestations
    pub attestation_history: Vec<(u64, bool)>,  // (timestamp, passed)
    /// Bonus percentage for this security level
    pub bonus_percentage: f64,
}

/// Represents an attestation of hardware security
pub struct SecurityAttestation {
    /// Public key of the validator
    pub validator: Vec<u8>,
    /// Timestamp of the attestation
    pub timestamp: u64,
    /// Security level attested
    pub security_level: u8,
    /// Evidence supporting the attestation
    pub evidence: Vec<u8>,
    /// Entity that performed the audit
    pub auditor: Option<String>,
    /// Whether the attestation passed
    pub passed: bool,
    /// Additional notes about the attestation
    pub notes: String,
}

// Formal verification structures
/// Represents a formal verification of a contract
pub struct FormalVerification {
    /// ID of the contract being verified
    pub contract_id: String,
    /// Method used for verification
    pub verification_method: String,
    /// Entity that performed the verification
    pub verifier: String,
    /// Timestamp of the verification
    pub timestamp: u64,
    /// Percentage of code covered by the verification
    pub coverage_percentage: f64,
    /// Whether the verification passed
    pub passed: bool,
    /// Hash of the verification report
    pub report_hash: Vec<u8>,
    /// URL where the report can be accessed
    pub report_url: String,
    /// Timestamp when the verification expires
    pub expiration: u64,
}

/// Represents a contract that has undergone formal verification
pub struct VerifiedContract {
    /// Unique identifier for the contract
    pub id: String,
    /// Name of the contract
    pub name: String,
    /// Version of the contract
    pub version: String,
    /// Hash of the contract code
    pub hash: Vec<u8>,
    /// Current verification status
    pub verification_status: VerificationStatus,
    /// List of verifications performed on this contract
    pub verifications: Vec<FormalVerification>,
    /// Whether the contract is eligible for verification bonuses
    pub bonus_eligible: bool,
}

/// Status of a contract's verification
pub enum VerificationStatus {
    /// Contract has not been verified
    Unverified,
    /// Contract has been partially verified
    PartiallyVerified,
    /// Contract has been fully verified
    FullyVerified,
    /// Verification has expired
    VerificationExpired,
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
            committee: Vec::new(),
            last_rotation: 0,
            reputation_scores: HashMap::new(),
            pending_assessments: Vec::new(),
            external_data_sources: Vec::new(),
            reputation_history: HashMap::new(),
        }
    }
}

impl DiversityMetrics {
    pub fn new() -> Self {
        DiversityMetrics {
            timestamp: 0,
            entity_diversity_score: 0.0,
            geographic_diversity_score: 0.0,
            stake_distribution_score: 0.0,
            client_diversity_score: 0.0,
            overall_diversity_score: 0.0,
            validator_count: 0,
            active_stake: 0,
            recommendations: Vec::new(),
        }
    }
}

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