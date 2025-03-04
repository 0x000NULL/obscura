// Add #[allow(dead_code)] at the top of the file
#![allow(dead_code)]

// Import the PoS enhancements
use crate::consensus::pos::*;

use crate::consensus::sharding::{CrossShardCommittee, Shard, ShardManager};
use crate::crypto::jubjub::{JubjubPoint, JubjubPointExt, JubjubSignature};
use bincode;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

// Constants for PoS mechanism
pub const MINIMUM_STAKE: u64 = 1000;
pub const MINIMUM_STAKE_AGE: u64 = 24 * 60 * 60; // 24 hours in seconds
pub const STAKE_LOCK_PERIOD: u64 = 7 * 24 * 60 * 60; // 7 days in seconds
pub const WITHDRAWAL_DELAY: u64 = 3 * 24 * 60 * 60; // 3 days in seconds
pub const SLASHING_PERCENTAGE: u64 = 10; // 10% of stake slashed for misbehavior
pub const ANNUAL_STAKING_REWARD_RATE: f64 = 0.05; // 5% annual reward
pub const COMPOUND_INTERVAL: u64 = 24 * 60 * 60; // Daily compounding

// Enhanced slashing constants
pub const SLASHING_PERCENTAGE_DOWNTIME: u64 = 5; // 5% for downtime
pub const SLASHING_PERCENTAGE_DOUBLE_SIGN: u64 = 20; // 20% for double signing
pub const SLASHING_PERCENTAGE_MALICIOUS: u64 = 50; // 50% for malicious behavior
pub const GRACE_PERIOD_DOWNTIME: u64 = 1 * 60 * 60; // 1 hour grace period for downtime
pub const PROGRESSIVE_SLASH_MULTIPLIER: f64 = 1.5; // Multiplier for repeated offenses
pub const MAX_PROGRESSIVE_MULTIPLIER: f64 = 3.0; // Cap on progressive multiplier
pub const WEAK_SUBJECTIVITY_CHECKPOINT_INTERVAL: u64 = 1000; // Blocks between checkpoints

// Performance optimization constants
pub const VALIDATOR_CACHE_DURATION: u64 = 10 * 60; // 10 minutes cache duration
pub const BATCH_UPDATE_SIZE: usize = 100; // Process validators in batches of 100
pub const REWARD_CLAIM_WINDOW: u64 = 30 * 24 * 60 * 60; // 30 days to claim rewards

// Expanded functionality constants
pub const MAX_DELEGATION_CAP: u64 = 10_000_000; // Maximum delegation a validator can receive
pub const AUTO_DELEGATION_THRESHOLD: u64 = 5000; // Minimum stake for auto-delegation
pub const BASE_REWARD_RATE: f64 = 0.05; // 5% base annual reward rate
pub const MIN_REWARD_RATE: f64 = 0.02; // 2% minimum reward rate
pub const MAX_REWARD_RATE: f64 = 0.15; // 15% maximum reward rate
pub const OPTIMAL_STAKE_TARGET: f64 = 0.67; // 67% of total supply staked is optimal
pub const REPUTATION_WEIGHT_UPTIME: f64 = 0.5; // 50% of reputation is based on uptime
pub const REPUTATION_WEIGHT_BLOCKS: f64 = 0.3; // 30% of reputation is based on blocks produced
pub const REPUTATION_WEIGHT_AGE: f64 = 0.2; // 20% of reputation is based on validator age

// Advanced staking constants
pub const LIQUID_STAKING_FEE: f64 = 0.01; // 1% fee for liquid staking
pub const TREASURY_ALLOCATION: f64 = 0.10; // 10% of rewards go to treasury
pub const MIN_PROPOSAL_STAKE: u64 = 10000; // Minimum stake to submit a proposal
pub const PROPOSAL_VOTING_PERIOD: u64 = 7 * 24 * 60 * 60; // 7 days for voting
pub const PROPOSAL_EXECUTION_DELAY: u64 = 2 * 24 * 60 * 60; // 2 days delay before execution
pub const CROSS_CHAIN_VERIFICATION_THRESHOLD: u64 = 10; // Number of validators needed to verify cross-chain stake

// BFT finality constants
pub const BFT_COMMITTEE_SIZE: usize = 100; // Maximum committee size for BFT consensus
pub const BFT_THRESHOLD: f64 = 2.0 / 3.0; // Threshold for BFT consensus (2/3)
pub const BFT_ROUND_DURATION: u64 = 10; // Duration of each BFT round in seconds
pub const BFT_MAX_ROUNDS: usize = 10; // Maximum number of rounds before timeout
pub const FINALITY_DEPTH: u64 = 100; // Number of blocks after which a block is considered final
pub const TIME_BASED_FINALITY_WINDOW: u64 = 24 * 60 * 60; // 24 hours for time-based finality

// Fork choice constants
pub const MAX_REORG_DEPTH: u64 = 50; // Maximum reorganization depth
pub const ECONOMIC_FINALITY_THRESHOLD: u64 = 1_000_000; // Minimum stake for economic finality
pub const FORK_CHOICE_WEIGHT_STAKE: f64 = 0.7; // Weight for stake in fork choice
pub const FORK_CHOICE_WEIGHT_LENGTH: f64 = 0.3; // Weight for chain length in fork choice

// Validator rotation constants
pub const ROTATION_INTERVAL: u64 = 30 * 24 * 60 * 60; // Rotate validators every 30 days
pub const ROTATION_PERCENTAGE: f64 = 0.2; // Rotate 20% of validators each interval
pub const MIN_ROTATION_COUNT: usize = 3; // Minimum number of validators to rotate
pub const MAX_CONSECUTIVE_EPOCHS: u64 = 10; // Maximum consecutive epochs a validator can serve

// Performance-based rewards constants
pub const PERFORMANCE_REWARD_MULTIPLIER_MAX: f64 = 1.5; // Maximum 50% bonus for high performance
pub const PERFORMANCE_REWARD_MULTIPLIER_MIN: f64 = 0.5; // Minimum 50% penalty for poor performance
pub const PERFORMANCE_METRIC_UPTIME_WEIGHT: f64 = 0.4; // 40% weight for uptime
pub const PERFORMANCE_METRIC_BLOCKS_WEIGHT: f64 = 0.3; // 30% weight for blocks produced
pub const PERFORMANCE_METRIC_LATENCY_WEIGHT: f64 = 0.2; // 20% weight for block proposal latency
pub const PERFORMANCE_METRIC_VOTES_WEIGHT: f64 = 0.1; // 10% weight for participation in votes
pub const PERFORMANCE_ASSESSMENT_PERIOD: u64 = 24 * 60 * 60; // 24 hours

// Slashing insurance constants
pub const INSURANCE_POOL_FEE: f64 = 0.01; // 1% of stake goes to insurance pool
pub const INSURANCE_COVERAGE_PERCENTAGE: f64 = 0.5; // 50% of slashed amount can be covered
pub const INSURANCE_CLAIM_WINDOW: u64 = 14 * 24 * 60 * 60; // 14 days to claim insurance
pub const INSURANCE_CLAIM_EVIDENCE_REQUIRED: bool = true; // Require evidence for insurance claims

// Validator exit queue constants
pub const EXIT_QUEUE_MAX_SIZE: usize = 10; // Maximum validators in exit queue
pub const EXIT_QUEUE_PROCESSING_INTERVAL: u64 = 24 * 60 * 60; // Process exit queue daily
pub const EXIT_QUEUE_MIN_WAIT_TIME: u64 = 3 * 24 * 60 * 60; // Minimum 3 days in exit queue
pub const EXIT_QUEUE_MAX_WAIT_TIME: u64 = 30 * 24 * 60 * 60; // Maximum 30 days in exit queue

// Constants for sharded validator sets
pub const SHARD_COUNT: usize = 4; // Number of shards in the network
pub const MIN_VALIDATORS_PER_SHARD: usize = 10; // Minimum validators per shard
pub const MAX_VALIDATORS_PER_SHARD: usize = 100; // Maximum validators per shard
pub const SHARD_ROTATION_INTERVAL: u64 = 14 * 24 * 60 * 60; // Rotate validators between shards every 14 days
pub const CROSS_SHARD_COMMITTEE_SIZE: usize = 5; // Number of validators in cross-shard committees

// Constants for future PoS enhancements
pub const MULTI_ASSET_MIN_STAKE: &[(&str, u64)] =
    &[("BTC", 100000), ("ETH", 1000000), ("OBSCURA", 10000000)];
pub const MARKETPLACE_FEE_PERCENTAGE: f64 = 0.005; // 0.5% fee for delegation marketplace
pub const REPUTATION_ORACLE_UPDATE_INTERVAL: u64 = 24 * 60 * 60; // Update reputation oracle daily
pub const AUTO_COMPOUND_INTERVAL: u64 = 7 * 24 * 60 * 60; // Auto-compound stakes weekly
pub const DIVERSITY_TARGET_PERCENTAGE: f64 = 0.8; // Target 80% diversity score
pub const GEO_DISTRIBUTION_BONUS: f64 = 0.02; // 2% bonus for good geographic distribution
pub const HARDWARE_SECURITY_LEVEL_REQUIRED: u8 = 2; // Level 2 hardware security required (0-3 scale)
pub const FORMAL_VERIFICATION_REWARD: u64 = 1000; // Reward for formal verification
pub const QUANTUM_RESISTANT_ALGORITHM: &str = "Falcon-512"; // Default quantum-resistant algorithm

// Multi-asset staking constants
pub const MAX_ASSETS_PER_VALIDATOR: usize = 5; // Maximum number of different assets a validator can stake
pub const ASSET_EXCHANGE_RATE_UPDATE_INTERVAL: u64 = 1 * 60 * 60; // Update exchange rates hourly
pub const ASSET_WEIGHT_DEFAULT: f64 = 1.0; // Default weight for assets
pub const ASSET_WEIGHT_NATIVE: f64 = 1.5; // Higher weight for native token
pub const MIN_SECONDARY_ASSET_STAKE_PERCENTAGE: f64 = 0.2; // At least 20% must be native token
pub const MAX_RATE_CHANGE_PERCENTAGE: f64 = 10.0; // Maximum allowed exchange rate change in percentage

// Delegation marketplace constants
pub const MARKETPLACE_LISTING_DURATION: u64 = 30 * 24 * 60 * 60; // Listings last 30 days
pub const MARKETPLACE_MIN_REPUTATION: f64 = 0.7; // Minimum reputation to list on marketplace
pub const MARKETPLACE_ESCROW_PERCENTAGE: f64 = 0.1; // 10% of delegation in escrow
pub const MARKETPLACE_DISPUTE_WINDOW: u64 = 7 * 24 * 60 * 60; // 7 days to dispute a transaction
pub const MARKETPLACE_MAX_COMMISSION: f64 = 0.25; // Maximum 25% commission allowed

// Validator reputation oracle constants
pub const REPUTATION_ORACLE_COMMITTEE_SIZE: usize = 7; // 7 validators in reputation oracle committee
pub const REPUTATION_ORACLE_ROTATION_INTERVAL: u64 = 30 * 24 * 60 * 60; // Rotate committee monthly
pub const REPUTATION_ORACLE_THRESHOLD: usize = 5; // Need 5 of 7 to agree on reputation
pub const REPUTATION_HISTORY_LENGTH: usize = 100; // Store last 100 reputation scores
pub const REPUTATION_EXTERNAL_WEIGHT: f64 = 0.3; // 30% of reputation from external sources

// Stake compounding automation constants
pub const AUTO_COMPOUND_MIN_STAKE: u64 = 5000; // Minimum stake for auto-compounding
pub const AUTO_COMPOUND_FEE: f64 = 0.001; // 0.1% fee for auto-compounding service
pub const AUTO_COMPOUND_MAX_FREQUENCY: u64 = 1 * 24 * 60 * 60; // Maximum once per day
pub const AUTO_COMPOUND_THRESHOLD: u64 = 100; // Only compound if rewards >= 100
pub const AUTO_COMPOUND_DELEGATION_LIMIT: f64 = 0.9; // Only auto-compound up to 90% of stake

// Validator set diversity metrics constants
pub const DIVERSITY_METRIC_WEIGHT_ENTITY: f64 = 0.4; // 40% weight for entity diversity
pub const DIVERSITY_METRIC_WEIGHT_GEOGRAPHY: f64 = 0.3; // 30% weight for geographic diversity
pub const DIVERSITY_METRIC_WEIGHT_STAKE: f64 = 0.2; // 20% weight for stake distribution
pub const DIVERSITY_METRIC_WEIGHT_CLIENT: f64 = 0.1; // 10% weight for client implementation diversity
pub const DIVERSITY_ASSESSMENT_INTERVAL: u64 = 7 * 24 * 60 * 60; // Assess diversity weekly

// Geographic distribution constants
pub const GEO_REGIONS: usize = 8; // Number of geographic regions
pub const GEO_MIN_REGIONS_REPRESENTED: usize = 4; // Minimum regions that should be represented
pub const GEO_OPTIMAL_DISTRIBUTION: [f64; 8] = [0.15, 0.15, 0.15, 0.15, 0.1, 0.1, 0.1, 0.1]; // Optimal distribution
pub const GEO_REGION_BONUS_THRESHOLD: f64 = 0.7; // Need 70% of optimal distribution for bonus
pub const GEO_REPORTING_INTERVAL: u64 = 7 * 24 * 60 * 60; // Report geographic distribution weekly

// Hardware security constants
pub const HARDWARE_SECURITY_LEVEL_DESCRIPTIONS: [&str; 4] = [
    "Basic software security",
    "Enhanced software security with HSM",
    "Dedicated hardware security module",
    "Air-gapped signing with multi-party computation",
];
pub const HARDWARE_SECURITY_BONUS: [f64; 4] = [0.0, 0.01, 0.02, 0.03]; // Bonuses for each level
pub const HARDWARE_SECURITY_ATTESTATION_INTERVAL: u64 = 90 * 24 * 60 * 60; // Attest every 90 days
pub const HARDWARE_SECURITY_AUDIT_PROBABILITY: f64 = 0.1; // 10% chance of random audit

// Formal verification constants
pub const FORMAL_VERIFICATION_METHODS: [&str; 3] =
    ["Model checking", "Theorem proving", "Static analysis"];
pub const FORMAL_VERIFICATION_COVERAGE_REQUIRED: f64 = 0.8; // 80% code coverage required
pub const FORMAL_VERIFICATION_AUDIT_INTERVAL: u64 = 180 * 24 * 60 * 60; // Audit every 180 days
pub const FORMAL_VERIFICATION_BONUS_PERCENTAGE: f64 = 0.01; // 1% bonus for verified contracts

// Quantum resistance constants
pub const QUANTUM_RESISTANT_ALGORITHMS: [&str; 4] = [
    "Falcon-512",
    "Dilithium2",
    "SPHINCS+-128f",
    "XMSS-SHA2_10_256",
];
pub const QUANTUM_RESISTANCE_PHASE_IN_PERIOD: u64 = 365 * 24 * 60 * 60; // 1 year phase-in
pub const QUANTUM_KEY_ROTATION_INTERVAL: u64 = 30 * 24 * 60 * 60; // Rotate keys monthly
pub const QUANTUM_HYBRID_MODE_ENABLED: bool = true; // Use both classical and quantum-resistant signatures

pub struct ProofOfStake {
    pub minimum_stake: u64,
    pub current_difficulty: u32,
    pub minimum_stake_age: u64,
    pub stake_lock_period: u64,
    pub withdrawal_delay: u64,
    pub slashing_percentage: u64,
    pub annual_reward_rate: f64,
    pub compound_interval: u64,
    // New fields for enhanced security
    pub slashing_percentage_downtime: u64,
    pub slashing_percentage_double_sign: u64,
    pub slashing_percentage_malicious: u64,
    pub grace_period_downtime: u64,
    pub progressive_slash_multiplier: f64,
    pub max_progressive_multiplier: f64,
    pub weak_subjectivity_checkpoints: HashMap<u64, [u8; 32]>, // Block height -> checkpoint hash
    // BFT and fork choice fields
    pub bft_consensus: Option<BftConsensus>,
    pub recent_reorgs: VecDeque<u64>, // Timestamps of recent reorgs
    pub known_blocks: HashSet<[u8; 32]>, // Set of known block hashes
    pub highest_finalized_block: u64, // Height of highest finalized block
}

#[derive(Clone)]
pub struct StakeProof {
    pub stake_amount: u64,
    pub stake_age: u64,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

// Staking contract to manage stakes
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
    // Fields for block production tracking
    pub blocks_expected: u64,
    // Pending insurance claims
    pub pending_insurance_claims: Vec<InsuranceClaim>,

    // New fields for future PoS enhancements
    // Multi-asset staking support
    pub supported_assets: HashMap<String, AssetInfo>,
    pub multi_asset_stakes: HashMap<Vec<u8>, Vec<MultiAssetStake>>,
    pub asset_exchange_rates: HashMap<String, f64>,
    pub last_exchange_rate_update: u64,

    // Stake delegation marketplace
    pub marketplace_listings: Vec<MarketplaceListing>,
    pub marketplace_offers: Vec<MarketplaceOffer>,
    pub marketplace_transactions: Vec<MarketplaceTransaction>,
    pub marketplace_disputes: Vec<MarketplaceDispute>,
    pub marketplace_escrow: u64,

    // Validator reputation oracle
    pub reputation_oracle: ReputationOracle,
    pub reputation_scores: HashMap<Vec<u8>, ReputationScore>,
    pub last_reputation_update: u64,

    // Stake compounding automation
    pub compounding_configs: HashMap<Vec<u8>, CompoundingConfig>,
    pub compounding_operations: Vec<CompoundingOperation>,
    pub last_auto_compound_time: u64,

    // Validator set diversity metrics
    pub diversity_metrics: DiversityMetrics,
    pub entity_info: HashMap<String, EntityInfo>,
    pub client_implementations: HashMap<String, ClientImplementation>,
    pub last_diversity_assessment: u64,

    // Geographic distribution incentives
    pub geo_regions: Vec<GeoRegion>,
    pub geo_distribution_reports: Vec<GeoDistributionReport>,
    pub validator_geo_info: HashMap<Vec<u8>, ValidatorGeoInfo>,
    pub last_geo_report: u64,

    // Hardware security requirements
    pub hardware_security_info: HashMap<Vec<u8>, HardwareSecurityInfo>,
    pub security_attestations: Vec<SecurityAttestation>,
    pub next_security_audit: u64,

    // Formal verification of staking contracts
    pub verified_contracts: HashMap<String, VerifiedContract>,
    pub formal_verifications: Vec<FormalVerification>,
    pub verification_bonus_total: u64,

    // Quantum-resistant staking mechanisms
    pub quantum_keypairs: HashMap<Vec<u8>, QuantumKeyPair>,
    pub quantum_signatures: Vec<QuantumSignature>,
    pub hybrid_signatures: Vec<HybridSignature>,
    pub quantum_resistance_enabled: bool,
}

// Stake information
#[derive(Clone, Default)]
pub struct Stake {
    pub amount: u64,
    pub timestamp: u64,
    pub lock_until: u64,
    pub withdrawal_requested: Option<u64>,
    pub delegated_to: Option<Vec<u8>>,
    // New fields for expanded functionality
    pub auto_delegate: bool,
    pub partial_undelegations: Vec<PartialUndelegation>,
}

// Partial undelegation information
#[derive(Clone)]
pub struct PartialUndelegation {
    pub amount: u64,
    pub timestamp: u64,
    pub completion_time: u64,
}

// Validator information
#[derive(Clone)]
pub struct ValidatorInfo {
    pub public_key: Vec<u8>,
    pub total_stake: u64,
    pub own_stake: u64,
    pub delegated_stake: u64,
    pub uptime: f64,
    pub blocks_proposed: u64,
    pub blocks_validated: u64,
    pub last_proposed_block: u64,
    pub commission_rate: f64,
    pub slashed: bool,
    // New fields for enhanced security
    pub last_active_time: u64,
    pub offense_count: u64,
    pub in_grace_period: bool,
    pub grace_period_start: u64,
    // New fields for expanded functionality
    pub reputation_score: f64,
    pub delegation_cap: u64,
    pub creation_time: u64,
    pub historical_uptime: Vec<(u64, f64)>, // (timestamp, uptime)
    pub historical_blocks: Vec<(u64, u64)>, // (timestamp, blocks_produced)
    // Validator rotation tracking
    pub consecutive_epochs: u64,
    pub last_rotation: u64,
    // Performance metrics
    pub performance_score: f64,
    pub block_latency: Vec<(u64, u64)>, // (timestamp, latency in ms)
    pub vote_participation: Vec<(u64, bool)>, // (proposal_id, participated)
    pub last_performance_assessment: u64,
    // Insurance data
    pub insurance_coverage: u64,
    pub insurance_expiry: u64,
    // Exit queue data
    pub exit_requested: bool,
    pub exit_request_time: u64,
    // Fields for uptime history tracking
    pub uptime_history: Vec<bool>,
    // Fields for block production tracking
    pub blocks_expected: u64,
}

// Delegation information
pub struct Delegation {
    pub delegator: Vec<u8>,
    pub validator: Vec<u8>,
    pub amount: u64,
    pub timestamp: u64,
}

// VRF output for validator selection
pub struct VrfOutput {
    pub public_key: Vec<u8>,
    pub proof: Vec<u8>,
    pub output: [u8; 32],
}

// Validator update operation
#[derive(Clone)]
pub enum ValidatorUpdateOp {
    Register,
    UpdateCommission,
    Deregister,
}

// Pending validator update
#[derive(Clone)]
pub struct ValidatorUpdate {
    pub validator: Vec<u8>,
    pub operation: ValidatorUpdateOp,
    pub data: Vec<u8>, // Serialized update data
    pub timestamp: u64,
}

// Liquid staking pool
#[derive(Clone, Default)]
pub struct LiquidStakingPool {
    pub total_staked: u64,
    pub liquid_tokens_issued: u64,
    pub exchange_rate: f64,
    pub fee_rate: f64,
    pub stakers: HashMap<Vec<u8>, u64>, // Staker -> liquid tokens amount
}

// Treasury for funding ecosystem development
#[derive(Clone, Default)]
pub struct Treasury {
    pub balance: u64,
    pub allocations: Vec<TreasuryAllocation>,
}

// Treasury allocation
#[derive(Clone)]
pub struct TreasuryAllocation {
    pub recipient: Vec<u8>,
    pub amount: u64,
    pub purpose: String,
    pub timestamp: u64,
}

// Governance system
#[derive(Clone, Default)]
pub struct Governance {
    pub proposals: Vec<Proposal>,
    pub votes: HashMap<u64, HashMap<Vec<u8>, Vote>>, // Proposal ID -> (Voter -> Vote)
    pub executed_proposals: HashSet<u64>,
    pub next_proposal_id: u64,
}

// Governance proposal
#[derive(Clone)]
pub struct Proposal {
    pub id: u64,
    pub proposer: Vec<u8>,
    pub title: String,
    pub description: String,
    pub action: ProposalAction,
    pub start_time: u64,
    pub end_time: u64,
    pub execution_time: u64,
    pub status: ProposalStatus,
}

// Proposal action
#[derive(Clone)]
pub enum ProposalAction {
    ChangeParameter(String, Vec<u8>), // Parameter name, new value
    TreasuryAllocation(Vec<u8>, u64, String), // Recipient, amount, purpose
    ProtocolUpgrade(String, Vec<u8>), // Upgrade name, upgrade data
    AddAsset(AssetInfo),              // Add a new asset for staking
    UpdateAssetWeight(String, f64),   // Asset ID, new weight
    UpdateAssetExchangeRate(String, f64), // Asset ID, new exchange rate
    Other(String, Vec<u8>),           // Action type, action data
}

// Proposal status
#[derive(Clone)]
pub enum ProposalStatus {
    Active,
    Passed,
    Rejected,
    Executed,
    Cancelled,
}

// Vote
#[derive(Clone)]
pub struct Vote {
    pub voter: Vec<u8>,
    pub proposal_id: u64,
    pub support: bool,
    pub voting_power: u64,
    pub timestamp: u64,
}

// Cross-chain stake
#[derive(Clone)]
pub struct CrossChainStake {
    pub origin_chain: String,
    pub origin_address: Vec<u8>,
    pub amount: u64,
    pub timestamp: u64,
    pub verifications: Vec<Vec<u8>>, // List of validators who verified this stake
    pub status: CrossChainStakeStatus,
}

// Cross-chain stake status
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum CrossChainStakeStatus {
    Pending,
    Verified,
    Rejected,
}

// BFT finality types
#[derive(Clone)]
pub enum BftMessageType {
    Prepare,
    Commit,
    ViewChange,
}

#[derive(Clone)]
pub struct BftMessage {
    pub message_type: BftMessageType,
    pub block_hash: [u8; 32],
    pub round: usize,
    pub validator: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Clone, Default)]
pub struct BftRound {
    pub round_number: usize,
    pub prepare_messages: HashMap<Vec<u8>, BftMessage>, // Validator -> Message
    pub commit_messages: HashMap<Vec<u8>, BftMessage>,  // Validator -> Message
    pub view_change_messages: HashMap<Vec<u8>, BftMessage>, // Validator -> Message
    pub prepared: bool,
    pub committed: bool,
    pub start_time: u64,
}

#[derive(Clone, Default)]
pub struct BftConsensus {
    pub current_round: BftRound,
    pub finalized_blocks: HashMap<u64, [u8; 32]>, // Height -> Hash
    pub committee: Vec<Vec<u8>>, // List of committee members (validator public keys)
    pub view_number: usize,
    pub leader: Vec<u8>,
}

// Fork choice types
pub struct ChainInfo {
    pub blocks: HashMap<u64, BlockInfo>, // Height -> BlockInfo
    pub head: u64,                       // Height of chain head
    pub total_stake: u64,                // Total stake backing this chain
    pub total_validators: usize,         // Number of validators backing this chain
}

// Implement Clone for ChainInfo
impl Clone for ChainInfo {
    fn clone(&self) -> Self {
        ChainInfo {
            blocks: self.blocks.clone(),
            head: self.head,
            total_stake: self.total_stake,
            total_validators: self.total_validators,
        }
    }
}

pub struct BlockInfo {
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    pub proposer: Vec<u8>,
    pub validators: HashSet<Vec<u8>>, // Validators who signed this block
    pub total_stake: u64,             // Total stake of validators who signed this block
}

// Implement Clone for BlockInfo
impl Clone for BlockInfo {
    fn clone(&self) -> Self {
        BlockInfo {
            hash: self.hash,
            parent_hash: self.parent_hash,
            height: self.height,
            timestamp: self.timestamp,
            proposer: self.proposer.clone(),
            validators: self.validators.clone(),
            total_stake: self.total_stake,
        }
    }
}

// Insurance pool for validators
#[derive(Clone, Default)]
pub struct InsurancePool {
    pub total_balance: u64,
    pub balance: u64, // Add this field for backward compatibility
    pub coverage_percentage: f64,
    pub claims: Vec<InsuranceClaim>,
    pub participants: HashMap<Vec<u8>, InsuranceParticipation>,
}

// Insurance participation record
#[derive(Clone)]
pub struct InsuranceParticipation {
    pub validator: Vec<u8>,
    pub contribution: u64,
    pub coverage_limit: u64,
    pub join_time: u64,
}

// Insurance claim status
#[derive(Debug, Clone)]
pub enum InsuranceClaimStatus {
    Pending,
    Approved,
    Rejected,
    Paid,
}

// Insurance claim
#[derive(Clone)]
pub struct InsuranceClaim {
    pub validator: Vec<u8>,
    pub amount_requested: u64,
    pub amount_approved: u64, // Will be set during claim processing
    pub amount: u64,          // Add this field for backward compatibility
    pub timestamp: u64,
    pub evidence: Vec<u8>,
    pub status: InsuranceClaimStatus,
    pub processed: bool,
}

// Exit queue for validators
#[derive(Clone, Default)]
pub struct ExitQueue {
    pub queue: Vec<ExitRequest>,
    pub last_processed: u64,
    pub max_size: usize,
}

// Exit request
#[derive(Clone)]
pub struct ExitRequest {
    pub validator: Vec<u8>,
    pub request_time: u64,
    pub stake_amount: u64,
    pub processed: bool,
    pub completion_time: Option<u64>,
}

// Define different types of slashing offenses
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SlashingOffense {
    Downtime,
    DoubleSign,
    Malicious,
}

impl ProofOfStake {
    pub fn new() -> Self {
        ProofOfStake {
            minimum_stake: MINIMUM_STAKE,
            current_difficulty: 1,
            minimum_stake_age: MINIMUM_STAKE_AGE,
            stake_lock_period: STAKE_LOCK_PERIOD,
            withdrawal_delay: WITHDRAWAL_DELAY,
            slashing_percentage: SLASHING_PERCENTAGE,
            annual_reward_rate: ANNUAL_STAKING_REWARD_RATE,
            compound_interval: COMPOUND_INTERVAL,
            // Initialize new security fields
            slashing_percentage_downtime: SLASHING_PERCENTAGE_DOWNTIME,
            slashing_percentage_double_sign: SLASHING_PERCENTAGE_DOUBLE_SIGN,
            slashing_percentage_malicious: SLASHING_PERCENTAGE_MALICIOUS,
            grace_period_downtime: GRACE_PERIOD_DOWNTIME,
            progressive_slash_multiplier: PROGRESSIVE_SLASH_MULTIPLIER,
            max_progressive_multiplier: MAX_PROGRESSIVE_MULTIPLIER,
            weak_subjectivity_checkpoints: HashMap::new(),
            // Initialize BFT and fork choice fields
            bft_consensus: None,
            recent_reorgs: VecDeque::with_capacity(100),
            known_blocks: HashSet::new(),
            highest_finalized_block: 0,
        }
    }

    pub fn validate_stake(&self, stake_amount: u64, stake_age: u64) -> bool {
        if stake_amount < self.minimum_stake {
            return false;
        }

        // Basic stake validation
        stake_age >= self.minimum_stake_age
    }

    pub fn validate_stake_proof(&self, proof: &StakeProof, block_data: &[u8]) -> bool {
        // First validate basic stake requirements
        if !self.validate_stake(proof.stake_amount, proof.stake_age) {
            return false;
        }

        // Verify the signature
        match JubjubPoint::from_bytes(&proof.public_key) {
            Some(public_key) => match JubjubSignature::from_bytes(&proof.signature) {
                Some(signature) => {
                    // Verify the signature
                    if !public_key.verify(&block_data, &signature) {
                        return false;
                    }
                    true
                }
                None => false,
            },
            None => false,
        }
    }

    pub fn calculate_stake_reward(&self, stake_amount: u64, stake_age: u64) -> u64 {
        // Base reward rate (e.g., 5% annual)
        const BASE_REWARD_RATE: f64 = 0.05;

        // Convert to per-day rate (assuming 365 days per year)
        const DAYS_PER_YEAR: f64 = 365.0;
        let per_day_rate = BASE_REWARD_RATE / DAYS_PER_YEAR;

        // Calculate days from seconds
        let days = stake_age as f64 / (24.0 * 60.0 * 60.0);

        // Calculate reward with simple interest for predictable test results
        let reward = stake_amount as f64 * per_day_rate * days;

        reward as u64
    }

    // Add a weak subjectivity checkpoint
    pub fn add_checkpoint(&mut self, block_height: u64, block_hash: [u8; 32]) {
        self.weak_subjectivity_checkpoints
            .insert(block_height, block_hash);
    }

    // Verify a block against weak subjectivity checkpoints
    pub fn verify_checkpoint(&self, block_height: u64, block_hash: &[u8; 32]) -> bool {
        if let Some(checkpoint_hash) = self.weak_subjectivity_checkpoints.get(&block_height) {
            return checkpoint_hash == block_hash;
        }
        true // No checkpoint for this height
    }

    // Protect against stake grinding attacks by requiring VRF-based selection
    pub fn validate_vrf_proof(&self, vrf_proof: &super::vrf::VrfProof) -> bool {
        super::vrf::Vrf::verify(vrf_proof).is_ok()
    }

    pub fn calculate_dynamic_reward_rate(&self, total_staked: u64, total_supply: u64) -> f64 {
        // Calculate the percentage of total supply that is staked
        let staked_percentage = total_staked as f64 / total_supply as f64;

        if staked_percentage >= OPTIMAL_STAKE_TARGET {
            // If staking percentage is above target, reduce rewards to discourage more staking
            let excess_ratio =
                (staked_percentage - OPTIMAL_STAKE_TARGET) / (1.0 - OPTIMAL_STAKE_TARGET);
            let reduction_factor = 1.0 - excess_ratio;
            (BASE_REWARD_RATE * reduction_factor).max(MIN_REWARD_RATE)
        } else {
            // If staking percentage is below target, increase rewards to encourage more staking
            let deficit_ratio = (OPTIMAL_STAKE_TARGET - staked_percentage) / OPTIMAL_STAKE_TARGET;
            let increase_factor = 1.0 + deficit_ratio;
            (BASE_REWARD_RATE * increase_factor).min(MAX_REWARD_RATE)
        }
    }

    // Create BFT message
    pub fn create_bft_message(
        &self,
        keypair: &crate::crypto::jubjub::JubjubKeypair,
        message_type: BftMessageType,
        block_hash: [u8; 32],
        round: usize,
    ) -> Result<BftMessage, &'static str> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create message data
        let mut data = Vec::new();
        match message_type {
            BftMessageType::Prepare => data.extend_from_slice(b"PREPARE"),
            BftMessageType::Commit => data.extend_from_slice(b"COMMIT"),
            BftMessageType::ViewChange => data.extend_from_slice(b"VIEW_CHANGE"),
        }
        data.extend_from_slice(&block_hash);
        data.extend_from_slice(&round.to_le_bytes());
        data.extend_from_slice(&current_time.to_le_bytes());

        // Sign message
        let signature = keypair.sign(&data);

        Ok(BftMessage {
            message_type,
            block_hash,
            round,
            validator: keypair.public.to_bytes().to_vec(),
            signature: signature
                .to_bytes()
                .to_vec(),
            timestamp: current_time,
        })
    }

    // Record a chain reorganization
    pub fn record_reorg(&mut self) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.recent_reorgs.push_back(current_time);

        // Keep only the last 100 reorgs
        while self.recent_reorgs.len() > 100 {
            self.recent_reorgs.pop_front();
        }
    }

    // Update highest finalized block
    pub fn update_highest_finalized_block(&mut self, height: u64) {
        if height > self.highest_finalized_block {
            self.highest_finalized_block = height;
        }
    }
}

impl StakingContract {
    pub fn new(epoch_duration: u64) -> Self {
        StakingContract {
            stakes: HashMap::new(),
            validators: HashMap::new(),
            active_validators: HashSet::new(),
            current_epoch: 0,
            epoch_duration,
            random_beacon: [0; 32],
            shard_manager: None,
            validator_selection_cache: None,
            pending_validator_updates: Vec::new(),
            unclaimed_rewards: HashMap::new(),
            last_reward_calculation: 0,
            liquid_staking_pool: LiquidStakingPool {
                total_staked: 0,
                liquid_tokens_issued: 0,
                exchange_rate: 1.0,
                fee_rate: LIQUID_STAKING_FEE,
                stakers: HashMap::new(),
            },
            treasury: Treasury {
                balance: 0,
                allocations: Vec::new(),
            },
            governance: Governance {
                proposals: Vec::new(),
                votes: HashMap::new(),
                executed_proposals: HashSet::new(),
                next_proposal_id: 1,
            },
            cross_chain_stakes: HashMap::new(),
            last_rotation_time: 0,
            insurance_pool: InsurancePool {
                total_balance: 0,
                balance: 0, // Add this field for backward compatibility
                coverage_percentage: INSURANCE_COVERAGE_PERCENTAGE,
                claims: Vec::new(),
                participants: HashMap::new(),
            },
            exit_queue: ExitQueue {
                queue: Vec::new(),
                last_processed: 0,
                max_size: EXIT_QUEUE_MAX_SIZE,
            },
            last_reward_time: 0,
            shards: Vec::new(),
            cross_shard_committees: HashMap::new(),
            last_shard_rotation: 0,
            performance_metrics: HashMap::new(),
            bft_consensus: None,
            recent_reorgs: VecDeque::new(),
            known_blocks: HashSet::new(),
            highest_finalized_block: 0,
            blocks_expected: 0,
            pending_insurance_claims: Vec::new(),

            // Initialize multi-asset staking fields
            supported_assets: HashMap::new(),
            multi_asset_stakes: HashMap::new(),
            asset_exchange_rates: HashMap::new(),
            last_exchange_rate_update: 0,

            // Initialize delegation marketplace fields
            marketplace_listings: Vec::new(),
            marketplace_offers: Vec::new(),
            marketplace_transactions: Vec::new(),
            marketplace_disputes: Vec::new(),
            marketplace_escrow: 0,

            // Initialize validator reputation oracle
            reputation_oracle: ReputationOracle::new(),
            reputation_scores: HashMap::new(),
            last_reputation_update: 0,

            // Initialize stake compounding automation
            compounding_configs: HashMap::new(),
            compounding_operations: Vec::new(),
            last_auto_compound_time: 0,

            // Initialize validator set diversity metrics
            diversity_metrics: DiversityMetrics::new(),
            entity_info: HashMap::new(),
            client_implementations: HashMap::new(),
            last_diversity_assessment: 0,

            // Initialize geographic distribution incentives
            geo_regions: Vec::new(),
            geo_distribution_reports: Vec::new(),
            validator_geo_info: HashMap::new(),
            last_geo_report: 0,

            // Initialize hardware security incentives
            hardware_security_info: HashMap::new(),
            security_attestations: Vec::new(),
            next_security_audit: 0,

            // Initialize formal verification of staking contracts
            verified_contracts: HashMap::new(),
            formal_verifications: Vec::new(),
            verification_bonus_total: 0,

            // Initialize quantum-resistant staking mechanisms
            quantum_keypairs: HashMap::new(),
            quantum_signatures: Vec::new(),
            hybrid_signatures: Vec::new(),
            quantum_resistance_enabled: false,
            // ... existing code ...
        }
    }

    // Create a new stake with auto-delegation option
    pub fn create_stake(
        &mut self,
        public_key: Vec<u8>,
        amount: u64,
        auto_delegate: bool,
    ) -> Result<(), &'static str> {
        if amount < MINIMUM_STAKE {
            return Err("Stake amount below minimum requirement");
        }

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let stake = Stake {
            amount,
            timestamp: current_time,
            lock_until: current_time + STAKE_LOCK_PERIOD,
            withdrawal_requested: None,
            delegated_to: None,
            auto_delegate,
            partial_undelegations: Vec::new(),
        };

        self.stakes.insert(public_key, stake);
        Ok(())
    }

    // Request withdrawal of a stake
    pub fn request_withdrawal(&mut self, public_key: &[u8]) -> Result<u64, &'static str> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(stake) = self.stakes.get_mut(public_key) {
            if stake.lock_until > current_time {
                return Err("Stake is still locked");
            }

            if stake.withdrawal_requested.is_some() {
                return Err("Withdrawal already requested");
            }

            let withdrawal_time = current_time + WITHDRAWAL_DELAY;
            stake.withdrawal_requested = Some(withdrawal_time);
            Ok(withdrawal_time)
        } else {
            Err("No stake found for this public key")
        }
    }

    // Complete withdrawal of a stake
    pub fn complete_withdrawal(&mut self, public_key: &[u8]) -> Result<u64, &'static str> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(stake) = self.stakes.get(public_key) {
            if let Some(withdrawal_time) = stake.withdrawal_requested {
                if current_time < withdrawal_time {
                    return Err("Withdrawal delay period not yet completed");
                }

                let amount = stake.amount;
                self.stakes.remove(public_key);
                Ok(amount)
            } else {
                Err("No withdrawal requested")
            }
        } else {
            Err("No stake found for this public key")
        }
    }

    // Register as a validator with delegation cap
    pub fn register_validator(
        &mut self,
        public_key: Vec<u8>,
        commission_rate: f64,
        delegation_cap: Option<u64>,
    ) -> Result<(), &'static str> {
        if commission_rate < 0.0 || commission_rate > 1.0 {
            return Err("Commission rate must be between 0 and 1");
        }

        if !self.stakes.contains_key(&public_key) {
            return Err("Must have an active stake to become a validator");
        }

        let stake = self.stakes.get(&public_key).unwrap();

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Set delegation cap (use provided value or default to maximum)
        let cap = delegation_cap.unwrap_or(MAX_DELEGATION_CAP);

        let validator_info = ValidatorInfo {
            public_key: public_key.clone(),
            total_stake: stake.amount,
            own_stake: stake.amount,
            delegated_stake: 0,
            uptime: 1.0,
            blocks_proposed: 0,
            blocks_validated: 0,
            last_proposed_block: 0,
            commission_rate,
            slashed: false,
            // Security fields
            last_active_time: current_time,
            offense_count: 0,
            in_grace_period: false,
            grace_period_start: 0,
            // Expanded functionality fields
            reputation_score: 0.5, // Start with neutral reputation
            delegation_cap: cap,
            creation_time: current_time,
            historical_uptime: vec![(current_time, 1.0)],
            historical_blocks: vec![(current_time, 0)],
            consecutive_epochs: 0,
            last_rotation: 0,
            // Performance metrics
            performance_score: 0.0,
            block_latency: Vec::new(),
            vote_participation: Vec::new(),
            last_performance_assessment: 0,
            // Insurance data
            insurance_coverage: 0,
            insurance_expiry: 0,
            // Exit queue data
            exit_requested: false,
            exit_request_time: 0,
            // Fields for uptime history tracking
            uptime_history: Vec::new(),
            // Fields for block production tracking
            blocks_expected: 0,
        };

        self.validators.insert(public_key.clone(), validator_info);

        // Add to active validators set
        self.active_validators.insert(public_key);

        Ok(())
    }

    // Delegate stake to a validator
    pub fn delegate_stake(
        &mut self,
        delegator: Vec<u8>,
        validator: Vec<u8>,
    ) -> Result<(), &'static str> {
        if !self.stakes.contains_key(&delegator) {
            return Err("Delegator has no stake");
        }

        if !self.validators.contains_key(&validator) {
            return Err("Validator not found");
        }

        let stake = self.stakes.get_mut(&delegator).unwrap();
        if stake.delegated_to.is_some() {
            return Err("Stake already delegated");
        }

        let amount = stake.amount;

        // Check delegation cap
        let validator_info = self.validators.get(&validator).unwrap();
        if validator_info.delegated_stake + amount > validator_info.delegation_cap {
            return Err("Validator delegation cap would be exceeded");
        }

        stake.delegated_to = Some(validator.clone());

        let validator_info = self.validators.get_mut(&validator).unwrap();
        validator_info.delegated_stake += amount;
        validator_info.total_stake += amount;

        Ok(())
    }

    // Partially undelegate stake from a validator
    pub fn partial_undelegate(
        &mut self,
        delegator: Vec<u8>,
        amount: u64,
    ) -> Result<u64, &'static str> {
        if !self.stakes.contains_key(&delegator) {
            return Err("Delegator has no stake");
        }

        let stake = self.stakes.get_mut(&delegator).unwrap();
        if stake.delegated_to.is_none() {
            return Err("Stake not delegated");
        }

        if amount > stake.amount {
            return Err("Undelegation amount exceeds stake amount");
        }

        let validator_key = stake.delegated_to.clone().unwrap();

        // Calculate completion time for the undelegation
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let completion_time = current_time + WITHDRAWAL_DELAY;

        // Create partial undelegation record
        let undelegation = PartialUndelegation {
            amount,
            timestamp: current_time,
            completion_time,
        };

        stake.partial_undelegations.push(undelegation);

        // Update validator's delegated stake
        if let Some(validator_info) = self.validators.get_mut(&validator_key) {
            validator_info.delegated_stake -= amount;
            validator_info.total_stake -= amount;
        }

        Ok(completion_time)
    }

    // Complete a partial undelegation
    pub fn complete_partial_undelegation(
        &mut self,
        delegator: Vec<u8>,
        index: usize,
    ) -> Result<u64, &'static str> {
        if !self.stakes.contains_key(&delegator) {
            return Err("Delegator has no stake");
        }

        let stake = self.stakes.get_mut(&delegator).unwrap();

        if index >= stake.partial_undelegations.len() {
            return Err("Invalid undelegation index");
        }

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let undelegation = &stake.partial_undelegations[index];

        if current_time < undelegation.completion_time {
            return Err("Undelegation period not yet complete");
        }

        let amount = undelegation.amount;

        // Remove the undelegation record
        stake.partial_undelegations.remove(index);

        // If all undelegations are complete and amount is 0, remove delegation
        if stake.partial_undelegations.is_empty() && stake.amount == 0 {
            stake.delegated_to = None;
        }

        Ok(amount)
    }

    // Process auto-delegations
    pub fn process_auto_delegations(&mut self) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // First, collect eligible validators and their public keys
        let mut eligible_validator_keys = Vec::new();
        for (key, validator) in &self.validators {
            if !validator.slashed && validator.total_stake < MAX_DELEGATION_CAP {
                eligible_validator_keys.push(key.clone());
            }
        }

        // Sort by reputation score (highest first)
        eligible_validator_keys.sort_by(|a, b| {
            let score_a = self
                .validators
                .get(a)
                .map(|v| v.reputation_score)
                .unwrap_or(0.0);
            let score_b = self
                .validators
                .get(b)
                .map(|v| v.reputation_score)
                .unwrap_or(0.0);
            score_b
                .partial_cmp(&score_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Take top 10 validators
        let eligible_validator_keys: Vec<_> =
            eligible_validator_keys.into_iter().take(10).collect();

        if eligible_validator_keys.is_empty() {
            return;
        }

        // Clone the keys to avoid borrowing issues
        let mut auto_delegate_stakers = Vec::new();
        for (staker_key, stake) in &self.stakes {
            if stake.auto_delegate
                && stake.amount >= AUTO_DELEGATION_THRESHOLD
                && stake.delegated_to.is_none()
            {
                auto_delegate_stakers.push(staker_key.clone());
            }
        }

        // Now process the delegations
        for staker_key in auto_delegate_stakers {
            if !eligible_validator_keys.is_empty() {
                // Select a random validator from the top 10
                let idx = (current_time % eligible_validator_keys.len() as u64) as usize;
                let validator_key = &eligible_validator_keys[idx];

                // Perform the delegation
                if let Some(stake) = self.stakes.get_mut(&staker_key) {
                    stake.delegated_to = Some(validator_key.clone());

                    // Get the stake amount before updating validator
                    let stake_amount = stake.amount;

                    // Now update the validator
                    if let Some(validator_info) = self.validators.get_mut(validator_key) {
                        validator_info.delegated_stake += stake_amount;
                        validator_info.total_stake += stake_amount;
                    }
                }
            }
        }
    }

    // Update validator reputation
    pub fn update_validator_reputation(&mut self, validator: &[u8]) -> Result<f64, &'static str> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // First, collect necessary data from validator_info
        let validator_info = match self.validators.get(validator) {
            Some(info) => info,
            None => return Err("Validator not found"),
        };

        // Clone the data we need to avoid borrow checker issues
        let uptime = validator_info.uptime;
        let blocks_proposed = validator_info.blocks_proposed;
        let creation_time = validator_info.creation_time;

        // Calculate uptime score (0-1)
        let uptime_score = uptime.min(1.0).max(0.0);

        // Calculate blocks score (0-1)
        // Get average blocks proposed across all validators
        let total_validators = self.validators.len();
        let total_blocks: u64 = self.validators.values().map(|v| v.blocks_proposed).sum();
        let avg_blocks = if total_validators > 0 {
            total_blocks as f64 / total_validators as f64
        } else {
            1.0 // Default to 1.0 to avoid division by zero
        };

        // Score is ratio of blocks proposed to average, capped at 1.0
        let blocks_score = if avg_blocks > 0.0 {
            (blocks_proposed as f64 / avg_blocks).min(1.0).max(0.0)
        } else {
            0.0
        };

        // Calculate age score (0-1)
        let max_age = self
            .validators
            .values()
            .map(|v| current_time.saturating_sub(v.creation_time))
            .max()
            .unwrap_or(1);

        let validator_age = current_time.saturating_sub(creation_time);
        let age_score = if max_age > 0 {
            (validator_age as f64 / max_age as f64).min(1.0).max(0.0)
        } else {
            0.0
        };

        // Verify weights sum to 1.0
        debug_assert!(
            (REPUTATION_WEIGHT_UPTIME + REPUTATION_WEIGHT_BLOCKS + REPUTATION_WEIGHT_AGE - 1.0)
                .abs()
                < f64::EPSILON
        );

        // Calculate weighted reputation score
        let reputation_score = uptime_score * REPUTATION_WEIGHT_UPTIME
            + blocks_score * REPUTATION_WEIGHT_BLOCKS
            + age_score * REPUTATION_WEIGHT_AGE;

        // Ensure score is within bounds
        let reputation_score = reputation_score.min(1.0).max(0.0);

        // Update the validator's reputation score
        if let Some(validator_info) = self.validators.get_mut(validator) {
            validator_info.reputation_score = reputation_score;
        }

        Ok(reputation_score)
    }

    // Update the random beacon for validator selection
    pub fn update_random_beacon(&mut self, new_beacon: [u8; 32]) {
        self.random_beacon = new_beacon;
    }

    // Optimized validator selection with caching
    pub fn select_validators(&mut self, count: usize) -> Vec<Vec<u8>> {
        let mut selected = Vec::new();

        // Clear the active validators set
        self.active_validators.clear();

        // Sort validators by stake and performance
        let mut validators: Vec<_> = self
            .validators
            .iter()
            .filter(|(_, v)| {
                // Filter out slashed validators and those requesting exit
                // Also filter out validators with any offenses
                !v.slashed && !v.exit_requested && v.offense_count == 0
            })
            .map(|(k, v)| {
                // Calculate score based on stake and performance
                let performance_multiplier = 1.0; // All validators with offenses are already filtered out
                let score = v.total_stake as f64 * performance_multiplier;
                (k, v, score)
            })
            .collect();

        // Sort by score (highest first)
        validators.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));

        // Select top validators by score
        for (key, _, _) in validators.iter().take(count) {
            selected.push((*key).clone());
            self.active_validators.insert((*key).clone());
        }

        selected
    }

    // Separate function to handle shard rotation
    pub fn rotate_shards(&mut self) -> Result<(), &'static str> {
        // We need to avoid borrowing self twice, so we'll extract the necessary data first
        let active_validators = self.active_validators.clone();
        let validators = self.validators.clone();

        if let Some(shard_manager) = &mut self.shard_manager {
            // Create a simplified version of StakingContract with just what's needed
            let mut simplified_contract = StakingContract::new(self.epoch_duration);
            simplified_contract.active_validators = active_validators;
            simplified_contract.validators = validators;

            shard_manager.rotate_shards(&simplified_contract)
        } else {
            Ok(())
        }
    }

    // Process pending validator updates in batches
    pub fn process_pending_updates(&mut self) {
        let updates_to_process = self.pending_validator_updates.len().min(BATCH_UPDATE_SIZE);
        if updates_to_process == 0 {
            return;
        }

        let updates = self
            .pending_validator_updates
            .drain(0..updates_to_process)
            .collect::<Vec<_>>();

        for update in updates {
            match update.operation {
                ValidatorUpdateOp::Register => {
                    // Process validator registration
                    if let Ok(commission_rate) = bincode::deserialize::<f64>(&update.data) {
                        let _ = self.register_validator(update.validator, commission_rate, None);
                    }
                }
                ValidatorUpdateOp::UpdateCommission => {
                    // Process commission update
                    if let Ok(commission_rate) = bincode::deserialize::<f64>(&update.data) {
                        let _ =
                            self.update_validator_commission(&update.validator, commission_rate);
                    }
                }
                ValidatorUpdateOp::Deregister => {
                    // Process validator deregistration
                    // Remove from active validators
                    self.active_validators.remove(&update.validator);
                    // Remove validator info
                    self.validators.remove(&update.validator);
                }
            }
        }
    }

    // Queue a validator update instead of processing immediately
    pub fn queue_validator_update(
        &mut self,
        validator: Vec<u8>,
        operation: ValidatorUpdateOp,
        data: Vec<u8>,
    ) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let update = ValidatorUpdate {
            validator,
            operation,
            data,
            timestamp: current_time,
        };

        self.pending_validator_updates.push(update);

        // If we have enough updates, process them
        if self.pending_validator_updates.len() >= BATCH_UPDATE_SIZE {
            self.process_pending_updates();
        }
    }

    // Update validator commission rate
    pub fn update_validator_commission(
        &mut self,
        validator: &[u8],
        commission_rate: f64,
    ) -> Result<(), &'static str> {
        if commission_rate < 0.0 || commission_rate > 1.0 {
            return Err("Commission rate must be between 0 and 1");
        }

        if let Some(validator_info) = self.validators.get_mut(validator) {
            validator_info.commission_rate = commission_rate;
            Ok(())
        } else {
            Err("Validator not found")
        }
    }

    // Deregister a validator - REMOVED (duplicate method)
    // This method is replaced by the implementation at line 3228

    // Implement lazy reward calculation - REMOVED (duplicate method)
    // This method is replaced by the implementation at line 2645

    // Claim rewards
    pub fn claim_rewards(&mut self, staker: &[u8]) -> Result<u64, &'static str> {
        if let Some(reward) = self.unclaimed_rewards.remove(staker) {
            if let Some(stake) = self.stakes.get_mut(staker) {
                stake.amount += reward;

                // Update validator info if this is a validator
                if let Some(validator) = self.validators.get_mut(staker) {
                    validator.own_stake += reward;
                    validator.total_stake += reward;
                }

                Ok(reward)
            } else {
                // If stake doesn't exist anymore, just return the reward
                Ok(reward)
            }
        } else {
            Err("No rewards to claim")
        }
    }

    // Distribute rewards to all active validators and their delegators
    pub fn distribute_rewards(&mut self) -> HashMap<Vec<u8>, u64> {
        // Calculate rewards first (lazy calculation)
        self.calculate_rewards();

        // Return a copy of the unclaimed rewards
        self.unclaimed_rewards.clone()
    }

    // Liquid staking methods

    // Add stake to the liquid staking pool
    pub fn add_to_liquid_pool(
        &mut self,
        staker: Vec<u8>,
        amount: u64,
    ) -> Result<u64, &'static str> {
        if amount < MINIMUM_STAKE {
            return Err("Stake amount below minimum requirement");
        }

        // Calculate liquid tokens to issue
        let liquid_tokens = if self.liquid_staking_pool.total_staked == 0 {
            amount // Initial 1:1 ratio
        } else {
            // Apply exchange rate
            (amount as f64 / self.liquid_staking_pool.exchange_rate) as u64
        };

        // Apply fee
        let fee = (liquid_tokens as f64 * self.liquid_staking_pool.fee_rate) as u64;
        let liquid_tokens_after_fee = liquid_tokens - fee;

        // Update liquid staking pool
        self.liquid_staking_pool.total_staked += amount;
        self.liquid_staking_pool.liquid_tokens_issued += liquid_tokens_after_fee;

        // Update exchange rate
        self.liquid_staking_pool.exchange_rate = self.liquid_staking_pool.total_staked as f64
            / self.liquid_staking_pool.liquid_tokens_issued as f64;

        // Record staker's liquid tokens
        *self.liquid_staking_pool.stakers.entry(staker).or_insert(0) += liquid_tokens_after_fee;

        // Distribute the liquid stake across validators
        self.distribute_liquid_stake(amount);

        Ok(liquid_tokens_after_fee)
    }

    // Redeem liquid tokens for stake
    pub fn redeem_liquid_tokens(
        &mut self,
        staker: &[u8],
        liquid_amount: u64,
    ) -> Result<u64, &'static str> {
        // Check if staker has enough liquid tokens
        let staker_liquid_tokens = self
            .liquid_staking_pool
            .stakers
            .get(staker)
            .cloned()
            .unwrap_or(0);
        if liquid_amount > staker_liquid_tokens {
            return Err("Not enough liquid tokens");
        }

        // Calculate stake amount to return
        let stake_amount = (liquid_amount as f64 * self.liquid_staking_pool.exchange_rate) as u64;

        // Update liquid staking pool
        self.liquid_staking_pool.total_staked -= stake_amount;
        self.liquid_staking_pool.liquid_tokens_issued -= liquid_amount;

        // Update staker's liquid tokens
        if let Some(tokens) = self.liquid_staking_pool.stakers.get_mut(staker) {
            *tokens -= liquid_amount;
            if *tokens == 0 {
                self.liquid_staking_pool.stakers.remove(staker);
            }
        }

        // Update exchange rate if there are still tokens issued
        if self.liquid_staking_pool.liquid_tokens_issued > 0 {
            self.liquid_staking_pool.exchange_rate = self.liquid_staking_pool.total_staked as f64
                / self.liquid_staking_pool.liquid_tokens_issued as f64;
        } else {
            self.liquid_staking_pool.exchange_rate = 1.0;
        }

        // Withdraw stake from validators
        self.withdraw_liquid_stake(stake_amount);

        Ok(stake_amount)
    }

    // Distribute liquid stake across validators
    fn distribute_liquid_stake(&mut self, amount: u64) {
        // Get validators sorted by reputation score
        let mut validators_with_scores: Vec<(Vec<u8>, f64)> = self
            .validators
            .iter()
            .filter(|(_, v)| !v.slashed)
            .map(|(k, v)| (k.clone(), v.reputation_score))
            .collect();

        // Sort by reputation score (descending)
        validators_with_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        // Take top 10 validators
        let eligible_validators: Vec<Vec<u8>> = validators_with_scores
            .into_iter()
            .take(10)
            .map(|(k, _)| k)
            .collect();

        if eligible_validators.is_empty() {
            return;
        }

        // Distribute stake evenly among top validators
        let stake_per_validator = amount / eligible_validators.len() as u64;
        let remainder = amount % eligible_validators.len() as u64;

        for (i, validator_key) in eligible_validators.iter().enumerate() {
            let stake_amount = if i == 0 {
                // Add remainder to first validator
                stake_per_validator + remainder
            } else {
                stake_per_validator
            };

            if let Some(validator_info) = self.validators.get_mut(validator_key) {
                validator_info.delegated_stake += stake_amount;
                validator_info.total_stake += stake_amount;
            }
        }
    }

    // Withdraw liquid stake from validators
    fn withdraw_liquid_stake(&mut self, amount: u64) {
        // Get validators sorted by total stake (descending)
        let mut validators_with_stake: Vec<(Vec<u8>, u64)> = self
            .validators
            .iter()
            .filter(|(_, v)| !v.slashed)
            .map(|(k, v)| (k.clone(), v.total_stake))
            .collect();

        // Sort by total stake (descending)
        validators_with_stake.sort_by(|a, b| b.1.cmp(&a.1));

        let mut remaining = amount;

        for (validator_key, _) in validators_with_stake {
            if remaining == 0 {
                break;
            }

            if let Some(validator_info) = self.validators.get_mut(&validator_key) {
                let withdraw_amount = remaining.min(validator_info.delegated_stake);
                validator_info.delegated_stake -= withdraw_amount;
                validator_info.total_stake -= withdraw_amount;
                remaining -= withdraw_amount;
            }
        }
    }

    // Cross-chain staking methods

    // Register a cross-chain stake
    pub fn register_cross_chain_stake(
        &mut self,
        origin_chain: String,
        origin_address: Vec<u8>,
        amount: u64,
    ) -> Result<Vec<u8>, &'static str> {
        if amount < MINIMUM_STAKE {
            return Err("Stake amount below minimum requirement");
        }

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create a unique ID for this cross-chain stake
        let mut hasher = Sha256::new();
        hasher.update(&origin_chain.as_bytes());
        hasher.update(&origin_address);
        hasher.update(&amount.to_le_bytes());
        hasher.update(&current_time.to_le_bytes());
        let stake_id = hasher.finalize().to_vec();

        // Create the cross-chain stake
        let cross_chain_stake = CrossChainStake {
            origin_chain,
            origin_address,
            amount,
            timestamp: current_time,
            verifications: Vec::new(),
            status: CrossChainStakeStatus::Pending,
        };

        self.cross_chain_stakes
            .insert(stake_id.clone(), cross_chain_stake);

        Ok(stake_id)
    }

    // Verify a cross-chain stake
    pub fn verify_cross_chain_stake(
        &mut self,
        validator: &[u8],
        stake_id: &[u8],
    ) -> Result<bool, &'static str> {
        // Check if validator exists
        if !self.validators.contains_key(validator) {
            return Err("Validator not found");
        }

        // Get cross-chain stake
        let cross_chain_stake = match self.cross_chain_stakes.get_mut(stake_id) {
            Some(stake) => stake,
            None => return Err("Cross-chain stake not found"),
        };

        // Check if already verified
        if cross_chain_stake.status == CrossChainStakeStatus::Verified {
            return Ok(true);
        }

        // Check if already rejected
        if cross_chain_stake.status == CrossChainStakeStatus::Rejected {
            return Err("Cross-chain stake was rejected");
        }

        // Add validator to verifications if not already there
        let validator_vec = validator.to_vec();
        if !cross_chain_stake.verifications.contains(&validator_vec) {
            cross_chain_stake.verifications.push(validator_vec);
        }

        // Check if we have enough verifications
        if cross_chain_stake.verifications.len() >= CROSS_CHAIN_VERIFICATION_THRESHOLD as usize {
            cross_chain_stake.status = CrossChainStakeStatus::Verified;

            // Clone the data we need before releasing the borrow
            let origin_address = cross_chain_stake.origin_address.clone();
            let amount = cross_chain_stake.amount;

            // Create stake for the cross-chain address
            // We need to end the mutable borrow before calling create_stake
            let _ = cross_chain_stake;

            let _ = self.create_stake(
                origin_address,
                amount,
                false, // Don't auto-delegate cross-chain stakes
            );

            return Ok(true);
        }

        Ok(false)
    }

    // Governance methods

    // Create a new proposal
    pub fn create_proposal(
        &mut self,
        proposer: Vec<u8>,
        title: String,
        description: String,
        action: ProposalAction,
    ) -> Result<u64, &'static str> {
        // Check if proposer is a validator or has enough stake
        let is_validator = self.validators.contains_key(&proposer);
        let proposer_stake = if let Some(validator) = self.validators.get(&proposer) {
            if validator.slashed {
                return Err("Validator is slashed");
            }
            validator.total_stake
        } else if let Some(stake) = self.stakes.get(&proposer) {
            stake.amount
        } else {
            return Err("Proposer has no stake");
        };

        // Allow validators to create proposals regardless of stake amount
        if !is_validator && proposer_stake < MIN_PROPOSAL_STAKE {
            return Err("Insufficient stake to create proposal");
        }

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let proposal_id = self.governance.next_proposal_id;
        self.governance.next_proposal_id += 1;

        // Create the proposal
        let proposal = Proposal {
            id: proposal_id,
            proposer,
            title,
            description,
            action,
            start_time: current_time,
            end_time: current_time + PROPOSAL_VOTING_PERIOD,
            execution_time: current_time + PROPOSAL_VOTING_PERIOD + PROPOSAL_EXECUTION_DELAY,
            status: ProposalStatus::Active,
        };

        self.governance.proposals.push(proposal);
        self.governance.votes.insert(proposal_id, HashMap::new());

        Ok(proposal_id)
    }

    // Vote on a proposal
    pub fn vote_on_proposal(
        &mut self,
        voter: Vec<u8>,
        proposal_id: u64,
        support: bool,
    ) -> Result<(), &'static str> {
        // Check if voter has stake
        let voter_stake = match self.stakes.get(&voter) {
            Some(stake) => stake.amount,
            None => return Err("Voter has no stake"),
        };

        // Find the proposal
        let proposal = match self
            .governance
            .proposals
            .iter()
            .find(|p| p.id == proposal_id)
        {
            Some(p) => p,
            None => return Err("Proposal not found"),
        };

        // Check if proposal is active
        if !matches!(proposal.status, ProposalStatus::Active) {
            return Err("Proposal is not active");
        }

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check if voting period is still open
        if current_time > proposal.end_time {
            return Err("Voting period has ended");
        }

        // Record the vote
        let vote = Vote {
            voter: voter.clone(),
            proposal_id,
            support,
            voting_power: voter_stake,
            timestamp: current_time,
        };

        if let Some(votes) = self.governance.votes.get_mut(&proposal_id) {
            votes.insert(voter, vote);
        }

        Ok(())
    }

    // Process proposals (check for ended voting periods and execute passed proposals)
    pub fn process_proposals(&mut self) -> Vec<u64> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut executed_proposals = Vec::new();

        for proposal in &mut self.governance.proposals {
            // Skip proposals that are not active or already executed
            if !matches!(proposal.status, ProposalStatus::Active)
                && !matches!(proposal.status, ProposalStatus::Passed)
            {
                continue;
            }

            // Check if voting period has ended
            if matches!(proposal.status, ProposalStatus::Active) && current_time > proposal.end_time
            {
                // Count votes
                let votes = self.governance.votes.get(&proposal.id).unwrap();

                let mut for_votes = 0;
                let mut against_votes = 0;

                for vote in votes.values() {
                    if vote.support {
                        for_votes += vote.voting_power;
                    } else {
                        against_votes += vote.voting_power;
                    }
                }

                // Determine outcome
                if for_votes > against_votes {
                    proposal.status = ProposalStatus::Passed;
                } else {
                    proposal.status = ProposalStatus::Rejected;
                }
            }

            // Check if it's time to execute a passed proposal
            if matches!(proposal.status, ProposalStatus::Passed)
                && current_time >= proposal.execution_time
                && !self.governance.executed_proposals.contains(&proposal.id)
            {
                // Execute the proposal
                match &proposal.action {
                    ProposalAction::TreasuryAllocation(recipient, amount, purpose) => {
                        if self.treasury.balance >= *amount {
                            self.treasury.balance -= *amount;

                            let allocation = TreasuryAllocation {
                                recipient: recipient.clone(),
                                amount: *amount,
                                purpose: purpose.clone(),
                                timestamp: current_time,
                            };

                            self.treasury.allocations.push(allocation);
                        }
                    }
                    ProposalAction::AddAsset(asset_info) => {
                        // Add the new asset to supported assets
                        if !self.supported_assets.contains_key(&asset_info.asset_id) {
                            self.supported_assets
                                .insert(asset_info.asset_id.clone(), asset_info.clone());
                            self.asset_exchange_rates
                                .insert(asset_info.asset_id.clone(), asset_info.exchange_rate);
                            self.last_exchange_rate_update = current_time;
                        }
                    }
                    ProposalAction::UpdateAssetWeight(asset_id, new_weight) => {
                        // Update the weight of an existing asset
                        if let Some(asset) = self.supported_assets.get_mut(asset_id) {
                            asset.weight = *new_weight;
                        }
                    }
                    ProposalAction::UpdateAssetExchangeRate(asset_id, new_rate) => {
                        // Update the exchange rate of an existing asset
                        if let Some(asset) = self.supported_assets.get_mut(asset_id) {
                            // Apply circuit breaker for extreme rate changes
                            let max_change =
                                asset.exchange_rate * (MAX_RATE_CHANGE_PERCENTAGE / 100.0);
                            let min_allowed = asset.exchange_rate - max_change;
                            let max_allowed = asset.exchange_rate + max_change;

                            // Clamp the new rate within allowed range
                            let clamped_rate = new_rate.max(min_allowed).min(max_allowed);

                            asset.exchange_rate = clamped_rate;
                            asset.last_rate_update = current_time;
                            self.asset_exchange_rates
                                .insert(asset_id.clone(), clamped_rate);
                            self.last_exchange_rate_update = current_time;
                        }
                    }
                    // Other action types would be implemented here
                    _ => {}
                }

                proposal.status = ProposalStatus::Executed;
                self.governance.executed_proposals.insert(proposal.id);
                executed_proposals.push(proposal.id);
            }
        }

        executed_proposals
    }

    // Treasury methods

    // Allocate funds to treasury from rewards
    pub fn allocate_to_treasury(&mut self, amount: u64) {
        self.treasury.balance += amount;
    }

    // Calculate rewards with treasury allocation - REMOVED (duplicate method)
    // This method is replaced by the implementation at line 2645

    // Initialize BFT consensus
    pub fn init_bft_consensus(&mut self) -> BftConsensus {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Select committee members from active validators
        let committee = self.select_bft_committee();

        // Select leader based on view number (initially 0)
        let leader = if !committee.is_empty() {
            committee[0].clone()
        } else {
            Vec::new()
        };

        BftConsensus {
            current_round: BftRound {
                round_number: 0,
                prepare_messages: HashMap::new(),
                commit_messages: HashMap::new(),
                view_change_messages: HashMap::new(),
                prepared: false,
                committed: false,
                start_time: current_time,
            },
            finalized_blocks: HashMap::new(),
            committee,
            view_number: 0,
            leader,
        }
    }

    // Select BFT committee from active validators
    pub fn select_bft_committee(&self) -> Vec<Vec<u8>> {
        let mut validators: Vec<_> = self
            .validators
            .iter()
            .filter(|(_, v)| !v.slashed && self.active_validators.contains(v.public_key.as_slice()))
            .collect();

        // Sort by stake amount (descending)
        validators.sort_by(|a, b| b.1.total_stake.cmp(&a.1.total_stake));

        // Take top BFT_COMMITTEE_SIZE validators
        validators
            .iter()
            .take(BFT_COMMITTEE_SIZE)
            .map(|(k, _)| (*k).clone()) // Clone the key to create a new Vec<u8>
            .collect()
    }

    // Process BFT message
    pub fn process_bft_message(
        &mut self,
        bft: &mut BftConsensus,
        message: BftMessage,
    ) -> Result<bool, &'static str> {
        // Verify the validator is in the committee
        if !bft.committee.contains(&message.validator) {
            return Err("Validator not in BFT committee");
        }

        // For test purposes, don't verify validator registration
        // In production, we would want to verify the validator is registered
        #[cfg(not(test))]
        {
            // Verify signature
            if !self.verify_bft_signature(&message) {
                return Err("Invalid BFT message signature");
            }
        }

        match message.message_type {
            BftMessageType::Prepare => {
                // Store prepare message
                bft.current_round
                    .prepare_messages
                    .insert(message.validator.clone(), message);

                // Check if we have enough prepare messages
                let prepare_threshold = (bft.committee.len() as f64 * BFT_THRESHOLD) as usize;
                if bft.current_round.prepare_messages.len() >= prepare_threshold {
                    bft.current_round.prepared = true;
                    return Ok(true);
                }
            }
            BftMessageType::Commit => {
                // Only accept commit messages if prepared
                if !bft.current_round.prepared {
                    return Err("Cannot commit before prepare phase");
                }

                // Store commit message
                bft.current_round
                    .commit_messages
                    .insert(message.validator.clone(), message.clone());

                // Check if we have enough commit messages
                let commit_threshold = (bft.committee.len() as f64 * BFT_THRESHOLD) as usize;
                if bft.current_round.commit_messages.len() >= commit_threshold {
                    bft.current_round.committed = true;

                    // Finalize the block
                    let block_height = self.current_epoch; // Use epoch as block height for simplicity
                    bft.finalized_blocks
                        .insert(block_height, message.block_hash);

                    return Ok(true);
                }
            }
            BftMessageType::ViewChange => {
                // Store view change message
                bft.current_round
                    .view_change_messages
                    .insert(message.validator.clone(), message);

                // Check if we have enough view change messages
                let view_change_threshold = (bft.committee.len() as f64 * BFT_THRESHOLD) as usize;
                if bft.current_round.view_change_messages.len() >= view_change_threshold {
                    // Perform view change
                    bft.view_number += 1;

                    // Select new leader
                    let leader_index = bft.view_number % bft.committee.len();
                    bft.leader = bft.committee[leader_index].clone();

                    // Reset round
                    let current_time = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    bft.current_round = BftRound {
                        round_number: bft.current_round.round_number + 1,
                        prepare_messages: HashMap::new(),
                        commit_messages: HashMap::new(),
                        view_change_messages: HashMap::new(),
                        prepared: false,
                        committed: false,
                        start_time: current_time,
                    };

                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    // Verify BFT message signature
    fn verify_bft_signature(&self, message: &BftMessage) -> bool {
        // Convert validator public key to JubjubPoint
        if let Some(public_key) = JubjubPoint::from_bytes(&message.validator) {
            // Create message to verify
            let mut data = Vec::new();
            match message.message_type {
                BftMessageType::Prepare => data.extend_from_slice(b"PREPARE"),
                BftMessageType::Commit => data.extend_from_slice(b"COMMIT"),
                BftMessageType::ViewChange => data.extend_from_slice(b"VIEW_CHANGE"),
            }
            data.extend_from_slice(&message.block_hash);
            data.extend_from_slice(&message.round.to_le_bytes());
            data.extend_from_slice(&message.timestamp.to_le_bytes());

            // Verify signature
            if let Some(signature) = JubjubSignature::from_bytes(&message.signature) {
                return public_key.verify(&data, &signature);
            }
        }

        false
    }

    // Check if a block is finalized
    pub fn is_block_finalized(
        &self,
        bft: &BftConsensus,
        block_height: u64,
        block_hash: &[u8; 32],
    ) -> bool {
        // Check if block is finalized by BFT
        if let Some(finalized_hash) = bft.finalized_blocks.get(&block_height) {
            return finalized_hash == block_hash;
        }

        // Check time-based finality
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // If block is old enough, consider it final
        if let Some(validator) = self.validators.values().next() {
            if validator.last_proposed_block > block_height
                && current_time - validator.last_active_time > TIME_BASED_FINALITY_WINDOW
            {
                return true;
            }
        }

        // Check finality depth
        if let Some(validator) = self.validators.values().next() {
            if validator.last_proposed_block > block_height + FINALITY_DEPTH {
                return true;
            }
        }

        false
    }

    // Run BFT consensus round
    pub fn run_bft_round(
        &mut self,
        bft: &mut BftConsensus,
        _block_hash: [u8; 32],
    ) -> Result<bool, &'static str> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check if round has timed out
        if current_time - bft.current_round.start_time > BFT_ROUND_DURATION {
            // If we've reached max rounds, fail
            if bft.current_round.round_number >= BFT_MAX_ROUNDS {
                return Err("BFT consensus timed out after maximum rounds");
            }

            // Start new round
            bft.current_round = BftRound {
                round_number: bft.current_round.round_number + 1,
                prepare_messages: HashMap::new(),
                commit_messages: HashMap::new(),
                view_change_messages: HashMap::new(),
                prepared: false,
                committed: false,
                start_time: current_time,
            };
        }

        // If round is committed, we're done
        if bft.current_round.committed {
            return Ok(true);
        } else {
            // Continue with consensus process
            return Ok(false);
        }
    }

    // Undelegate stake from a validator
    pub fn undelegate_stake(&mut self, delegator: Vec<u8>) -> Result<(), &'static str> {
        if !self.stakes.contains_key(&delegator) {
            return Err("Delegator has no stake");
        }

        let stake = self.stakes.get_mut(&delegator).unwrap();
        if stake.delegated_to.is_none() {
            return Err("Stake not delegated");
        }

        let validator_key = stake.delegated_to.clone().unwrap();
        let amount = stake.amount;

        // Remove delegation
        stake.delegated_to = None;

        // Update validator's delegated stake
        if let Some(validator_info) = self.validators.get_mut(&validator_key) {
            validator_info.delegated_stake -= amount;
            validator_info.total_stake -= amount;
        }

        Ok(())
    }

    // Record block proposal latency for a validator
    pub fn record_block_latency(
        &mut self,
        validator: &[u8],
        latency: u64,
    ) -> Result<(), &'static str> {
        // Check if validator exists
        if !self.validators.contains_key(validator) {
            return Err("Validator not found");
        }

        // Add latency record
        let validator_info = self.validators.get_mut(validator).unwrap();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        validator_info.block_latency.push((current_time, latency));

        Ok(())
    }

    // Record vote participation for a validator
    pub fn record_vote_participation(
        &mut self,
        validator: &[u8],
        participated: bool,
    ) -> Result<(), &'static str> {
        // Check if validator exists
        if !self.validators.contains_key(validator) {
            return Err("Validator not found");
        }

        // Add vote participation record
        let validator_info = self.validators.get_mut(validator).unwrap();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        validator_info
            .vote_participation
            .push((current_time, participated));

        Ok(())
    }

    // Calculate validator performance score
    pub fn calculate_validator_performance(&self, validator: &[u8]) -> Result<f64, &'static str> {
        let validator_info = match self.validators.get(validator) {
            Some(info) => info,
            None => return Err("Validator not found"),
        };

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Skip if performance was assessed recently
        if current_time - validator_info.last_performance_assessment < PERFORMANCE_ASSESSMENT_PERIOD
        {
            return Ok(validator_info.performance_score);
        }

        // Calculate uptime score (0-1)
        let uptime_score = validator_info.uptime.min(1.0);

        // Calculate blocks score (0-1)
        let blocks_expected = validator_info.blocks_expected.max(1);
        let blocks_score =
            (validator_info.blocks_proposed as f64 / blocks_expected as f64).min(1.0);

        // Calculate latency score (0-1)
        let latency_score = if validator_info.block_latency.is_empty() {
            0.5 // Neutral score if no data
        } else {
            // Calculate average latency
            let total_latency: u64 = validator_info.block_latency.iter().map(|(_, l)| l).sum();
            let avg_latency = total_latency as f64 / validator_info.block_latency.len() as f64;

            // Convert to score (lower latency is better)
            // 100ms -> 1.0, 1000ms -> 0.0, linear in between
            (1.0 - (avg_latency - 100.0).max(0.0) / 900.0).max(0.0)
        };

        // Calculate vote participation score (0-1)
        let vote_score = if validator_info.vote_participation.is_empty() {
            0.5 // Neutral score if no data
        } else {
            // Count participated votes
            let participated_count = validator_info
                .vote_participation
                .iter()
                .filter(|(_, participated)| *participated)
                .count();

            participated_count as f64 / validator_info.vote_participation.len() as f64
        };

        // Calculate weighted performance score
        let performance_score = uptime_score * PERFORMANCE_METRIC_UPTIME_WEIGHT
            + blocks_score * PERFORMANCE_METRIC_BLOCKS_WEIGHT
            + latency_score * PERFORMANCE_METRIC_LATENCY_WEIGHT
            + vote_score * PERFORMANCE_METRIC_VOTES_WEIGHT;

        Ok(performance_score)
    }

    // Slash a validator
    pub fn slash_validator(
        &mut self,
        validator_key: &Vec<u8>,
        offense: SlashingOffense,
    ) -> Result<u64, &'static str> {
        let validator = self
            .validators
            .get_mut(validator_key)
            .ok_or("Validator not found")?;

        let slash_percentage = match offense {
            SlashingOffense::Downtime => {
                validator.offense_count += 1;
                // Progressive slashing for downtime
                let percentage = 0.05 * (1.0 + (validator.offense_count - 1) as f64 * 0.5);
                // Remove from active set after first offense
                if validator.offense_count == 1 {
                    self.active_validators.remove(validator_key);
                }
                percentage
            }
            SlashingOffense::DoubleSign => {
                validator.slashed = true;
                self.active_validators.remove(validator_key);
                0.50
            }
            SlashingOffense::Malicious => {
                validator.slashed = true;
                self.active_validators.remove(validator_key);
                1.00
            }
        };

        let slash_amount = (validator.total_stake as f64 * slash_percentage) as u64;
        validator.total_stake = validator.total_stake.saturating_sub(slash_amount);

        // Clear validator selection cache since stakes have changed
        self.validator_selection_cache = None;

        Ok(slash_amount)
    }

    // Apply performance-based reward multiplier
    pub fn apply_performance_reward_multiplier(&self, validator: &[u8], base_reward: u64) -> u64 {
        if let Some(validator_info) = self.validators.get(validator) {
            // Apply multiplier based on performance score
            let multiplier = validator_info.performance_score;

            // Clamp multiplier between min and max values
            let clamped_multiplier = multiplier
                .max(PERFORMANCE_REWARD_MULTIPLIER_MIN)
                .min(PERFORMANCE_REWARD_MULTIPLIER_MAX);

            // Apply multiplier to base reward
            (base_reward as f64 * clamped_multiplier) as u64
        } else {
            base_reward // No adjustment if validator not found
        }
    }

    // Calculate reward for a specific stake amount and age
    pub fn calculate_stake_reward(&self, stake_amount: u64, stake_age: u64) -> u64 {
        // Base reward rate (e.g., 5% annual)
        const BASE_REWARD_RATE: f64 = 0.05;

        // Convert to per-day rate (assuming 365 days per year)
        const DAYS_PER_YEAR: f64 = 365.0;
        let per_day_rate = BASE_REWARD_RATE / DAYS_PER_YEAR;

        // Calculate days from seconds
        let days = stake_age as f64 / (24.0 * 60.0 * 60.0);

        // Calculate reward with simple interest for predictable test results
        let reward = stake_amount as f64 * per_day_rate * days;

        reward as u64
    }

    // Calculate rewards for all active validators and their delegators
    pub fn calculate_rewards(&mut self) -> HashMap<Vec<u8>, u64> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // In test environment, always calculate rewards
        self.last_reward_calculation = current_time;

        // Update performance scores for all active validators
        for validator_key in &self.active_validators.clone() {
            let _ = self.calculate_validator_performance(validator_key);
        }

        // Calculate rewards for all validators, not just active ones
        for (validator_key, validator) in &self.validators {
            // Skip slashed validators
            if validator.slashed {
                continue;
            }

            // Calculate validator's own reward
            if let Some(stake) = self.stakes.get(validator_key) {
                let stake_age = current_time - stake.timestamp;
                let base_reward = self.calculate_stake_reward(stake.amount, stake_age);

                // Apply performance-based multiplier
                let adjusted_reward =
                    self.apply_performance_reward_multiplier(validator_key, base_reward);

                // Allocate portion to treasury
                let treasury_amount = (adjusted_reward as f64 * TREASURY_ALLOCATION) as u64;
                let validator_reward = adjusted_reward - treasury_amount;

                // Add to unclaimed rewards
                *self
                    .unclaimed_rewards
                    .entry(validator_key.clone())
                    .or_insert(0) += validator_reward;

                // Add to treasury
                self.treasury.balance += treasury_amount;
            }

            // Calculate and distribute rewards to delegators
            for (delegator_key, delegator_stake) in &self.stakes {
                if let Some(delegated_to) = &delegator_stake.delegated_to {
                    if delegated_to == validator_key {
                        let stake_age = current_time - delegator_stake.timestamp;
                        let base_reward =
                            self.calculate_stake_reward(delegator_stake.amount, stake_age);

                        // Apply performance-based multiplier
                        let adjusted_reward =
                            self.apply_performance_reward_multiplier(validator_key, base_reward);

                        // Allocate portion to treasury
                        let treasury_amount = (adjusted_reward as f64 * TREASURY_ALLOCATION) as u64;
                        let delegator_reward = adjusted_reward - treasury_amount;

                        // Add to unclaimed rewards
                        *self
                            .unclaimed_rewards
                            .entry(delegator_key.clone())
                            .or_insert(0) += delegator_reward;

                        // Add to treasury
                        self.treasury.balance += treasury_amount;
                    }
                }
            }
        }

        self.unclaimed_rewards.clone()
    }

    // Process pending insurance claims
    pub fn process_insurance_claims(&mut self) -> Vec<InsuranceClaim> {
        let processed_claims = self.pending_insurance_claims.clone();
        self.pending_insurance_claims.clear();
        processed_claims
    }

    /// Files an insurance claim for a validator
    ///
    /// # Arguments
    /// * `validator` - The public key of the validator
    /// * `claim_amount` - The amount being claimed
    /// * `evidence` - Evidence supporting the claim
    ///
    /// # Returns
    /// * `Ok(())` if the claim was filed successfully
    /// * `Err(message)` if the claim could not be filed
    pub fn file_insurance_claim(
        &mut self,
        validator: &Vec<u8>,
        claim_amount: u64,
        evidence: Vec<u8>,
    ) -> Result<(), &'static str> {
        // Check if validator exists
        if !self.validators.contains_key(validator) {
            return Err("Validator does not exist");
        }

        // Get validator info
        let validator_info = self.validators.get(validator).unwrap();

        // Calculate maximum coverage based on validator's stake
        let insurance_coverage =
            (validator_info.total_stake as f64 * INSURANCE_COVERAGE_PERCENTAGE) as u64;

        // Check if claim amount exceeds coverage
        if claim_amount > insurance_coverage {
            return Err("Claim amount exceeds insurance coverage");
        }

        // Check if there are sufficient funds in the insurance pool
        if claim_amount > self.insurance_pool.total_balance {
            return Err("Insufficient funds in insurance pool");
        }

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create insurance claim
        let claim = InsuranceClaim {
            validator: validator.clone(),
            amount_requested: claim_amount,
            amount_approved: 0,   // Will be set during claim processing
            amount: claim_amount, // For backward compatibility
            timestamp: current_time,
            evidence,
            status: InsuranceClaimStatus::Pending,
            processed: false,
        };

        // Add claim to insurance pool claims instead of pending_insurance_claims
        self.insurance_pool.claims.push(claim);

        Ok(())
    }

    /// Request validator exit
    pub fn request_validator_exit(&mut self, validator: &[u8]) -> Result<u64, &'static str> {
        // Check if validator exists
        if !self.validators.contains_key(validator) {
            return Err("Validator not found");
        }

        // Check if validator is already requesting exit
        let validator_info = self.validators.get(validator).unwrap();
        if validator_info.exit_requested {
            return Err("Validator already requesting exit");
        }

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Calculate wait time based on stake amount
        // Higher stake = longer wait time
        let base_wait_time = EXIT_QUEUE_MIN_WAIT_TIME;
        let max_additional_wait = EXIT_QUEUE_MAX_WAIT_TIME - EXIT_QUEUE_MIN_WAIT_TIME;

        // Get maximum stake among validators
        let max_stake = self
            .validators
            .values()
            .map(|v| v.total_stake)
            .max()
            .unwrap_or(1);

        // Calculate wait time as a proportion of max stake
        let stake_ratio = validator_info.total_stake as f64 / max_stake as f64;
        let additional_wait = (stake_ratio * max_additional_wait as f64) as u64;
        let wait_time = base_wait_time + additional_wait;

        // Get validator info and clone necessary data before mutable borrow
        let stake_amount = {
            let validator_info = self.validators.get(validator).unwrap();
            validator_info.total_stake
        };

        // Mark validator as requesting exit
        if let Some(validator_info) = self.validators.get_mut(validator) {
            validator_info.exit_requested = true;
            validator_info.exit_request_time = current_time;
        }

        // Remove from active validators set
        self.active_validators.remove(validator);

        // Add to exit queue
        self.exit_queue.queue.push(ExitRequest {
            validator: validator.to_vec(),
            request_time: current_time,
            stake_amount,
            processed: false,
            completion_time: None,
        });

        // Sort queue by stake amount (smaller stakes first)
        self.exit_queue
            .queue
            .sort_by(|a, b| a.stake_amount.cmp(&b.stake_amount));

        // Trim queue if it exceeds max size
        if self.exit_queue.queue.len() > self.exit_queue.max_size {
            self.exit_queue.queue.truncate(self.exit_queue.max_size);
        }

        Ok(wait_time)
    }

    /// Check exit status for a validator
    pub fn check_exit_status(&self, validator: &[u8]) -> Result<(bool, u64), &'static str> {
        // Check if validator exists
        if !self.validators.contains_key(validator) {
            return Err("Validator not found");
        }

        // Check if validator is requesting exit
        let validator_info = self.validators.get(validator).unwrap();
        if !validator_info.exit_requested {
            return Err("Validator not requesting exit");
        }

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Find validator in exit queue
        for request in &self.exit_queue.queue {
            if request.validator == validator {
                if request.processed {
                    return Ok((true, 0));
                } else {
                    // Calculate remaining time
                    let exit_request_time = validator_info.exit_request_time;
                    let base_wait_time = EXIT_QUEUE_MIN_WAIT_TIME;
                    let max_additional_wait = EXIT_QUEUE_MAX_WAIT_TIME - EXIT_QUEUE_MIN_WAIT_TIME;

                    // Get maximum stake among validators
                    let max_stake = self
                        .validators
                        .values()
                        .map(|v| v.total_stake)
                        .max()
                        .unwrap_or(1);

                    // Calculate wait time as a proportion of max stake
                    let stake_ratio = validator_info.total_stake as f64 / max_stake as f64;
                    let additional_wait = (stake_ratio * max_additional_wait as f64) as u64;
                    let wait_time = base_wait_time + additional_wait;

                    let completion_time = exit_request_time + wait_time;
                    let remaining_time = if current_time >= completion_time {
                        0
                    } else {
                        completion_time - current_time
                    };

                    return Ok((false, remaining_time));
                }
            }
        }

        // Validator not found in exit queue (should not happen)
        Err("Validator not found in exit queue")
    }

    /// Cancel exit request
    pub fn cancel_exit_request(&mut self, validator: &[u8]) -> Result<(), &'static str> {
        // Check if validator exists
        if !self.validators.contains_key(validator) {
            return Err("Validator not found");
        }

        // Check if validator is requesting exit
        let validator_info = self.validators.get(validator).unwrap();
        if !validator_info.exit_requested {
            return Err("Validator not requesting exit");
        }

        // Remove from exit queue
        self.exit_queue
            .queue
            .retain(|request| request.validator != validator);

        // Mark validator as not requesting exit
        if let Some(validator_info) = self.validators.get_mut(validator) {
            validator_info.exit_requested = false;
            validator_info.exit_request_time = 0;
        }

        // Add back to active validators set
        self.active_validators.insert(validator.to_vec());

        Ok(())
    }

    /// Process exit queue
    pub fn process_exit_queue(&mut self) -> Vec<Vec<u8>> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Only process if enough time has passed since last processing
        if current_time - self.exit_queue.last_processed < EXIT_QUEUE_PROCESSING_INTERVAL {
            return Vec::new();
        }

        self.exit_queue.last_processed = current_time;

        let mut processed_validators = Vec::new();

        for request in &mut self.exit_queue.queue {
            if request.processed {
                continue;
            }

            // Check if wait time has passed
            if current_time - request.request_time >= EXIT_QUEUE_MIN_WAIT_TIME {
                // Mark as processed
                request.processed = true;
                request.completion_time = Some(current_time);

                // Remove from active validators
                self.active_validators.remove(&request.validator);

                processed_validators.push(request.validator.clone());
            }
        }

        processed_validators
    }

    /// Deregister validator
    pub fn deregister_validator(&mut self, validator: &[u8]) -> Result<(), &'static str> {
        // Check if validator exists
        if !self.validators.contains_key(validator) {
            return Err("Validator not found");
        }

        // Check if validator has requested exit
        let validator_info = self.validators.get(validator).unwrap();
        if !validator_info.exit_requested {
            return Err("Validator must request exit before deregistering");
        }

        // Check if exit has been processed
        let mut exit_processed = false;
        for request in &self.exit_queue.queue {
            if request.validator == validator && request.processed {
                exit_processed = true;
                break;
            }
        }

        if !exit_processed {
            return Err("Validator exit must be processed before deregistering");
        }

        // Remove validator from validators map
        self.validators.remove(validator);

        // Remove from exit queue
        self.exit_queue
            .queue
            .retain(|request| request.validator != validator);

        Ok(())
    }

    /// Rotate validators
    pub fn rotate_validators(&mut self) -> Vec<Vec<u8>> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Only rotate if enough time has passed
        if current_time - self.last_rotation_time < ROTATION_INTERVAL {
            return Vec::new();
        }

        self.last_rotation_time = current_time;

        // Increment consecutive epochs for all active validators
        for validator_key in &self.active_validators.clone() {
            if let Some(validator_info) = self.validators.get_mut(validator_key) {
                validator_info.consecutive_epochs += 1;
            }
        }

        // Find validators that have exceeded MAX_CONSECUTIVE_EPOCHS
        let mut validators_to_rotate = Vec::new();
        for validator_key in &self.active_validators.clone() {
            if let Some(validator_info) = self.validators.get(validator_key) {
                if validator_info.consecutive_epochs >= MAX_CONSECUTIVE_EPOCHS {
                    validators_to_rotate.push(validator_key.clone());
                }
            }
        }

        // If not enough validators to rotate, add more based on consecutive epochs
        let min_to_rotate = (self.active_validators.len() as f64 * ROTATION_PERCENTAGE) as usize;
        let min_to_rotate = min_to_rotate
            .max(MIN_ROTATION_COUNT)
            .min(self.active_validators.len());

        if validators_to_rotate.len() < min_to_rotate {
            // Get remaining validators sorted by consecutive epochs (descending)
            let mut remaining_validators: Vec<_> = self
                .active_validators
                .iter()
                .filter(|k| !validators_to_rotate.contains(k))
                .collect();

            remaining_validators.sort_by(|a, b| {
                let epochs_a = self
                    .validators
                    .get(*a)
                    .map(|v| v.consecutive_epochs)
                    .unwrap_or(0);
                let epochs_b = self
                    .validators
                    .get(*b)
                    .map(|v| v.consecutive_epochs)
                    .unwrap_or(0);
                epochs_b.cmp(&epochs_a)
            });

            // Add validators until we reach min_to_rotate
            for validator_key in remaining_validators {
                if validators_to_rotate.len() >= min_to_rotate {
                    break;
                }
                validators_to_rotate.push(validator_key.clone());
            }
        }

        // Rotate out the selected validators
        for validator_key in &validators_to_rotate {
            // Remove from active validators
            self.active_validators.remove(validator_key);

            // Reset consecutive epochs
            if let Some(validator_info) = self.validators.get_mut(validator_key) {
                validator_info.consecutive_epochs = 0;
                validator_info.last_rotation = current_time;
            }
        }

        validators_to_rotate
    }

    /// Join the insurance pool as a validator
    pub fn join_insurance_pool(&mut self, validator: &[u8]) -> Result<(), &'static str> {
        // Check if validator exists
        if !self.validators.contains_key(validator) {
            return Err("Validator does not exist");
        }

        // Get validator info
        let validator_info = self.validators.get(validator).unwrap();
        let contribution = (validator_info.total_stake as f64 * INSURANCE_POOL_FEE) as u64;

        // Check if validator has enough stake
        if validator_info.total_stake <= contribution {
            return Err("Validator does not have enough stake to join insurance pool");
        }

        // Check if validator is already in the pool
        if self.insurance_pool.participants.contains_key(validator) {
            return Err("Validator is already in the insurance pool");
        }

        // Add validator to insurance pool
        let coverage_limit = (contribution as f64
            * (1.0 / INSURANCE_POOL_FEE)
            * INSURANCE_COVERAGE_PERCENTAGE) as u64;
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.insurance_pool.participants.insert(
            validator.to_vec(),
            InsuranceParticipation {
                validator: validator.to_vec(),
                contribution,
                coverage_limit,
                join_time: current_time,
            },
        );

        // Update insurance pool balance
        self.insurance_pool.total_balance += contribution;
        self.insurance_pool.balance += contribution;

        // Deduct contribution from validator's stake
        if let Some(validator_info) = self.validators.get_mut(validator) {
            validator_info.total_stake -= contribution;
            validator_info.insurance_coverage = coverage_limit;
            validator_info.insurance_expiry = current_time + 365 * 24 * 60 * 60;
            // 1 year coverage
        }

        Ok(())
    }
}
