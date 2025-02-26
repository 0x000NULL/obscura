use crate::blockchain::{Block, OutPoint, Transaction, TransactionOutput};
use crate::consensus::sharding::ShardManager;
use crate::consensus::threshold_sig::{ThresholdError, ThresholdSignature, ValidatorAggregation};
use crate::crypto;
use bincode;
use ed25519_dalek::{Keypair, PublicKey, Signature, Verifier};
use rand_core::{OsRng, RngCore};
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
pub const PERFORMANCE_ASSESSMENT_PERIOD: u64 = 7 * 24 * 60 * 60; // 7 days for performance assessment

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
}

// Stake information
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
pub struct PartialUndelegation {
    pub amount: u64,
    pub timestamp: u64,
    pub completion_time: u64,
}

// Validator information
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
pub enum ValidatorUpdateOp {
    Register,
    UpdateCommission,
    Deregister,
}

// Pending validator update
pub struct ValidatorUpdate {
    pub validator: Vec<u8>,
    pub operation: ValidatorUpdateOp,
    pub data: Vec<u8>, // Serialized update data
    pub timestamp: u64,
}

// Liquid staking pool
pub struct LiquidStakingPool {
    pub total_staked: u64,
    pub liquid_tokens_issued: u64,
    pub exchange_rate: f64,
    pub fee_rate: f64,
    pub stakers: HashMap<Vec<u8>, u64>, // Staker -> liquid tokens amount
}

// Treasury for funding ecosystem development
pub struct Treasury {
    pub balance: u64,
    pub allocations: Vec<TreasuryAllocation>,
}

// Treasury allocation
pub struct TreasuryAllocation {
    pub recipient: Vec<u8>,
    pub amount: u64,
    pub purpose: String,
    pub timestamp: u64,
}

// Governance system
pub struct Governance {
    pub proposals: Vec<Proposal>,
    pub votes: HashMap<u64, HashMap<Vec<u8>, Vote>>, // Proposal ID -> (Voter -> Vote)
    pub executed_proposals: HashSet<u64>,
    pub next_proposal_id: u64,
}

// Governance proposal
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
pub enum ProposalAction {
    ChangeParameter(String, Vec<u8>), // Parameter name, new value
    TreasuryAllocation(Vec<u8>, u64, String), // Recipient, amount, purpose
    ProtocolUpgrade(String, Vec<u8>), // Upgrade name, upgrade data
    Other(String, Vec<u8>),           // Action type, action data
}

// Proposal status
pub enum ProposalStatus {
    Active,
    Passed,
    Rejected,
    Executed,
    Cancelled,
}

// Vote
pub struct Vote {
    pub voter: Vec<u8>,
    pub proposal_id: u64,
    pub support: bool,
    pub voting_power: u64,
    pub timestamp: u64,
}

// Cross-chain stake
pub struct CrossChainStake {
    pub origin_chain: String,
    pub origin_address: Vec<u8>,
    pub amount: u64,
    pub timestamp: u64,
    pub verifications: Vec<Vec<u8>>, // List of validators who verified this stake
    pub status: CrossChainStakeStatus,
}

// Cross-chain stake status
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

pub struct BftRound {
    pub round_number: usize,
    pub prepare_messages: HashMap<Vec<u8>, BftMessage>, // Validator -> Message
    pub commit_messages: HashMap<Vec<u8>, BftMessage>,  // Validator -> Message
    pub view_change_messages: HashMap<Vec<u8>, BftMessage>, // Validator -> Message
    pub prepared: bool,
    pub committed: bool,
    pub start_time: u64,
}

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

pub struct BlockInfo {
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    pub proposer: Vec<u8>,
    pub validators: HashSet<Vec<u8>>, // Validators who signed this block
    pub total_stake: u64,             // Total stake of validators who signed this block
}

// Insurance pool for validators
pub struct InsurancePool {
    pub total_balance: u64,
    pub coverage_percentage: f64,
    pub claims: Vec<InsuranceClaim>,
    pub participants: HashMap<Vec<u8>, InsuranceParticipation>,
}

// Insurance participation record
pub struct InsuranceParticipation {
    pub validator: Vec<u8>,
    pub contribution: u64,
    pub coverage_limit: u64,
    pub join_time: u64,
}

// Insurance claim status
pub enum InsuranceClaimStatus {
    Pending,
    Approved,
    Rejected,
    Paid,
}

// Insurance claim
pub struct InsuranceClaim {
    pub validator: Vec<u8>,
    pub amount_requested: u64,
    pub amount_approved: u64, // Will be set during claim processing
    pub timestamp: u64,
    pub evidence: Vec<u8>,
    pub status: InsuranceClaimStatus,
    pub processed: bool,
}

// Exit queue for validators
pub struct ExitQueue {
    pub queue: Vec<ExitRequest>,
    pub last_processed: u64,
    pub max_size: usize,
}

// Exit request
pub struct ExitRequest {
    pub validator: Vec<u8>,
    pub request_time: u64,
    pub stake_amount: u64,
    pub processed: bool,
    pub completion_time: Option<u64>,
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
        match PublicKey::from_bytes(&proof.public_key) {
            Ok(public_key) => match Signature::from_bytes(&proof.signature) {
                Ok(signature) => public_key.verify(block_data, &signature).is_ok(),
                Err(_) => false,
            },
            Err(_) => false,
        }
    }

    pub fn calculate_stake_reward(&self, stake_amount: u64, stake_age: u64) -> u64 {
        // Calculate reward using compound interest formula
        // A = P(1 + r/n)^(nt)
        // Where:
        // A = final amount
        // P = principal (stake_amount)
        // r = annual rate (annual_reward_rate)
        // n = number of times compounded per year (365 days / compound_interval in days)
        // t = time in years (stake_age / seconds in a year)

        let compounds_per_year = (365.0 * 24.0 * 60.0 * 60.0) / self.compound_interval as f64;
        let time_in_years = stake_age as f64 / (365.0 * 24.0 * 60.0 * 60.0);

        let final_amount = stake_amount as f64
            * (1.0 + (self.annual_reward_rate / compounds_per_year))
                .powf(compounds_per_year * time_in_years);

        let reward = (final_amount - stake_amount as f64) as u64;
        reward
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
        keypair: &ed25519_dalek::Keypair,
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
            signature: signature.to_bytes().to_vec(),
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
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

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
            last_reward_calculation: current_time,
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
            last_rotation_time: current_time,
            insurance_pool: InsurancePool {
                total_balance: 0,
                coverage_percentage: INSURANCE_COVERAGE_PERCENTAGE,
                claims: Vec::new(),
                participants: HashMap::new(),
            },
            exit_queue: ExitQueue {
                queue: Vec::new(),
                last_processed: 0,
                max_size: EXIT_QUEUE_MAX_SIZE,
            },
            last_reward_time: current_time,
            shards: Vec::new(),
            cross_shard_committees: HashMap::new(),
            last_shard_rotation: current_time,
            performance_metrics: HashMap::new(),
            bft_consensus: None,
            recent_reorgs: VecDeque::new(),
            known_blocks: HashSet::new(),
            highest_finalized_block: 0,
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
            auto_delegate: auto_delegate,
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
        };

        self.validators.insert(public_key, validator_info);
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
        // Get validators sorted by reputation score
        let mut validators: Vec<_> = self.validators.values().collect();
        validators.sort_by(|a, b| b.reputation_score.partial_cmp(&a.reputation_score).unwrap());

        // Only consider top validators that aren't slashed and have room for delegation
        let eligible_validators: Vec<_> = validators
            .into_iter()
            .filter(|v| !v.slashed && v.delegated_stake < v.delegation_cap)
            .collect();

        if eligible_validators.is_empty() {
            return;
        }

        // Process auto-delegations
        for (staker_key, stake) in &mut self.stakes {
            // Skip if already delegated or below threshold
            if stake.delegated_to.is_some()
                || !stake.auto_delegate
                || stake.amount < AUTO_DELEGATION_THRESHOLD
            {
                continue;
            }

            // Find best validator with capacity
            for validator in &eligible_validators {
                if validator.delegated_stake + stake.amount <= validator.delegation_cap {
                    // Auto-delegate to this validator
                    stake.delegated_to = Some(validator.public_key.clone());

                    // Update validator stats
                    if let Some(validator_info) = self.validators.get_mut(&validator.public_key) {
                        validator_info.delegated_stake += stake.amount;
                        validator_info.total_stake += stake.amount;
                    }

                    break;
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

        if let Some(validator_info) = self.validators.get_mut(validator) {
            // Add current metrics to historical data
            validator_info
                .historical_uptime
                .push((current_time, validator_info.uptime));
            validator_info
                .historical_blocks
                .push((current_time, validator_info.blocks_proposed));

            // Calculate uptime score (0-1)
            let uptime_score = validator_info.uptime;

            // Calculate blocks produced score (0-1)
            // Compare to average blocks produced by all validators
            let avg_blocks = self
                .validators
                .values()
                .map(|v| v.blocks_proposed)
                .sum::<u64>() as f64
                / self.validators.len() as f64;

            let blocks_score = if avg_blocks > 0.0 {
                (validator_info.blocks_proposed as f64 / avg_blocks).min(1.0)
            } else {
                0.0
            };

            // Calculate age score (0-1)
            let max_age = current_time
                - self
                    .validators
                    .values()
                    .map(|v| v.creation_time)
                    .min()
                    .unwrap_or(current_time);

            let validator_age = current_time - validator_info.creation_time;
            let age_score = if max_age > 0 {
                validator_age as f64 / max_age as f64
            } else {
                0.0
            };

            // Calculate weighted reputation score
            let reputation = (uptime_score * REPUTATION_WEIGHT_UPTIME)
                + (blocks_score * REPUTATION_WEIGHT_BLOCKS)
                + (age_score * REPUTATION_WEIGHT_AGE);

            validator_info.reputation_score = reputation;

            Ok(reputation)
        } else {
            Err("Validator not found")
        }
    }

    // Update the random beacon for validator selection
    pub fn update_random_beacon(&mut self, new_beacon: [u8; 32]) {
        self.random_beacon = new_beacon;
    }

    // Optimized validator selection with caching
    pub fn select_validators(&mut self, max_validators: usize) -> Vec<Vec<u8>> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check if we have a valid cached result
        if let Some((cached_validators, cache_time)) = &self.validator_selection_cache {
            if current_time - cache_time < VALIDATOR_CACHE_DURATION {
                return cached_validators.clone();
            }
        }

        // Process any pending validator updates before selection
        self.process_pending_updates();

        self.current_epoch += 1;
        self.active_validators.clear();

        // Get all eligible validators (not slashed)
        let eligible_validators: Vec<_> = self.validators.values().filter(|v| !v.slashed).collect();

        if eligible_validators.is_empty() {
            let empty_result = Vec::new();
            self.validator_selection_cache = Some((empty_result.clone(), current_time));
            return empty_result;
        }

        // Create a weighted selection based on stake amount
        let mut total_stake = 0;
        for validator in &eligible_validators {
            total_stake += validator.total_stake;
        }

        // Use VRF for deterministic but unpredictable selection
        let mut selected = Vec::new();
        let mut rng = rand::thread_rng();

        // Create a deterministic seed based on the current epoch and random beacon
        let mut seed = [0u8; 32];
        let epoch_bytes = self.current_epoch.to_le_bytes();
        for i in 0..8 {
            seed[i] = epoch_bytes[i];
        }
        for i in 0..32 {
            seed[i] ^= self.random_beacon[i];
        }

        // Use the seed to create a deterministic but unpredictable selection
        let mut hasher = Sha256::new();
        hasher.update(&seed);
        let selection_seed = hasher.finalize();

        // Select validators based on stake weight and the selection seed
        for i in 0..max_validators.min(eligible_validators.len()) {
            // Create a new selection point for each validator
            hasher = Sha256::new();
            hasher.update(&selection_seed);
            hasher.update(&i.to_le_bytes()); // Add iteration to make each selection different
            let selection_bytes = hasher.finalize();

            // Convert first 8 bytes to u64 for selection point
            let mut selection_point = 0u64;
            for i in 0..8 {
                selection_point = (selection_point << 8) | (selection_bytes[i] as u64);
            }
            selection_point = selection_point % total_stake;

            for validator in &eligible_validators {
                if selected.contains(&validator.public_key) {
                    continue;
                }

                if selection_point < validator.total_stake {
                    selected.push(validator.public_key.clone());
                    self.active_validators.insert(validator.public_key.clone());
                    break;
                }

                selection_point -= validator.total_stake;
            }
        }

        // Cache the result
        self.validator_selection_cache = Some((selected.clone(), current_time));

        // Rotate shards if needed
        if let Some(manager) = &mut self.shard_manager {
            let _ = manager.rotate_shards(self);
        }

        selected
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
                    let _ = self.deregister_validator(&update.validator);
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

    // Deregister a validator
    pub fn deregister_validator(&mut self, validator: &[u8]) -> Result<(), &'static str> {
        if !self.validators.contains_key(validator) {
            return Err("Validator not found");
        }

        // Remove from active validators if present
        self.active_validators.remove(validator);

        // Remove from validators map
        self.validators.remove(validator);

        // Undelegate all stakes delegated to this validator
        for (delegator_key, stake) in &mut self.stakes {
            if let Some(delegated_to) = &stake.delegated_to {
                if delegated_to == validator {
                    stake.delegated_to = None;
                }
            }
        }

        Ok(())
    }

    // Implement lazy reward calculation
    pub fn calculate_rewards(&mut self) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Only calculate rewards if enough time has passed
        if current_time - self.last_reward_calculation < COMPOUND_INTERVAL {
            return;
        }

        self.last_reward_calculation = current_time;

        for validator_key in &self.active_validators {
            if let Some(validator) = self.validators.get(validator_key) {
                // Calculate validator's own reward
                if let Some(stake) = self.stakes.get(validator_key) {
                    let stake_age = current_time - stake.timestamp;
                    let reward = calculate_stake_reward(stake.amount, stake_age);

                    // Add to unclaimed rewards
                    *self
                        .unclaimed_rewards
                        .entry(validator_key.clone())
                        .or_insert(0) += reward;
                }

                // Calculate and distribute rewards to delegators
                for (delegator_key, delegator_stake) in &self.stakes {
                    if let Some(delegated_to) = &delegator_stake.delegated_to {
                        if delegated_to == validator_key {
                            let stake_age = current_time - delegator_stake.timestamp;
                            let total_reward =
                                calculate_stake_reward(delegator_stake.amount, stake_age);

                            // Apply commission
                            let validator_commission =
                                (total_reward as f64 * validator.commission_rate) as u64;
                            let delegator_reward = total_reward - validator_commission;

                            // Add to unclaimed rewards
                            *self
                                .unclaimed_rewards
                                .entry(delegator_key.clone())
                                .or_insert(0) += delegator_reward;
                            *self
                                .unclaimed_rewards
                                .entry(validator_key.clone())
                                .or_insert(0) += validator_commission;
                        }
                    }
                }
            }
        }
    }

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
        let mut validators: Vec<_> = self.validators.values().collect();
        validators.sort_by(|a, b| b.reputation_score.partial_cmp(&a.reputation_score).unwrap());

        // Only consider top validators that aren't slashed and have room for delegation
        let eligible_validators: Vec<_> = validators
            .into_iter()
            .filter(|v| !v.slashed && v.delegated_stake < v.delegation_cap)
            .collect();

        if eligible_validators.is_empty() {
            return;
        }

        // Distribute stake evenly among top validators
        let stake_per_validator = amount / eligible_validators.len() as u64;
        let mut remaining = amount;

        for validator in eligible_validators {
            let stake_amount = stake_per_validator.min(remaining);
            remaining -= stake_amount;

            if stake_amount == 0 {
                break;
            }

            // Update validator stats
            if let Some(validator_info) = self.validators.get_mut(&validator.public_key) {
                validator_info.delegated_stake += stake_amount;
                validator_info.total_stake += stake_amount;
            }

            if remaining == 0 {
                break;
            }
        }
    }

    // Withdraw liquid stake from validators
    fn withdraw_liquid_stake(&mut self, amount: u64) {
        // Get validators sorted by reputation score (lowest first)
        let mut validators: Vec<_> = self.validators.values().collect();
        validators.sort_by(|a, b| a.reputation_score.partial_cmp(&b.reputation_score).unwrap());

        let mut remaining = amount;

        for validator in validators {
            if remaining == 0 {
                break;
            }

            if let Some(validator_info) = self.validators.get_mut(&validator.public_key) {
                let withdraw_amount = validator_info.delegated_stake.min(remaining);
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
        // Check if validator is active
        if !self.active_validators.contains(validator) {
            return Err("Not an active validator");
        }

        // Get the cross-chain stake
        let cross_chain_stake = match self.cross_chain_stakes.get_mut(stake_id) {
            Some(stake) => stake,
            None => return Err("Cross-chain stake not found"),
        };

        // Check if already verified by this validator
        if cross_chain_stake
            .verifications
            .contains(&validator.to_vec())
        {
            return Err("Already verified by this validator");
        }

        // Add verification
        cross_chain_stake.verifications.push(validator.to_vec());

        // Check if we have enough verifications
        if cross_chain_stake.verifications.len() >= CROSS_CHAIN_VERIFICATION_THRESHOLD as usize {
            cross_chain_stake.status = CrossChainStakeStatus::Verified;

            // Create a stake for the cross-chain address
            let _ = self.create_stake(
                cross_chain_stake.origin_address.clone(),
                cross_chain_stake.amount,
                false,
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
        // Check if proposer has enough stake
        let proposer_stake = match self.stakes.get(&proposer) {
            Some(stake) => stake.amount,
            None => return Err("Proposer has no stake"),
        };

        if proposer_stake < MIN_PROPOSAL_STAKE {
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

    // Calculate rewards with treasury allocation
    pub fn calculate_rewards(&mut self) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Only calculate rewards if enough time has passed
        if current_time - self.last_reward_calculation < COMPOUND_INTERVAL {
            return;
        }

        self.last_reward_calculation = current_time;

        for validator_key in &self.active_validators {
            if let Some(validator) = self.validators.get(validator_key) {
                // Calculate validator's own reward
                if let Some(stake) = self.stakes.get(validator_key) {
                    let stake_age = current_time - stake.timestamp;
                    let total_reward = calculate_stake_reward(stake.amount, stake_age);

                    // Allocate portion to treasury
                    let treasury_amount = (total_reward as f64 * TREASURY_ALLOCATION) as u64;
                    let validator_reward = total_reward - treasury_amount;

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
                            let total_reward =
                                calculate_stake_reward(delegator_stake.amount, stake_age);

                            // Allocate portion to treasury
                            let treasury_amount =
                                (total_reward as f64 * TREASURY_ALLOCATION) as u64;
                            let remaining_reward = total_reward - treasury_amount;

                            // Apply commission
                            let validator_commission =
                                (remaining_reward as f64 * validator.commission_rate) as u64;
                            let delegator_reward = remaining_reward - validator_commission;

                            // Add to unclaimed rewards
                            *self
                                .unclaimed_rewards
                                .entry(delegator_key.clone())
                                .or_insert(0) += delegator_reward;
                            *self
                                .unclaimed_rewards
                                .entry(validator_key.clone())
                                .or_insert(0) += validator_commission;

                            // Add to treasury
                            self.treasury.balance += treasury_amount;
                        }
                    }
                }
            }
        }
    }

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
        // Get validators sorted by stake amount
        let mut validators: Vec<_> = self
            .validators
            .iter()
            .filter(|(_, v)| !v.slashed && self.active_validators.contains(v.public_key.as_slice()))
            .collect();

        validators.sort_by(|(_, a), (_, b)| b.total_stake.cmp(&a.total_stake));

        // Take top BFT_COMMITTEE_SIZE validators
        validators
            .iter()
            .take(BFT_COMMITTEE_SIZE)
            .map(|(k, _)| k.clone())
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

        // Verify signature
        if !self.verify_bft_signature(&message) {
            return Err("Invalid BFT message signature");
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
        // Convert validator public key to ed25519 public key
        if let Ok(public_key) = ed25519_dalek::PublicKey::from_bytes(&message.validator) {
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
            if let Ok(signature) = ed25519_dalek::Signature::from_bytes(&message.signature) {
                return public_key.verify(&data, &signature).is_ok();
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
        block_hash: [u8; 32],
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
        }

        Ok(false)
    }

    // Determine the canonical chain when forks exist
    pub fn choose_canonical_chain(&self, chains: &[ChainInfo]) -> Option<usize> {
        if chains.is_empty() {
            return None;
        }

        if chains.len() == 1 {
            return Some(0);
        }

        // First check for finalized blocks
        for (i, chain) in chains.iter().enumerate() {
            let mut is_finalized = false;

            // Check if any block in the chain is finalized by BFT
            for (height, block_info) in &chain.blocks {
                if let Some(bft) = self.bft_consensus.as_ref() {
                    if bft.finalized_blocks.contains_key(height)
                        && bft.finalized_blocks[height] == block_info.hash
                    {
                        is_finalized = true;
                        break;
                    }
                }
            }

            if is_finalized {
                return Some(i);
            }
        }

        // Check economic finality (significant stake backing a chain)
        for (i, chain) in chains.iter().enumerate() {
            if chain.total_stake >= ECONOMIC_FINALITY_THRESHOLD {
                return Some(i);
            }
        }

        // Apply weighted fork choice rule
        let mut best_score = 0.0;
        let mut best_chain = 0;

        for (i, chain) in chains.iter().enumerate() {
            // Calculate stake score (normalized)
            let max_stake = chains.iter().map(|c| c.total_stake).max().unwrap_or(1);
            let stake_score = chain.total_stake as f64 / max_stake as f64;

            // Calculate length score (normalized)
            let max_length = chains.iter().map(|c| c.head).max().unwrap_or(1);
            let length_score = chain.head as f64 / max_length as f64;

            // Calculate weighted score
            let score = (stake_score * FORK_CHOICE_WEIGHT_STAKE)
                + (length_score * FORK_CHOICE_WEIGHT_LENGTH);

            if score > best_score {
                best_score = score;
                best_chain = i;
            }
        }

        Some(best_chain)
    }

    // Check if a chain reorganization is allowed
    pub fn is_reorg_allowed(&self, current_chain: &ChainInfo, new_chain: &ChainInfo) -> bool {
        // Don't allow reorgs beyond MAX_REORG_DEPTH
        if current_chain.head > new_chain.head + MAX_REORG_DEPTH {
            return false;
        }

        // Find common ancestor
        let mut common_height = 0;
        for height in (0..=current_chain.head.min(new_chain.head)).rev() {
            if current_chain.blocks.contains_key(&height)
                && new_chain.blocks.contains_key(&height)
                && current_chain.blocks[&height].hash == new_chain.blocks[&height].hash
            {
                common_height = height;
                break;
            }
        }

        // Calculate reorg depth
        let reorg_depth = current_chain.head - common_height;

        // Don't allow deep reorgs
        if reorg_depth > MAX_REORG_DEPTH {
            return false;
        }

        // Check if any block in the current chain is finalized
        for height in common_height..=current_chain.head {
            if let Some(block_info) = current_chain.blocks.get(&height) {
                if let Some(bft) = self.bft_consensus.as_ref() {
                    if bft.finalized_blocks.contains_key(&height)
                        && bft.finalized_blocks[&height] == block_info.hash
                    {
                        return false; // Can't reorg finalized blocks
                    }
                }
            }
        }

        // Check economic finality
        if current_chain.total_stake >= ECONOMIC_FINALITY_THRESHOLD
            && reorg_depth > MAX_REORG_DEPTH / 2
        {
            return false;
        }

        true
    }

    // Detect potential attacks based on chain behavior
    pub fn detect_attacks(&self, chains: &[ChainInfo]) -> Vec<String> {
        let mut attacks = Vec::new();

        // Check for frequent reorgs
        if chains.len() > 1 {
            // Count recent reorgs
            let reorg_count = self.recent_reorgs.len();
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // If we have many recent reorgs, it might be an attack
            if reorg_count > 5 {
                let oldest_reorg = self.recent_reorgs.front().unwrap();
                if current_time - oldest_reorg < 3600 {
                    // Within the last hour
                    attacks.push(format!(
                        "Potential 51% attack: {} reorgs in the last hour",
                        reorg_count
                    ));
                }
            }
        }

        // Check for long-range attacks (very old blocks suddenly appearing)
        for chain in chains {
            for (height, block_info) in &chain.blocks {
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                if current_time - block_info.timestamp > 7 * 24 * 60 * 60 {
                    // Older than a week
                    if *height > self.highest_finalized_block
                        && !self.known_blocks.contains(&block_info.hash)
                    {
                        attacks.push(format!(
                            "Potential long-range attack: Old block at height {} suddenly appeared",
                            height
                        ));
                    }
                }
            }
        }

        // Check for nothing-at-stake behavior (validators signing multiple chains)
        let mut validators_chains = HashMap::new();
        for (i, chain) in chains.iter().enumerate() {
            for block_info in chain.blocks.values() {
                for validator in &block_info.validators {
                    validators_chains
                        .entry(validator.clone())
                        .or_insert_with(HashSet::new)
                        .insert(i);
                }
            }
        }

        for (validator, signed_chains) in validators_chains {
            if signed_chains.len() > 1 {
                attacks.push(format!(
                    "Nothing-at-stake violation: Validator {:?} signed multiple competing chains",
                    validator
                ));
            }
        }

        attacks
    }

    // Add a block to the chain info
    pub fn add_block_to_chain(
        &mut self,
        chain: &mut ChainInfo,
        block: &crate::blockchain::Block,
    ) -> Result<(), &'static str> {
        let block_hash = block.hash();
        let parent_hash = block.header.previous_hash;
        let height = block.header.height;
        let timestamp = block.header.timestamp;

        // Verify block connects to chain
        if height > 0 {
            if !chain.blocks.contains_key(&(height - 1)) {
                return Err("Block doesn't connect to chain");
            }

            if chain.blocks[&(height - 1)].hash != parent_hash {
                return Err("Block parent hash doesn't match chain");
            }
        }

        // Get block proposer and validators
        let proposer = match block.header.miner.clone() {
            Some(miner) => miner,
            None => return Err("Block has no proposer"),
        };

        // Calculate total stake of validators who signed this block
        let mut validators = HashSet::new();
        let mut total_stake = 0;

        // In a real implementation, we would extract validator signatures from the block
        // For now, we'll just use the proposer
        validators.insert(proposer.clone());

        if let Some(validator_info) = self.validators.get(&proposer) {
            total_stake += validator_info.total_stake;
        }

        // Create block info
        let block_info = BlockInfo {
            hash: block_hash,
            parent_hash,
            height,
            timestamp,
            proposer,
            validators,
            total_stake,
        };

        // Add to chain
        chain.blocks.insert(height, block_info);

        // Update chain head if this is a new tip
        if height > chain.head {
            chain.head = height;
        }

        // Update chain total stake
        chain.total_stake = chain.blocks.values().map(|b| b.total_stake).sum();

        // Update chain total validators
        let mut all_validators = HashSet::new();
        for block in chain.blocks.values() {
            all_validators.extend(block.validators.iter().cloned());
        }
        chain.total_validators = all_validators.len();

        // Add to known blocks
        self.known_blocks.insert(block_hash);

        Ok(())
    }

    // Rotate validators to enhance security
    pub fn rotate_validators(&mut self) -> Vec<Vec<u8>> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check if it's time to rotate
        if self.last_rotation_time + ROTATION_INTERVAL > current_time {
            return Vec::new(); // Not time to rotate yet
        }

        // Get active validators sorted by consecutive epochs served
        let mut active_validators: Vec<_> = self
            .validators
            .iter()
            .filter(|(k, v)| !v.slashed && self.active_validators.contains(*k))
            .collect();

        if active_validators.is_empty() {
            return Vec::new(); // No active validators to rotate
        }

        // Sort by consecutive epochs (descending)
        active_validators.sort_by(|(_, a), (_, b)| b.consecutive_epochs.cmp(&a.consecutive_epochs));

        // Calculate how many validators to rotate
        let rotation_count = (active_validators.len() as f64 * ROTATION_PERCENTAGE) as usize;
        let rotation_count = rotation_count
            .max(MIN_ROTATION_COUNT)
            .min(active_validators.len() / 2);

        // Select validators to rotate out (those who served the most consecutive epochs)
        let rotated_out: Vec<Vec<u8>> = active_validators
            .iter()
            .take(rotation_count)
            .map(|(k, _)| (*k).clone())
            .collect();

        // Remove them from active validators
        for validator in &rotated_out {
            self.active_validators.remove(validator);

            // Reset consecutive epochs
            if let Some(validator_info) = self.validators.get_mut(validator) {
                validator_info.consecutive_epochs = 0;
            }
        }

        // Select new validators to rotate in
        let mut potential_validators: Vec<_> = self
            .validators
            .iter()
            .filter(|(k, v)| !v.slashed && !self.active_validators.contains(*k))
            .collect();

        // Sort by stake amount (descending)
        potential_validators.sort_by(|(_, a), (_, b)| b.total_stake.cmp(&a.total_stake));

        // Rotate in the same number of validators
        let rotated_in: Vec<Vec<u8>> = potential_validators
            .iter()
            .take(rotation_count)
            .map(|(k, _)| (*k).clone())
            .collect();

        // Add them to active validators
        for validator in &rotated_in {
            self.active_validators.insert(validator.clone());
        }

        // Update last rotation time
        self.last_rotation_time = current_time;

        // Increment consecutive epochs for remaining validators
        for (key, validator) in &mut self.validators {
            if self.active_validators.contains(key) {
                validator.consecutive_epochs += 1;

                // Force rotation for validators that served too many consecutive epochs
                if validator.consecutive_epochs >= MAX_CONSECUTIVE_EPOCHS {
                    self.active_validators.remove(key);
                    validator.consecutive_epochs = 0;
                    rotated_out.push(key.clone());
                }
            }
        }

        // Return the validators that were rotated out
        rotated_out
    }

    // Calculate performance score for a validator
    pub fn calculate_validator_performance(
        &mut self,
        validator: &[u8],
    ) -> Result<f64, &'static str> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let validator_info = match self.validators.get_mut(validator) {
            Some(info) => info,
            None => return Err("Validator not found"),
        };

        // Only recalculate if enough time has passed since last assessment
        if current_time - validator_info.last_performance_assessment < PERFORMANCE_ASSESSMENT_PERIOD
        {
            return Ok(validator_info.performance_score);
        }

        // Calculate uptime score (0.0 - 1.0)
        let uptime_score = validator_info.uptime;

        // Calculate blocks produced score (0.0 - 1.0)
        // Compare to the average blocks produced by active validators
        let avg_blocks = self
            .validators
            .values()
            .filter(|v| self.active_validators.contains(&v.public_key))
            .map(|v| v.blocks_proposed)
            .sum::<u64>() as f64
            / self.active_validators.len().max(1) as f64;

        let blocks_score = if avg_blocks > 0.0 {
            (validator_info.blocks_proposed as f64 / avg_blocks).min(2.0) / 2.0
        } else {
            0.5 // Default if no blocks have been produced
        };

        // Calculate latency score (0.0 - 1.0)
        // Lower latency is better
        let latency_score = if validator_info.block_latency.is_empty() {
            0.5 // Default if no latency data
        } else {
            // Get average latency for this validator
            let avg_latency = validator_info
                .block_latency
                .iter()
                .map(|(_, latency)| *latency)
                .sum::<u64>() as f64
                / validator_info.block_latency.len() as f64;

            // Get network average latency
            let network_avg_latency = self
                .validators
                .values()
                .flat_map(|v| v.block_latency.iter().map(|(_, l)| *l))
                .sum::<u64>() as f64
                / self
                    .validators
                    .values()
                    .map(|v| v.block_latency.len())
                    .sum::<usize>()
                    .max(1) as f64;

            if network_avg_latency > 0.0 {
                // Lower is better, so invert the ratio
                (1.0 - (avg_latency / network_avg_latency).min(2.0) / 2.0).max(0.0)
            } else {
                0.5
            }
        };

        // Calculate vote participation score (0.0 - 1.0)
        let vote_score = if validator_info.vote_participation.is_empty() {
            0.5 // Default if no vote data
        } else {
            validator_info
                .vote_participation
                .iter()
                .filter(|(_, participated)| *participated)
                .count() as f64
                / validator_info.vote_participation.len() as f64
        };

        // Calculate weighted performance score
        let performance_score = (uptime_score * PERFORMANCE_METRIC_UPTIME_WEIGHT)
            + (blocks_score * PERFORMANCE_METRIC_BLOCKS_WEIGHT)
            + (latency_score * PERFORMANCE_METRIC_LATENCY_WEIGHT)
            + (vote_score * PERFORMANCE_METRIC_VOTES_WEIGHT);

        // Update validator performance score
        validator_info.performance_score = performance_score;
        validator_info.last_performance_assessment = current_time;

        // Store historical performance data
        self.performance_metrics
            .entry(validator.to_vec())
            .or_insert_with(Vec::new)
            .push((current_time, performance_score));

        // Trim historical data to keep only recent entries
        if let Some(metrics) = self.performance_metrics.get_mut(validator) {
            // Keep only last 30 entries
            if metrics.len() > 30 {
                metrics.sort_by_key(|(timestamp, _)| *timestamp);
                *metrics = metrics.iter().skip(metrics.len() - 30).cloned().collect();
            }
        }

        Ok(performance_score)
    }

    // Apply performance-based reward multiplier
    pub fn apply_performance_reward_multiplier(&self, validator: &[u8], base_reward: u64) -> u64 {
        let validator_info = match self.validators.get(validator) {
            Some(info) => info,
            None => return base_reward, // No adjustment if validator not found
        };

        // Calculate multiplier based on performance score
        // Performance score is 0.0-1.0, map to PERFORMANCE_REWARD_MULTIPLIER_MIN-PERFORMANCE_REWARD_MULTIPLIER_MAX
        let multiplier = PERFORMANCE_REWARD_MULTIPLIER_MIN
            + (validator_info.performance_score
                * (PERFORMANCE_REWARD_MULTIPLIER_MAX - PERFORMANCE_REWARD_MULTIPLIER_MIN));

        // Apply multiplier to base reward
        (base_reward as f64 * multiplier) as u64
    }

    // Record block proposal latency
    pub fn record_block_latency(
        &mut self,
        validator: &[u8],
        latency_ms: u64,
    ) -> Result<(), &'static str> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let validator_info = match self.validators.get_mut(validator) {
            Some(info) => info,
            None => return Err("Validator not found"),
        };

        // Add latency data
        validator_info
            .block_latency
            .push((current_time, latency_ms));

        // Keep only recent entries (last 100)
        if validator_info.block_latency.len() > 100 {
            validator_info
                .block_latency
                .sort_by_key(|(timestamp, _)| *timestamp);
            validator_info.block_latency = validator_info
                .block_latency
                .iter()
                .skip(validator_info.block_latency.len() - 100)
                .cloned()
                .collect();
        }

        Ok(())
    }

    // Record vote participation
    pub fn record_vote_participation(
        &mut self,
        validator: &[u8],
        proposal_id: u64,
        participated: bool,
    ) -> Result<(), &'static str> {
        let validator_info = match self.validators.get_mut(validator) {
            Some(info) => info,
            None => return Err("Validator not found"),
        };

        // Add vote participation data
        validator_info
            .vote_participation
            .push((proposal_id, participated));

        // Keep only recent entries (last 100)
        if validator_info.vote_participation.len() > 100 {
            validator_info.vote_participation = validator_info
                .vote_participation
                .iter()
                .skip(validator_info.vote_participation.len() - 100)
                .cloned()
                .collect();
        }

        Ok(())
    }

    // Update the calculate_rewards method to use performance-based rewards
    pub fn calculate_rewards(&mut self) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Only calculate rewards if enough time has passed
        if current_time - self.last_reward_calculation < COMPOUND_INTERVAL {
            return;
        }

        self.last_reward_calculation = current_time;

        // Update performance scores for all active validators
        for validator_key in &self.active_validators.clone() {
            let _ = self.calculate_validator_performance(validator_key);
        }

        for validator_key in &self.active_validators {
            if let Some(validator) = self.validators.get(validator_key) {
                // Calculate validator's own reward
                if let Some(stake) = self.stakes.get(validator_key) {
                    let stake_age = current_time - stake.timestamp;
                    let base_reward = calculate_stake_reward(stake.amount, stake_age);

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
                                calculate_stake_reward(delegator_stake.amount, stake_age);

                            // Apply performance-based multiplier
                            let adjusted_reward = self
                                .apply_performance_reward_multiplier(validator_key, base_reward);

                            // Allocate portion to treasury
                            let treasury_amount =
                                (adjusted_reward as f64 * TREASURY_ALLOCATION) as u64;
                            let remaining_reward = adjusted_reward - treasury_amount;

                            // Apply commission
                            let validator_commission =
                                (remaining_reward as f64 * validator.commission_rate) as u64;
                            let delegator_reward = remaining_reward - validator_commission;

                            // Add to unclaimed rewards
                            *self
                                .unclaimed_rewards
                                .entry(delegator_key.clone())
                                .or_insert(0) += delegator_reward;
                            *self
                                .unclaimed_rewards
                                .entry(validator_key.clone())
                                .or_insert(0) += validator_commission;

                            // Add to treasury
                            self.treasury.balance += treasury_amount;
                        }
                    }
                }
            }
        }
    }

    // Join the insurance pool
    pub fn join_insurance_pool(&mut self, validator: &[u8]) -> Result<u64, &'static str> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check if validator exists
        let validator_info = match self.validators.get(validator) {
            Some(info) => info,
            None => return Err("Validator not found"),
        };

        // Check if validator has enough stake
        let stake = match self.stakes.get(validator) {
            Some(stake) => stake,
            None => return Err("Validator has no stake"),
        };

        // Calculate insurance fee
        let insurance_fee = (stake.amount as f64 * INSURANCE_POOL_FEE) as u64;

        // Check if validator has enough stake to pay the fee
        if stake.amount <= insurance_fee {
            return Err("Insufficient stake to pay insurance fee");
        }

        // Calculate coverage limit
        let coverage_limit = (stake.amount as f64 * INSURANCE_COVERAGE_PERCENTAGE) as u64;

        // Add to insurance pool
        self.insurance_pool.participants.insert(
            validator.to_vec(),
            InsuranceParticipation {
                validator: validator.to_vec(),
                contribution: insurance_fee,
                coverage_limit,
                join_time: current_time,
            },
        );

        // Update insurance pool balance
        self.insurance_pool.total_balance += insurance_fee;

        // Update validator's insurance coverage
        if let Some(validator_info) = self.validators.get_mut(validator) {
            validator_info.insurance_coverage = coverage_limit;
            validator_info.insurance_expiry = current_time + 365 * 24 * 60 * 60;
            // 1 year coverage
        }

        // Deduct fee from validator's stake
        if let Some(stake) = self.stakes.get_mut(validator) {
            stake.amount -= insurance_fee;
        }

        Ok(coverage_limit)
    }

    // File an insurance claim
    pub fn file_insurance_claim(
        &mut self,
        validator: &[u8],
        amount: u64,
        evidence: Vec<u8>,
    ) -> Result<u64, &'static str> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check if validator is in the insurance pool
        let participation = match self.insurance_pool.participants.get(validator) {
            Some(participation) => participation,
            None => return Err("Validator not in insurance pool"),
        };

        // Check if validator has insurance coverage
        let validator_info = match self.validators.get(validator) {
            Some(info) => info,
            None => return Err("Validator not found"),
        };

        if validator_info.insurance_coverage == 0 || validator_info.insurance_expiry < current_time
        {
            return Err("Validator has no active insurance coverage");
        }

        // Check if claim amount is within coverage limit
        if amount > validator_info.insurance_coverage {
            return Err("Claim amount exceeds coverage limit");
        }

        // Check if evidence is required and provided
        if INSURANCE_CLAIM_EVIDENCE_REQUIRED && evidence.is_empty() {
            return Err("Evidence is required for insurance claims");
        }

        // Create insurance claim
        let claim = InsuranceClaim {
            validator: validator.to_vec(),
            amount_requested: amount,
            amount_approved: 0, // Will be set during claim processing
            timestamp: current_time,
            evidence,
            status: InsuranceClaimStatus::Pending,
            processed: false,
        };

        // Add claim to insurance pool
        self.insurance_pool.claims.push(claim);

        Ok(amount)
    }

    // Process insurance claims
    pub fn process_insurance_claims(&mut self) -> Vec<(Vec<u8>, u64)> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut processed_claims = Vec::new();

        // Process each pending claim
        for claim in &mut self.insurance_pool.claims {
            if let InsuranceClaimStatus::Pending = claim.status {
                // Check if claim is within the claim window
                if current_time - claim.timestamp > INSURANCE_CLAIM_WINDOW {
                    claim.status = InsuranceClaimStatus::Rejected;
                    continue;
                }

                // Check if validator has active insurance
                if let Some(validator_info) = self.validators.get(&claim.validator) {
                    if validator_info.insurance_coverage == 0
                        || validator_info.insurance_expiry < current_time
                    {
                        claim.status = InsuranceClaimStatus::Rejected;
                        continue;
                    }

                    // Check if claim amount is within coverage limit
                    if claim.amount_requested > validator_info.insurance_coverage {
                        claim.amount_approved = validator_info.insurance_coverage;
                    } else {
                        claim.amount_approved = claim.amount_requested;
                    }

                    // Check if insurance pool has enough balance
                    if claim.amount_approved > self.insurance_pool.total_balance {
                        claim.amount_approved = self.insurance_pool.total_balance;
                    }

                    // Approve claim
                    claim.status = InsuranceClaimStatus::Approved;
                } else {
                    claim.status = InsuranceClaimStatus::Rejected;
                }
            }

            // Process approved claims
            if let InsuranceClaimStatus::Approved = claim.status {
                // Pay out the claim
                if let Some(stake) = self.stakes.get_mut(&claim.validator) {
                    stake.amount += claim.amount_approved;

                    // Deduct from insurance pool balance
                    self.insurance_pool.total_balance -= claim.amount_approved;

                    // Update validator's insurance coverage
                    if let Some(validator_info) = self.validators.get_mut(&claim.validator) {
                        validator_info.insurance_coverage -= claim.amount_approved;
                    }

                    // Mark claim as paid
                    claim.status = InsuranceClaimStatus::Paid;

                    // Add to processed claims
                    processed_claims.push((claim.validator.clone(), claim.amount_approved));
                }
            }
        }

        // Remove old claims
        self.insurance_pool.claims.retain(|claim| {
            current_time - claim.timestamp <= 30 * 24 * 60 * 60 // Keep claims for 30 days
        });

        processed_claims
    }

    // Modify the slash_validator method to use insurance
    pub fn slash_validator(
        &mut self,
        validator: &[u8],
        offense: SlashingOffense,
    ) -> Result<u64, &'static str> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Get validator info
        let validator_info = match self.validators.get_mut(validator) {
            Some(info) => info,
            None => return Err("Validator not found"),
        };

        // Get validator stake
        let stake = match self.stakes.get_mut(validator) {
            Some(stake) => stake,
            None => return Err("Validator has no stake"),
        };

        // Determine slashing percentage based on offense
        let base_percentage = match offense {
            SlashingOffense::Downtime => {
                // Check if in grace period
                if validator_info.in_grace_period {
                    if current_time - validator_info.grace_period_start <= GRACE_PERIOD_DOWNTIME {
                        return Ok(0); // No slashing during grace period
                    } else {
                        validator_info.in_grace_period = false;
                    }
                } else {
                    // Start grace period
                    validator_info.in_grace_period = true;
                    validator_info.grace_period_start = current_time;
                    return Ok(0); // No slashing for first offense
                }
                SLASHING_PERCENTAGE_DOWNTIME
            }
            SlashingOffense::DoubleSign => {
                validator_info.slashed = true; // Permanent slashing for double signing
                SLASHING_PERCENTAGE_DOUBLE_SIGN
            }
            SlashingOffense::Malicious => {
                validator_info.slashed = true; // Permanent slashing for malicious behavior
                SLASHING_PERCENTAGE_MALICIOUS
            }
        };

        // Apply progressive multiplier for repeated offenses
        let multiplier = if validator_info.offense_count > 0 {
            (PROGRESSIVE_SLASH_MULTIPLIER.powf(validator_info.offense_count as f64))
                .min(MAX_PROGRESSIVE_MULTIPLIER)
        } else {
            1.0
        };

        // Calculate slash amount
        let slash_percentage = (base_percentage as f64 * multiplier) as u64;
        let slash_amount = (stake.amount * slash_percentage) / 100;

        // Check if validator has insurance coverage
        let mut insurance_coverage = 0;
        if let Some(participation) = self.insurance_pool.participants.get(validator) {
            if validator_info.insurance_coverage > 0
                && validator_info.insurance_expiry >= current_time
            {
                // Calculate insurance coverage
                insurance_coverage = (slash_amount as f64 * INSURANCE_COVERAGE_PERCENTAGE) as u64;
                insurance_coverage = insurance_coverage.min(validator_info.insurance_coverage);
            }
        }

        // Apply slashing
        let actual_slash_amount = slash_amount - insurance_coverage;
        stake.amount -= actual_slash_amount;

        // Update validator info
        validator_info.offense_count += 1;

        // If insurance was used, update coverage
        if insurance_coverage > 0 {
            validator_info.insurance_coverage -= insurance_coverage;

            // Add to treasury (slashed amount goes to treasury)
            self.treasury.balance += actual_slash_amount;

            // Create automatic insurance claim for covered amount
            let evidence = match offense {
                SlashingOffense::Downtime => b"Automatic claim for downtime slashing".to_vec(),
                SlashingOffense::DoubleSign => {
                    b"Automatic claim for double signing slashing".to_vec()
                }
                SlashingOffense::Malicious => {
                    b"Automatic claim for malicious behavior slashing".to_vec()
                }
            };

            let _ = self.file_insurance_claim(validator, insurance_coverage, evidence);
        } else {
            // Add to treasury (slashed amount goes to treasury)
            self.treasury.balance += actual_slash_amount;
        }

        // Remove from active validators if permanently slashed
        if validator_info.slashed {
            self.active_validators.remove(validator);
        }

        Ok(actual_slash_amount)
    }

    // Request to exit as a validator
    pub fn request_validator_exit(&mut self, validator: &[u8]) -> Result<u64, &'static str> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check if validator exists
        let validator_info = match self.validators.get_mut(validator) {
            Some(info) => info,
            None => return Err("Validator not found"),
        };

        // Check if validator has already requested exit
        if validator_info.exit_requested {
            return Err("Validator has already requested to exit");
        }

        // Check if validator has stake
        let stake = match self.stakes.get(validator) {
            Some(stake) => stake,
            None => return Err("Validator has no stake"),
        };

        // Mark validator as requesting exit
        validator_info.exit_requested = true;
        validator_info.exit_request_time = current_time;

        // Add to exit queue
        if self.exit_queue.queue.len() >= self.exit_queue.max_size {
            return Err("Exit queue is full, try again later");
        }

        self.exit_queue.queue.push(ExitRequest {
            validator: validator.to_vec(),
            request_time: current_time,
            stake_amount: stake.amount,
            processed: false,
            completion_time: None,
        });

        // Sort exit queue by stake amount (smaller stakes exit first)
        self.exit_queue.queue.sort_by_key(|req| req.stake_amount);

        // Calculate estimated wait time
        let position = self
            .exit_queue
            .queue
            .iter()
            .position(|req| req.validator == validator)
            .unwrap_or(0);

        let estimated_wait =
            EXIT_QUEUE_MIN_WAIT_TIME + (position as u64 * EXIT_QUEUE_PROCESSING_INTERVAL);

        Ok(estimated_wait.min(EXIT_QUEUE_MAX_WAIT_TIME))
    }

    // Process the validator exit queue
    pub fn process_exit_queue(&mut self) -> Vec<Vec<u8>> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Only process if enough time has passed
        if current_time - self.exit_queue.last_processed < EXIT_QUEUE_PROCESSING_INTERVAL {
            return Vec::new();
        }

        self.exit_queue.last_processed = current_time;

        let mut processed_validators = Vec::new();

        // Process validators in the queue
        for request in &mut self.exit_queue.queue {
            if request.processed {
                continue;
            }

            // Check if minimum wait time has passed
            if current_time - request.request_time < EXIT_QUEUE_MIN_WAIT_TIME {
                continue;
            }

            // Process exit request
            if let Some(validator_info) = self.validators.get_mut(&request.validator) {
                // Remove from active validators
                self.active_validators.remove(&request.validator);

                // Mark as no longer a validator
                validator_info.exit_requested = false;

                // Mark request as processed
                request.processed = true;
                request.completion_time = Some(current_time);

                // Add to processed list
                processed_validators.push(request.validator.clone());
            }
        }

        // Remove processed requests from queue after a delay
        self.exit_queue.queue.retain(|req| {
            !req.processed || req.completion_time.unwrap_or(0) + 7 * 24 * 60 * 60 > current_time
            // Keep for 7 days
        });

        processed_validators
    }

    // Check exit queue status for a validator
    pub fn check_exit_status(&self, validator: &[u8]) -> Result<(bool, u64), &'static str> {
        // Check if validator exists
        let validator_info = match self.validators.get(validator) {
            Some(info) => info,
            None => return Err("Validator not found"),
        };

        // Check if validator has requested exit
        if !validator_info.exit_requested {
            return Err("Validator has not requested to exit");
        }

        // Find position in exit queue
        let position = self
            .exit_queue
            .queue
            .iter()
            .position(|req| req.validator == validator && !req.processed);

        match position {
            Some(pos) => {
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                let request = &self.exit_queue.queue[pos];

                // Calculate remaining wait time
                let min_exit_time = request.request_time + EXIT_QUEUE_MIN_WAIT_TIME;
                let remaining_time = if current_time < min_exit_time {
                    min_exit_time - current_time
                } else {
                    // Estimate based on position and processing interval
                    (pos as u64 * EXIT_QUEUE_PROCESSING_INTERVAL).min(EXIT_QUEUE_MAX_WAIT_TIME)
                };

                Ok((false, remaining_time))
            }
            None => {
                // Check if request was processed
                let processed = self
                    .exit_queue
                    .queue
                    .iter()
                    .any(|req| req.validator == validator && req.processed);

                if processed {
                    Ok((true, 0))
                } else {
                    Err("Validator not found in exit queue")
                }
            }
        }
    }

    // Cancel exit request
    pub fn cancel_exit_request(&mut self, validator: &[u8]) -> Result<(), &'static str> {
        // Check if validator exists
        let validator_info = match self.validators.get_mut(validator) {
            Some(info) => info,
            None => return Err("Validator not found"),
        };

        // Check if validator has requested exit
        if !validator_info.exit_requested {
            return Err("Validator has not requested to exit");
        }

        // Reset exit request flag
        validator_info.exit_requested = false;

        // Remove from exit queue
        self.exit_queue
            .queue
            .retain(|req| req.validator != validator || req.processed);

        Ok(())
    }

    // Modify deregister_validator to use exit queue
    pub fn deregister_validator(&mut self, validator: &[u8]) -> Result<(), &'static str> {
        // Check if validator exists
        let validator_info = match self.validators.get(validator) {
            Some(info) => info,
            None => return Err("Validator not found"),
        };

        // Check if validator has completed exit process
        if validator_info.exit_requested {
            // Check exit status
            let (completed, _) = self.check_exit_status(validator)?;

            if !completed {
                return Err("Validator exit is still in progress");
            }
        } else {
            // Request exit first
            self.request_validator_exit(validator)?;
            return Err("Validator must complete exit process before deregistering");
        }

        // Remove from active validators
        self.active_validators.remove(validator);

        // Remove validator info
        self.validators.remove(validator);

        Ok(())
    }
}

impl super::ConsensusEngine for ProofOfStake {
    fn validate_block(&self, block: &Block) -> bool {
        // TODO: Implement full validation with stake proof
        true
    }

    fn calculate_next_difficulty(&self) -> u32 {
        self.current_difficulty
    }
}

// Standalone functions for easier access

pub fn validate_stake(proof: &StakeProof) -> bool {
    let pos = ProofOfStake::new();
    pos.validate_stake(proof.stake_amount, proof.stake_age)
}

pub fn calculate_stake_reward(stake_amount: u64, stake_time: u64) -> u64 {
    let pos = ProofOfStake::new();
    pos.calculate_stake_reward(stake_amount, stake_time)
}

// Create a staking transaction
pub fn create_staking_transaction(
    public_key: &[u8],
    amount: u64,
    keypair: &Keypair,
    utxos: &[(OutPoint, TransactionOutput)],
) -> Option<Transaction> {
    // TODO: Implement staking transaction creation
    None
}

// Create a withdrawal transaction
pub fn create_withdrawal_transaction(
    public_key: &[u8],
    amount: u64,
    keypair: &Keypair,
) -> Option<Transaction> {
    // TODO: Implement withdrawal transaction creation
    None
}

// Create a delegation transaction
pub fn create_delegation_transaction(
    delegator: &[u8],
    validator: &[u8],
    keypair: &Keypair,
) -> Option<Transaction> {
    // TODO: Implement delegation transaction creation
    None
}

// Define different types of slashing offenses
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SlashingOffense {
    Downtime,
    DoubleSign,
    Malicious,
}

// Shard structure
pub struct Shard {
    pub id: usize,
    pub validators: HashSet<Vec<u8>>, // Set of validator public keys in this shard
    pub total_stake: u64,
    pub active: bool,
}

// Cross-shard committee for cross-shard transactions
pub struct CrossShardCommittee {
    pub shard1: usize,
    pub shard2: usize,
    pub validators: Vec<Vec<u8>>, // List of validator public keys in this committee
    pub created_at: u64,
    pub signatures: HashMap<Vec<u8>, Vec<u8>>, // Validator -> Signature
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stake_validation() {
        let pos = ProofOfStake::new();

        // Test valid stake
        assert!(pos.validate_stake(2000, 25 * 60 * 60));

        // Test invalid stake amount
        assert!(!pos.validate_stake(500, 25 * 60 * 60));

        // Test invalid stake age
        assert!(!pos.validate_stake(2000, 12 * 60 * 60));
    }

    #[test]
    fn test_stake_reward_calculation() {
        let pos = ProofOfStake::new();

        // Test reward for 1000 tokens staked for 30 days
        let reward = pos.calculate_stake_reward(1000, 30 * 24 * 60 * 60);

        // Expected reward should be approximately 0.41% for 30 days (5% annual rate)
        // 1000 * 0.0041 = 4.1
        assert!(reward >= 4 && reward <= 5);
    }

    #[test]
    fn test_staking_contract() {
        let mut contract = StakingContract::new(24 * 60 * 60); // 1 day epoch

        // Create a stake
        let public_key = vec![1, 2, 3, 4];
        assert!(contract
            .create_stake(public_key.clone(), 2000, true)
            .is_ok());

        // Try to create a stake with insufficient amount
        let public_key2 = vec![5, 6, 7, 8];
        assert!(contract
            .create_stake(public_key2.clone(), 500, true)
            .is_err());

        // Register as validator
        assert!(contract
            .register_validator(public_key.clone(), 0.1, None)
            .is_ok());

        // Select validators
        let selected = contract.select_validators(10);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], public_key);
    }
}
