#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

constexpr static const uint32_t INITIAL_DIFFICULTY = 545259519;

constexpr static const uint32_t MIN_DIFFICULTY = 1;

constexpr static const uint32_t MAX_DIFFICULTY = 545259519;

constexpr static const uint64_t TARGET_BLOCK_TIME = 60;

constexpr static const uintptr_t DIFFICULTY_WINDOW = 10;

constexpr static const uint64_t MAX_TIME_ADJUSTMENT = 300;

constexpr static const uint64_t MIN_TIME_ADJUSTMENT = 30;

constexpr static const uintptr_t EMERGENCY_BLOCKS_THRESHOLD = 3;

constexpr static const uint64_t EMERGENCY_TIME_THRESHOLD = 300;

constexpr static const uintptr_t EMA_WINDOW = 20;

constexpr static const uintptr_t MTP_WINDOW = 11;

constexpr static const double EMA_ALPHA = 0.1;

constexpr static const double OSCILLATION_DAMP_FACTOR = 0.75;

constexpr static const uintptr_t HASHRATE_WINDOW = 50;

constexpr static const double MAX_STAKE_WEIGHT = 0.3;

constexpr static const uint64_t ATTACK_THRESHOLD = 600;

constexpr static const double HASHRATE_VARIANCE_THRESHOLD = 0.5;

constexpr static const uint64_t TIME_WARP_THRESHOLD = 15;

constexpr static const double DIFFICULTY_OSCILLATION_THRESHOLD = 0.3;

constexpr static const double BLOCK_TIME_VARIANCE_THRESHOLD = 0.4;

constexpr static const double ADAPTIVE_WEIGHT_THRESHOLD = 0.2;

constexpr static const uintptr_t MAX_CONSECUTIVE_ADJUSTMENTS = 3;

constexpr static const uintptr_t VISUALIZATION_WINDOW = 100;

constexpr static const double HASHRATE_CENTRALIZATION_THRESHOLD = 0.3;

constexpr static const double NETWORK_LATENCY_THRESHOLD = 5.0;

constexpr static const uintptr_t PEER_DIVERSITY_THRESHOLD = 10;

constexpr static const double BLOCK_SIZE_VARIANCE_THRESHOLD = 0.5;

constexpr static const uint64_t INITIAL_BLOCK_REWARD = 50000000000;

constexpr static const uint64_t HALVING_INTERVAL = 2628000;

constexpr static const uint64_t GENESIS_TIMESTAMP = 1708905600;

constexpr static const uint64_t COINBASE_MATURITY = 100;

constexpr static const uintptr_t TARGET_BLOCK_SIZE = 1000000;

constexpr static const uint64_t MIN_FEE_RATE = 1;

constexpr static const uint64_t MAX_FEE_RATE = 10000;

/// Minimum fee increase required for Replace-By-Fee (RBF)
constexpr static const double MIN_RBF_FEE_INCREASE = 1.1;

/// Constants for BLS signature consensus
constexpr static const uintptr_t VALIDATOR_THRESHOLD_PERCENTAGE = 67;

constexpr static const uintptr_t MAX_VALIDATORS = 100;

constexpr static const uint64_t MIN_STAKE_AMOUNT = 1000;

constexpr static const uint64_t VALIDATOR_REWARD_PERCENTAGE = 5;

constexpr static const uint64_t MINIMUM_STAKE = 1000;

constexpr static const uint64_t MINIMUM_STAKE_AGE = ((24 * 60) * 60);

constexpr static const uint64_t STAKE_LOCK_PERIOD = (((7 * 24) * 60) * 60);

constexpr static const uint64_t WITHDRAWAL_DELAY = (((3 * 24) * 60) * 60);

constexpr static const uint64_t SLASHING_PERCENTAGE = 10;

constexpr static const double ANNUAL_STAKING_REWARD_RATE = 0.05;

constexpr static const uint64_t COMPOUND_INTERVAL = ((24 * 60) * 60);

constexpr static const uint64_t SLASHING_PERCENTAGE_DOWNTIME = 5;

constexpr static const uint64_t SLASHING_PERCENTAGE_DOUBLE_SIGN = 20;

constexpr static const uint64_t SLASHING_PERCENTAGE_MALICIOUS = 50;

constexpr static const uint64_t GRACE_PERIOD_DOWNTIME = ((1 * 60) * 60);

constexpr static const double PROGRESSIVE_SLASH_MULTIPLIER = 1.5;

constexpr static const double MAX_PROGRESSIVE_MULTIPLIER = 3.0;

constexpr static const uint64_t WEAK_SUBJECTIVITY_CHECKPOINT_INTERVAL = 1000;

constexpr static const uint64_t VALIDATOR_CACHE_DURATION = (10 * 60);

constexpr static const uintptr_t BATCH_UPDATE_SIZE = 100;

constexpr static const uint64_t REWARD_CLAIM_WINDOW = (((30 * 24) * 60) * 60);

constexpr static const uint64_t MAX_DELEGATION_CAP = 10000000;

constexpr static const uint64_t AUTO_DELEGATION_THRESHOLD = 5000;

constexpr static const double BASE_REWARD_RATE = 0.05;

constexpr static const double MIN_REWARD_RATE = 0.02;

constexpr static const double MAX_REWARD_RATE = 0.15;

constexpr static const double OPTIMAL_STAKE_TARGET = 0.67;

constexpr static const double REPUTATION_WEIGHT_UPTIME = 0.5;

constexpr static const double REPUTATION_WEIGHT_BLOCKS = 0.3;

constexpr static const double REPUTATION_WEIGHT_AGE = 0.2;

constexpr static const double LIQUID_STAKING_FEE = 0.01;

constexpr static const double TREASURY_ALLOCATION = 0.10;

constexpr static const uint64_t MIN_PROPOSAL_STAKE = 10000;

constexpr static const uint64_t PROPOSAL_VOTING_PERIOD = (((7 * 24) * 60) * 60);

constexpr static const uint64_t PROPOSAL_EXECUTION_DELAY = (((2 * 24) * 60) * 60);

constexpr static const uint64_t CROSS_CHAIN_VERIFICATION_THRESHOLD = 10;

constexpr static const uintptr_t BFT_COMMITTEE_SIZE = 100;

constexpr static const double BFT_THRESHOLD = (2.0 / 3.0);

constexpr static const uint64_t BFT_ROUND_DURATION = 10;

constexpr static const uintptr_t BFT_MAX_ROUNDS = 10;

constexpr static const uint64_t FINALITY_DEPTH = 100;

constexpr static const uint64_t TIME_BASED_FINALITY_WINDOW = ((24 * 60) * 60);

constexpr static const uint64_t MAX_REORG_DEPTH = 50;

constexpr static const uint64_t ECONOMIC_FINALITY_THRESHOLD = 1000000;

constexpr static const double FORK_CHOICE_WEIGHT_STAKE = 0.7;

constexpr static const double FORK_CHOICE_WEIGHT_LENGTH = 0.3;

constexpr static const uint64_t ROTATION_INTERVAL = (((30 * 24) * 60) * 60);

constexpr static const double ROTATION_PERCENTAGE = 0.2;

constexpr static const uintptr_t MIN_ROTATION_COUNT = 3;

constexpr static const uint64_t MAX_CONSECUTIVE_EPOCHS = 10;

constexpr static const double PERFORMANCE_REWARD_MULTIPLIER_MAX = 1.5;

constexpr static const double PERFORMANCE_REWARD_MULTIPLIER_MIN = 0.5;

constexpr static const double PERFORMANCE_METRIC_UPTIME_WEIGHT = 0.4;

constexpr static const double PERFORMANCE_METRIC_BLOCKS_WEIGHT = 0.3;

constexpr static const double PERFORMANCE_METRIC_LATENCY_WEIGHT = 0.2;

constexpr static const double PERFORMANCE_METRIC_VOTES_WEIGHT = 0.1;

constexpr static const uint64_t PERFORMANCE_ASSESSMENT_PERIOD = ((24 * 60) * 60);

constexpr static const double INSURANCE_POOL_FEE = 0.01;

constexpr static const double INSURANCE_COVERAGE_PERCENTAGE = 0.5;

constexpr static const uint64_t INSURANCE_CLAIM_WINDOW = (((14 * 24) * 60) * 60);

constexpr static const bool INSURANCE_CLAIM_EVIDENCE_REQUIRED = true;

constexpr static const uintptr_t EXIT_QUEUE_MAX_SIZE = 10;

constexpr static const uint64_t EXIT_QUEUE_PROCESSING_INTERVAL = ((24 * 60) * 60);

constexpr static const uint64_t EXIT_QUEUE_MIN_WAIT_TIME = (((3 * 24) * 60) * 60);

constexpr static const uint64_t EXIT_QUEUE_MAX_WAIT_TIME = (((30 * 24) * 60) * 60);

constexpr static const uintptr_t SHARD_COUNT = 4;

constexpr static const uintptr_t MIN_VALIDATORS_PER_SHARD = 10;

constexpr static const uintptr_t MAX_VALIDATORS_PER_SHARD = 100;

constexpr static const uint64_t SHARD_ROTATION_INTERVAL = (((14 * 24) * 60) * 60);

constexpr static const uintptr_t CROSS_SHARD_COMMITTEE_SIZE = 5;

constexpr static const double MARKETPLACE_FEE_PERCENTAGE = 0.005;

constexpr static const uint64_t REPUTATION_ORACLE_UPDATE_INTERVAL = ((24 * 60) * 60);

constexpr static const uint64_t AUTO_COMPOUND_INTERVAL = (((7 * 24) * 60) * 60);

constexpr static const double DIVERSITY_TARGET_PERCENTAGE = 0.8;

constexpr static const double GEO_DISTRIBUTION_BONUS = 0.02;

constexpr static const uint8_t HARDWARE_SECURITY_LEVEL_REQUIRED = 2;

constexpr static const uint64_t FORMAL_VERIFICATION_REWARD = 1000;

constexpr static const uintptr_t MAX_ASSETS_PER_VALIDATOR = 5;

constexpr static const uint64_t ASSET_EXCHANGE_RATE_UPDATE_INTERVAL = ((1 * 60) * 60);

constexpr static const double ASSET_WEIGHT_DEFAULT = 1.0;

constexpr static const double ASSET_WEIGHT_NATIVE = 1.5;

constexpr static const double MIN_SECONDARY_ASSET_STAKE_PERCENTAGE = 0.2;

constexpr static const double MAX_RATE_CHANGE_PERCENTAGE = 10.0;

constexpr static const uint64_t MARKETPLACE_LISTING_DURATION = (((30 * 24) * 60) * 60);

constexpr static const double MARKETPLACE_MIN_REPUTATION = 0.7;

constexpr static const double MARKETPLACE_ESCROW_PERCENTAGE = 0.1;

constexpr static const uint64_t MARKETPLACE_DISPUTE_WINDOW = (((7 * 24) * 60) * 60);

constexpr static const double MARKETPLACE_MAX_COMMISSION = 0.25;

constexpr static const uintptr_t REPUTATION_ORACLE_COMMITTEE_SIZE = 7;

constexpr static const uint64_t REPUTATION_ORACLE_ROTATION_INTERVAL = (((30 * 24) * 60) * 60);

constexpr static const uintptr_t REPUTATION_ORACLE_THRESHOLD = 5;

constexpr static const uintptr_t REPUTATION_HISTORY_LENGTH = 100;

constexpr static const double REPUTATION_EXTERNAL_WEIGHT = 0.3;

constexpr static const uint64_t AUTO_COMPOUND_MIN_STAKE = 5000;

constexpr static const double AUTO_COMPOUND_FEE = 0.001;

constexpr static const uint64_t AUTO_COMPOUND_MAX_FREQUENCY = (((1 * 24) * 60) * 60);

constexpr static const uint64_t AUTO_COMPOUND_THRESHOLD = 100;

constexpr static const double AUTO_COMPOUND_DELEGATION_LIMIT = 0.9;

constexpr static const double DIVERSITY_METRIC_WEIGHT_ENTITY = 0.4;

constexpr static const double DIVERSITY_METRIC_WEIGHT_GEOGRAPHY = 0.3;

constexpr static const double DIVERSITY_METRIC_WEIGHT_STAKE = 0.2;

constexpr static const double DIVERSITY_METRIC_WEIGHT_CLIENT = 0.1;

constexpr static const uint64_t DIVERSITY_ASSESSMENT_INTERVAL = (((7 * 24) * 60) * 60);

constexpr static const uintptr_t GEO_REGIONS = 8;

constexpr static const uintptr_t GEO_MIN_REGIONS_REPRESENTED = 4;

constexpr static const double GEO_REGION_BONUS_THRESHOLD = 0.7;

constexpr static const uint64_t GEO_REPORTING_INTERVAL = (((7 * 24) * 60) * 60);

constexpr static const uint64_t HARDWARE_SECURITY_ATTESTATION_INTERVAL = (((90 * 24) * 60) * 60);

constexpr static const double HARDWARE_SECURITY_AUDIT_PROBABILITY = 0.1;

constexpr static const double FORMAL_VERIFICATION_COVERAGE_REQUIRED = 0.8;

constexpr static const uint64_t FORMAL_VERIFICATION_AUDIT_INTERVAL = (((180 * 24) * 60) * 60);

constexpr static const double FORMAL_VERIFICATION_BONUS_PERCENTAGE = 0.01;

constexpr static const uint64_t QUANTUM_RESISTANCE_PHASE_IN_PERIOD = (((365 * 24) * 60) * 60);

constexpr static const uint64_t QUANTUM_KEY_ROTATION_INTERVAL = (((30 * 24) * 60) * 60);

constexpr static const bool QUANTUM_HYBRID_MODE_ENABLED = true;

constexpr static const uintptr_t DEFAULT_THRESHOLD = 2;

constexpr static const uintptr_t MAX_PARTICIPANTS = 100;

constexpr static const uint64_t DKG_TIMEOUT_SECONDS = 300;

constexpr static const uint64_t DEFAULT_VERIFICATION_TIMEOUT_SECONDS = 60;

constexpr static const uint32_t PROTOCOL_VERSION = 1;

constexpr static const uint32_t MIN_COMPATIBLE_VERSION = 1;

constexpr static const uint64_t HANDSHAKE_TIMEOUT_SECS = 30;

constexpr static const bool CONNECTION_OBFUSCATION_ENABLED = true;

constexpr static const uintptr_t TCP_BUFFER_SIZE_BASE = 8192;

constexpr static const uintptr_t TCP_BUFFER_JITTER_MAX = 2048;

constexpr static const uint64_t TIMEOUT_BASE_SECS = 300;

constexpr static const uint64_t TIMEOUT_JITTER_MAX_SECS = 60;

constexpr static const uint64_t KEEPALIVE_TIME_MIN_SECS = 30;

constexpr static const uint64_t KEEPALIVE_TIME_MAX_SECS = 90;

constexpr static const uint64_t KEEPALIVE_INTERVAL_MIN_SECS = 5;

constexpr static const uint64_t KEEPALIVE_INTERVAL_MAX_SECS = 15;

constexpr static const bool MESSAGE_PADDING_ENABLED = true;

constexpr static const uintptr_t MESSAGE_MIN_PADDING_BYTES = 64;

constexpr static const uintptr_t MESSAGE_MAX_PADDING_BYTES = 512;

constexpr static const bool MESSAGE_PADDING_TIMING_JITTER_ENABLED = true;

constexpr static const uint64_t MESSAGE_DUMMY_INTERVAL_MIN_MS = 5000;

constexpr static const uint64_t MESSAGE_DUMMY_INTERVAL_MAX_MS = 30000;

constexpr static const bool TRAFFIC_OBFUSCATION_ENABLED = true;

constexpr static const bool TRAFFIC_BURST_MODE_ENABLED = true;

constexpr static const uintptr_t TRAFFIC_BURST_MIN_MESSAGES = 2;

constexpr static const uintptr_t TRAFFIC_BURST_MAX_MESSAGES = 8;

constexpr static const uint64_t TRAFFIC_BURST_INTERVAL_MIN_MS = 5000;

constexpr static const uint64_t TRAFFIC_BURST_INTERVAL_MAX_MS = 60000;

constexpr static const bool TRAFFIC_CHAFF_ENABLED = true;

constexpr static const uintptr_t TRAFFIC_CHAFF_MIN_SIZE_BYTES = 32;

constexpr static const uintptr_t TRAFFIC_CHAFF_MAX_SIZE_BYTES = 512;

constexpr static const uint64_t TRAFFIC_CHAFF_INTERVAL_MIN_MS = 15000;

constexpr static const uint64_t TRAFFIC_CHAFF_INTERVAL_MAX_MS = 120000;

constexpr static const bool TRAFFIC_MORPHING_ENABLED = true;

constexpr static const bool TRAFFIC_CONSTANT_RATE_ENABLED = false;

constexpr static const uintptr_t TRAFFIC_CONSTANT_RATE_BYTES_PER_SEC = 1024;

constexpr static const bool MESSAGE_PADDING_DISTRIBUTION_UNIFORM = true;

constexpr static const uint64_t MESSAGE_PADDING_INTERVAL_MIN_MS = 5000;

constexpr static const uint64_t MESSAGE_PADDING_INTERVAL_MAX_MS = 30000;

constexpr static const bool MESSAGE_PADDING_SEND_DUMMY_ENABLED = true;

constexpr static const uint64_t MESSAGE_PADDING_DUMMY_INTERVAL_MIN_MS = 5000;

constexpr static const uint64_t MESSAGE_PADDING_DUMMY_INTERVAL_MAX_MS = 30000;

constexpr static const bool I2P_SUPPORT_ENABLED = true;

constexpr static const uint16_t I2P_DEFAULT_PORT = 0;

constexpr static const uint16_t I2P_PROXY_PORT = 4444;

constexpr static const uint64_t I2P_CONNECTION_TIMEOUT_SECS = 30;

constexpr static const uintptr_t MAX_CONNECTIONS_PER_NETWORK = 3;

constexpr static const double STEM_PROBABILITY = 0.9;

constexpr static const uintptr_t MIN_ROUTING_PATH_LENGTH = 2;

constexpr static const uintptr_t MAX_ROUTING_PATH_LENGTH = 10;

constexpr static const uint64_t FLUFF_PROPAGATION_DELAY_MIN_MS = 50;

constexpr static const uint64_t FLUFF_PROPAGATION_DELAY_MAX_MS = 500;

constexpr static const double MULTI_HOP_STEM_PROBABILITY = 0.3;

constexpr static const uintptr_t MAX_MULTI_HOP_LENGTH = 3;

constexpr static const bool USE_DECOY_TRANSACTIONS = true;

constexpr static const double DECOY_TRANSACTION_PROBABILITY = 0.05;

constexpr static const uint64_t DECOY_GENERATION_INTERVAL_MS = 30000;

constexpr static const bool BATCH_TRANSACTIONS_BEFORE_FLUFF = true;

constexpr static const uintptr_t MAX_BATCH_SIZE = 5;

constexpr static const uint64_t MAX_BATCH_WAIT_MS = 5000;

constexpr static const bool ADAPTIVE_TIMING_ENABLED = true;

constexpr static const double MULTI_PATH_ROUTING_PROBABILITY = 0.15;

constexpr static const bool TRAFFIC_ANALYSIS_PROTECTION_ENABLED = true;

constexpr static const double BACKGROUND_NOISE_PROBABILITY = 0.03;

constexpr static const uint32_t SUSPICIOUS_BEHAVIOR_THRESHOLD = 5;

constexpr static const bool SECURE_FAILOVER_ENABLED = true;

constexpr static const bool PRIVACY_LOGGING_ENABLED = false;

constexpr static const bool ENCRYPTED_PEER_COMMUNICATION = true;

constexpr static const bool DYNAMIC_PEER_SCORING_ENABLED = true;

constexpr static const double REPUTATION_SCORE_MAX = 100.0;

constexpr static const double REPUTATION_SCORE_MIN = -100.0;

constexpr static const double REPUTATION_DECAY_FACTOR = 0.95;

constexpr static const double REPUTATION_PENALTY_SUSPICIOUS = -10.0;

constexpr static const double REPUTATION_PENALTY_SYBIL = -20.0;

constexpr static const double REPUTATION_REWARD_SUCCESSFUL_RELAY = 2.0;

constexpr static const double REPUTATION_THRESHOLD_STEM = 0.5;

constexpr static const double REPUTATION_CRITICAL_PATH_THRESHOLD = 50.0;

constexpr static const double REPUTATION_WEIGHT_FACTOR = 2.5;

constexpr static const bool REPUTATION_ADAPTIVE_THRESHOLDS = true;

constexpr static const uintptr_t REPUTATION_MIN_SAMPLE_SIZE = 10;

constexpr static const double REPUTATION_RELIABILITY_BONUS = 10.0;

constexpr static const double REPUTATION_ENFORCED_RATIO = 0.7;

constexpr static const uintptr_t ANONYMITY_SET_MIN_SIZE = 3;

constexpr static const uintptr_t MIN_PEERS_FOR_SYBIL_DETECTION = 5;

constexpr static const bool ANTI_SNOOPING_ENABLED = true;

constexpr static const uint32_t MAX_TX_REQUESTS_BEFORE_PENALTY = 5;

constexpr static const double DUMMY_RESPONSE_PROBABILITY = 0.2;

constexpr static const bool STEGANOGRAPHIC_HIDING_ENABLED = true;

constexpr static const bool DIFFERENTIAL_PRIVACY_ENABLED = true;

constexpr static const double LAPLACE_SCALE_FACTOR = 10.0;

constexpr static const bool TOR_INTEGRATION_ENABLED = false;

constexpr static const uint16_t TOR_SOCKS_PORT = 9050;

constexpr static const uint16_t TOR_CONTROL_PORT = 9051;

constexpr static const bool MIXNET_INTEGRATION_ENABLED = false;

constexpr static const bool LAYERED_ENCRYPTION_ENABLED = true;

constexpr static const bool POST_QUANTUM_ENCRYPTION_ENABLED = false;

constexpr static const uintptr_t ECLIPSE_DEFENSE_IP_DIVERSITY_THRESHOLD = 3;

constexpr static const double ECLIPSE_DEFENSE_PEER_ROTATION_PERCENT = 0.2;

constexpr static const double ECLIPSE_ATTACK_THRESHOLD = 0.6;

constexpr static const bool AUTOMATIC_ATTACK_RESPONSE_ENABLED = true;

constexpr static const uintptr_t SYBIL_DETECTION_CLUSTER_THRESHOLD = 3;

constexpr static const uintptr_t MIN_AS_DIVERSITY = 2;

constexpr static const uintptr_t MIN_COUNTRY_DIVERSITY = 2;

constexpr static const double MIN_SUBNET_DIVERSITY_RATIO = 0.6;

constexpr static const uintptr_t ROUTE_DIVERSITY_CACHE_SIZE = 1000;

constexpr static const double ROUTE_REUSE_PENALTY = 0.3;

constexpr static const double DIVERSITY_SCORE_THRESHOLD = 0.7;

constexpr static const uintptr_t PATH_PATTERN_CACHE_SIZE = 100;

constexpr static const double PATTERN_SIMILARITY_THRESHOLD = 0.7;

constexpr static const uint64_t TIMING_JITTER_RANGE_MS = 100;

constexpr static const double MAX_PATTERN_FREQUENCY = 0.1;

constexpr static const uintptr_t ANONYMITY_SET_MAX_SIZE = 20;

constexpr static const bool ANONYMITY_SET_DYNAMIC_SIZING_ENABLED = true;

constexpr static const uintptr_t ANONYMITY_SET_K_ANONYMITY_LEVEL = 2;

constexpr static const bool ANONYMITY_SET_TRANSACTION_CORRELATION_RESISTANCE = true;

constexpr static const bool PLAUSIBLE_DENIABILITY_ENABLED = true;

constexpr static const double PLAUSIBLE_DENIABILITY_DUMMY_RATE = 0.15;

constexpr static const bool GRAPH_ANALYSIS_COUNTERMEASURES_ENABLED = true;

constexpr static const double GRAPH_ENTROPY_THRESHOLD = 0.7;

constexpr static const double TRANSACTION_FLOW_RANDOMIZATION_FACTOR = 0.3;

constexpr static const uintptr_t MIN_ENTROPY_SAMPLES = 5;

constexpr static const bool TRANSACTION_AGGREGATION_ENABLED = true;

constexpr static const uintptr_t MAX_AGGREGATION_SIZE = 10;

constexpr static const uint64_t AGGREGATION_TIMEOUT_MS = 2000;

constexpr static const uintptr_t STEM_BATCH_SIZE = 5;

constexpr static const uint64_t STEM_BATCH_TIMEOUT_MS = 3000;

constexpr static const uint64_t STEM_FLUFF_TRANSITION_MIN_DELAY_MS = 1000;

constexpr static const uint64_t STEM_FLUFF_TRANSITION_MAX_DELAY_MS = 5000;

constexpr static const uintptr_t FLUFF_ENTRY_POINTS_MIN = 2;

constexpr static const uintptr_t FLUFF_ENTRY_POINTS_MAX = 4;

constexpr static const bool ROUTING_TABLE_INFERENCE_RESISTANCE_ENABLED = true;

constexpr static const uint64_t ROUTING_TABLE_REFRESH_INTERVAL_MS = 30000;

extern "C" {

extern void *randomx_alloc_cache(uint32_t flags);

extern void randomx_init_cache(void *cache, const uint8_t *key, uintptr_t key_size);

extern void *randomx_create_vm(uint32_t flags, void *cache, void *dataset);

extern void randomx_calculate_hash(void *vm,
                                   const uint8_t *input,
                                   uintptr_t input_size,
                                   uint8_t *output);

extern void randomx_destroy_vm(void *vm);

extern void randomx_release_cache(void *cache);

void *_aligned_malloc(uintptr_t size, uintptr_t alignment);

void _aligned_free(void *ptr);

/// Allocate memory with the specified alignment
/// This function can be used as a replacement for _aligned_malloc
uint8_t *aligned_malloc(uintptr_t size, uintptr_t alignment);

/// Free memory allocated with aligned_malloc
/// This function can be used as a replacement for _aligned_free
void aligned_free(uint8_t *ptr, uintptr_t alignment);

} // extern "C"
