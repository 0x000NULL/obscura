pub mod pow;
pub mod pos;

pub trait ConsensusEngine {
    fn validate_block(&self, block: &crate::blockchain::Block) -> bool;
    fn calculate_next_difficulty(&self) -> u32;
}

pub struct HybridConsensus {
    pow_engine: pow::ProofOfWork,
    pos_engine: pos::ProofOfStake,
}

impl HybridConsensus {
    pub fn new() -> Self {
        HybridConsensus {
            pow_engine: pow::ProofOfWork::new(),
            pos_engine: pos::ProofOfStake::new(),
        }
    }
} 