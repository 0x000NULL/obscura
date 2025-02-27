use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum ProposalAction {
    TreasuryAllocation {
        recipient: Vec<u8>,
        amount: u64,
        description: String,
    },
    ParameterUpdate {
        parameter: String,
        value: String,
    },
    ValidatorUpdate {
        validator: Vec<u8>,
        action: String,
    },
}

#[derive(Debug, Default)]
pub struct Governance {
    pub proposals: HashMap<Vec<u8>, ProposalAction>,
    pub votes: HashMap<Vec<u8>, Vec<Vec<u8>>>,
    pub executed_proposals: Vec<Vec<u8>>,
    pub voting_period: u64,
    pub quorum: u64,
} 