use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq)]
pub enum BftMessageType {
    Prepare,
    Commit,
    ViewChange,
}

#[derive(Debug, Clone)]
pub struct BftMessage {
    pub view: u64,
    pub sequence: u64,
    pub message_type: BftMessageType,
    pub block_hash: Vec<u8>,
    pub sender: Vec<u8>,
    pub signature: Vec<u8>,
}

impl BftMessage {
    pub fn new(
        view: u64,
        sequence: u64,
        message_type: BftMessageType,
        block_hash: Vec<u8>,
        sender: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            view,
            sequence,
            message_type,
            block_hash,
            sender,
            signature,
        }
    }
}

#[derive(Debug, Default)]
pub struct BftConsensus {
    pub current_view: u64,
    pub sequence_number: u64,
    pub prepared_messages: Vec<BftMessage>,
    pub committed_messages: Vec<BftMessage>,
    pub view_change_messages: Vec<BftMessage>,
    pub committee: Vec<Vec<u8>>,
    pub current_leader: Vec<u8>,
}

impl BftConsensus {
    pub fn new() -> Self {
        Self {
            current_view: 0,
            sequence_number: 0,
            prepared_messages: Vec::new(),
            committed_messages: Vec::new(),
            view_change_messages: Vec::new(),
            committee: Vec::new(),
            current_leader: Vec::new(),
        }
    }

    pub fn process_message(&mut self, message: BftMessage) -> Result<(), String> {
        match message.message_type {
            BftMessageType::Prepare => {
                self.prepared_messages.push(message);
            },
            BftMessageType::Commit => {
                self.committed_messages.push(message);
            },
            BftMessageType::ViewChange => {
                self.view_change_messages.push(message);
            },
        }
        Ok(())
    }
} 