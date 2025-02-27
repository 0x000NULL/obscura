use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct ExitQueue {
    pub queue: Vec<(Vec<u8>, u64, u64)>, // (validator, request_time, unlock_time)
    pub processing_time: u64,
    pub max_exits_per_epoch: usize,
}

impl ExitQueue {
    pub fn new(max_exits_per_epoch: usize) -> Self {
        Self {
            queue: Vec::new(),
            processing_time: 0,
            max_exits_per_epoch,
        }
    }

    pub fn add_request(&mut self, validator: Vec<u8>, timestamp: SystemTime) -> u64 {
        let request_time = timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let unlock_time = request_time + 24 * 60 * 60; // 24 hours lock period
        
        // Check if validator already has a request
        if let Some(pos) = self.queue.iter().position(|(v, _, _)| v == &validator) {
            self.queue.remove(pos);
        }
        
        self.queue.push((validator, request_time, unlock_time));
        unlock_time
    }

    pub fn remove_request(&mut self, validator: Vec<u8>) {
        if let Some(pos) = self.queue.iter().position(|(v, _, _)| v == &validator) {
            self.queue.remove(pos);
        }
    }

    pub fn process_requests(&mut self, now: SystemTime) -> Vec<Vec<u8>> {
        let current_time = now
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut processed = Vec::new();
        let mut i = 0;
        let mut processed_count = 0;

        while i < self.queue.len() && processed_count < self.max_exits_per_epoch {
            if let Some((validator, _, unlock_time)) = self.queue.get(i) {
                if *unlock_time <= current_time {
                    processed.push(validator.clone());
                    self.queue.remove(i);
                    processed_count += 1;
                } else {
                    i += 1;
                }
            }
        }

        processed
    }
} 