use bincode::serialize;

impl Transaction {
    pub fn to_bytes(&self) -> Vec<u8> {
        serialize(self).unwrap_or_default()
    }
} 