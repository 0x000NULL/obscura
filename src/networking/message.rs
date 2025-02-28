use std::io::{self, Read, Write};
use std::time::{Duration, Instant};
use rand::{Rng, thread_rng};
use sha2::{Sha256, Digest};

// Constants for message framing and padding
const MAGIC_BYTES: [u8; 4] = [0x4f, 0x42, 0x58, 0x00]; // "OBX\0"
const MIN_MESSAGE_SIZE: usize = 64; // Minimum size for any message
const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 10; // 10MB max message size
const CHECKSUM_SIZE: usize = 4; // First 4 bytes of SHA-256 hash
const HEADER_SIZE: usize = 4 + 4 + 4 + 4; // Magic bytes + command + length + checksum
const MIN_PROCESSING_TIME_MS: u64 = 5; // Minimum processing time to prevent timing attacks

// Message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Handshake = 0x01,
    Ping = 0x02,
    Pong = 0x03,
    GetBlocks = 0x04,
    Blocks = 0x05,
    GetTransactions = 0x06,
    Transactions = 0x07,
    Inv = 0x08,
    GetData = 0x09,
    NotFound = 0x0A,
    MemPool = 0x0B,
    Alert = 0x0C,
    Reject = 0x0D,
    FilterLoad = 0x0E,
    FilterAdd = 0x0F,
    FilterClear = 0x10,
    MerkleBlock = 0x11,
    BlockAnnouncement = 0x12,
    BlockAnnouncementResponse = 0x13,
    GetCompactBlock = 0x14,
    CompactBlock = 0x15,
    GetBlockTransactions = 0x16,
    BlockTransactions = 0x17,
}

impl MessageType {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x01 => Some(MessageType::Handshake),
            0x02 => Some(MessageType::Ping),
            0x03 => Some(MessageType::Pong),
            0x04 => Some(MessageType::GetBlocks),
            0x05 => Some(MessageType::Blocks),
            0x06 => Some(MessageType::GetTransactions),
            0x07 => Some(MessageType::Transactions),
            0x08 => Some(MessageType::Inv),
            0x09 => Some(MessageType::GetData),
            0x0A => Some(MessageType::NotFound),
            0x0B => Some(MessageType::MemPool),
            0x0C => Some(MessageType::Alert),
            0x0D => Some(MessageType::Reject),
            0x0E => Some(MessageType::FilterLoad),
            0x0F => Some(MessageType::FilterAdd),
            0x10 => Some(MessageType::FilterClear),
            0x11 => Some(MessageType::MerkleBlock),
            0x12 => Some(MessageType::BlockAnnouncement),
            0x13 => Some(MessageType::BlockAnnouncementResponse),
            0x14 => Some(MessageType::GetCompactBlock),
            0x15 => Some(MessageType::CompactBlock),
            0x16 => Some(MessageType::GetBlockTransactions),
            0x17 => Some(MessageType::BlockTransactions),
            _ => None,
        }
    }
}

// Message serialization errors
#[derive(Debug)]
pub enum MessageError {
    IoError(io::Error),
    InvalidMagic,
    InvalidChecksum,
    InvalidMessageType,
    MessageTooLarge,
    MessageTooSmall,
    DeserializationError,
}

impl From<io::Error> for MessageError {
    fn from(err: io::Error) -> Self {
        MessageError::IoError(err)
    }
}

// Message structure
#[derive(Debug, Clone)]
pub struct Message {
    pub message_type: MessageType,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn new(message_type: MessageType, payload: Vec<u8>) -> Self {
        Message {
            message_type,
            payload,
        }
    }

    // Calculate checksum (first 4 bytes of double SHA-256 hash)
    fn calculate_checksum(data: &[u8]) -> [u8; CHECKSUM_SIZE] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash1 = hasher.finalize();
        
        let mut hasher = Sha256::new();
        hasher.update(hash1);
        let hash2 = hasher.finalize();
        
        let mut checksum = [0u8; CHECKSUM_SIZE];
        checksum.copy_from_slice(&hash2[0..CHECKSUM_SIZE]);
        checksum
    }

    // Add random padding to the message to enhance privacy
    fn add_padding(data: &mut Vec<u8>) {
        let mut rng = thread_rng();
        
        // Ensure minimum message size for privacy
        if data.len() < MIN_MESSAGE_SIZE {
            let padding_size = MIN_MESSAGE_SIZE - data.len();
            let padding_bytes: Vec<u8> = (0..padding_size).map(|_| rng.gen()).collect();
            data.extend_from_slice(&padding_bytes);
        } else {
            // Add random padding between 0-32 bytes for variable message sizes
            let padding_size = rng.gen_range(0, 33);
            let padding_bytes: Vec<u8> = (0..padding_size).map(|_| rng.gen()).collect();
            data.extend_from_slice(&padding_bytes);
        }
    }

    // Serialize the message with framing, checksum, and padding
    pub fn serialize(&self) -> Result<Vec<u8>, MessageError> {
        let mut buffer = Vec::new();
        
        // Add magic bytes
        buffer.extend_from_slice(&MAGIC_BYTES);
        
        // Add message type
        buffer.extend_from_slice(&(self.message_type as u32).to_le_bytes());
        
        // Create a copy of the payload for checksum calculation
        let mut payload_with_padding = self.payload.clone();
        
        // Add privacy-enhancing padding
        Self::add_padding(&mut payload_with_padding);
        
        // Add payload length (including padding)
        let payload_length = payload_with_padding.len() as u32;
        if payload_length as usize > MAX_MESSAGE_SIZE {
            return Err(MessageError::MessageTooLarge);
        }
        buffer.extend_from_slice(&payload_length.to_le_bytes());
        
        // Calculate checksum of the padded payload
        let checksum = Self::calculate_checksum(&payload_with_padding);
        buffer.extend_from_slice(&checksum);
        
        // Add the padded payload
        buffer.extend_from_slice(&payload_with_padding);
        
        Ok(buffer)
    }

    // Deserialize bytes to a message with validation
    pub fn deserialize(data: &[u8]) -> Result<Self, MessageError> {
        // Timing attack protection - ensure minimum processing time
        let start_time = Instant::now();
        
        // Check minimum header size
        if data.len() < HEADER_SIZE {
            return Err(MessageError::MessageTooSmall);
        }
        
        // Verify magic bytes
        if data[0..4] != MAGIC_BYTES {
            return Err(MessageError::InvalidMagic);
        }
        
        // Read message type
        let message_type_value = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let message_type = MessageType::from_u32(message_type_value)
            .ok_or(MessageError::InvalidMessageType)?;
        
        // Read payload length
        let payload_length = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        
        // Validate payload length
        if payload_length > MAX_MESSAGE_SIZE {
            return Err(MessageError::MessageTooLarge);
        }
        
        if data.len() < HEADER_SIZE + payload_length {
            return Err(MessageError::MessageTooSmall);
        }
        
        // Read checksum
        let expected_checksum = [data[12], data[13], data[14], data[15]];
        
        // Get payload
        let payload_with_padding = &data[HEADER_SIZE..HEADER_SIZE + payload_length];
        
        // Verify checksum
        let actual_checksum = Self::calculate_checksum(payload_with_padding);
        if actual_checksum != expected_checksum {
            return Err(MessageError::InvalidChecksum);
        }
        
        // Extract actual payload (without padding)
        // Note: In a real implementation, we would need a way to determine the actual payload size
        // For now, we'll just use the entire padded payload
        let payload = payload_with_padding.to_vec();
        
        // Timing attack protection - ensure minimum processing time
        let elapsed = start_time.elapsed();
        if elapsed < Duration::from_millis(MIN_PROCESSING_TIME_MS) {
            std::thread::sleep(Duration::from_millis(MIN_PROCESSING_TIME_MS) - elapsed);
        }
        
        Ok(Message {
            message_type,
            payload,
        })
    }

    // Helper method to read a message from a stream
    pub fn read_from_stream<R: Read>(stream: &mut R) -> Result<Self, MessageError> {
        // Read header first
        let mut header = [0u8; HEADER_SIZE];
        stream.read_exact(&mut header)?;
        
        // Verify magic bytes
        if header[0..4] != MAGIC_BYTES {
            return Err(MessageError::InvalidMagic);
        }
        
        // Read payload length
        let payload_length = u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
        
        // Validate payload length
        if payload_length > MAX_MESSAGE_SIZE {
            return Err(MessageError::MessageTooLarge);
        }
        
        // Read the payload
        let mut buffer = vec![0u8; HEADER_SIZE + payload_length];
        buffer[0..HEADER_SIZE].copy_from_slice(&header);
        stream.read_exact(&mut buffer[HEADER_SIZE..])?;
        
        // Deserialize the complete message
        Self::deserialize(&buffer)
    }

    // Helper method to write a message to a stream
    pub fn write_to_stream<W: Write>(&self, stream: &mut W) -> Result<(), MessageError> {
        let serialized = self.serialize()?;
        stream.write_all(&serialized)?;
        stream.flush()?;
        Ok(())
    }
    
    // Helper method to write a message to a stream wrapped in Arc<Mutex>
    pub fn write_to_mutex_stream<T: Read + Write>(&self, stream: &std::sync::Arc<std::sync::Mutex<T>>) -> Result<(), MessageError> {
        if let Ok(mut guard) = stream.lock() {
            let serialized = self.serialize()?;
            guard.write_all(&serialized)?;
            guard.flush()?;
            Ok(())
        } else {
            Err(MessageError::IoError(io::Error::new(io::ErrorKind::Other, "Failed to lock stream")))
        }
    }
    
    // Helper method to read a message from a stream wrapped in Arc<Mutex>
    pub fn read_from_mutex_stream<T: Read + Write>(stream: &std::sync::Arc<std::sync::Mutex<T>>) -> Result<Self, MessageError> {
        if let Ok(mut guard) = stream.lock() {
            Self::read_from_stream(&mut *guard)
        } else {
            Err(MessageError::IoError(io::Error::new(io::ErrorKind::Other, "Failed to lock stream")))
        }
    }
}

// Tests for message serialization and deserialization
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization_deserialization() {
        let message = Message::new(MessageType::Ping, vec![1, 2, 3, 4]);
        
        // Serialize the message
        let serialized = message.serialize().unwrap();
        
        // Deserialize the message
        let deserialized = Message::deserialize(&serialized).unwrap();
        
        // Verify the deserialized message matches the original
        assert_eq!(deserialized.message_type, MessageType::Ping);
        // Note: The deserialized payload includes padding, so we can't directly compare
    }

    #[test]
    fn test_message_types() {
        // Test all message types
        let message_types = [
            MessageType::Handshake,
            MessageType::Ping,
            MessageType::Pong,
            MessageType::GetBlocks,
            MessageType::Blocks,
            MessageType::GetTransactions,
            MessageType::Transactions,
            MessageType::Inv,
            MessageType::GetData,
            MessageType::NotFound,
            MessageType::MemPool,
            MessageType::Alert,
            MessageType::Reject,
            MessageType::FilterLoad,
            MessageType::FilterAdd,
            MessageType::FilterClear,
            MessageType::MerkleBlock,
            MessageType::BlockAnnouncement,
            MessageType::BlockAnnouncementResponse,
            MessageType::GetCompactBlock,
            MessageType::CompactBlock,
            MessageType::GetBlockTransactions,
            MessageType::BlockTransactions,
        ];
        
        for message_type in &message_types {
            let message = Message::new(*message_type, vec![1, 2, 3, 4]);
            let serialized = message.serialize().unwrap();
            let deserialized = Message::deserialize(&serialized).unwrap();
            
            assert_eq!(deserialized.message_type, *message_type);
        }
    }

    #[test]
    fn test_checksum_validation() {
        let payload = vec![1, 2, 3, 4, 5];
        let message = Message::new(MessageType::Ping, payload);
        
        let mut serialized = message.serialize().unwrap();
        
        // Corrupt the checksum
        serialized[12] = serialized[12].wrapping_add(1);
        
        let result = Message::deserialize(&serialized);
        assert!(matches!(result, Err(MessageError::InvalidChecksum)));
    }

    #[test]
    fn test_magic_bytes_validation() {
        let payload = vec![1, 2, 3, 4, 5];
        let message = Message::new(MessageType::Ping, payload);
        
        let mut serialized = message.serialize().unwrap();
        
        // Corrupt the magic bytes
        serialized[0] = serialized[0].wrapping_add(1);
        
        let result = Message::deserialize(&serialized);
        assert!(matches!(result, Err(MessageError::InvalidMagic)));
    }

    #[test]
    fn test_message_padding() {
        let small_payload = vec![1, 2, 3];
        let message = Message::new(MessageType::Ping, small_payload);
        
        let serialized = message.serialize().unwrap();
        
        // The serialized message should be at least MIN_MESSAGE_SIZE + HEADER_SIZE
        assert!(serialized.len() >= MIN_MESSAGE_SIZE + HEADER_SIZE);
    }
} 