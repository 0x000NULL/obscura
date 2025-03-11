use crate::networking::message::{Message, MessageType, MessageError};
use std::io::Cursor;
use std::sync::{Arc, Mutex};

#[test]
fn test_message_creation() {
    let msg = Message::new(MessageType::Ping, vec![1, 2, 3, 4]);
    assert_eq!(msg.message_type, MessageType::Ping);
    assert_eq!(msg.payload, vec![1, 2, 3, 4]);
    assert!(!msg.is_padded);
    assert_eq!(msg.padding_size, 0);
    assert!(!msg.is_morphed);
    assert!(msg.morph_type.is_none());
}

#[test]
fn test_message_type_conversion() {
    // Test valid conversions
    assert_eq!(MessageType::from_u32(0x01), Some(MessageType::Handshake));
    assert_eq!(MessageType::from_u32(0x02), Some(MessageType::Ping));
    assert_eq!(MessageType::from_u32(0x03), Some(MessageType::Pong));
    
    // Test invalid conversion
    assert_eq!(MessageType::from_u32(0xFF), None);
}

#[test]
fn test_message_serialization() {
    let original_msg = Message::new(MessageType::Ping, vec![1, 2, 3, 4]);
    let serialized = original_msg.serialize().unwrap();
    let deserialized = Message::deserialize(&serialized).unwrap();
    
    assert_eq!(deserialized.message_type, original_msg.message_type);
    assert_eq!(deserialized.payload, original_msg.payload);
    assert_eq!(deserialized.is_padded, original_msg.is_padded);
    assert_eq!(deserialized.padding_size, original_msg.padding_size);
}

#[test]
fn test_message_stream_io() {
    let original_msg = Message::new(MessageType::Ping, vec![1, 2, 3, 4]);
    let mut cursor = Cursor::new(Vec::new());
    
    // Test writing to stream
    original_msg.write_to_stream(&mut cursor).unwrap();
    
    // Reset cursor position
    cursor.set_position(0);
    
    // Test reading from stream
    let read_msg = Message::read_from_stream(&mut cursor).unwrap();
    
    assert_eq!(read_msg.message_type, original_msg.message_type);
    assert_eq!(read_msg.payload, original_msg.payload);
}

#[test]
fn test_message_mutex_stream_io() {
    let original_msg = Message::new(MessageType::Ping, vec![1, 2, 3, 4]);
    let stream = Arc::new(Mutex::new(Cursor::new(Vec::new())));
    
    // Test writing to mutex stream
    original_msg.write_to_mutex_stream(&stream).unwrap();
    
    // Reset cursor position
    {
        let mut guard = stream.lock().unwrap();
        guard.set_position(0);
    }
    
    // Test reading from mutex stream
    let read_msg = Message::read_from_mutex_stream(&stream).unwrap();
    
    assert_eq!(read_msg.message_type, original_msg.message_type);
    assert_eq!(read_msg.payload, original_msg.payload);
}

#[test]
fn test_message_padding() {
    let mut msg = Message::new(MessageType::Ping, vec![1, 2, 3, 4]);
    assert!(!msg.is_padding_applied());
    
    msg.set_padding_applied(true);
    assert!(msg.is_padding_applied());
}

#[test]
fn test_invalid_message_deserialization() {
    // Test with invalid magic bytes
    let invalid_magic = vec![0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00];
    assert!(matches!(Message::deserialize(&invalid_magic), Err(MessageError::InvalidMagic)));
    
    // Test with invalid message type
    let invalid_type = vec![0x4f, 0x42, 0x58, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00];
    assert!(matches!(Message::deserialize(&invalid_type), Err(MessageError::InvalidMessageType)));
    
    // Test with message too small
    let too_small = vec![0x4f, 0x42, 0x58, 0x00];
    assert!(matches!(Message::deserialize(&too_small), Err(MessageError::MessageTooSmall)));
}

#[test]
fn test_message_error_display() {
    let io_error = MessageError::IoError(std::io::Error::new(std::io::ErrorKind::Other, "test error"));
    assert!(format!("{}", io_error).contains("IO error"));
    
    let invalid_magic = MessageError::InvalidMagic;
    assert_eq!(format!("{}", invalid_magic), "Invalid magic bytes");
    
    let invalid_checksum = MessageError::InvalidChecksum;
    assert_eq!(format!("{}", invalid_checksum), "Invalid message checksum");
} 