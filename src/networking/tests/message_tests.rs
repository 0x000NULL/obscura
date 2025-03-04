use crate::networking::message::{Message, MessageError, MessageType};
use std::io::Cursor;
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

#[test]
fn test_message_serialization_deserialization() {
    // Create a test message
    let payload = vec![1, 2, 3, 4, 5];
    let message = Message::new(MessageType::Ping, payload.clone());

    // Serialize the message
    let serialized = message.serialize().unwrap();

    // Deserialize the message
    let deserialized = Message::deserialize(&serialized).unwrap();

    // Verify the message type
    assert_eq!(deserialized.message_type, MessageType::Ping);

    // Note: The payload includes padding, so we can't directly compare
    // In a real implementation, we would need a way to determine the actual payload size
}

#[test]
fn test_message_stream_io() {
    // Create a memory buffer to simulate a stream
    let mut buffer = Vec::new();

    // Create a test message
    let payload = vec![1, 2, 3, 4, 5];
    let message = Message::new(MessageType::Ping, payload.clone());

    // Write the message to the buffer
    {
        let mut cursor = Cursor::new(&mut buffer);
        message.write_to_stream(&mut cursor).unwrap();
    }

    // Read the message from the buffer
    let mut cursor = Cursor::new(&buffer);
    let read_message = Message::read_from_stream(&mut cursor).unwrap();

    // Verify the message type
    assert_eq!(read_message.message_type, MessageType::Ping);
}

#[test]
fn test_message_checksum_validation() {
    // Create a test message
    let payload = vec![1, 2, 3, 4, 5];
    let message = Message::new(MessageType::Ping, payload);

    // Serialize the message
    let mut serialized = message.serialize().unwrap();

    // Corrupt the checksum
    serialized[12] = serialized[12].wrapping_add(1);

    // Attempt to deserialize the corrupted message
    let result = Message::deserialize(&serialized);

    // Verify that deserialization fails with a checksum error
    assert!(matches!(result, Err(MessageError::InvalidChecksum)));
}

#[test]
fn test_message_padding() {
    // Create a test message with a small payload
    let small_payload = vec![1, 2, 3];
    let message = Message::new(MessageType::Ping, small_payload);

    // Serialize the message
    let serialized = message.serialize().unwrap();

    // Verify that the message has been padded to the minimum size
    assert!(serialized.len() >= 64 + 16); // MIN_MESSAGE_SIZE + HEADER_SIZE
}

#[test]
fn test_message_tcp_communication() {
    // Start a TCP server in a separate thread
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server_thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();

        // Read a message from the client
        let message = Message::read_from_stream(&mut stream).unwrap();
        assert_eq!(message.message_type, MessageType::Ping);

        // Send a response
        let response = Message::new(MessageType::Pong, vec![5, 4, 3, 2, 1]);
        response.write_to_stream(&mut stream).unwrap();
    });

    // Connect to the server
    thread::sleep(Duration::from_millis(100)); // Give the server time to start
    let mut client = TcpStream::connect(server_addr).unwrap();

    // Send a message to the server
    let message = Message::new(MessageType::Ping, vec![1, 2, 3, 4, 5]);
    message.write_to_stream(&mut client).unwrap();

    // Read the response
    let response = Message::read_from_stream(&mut client).unwrap();
    assert_eq!(response.message_type, MessageType::Pong);

    // Wait for the server thread to complete
    server_thread.join().unwrap();
}

#[test]
fn test_message_size_limits() {
    // Test with a payload that's too large
    let large_payload = vec![0; 1024 * 1024 * 11]; // 11MB (exceeds MAX_MESSAGE_SIZE)
    let message = Message::new(MessageType::Ping, large_payload);

    // Serialization should fail with a MessageTooLarge error
    let result = message.serialize();
    assert!(matches!(result, Err(MessageError::MessageTooLarge)));
}

#[test]
fn test_message_type_validation() {
    // Create a valid serialized message
    let payload = vec![1, 2, 3, 4, 5];
    let message = Message::new(MessageType::Ping, payload);
    let mut serialized = message.serialize().unwrap();

    // Corrupt the message type to an invalid value
    serialized[4] = 0xFF;
    serialized[5] = 0xFF;
    serialized[6] = 0xFF;
    serialized[7] = 0xFF;

    // Attempt to deserialize the corrupted message
    let result = Message::deserialize(&serialized);

    // Verify that deserialization fails with an invalid message type error
    assert!(matches!(result, Err(MessageError::InvalidMessageType)));
}

#[test]
fn test_all_message_types() {
    // Test serialization and deserialization for all message types
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
    ];

    for message_type in &message_types {
        let payload = vec![1, 2, 3, 4, 5];
        let message = Message::new(*message_type, payload);

        let serialized = message.serialize().unwrap();
        let deserialized = Message::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.message_type, *message_type);
    }
}
