impl Node {
    /// Handle a new incoming connection
    pub fn handle_incoming_connection(&self, stream: TcpStream) -> Result<(), NodeError> {
        let peer_addr = stream.peer_addr().map_err(|e| HandshakeError::IoError(e))?;
        
        // Apply fingerprinting protection to the socket parameters
        let mut stream_clone = stream.try_clone().map_err(|e| HandshakeError::IoError(e))?;
        self.apply_tcp_parameters(&mut stream_clone, &peer_addr).map_err(|e| HandshakeError::IoError(e))?;
        
        // Register the peer for fingerprinting protection
        self.register_peer_for_fingerprinting(peer_addr);
        
        // ... existing code continues ...
    }
    
    /// Connect to a peer
    pub fn connect_to_peer(&self, peer_addr: SocketAddr) -> Result<(), NodeError> {
        // ... existing code ...
        
        // Add a random delay before connection to prevent timing analysis
        let delay = self.get_connection_establishment_delay();
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        
        // ... connect to the peer ...
        
        // Apply fingerprinting protection settings
        if let Ok(stream) = TcpStream::connect(peer_addr) {
            // Apply TCP parameters for fingerprinting protection
            self.apply_tcp_parameters(&mut stream.try_clone().unwrap(), &peer_addr)
                .map_err(|e| NodeError::NetworkError(format!("Failed to apply TCP parameters: {}", e)))?;
            
            // Register the peer for fingerprinting protection
            self.register_peer_for_fingerprinting(peer_addr);
            
            // ... continue with connection establishment ...
        }
        
        // ... existing code continues ...
    }
    
    /// Disconnect from a peer
    pub fn disconnect_peer(&self, peer_addr: &SocketAddr) -> Result<(), NodeError> {
        // Unregister the peer from fingerprinting protection
        self.unregister_peer_from_fingerprinting(peer_addr);
        
        // ... existing code continues ...
    }
    
    /// Send a message to a specific peer with fingerprinting protection
    pub fn send_message(&self, peer_addr: SocketAddr, message_type: u32, payload: Vec<u8>) -> Result<(), io::Error> {
        // Apply fingerprinting protection to the message
        let (normalized_payload, delay) = self.maybe_delay_message(peer_addr, payload, message_type);
        
        // If there's a delay, add the message to the delayed queue
        if let Some(delay) = delay {
            // The message will be sent later when it's ready
            return Ok(());
        }
        
        // Send the message immediately
        // ... existing code to send the message with normalized_payload ...
        
        Ok(())
    }
    
    /// Process any delayed messages that are ready to be sent
    pub fn process_delayed_messages(&self) -> Result<(), NodeError> {
        // Get peers to check for delayed messages
        let peers = self.get_connected_peers();
        
        for peer_addr in peers {
            // Get any messages that are ready to be delivered
            let ready_messages = self.get_ready_messages(&peer_addr);
            
            // Send each ready message
            for (payload, message_type) in ready_messages {
                // ... code to send the message ...
            }
        }
        
        Ok(())
    }
    
    /// Get a handshake nonce for a new connection
    pub fn get_handshake_nonce(&self) -> u64 {
        // Use fingerprinting protection to get a nonce with added entropy
        self.get_handshake_nonce()
    }
    
    // ... existing code ...
} 