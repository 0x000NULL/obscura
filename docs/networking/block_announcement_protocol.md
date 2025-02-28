# Block Announcement Protocol

The Block Announcement Protocol is a key component of Obscura's network layer, designed to efficiently propagate new blocks across the network while maintaining privacy and security.

## Overview

The Block Announcement Protocol provides a structured way for nodes to announce new blocks to their peers and request block data when needed. It is designed with the following goals:

1. **Efficiency**: Minimize bandwidth usage by only sending full blocks when necessary
2. **Privacy**: Protect node identity and prevent timing attacks
3. **Reliability**: Ensure blocks propagate quickly and reliably across the network
4. **Security**: Prevent DoS attacks and other malicious behavior

## Protocol Flow

The block announcement protocol follows this general flow:

1. A node mines or receives a new valid block
2. The node creates a `BlockAnnouncement` message containing the block hash, height, and timestamp
3. The node selects a subset of peers to announce the block to (for privacy)
4. Receiving nodes check if they already have the block
5. If they don't have the block, they respond with a `BlockAnnouncementResponse` requesting the block
6. The original node sends a `CompactBlock` containing the block header and a subset of transactions
7. Receiving nodes attempt to reconstruct the full block using transactions in their mempool
8. If needed, receiving nodes request missing transactions with `GetBlockTransactions`
9. The original node responds with the missing transactions in a `BlockTransactions` message
10. Receiving nodes validate and process the complete block

## Message Types

The protocol uses the following message types:

### BlockAnnouncement

Announces a new block to peers.

```rust
pub struct BlockAnnouncement {
    pub block_hash: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    pub relay_count: u32,
}
```

- `block_hash`: The hash of the new block
- `height`: The height of the new block
- `timestamp`: The timestamp when the announcement was created
- `relay_count`: The number of times this announcement has been relayed

### BlockAnnouncementResponse

Response to a block announcement, indicating whether the node has the block and whether it wants to receive it.

```rust
pub struct BlockAnnouncementResponse {
    pub block_hash: [u8; 32],
    pub have_block: bool,
    pub request_compact: bool,
}
```

- `block_hash`: The hash of the announced block
- `have_block`: Whether the responding node already has this block
- `request_compact`: Whether the node wants to receive a compact version of the block

### CompactBlock

A compact representation of a block, containing the header and a subset of transactions.

```rust
pub struct CompactBlock {
    pub block_header: BlockHeader,
    pub nonce: u64,
    pub short_ids: Vec<u64>,
    pub prefilled_txs: Vec<Transaction>,
}
```

- `block_header`: The complete block header
- `nonce`: A random nonce used for short ID calculation
- `short_ids`: Short identifiers for transactions in the block
- `prefilled_txs`: A subset of full transactions (typically coinbase and a few others)

### GetBlockTransactions

Request for specific transactions from a block.

```rust
pub struct GetBlockTransactions {
    pub block_hash: [u8; 32],
    pub indexes: Vec<u32>,
}
```

- `block_hash`: The hash of the block
- `indexes`: Indexes of the requested transactions in the block

### BlockTransactions

Response containing requested transactions from a block.

```rust
pub struct BlockTransactions {
    pub block_hash: [u8; 32],
    pub transactions: Vec<Transaction>,
}
```

- `block_hash`: The hash of the block
- `transactions`: The requested transactions

## Privacy Features

The Block Announcement Protocol includes several privacy-enhancing features:

1. **Batched Announcements**: Nodes announce blocks to a small subset of peers rather than all peers
2. **Random Delays**: Announcements include random delays to prevent timing correlation
3. **Relay Count Limiting**: Announcements are only relayed a limited number of times
4. **Peer Rotation**: Different peers are selected for different announcements
5. **Timing Attack Protection**: Processing includes minimum time thresholds to prevent timing attacks

## Implementation Details

### BlockAnnouncementProtocol

The `BlockAnnouncementProtocol` struct manages the state of block announcements:

```rust
pub struct BlockAnnouncementProtocol {
    peer_manager: Arc<Mutex<PeerManager>>,
    announced_blocks: HashMap<[u8; 32], AnnouncedBlockInfo>,
    peer_announcements: HashMap<SocketAddr, HashSet<[u8; 32]>>,
    last_protocol_update: SystemTime,
}
```

It tracks:
- Which blocks have been announced
- Which peers have announced which blocks
- Statistics about block announcements

### BlockPropagation

The `BlockPropagation` struct handles the actual sending and receiving of block-related messages:

```rust
pub struct BlockPropagation {
    peer_manager: Arc<Mutex<PeerManager>>,
    known_blocks: HashSet<[u8; 32]>,
    pending_blocks: HashMap<[u8; 32], PendingBlock>,
    block_announcements: HashMap<[u8; 32], Vec<SocketAddr>>,
    last_announcement_time: HashMap<SocketAddr, SystemTime>,
    peers: HashMap<SocketAddr, PeerInfo>,
}
```

It manages:
- Tracking which blocks are known
- Managing pending blocks that are being downloaded
- Sending and receiving block-related messages
- Creating compact blocks from full blocks
- Reconstructing full blocks from compact blocks

## Best Practices

When implementing or using the Block Announcement Protocol:

1. **Limit Announcements**: Only announce blocks to a subset of peers
2. **Add Random Delays**: Include random delays when processing announcements
3. **Validate Before Relaying**: Always validate blocks before relaying announcements
4. **Clean Up Old Data**: Regularly clean up old announcement data
5. **Monitor Peer Behavior**: Track which peers are sending valid announcements
6. **Implement Rate Limiting**: Limit the number of announcements from any single peer
7. **Use Compact Blocks**: Prefer compact blocks over full blocks when possible

## Security Considerations

The Block Announcement Protocol includes several security features:

1. **Relay Count Limiting**: Prevents announcement flooding
2. **Peer Scoring**: Tracks peer behavior and penalizes misbehaving peers
3. **Validation Before Relaying**: Prevents propagation of invalid blocks
4. **Rate Limiting**: Prevents DoS attacks through excessive announcements
5. **Timeout Mechanisms**: Cleans up stale pending blocks

## Future Enhancements

Planned enhancements to the Block Announcement Protocol include:

1. **Graphene Block Relay**: More efficient block relay using set reconciliation
2. **Erlay**: More efficient transaction relay using set reconciliation
3. **Advanced Privacy Features**: Additional privacy enhancements for block propagation
4. **Adaptive Parameters**: Dynamically adjust protocol parameters based on network conditions
5. **Cross-Shard Block Propagation**: Efficient propagation of blocks across shards 