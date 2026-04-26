# Plan: add-blake3-checksum-to-every-message-variant-in-src

## Goal
Append a 32-byte BLAKE3 trailer to every serialized `Message`, verify it on deserialize, and emit `MessageError::ChecksumMismatch` on tamper.

## Steps
1. Add `const BLAKE3_CHECKSUM_SIZE: usize = 32;` near the existing framing constants in `src/networking/message.rs`.
2. Add a `ChecksumMismatch` variant to `MessageError` (with `Display` arm: "Blake3 checksum mismatch") so the existing `InvalidChecksum` (header SHA256d) and the new BLAKE3 trailer mismatch are distinguishable. Reuse `ChecksumMismatch` for the new trailer only; leave `InvalidChecksum` as the legacy header-checksum error so existing tests keep working.
3. In `Message::serialize`, after appending the padded payload to `buffer`, compute `blake3::hash(&buffer)` over the whole frame (magic + type + length + sha256-checksum + padded payload), and `extend_from_slice(blake3_hash.as_bytes())` to append the 32-byte trailer. This binds the trailer to the entire framed message, not just the payload, giving stronger tamper detection.
4. In `Message::deserialize`:
   - Tighten the size guard: require `data.len() >= HEADER_SIZE + payload_length + BLAKE3_CHECKSUM_SIZE`; otherwise `MessageError::MessageTooSmall`.
   - After the existing SHA256d header-checksum check on the payload, slice `data[HEADER_SIZE + payload_length .. HEADER_SIZE + payload_length + BLAKE3_CHECKSUM_SIZE]` as the expected BLAKE3 trailer.
   - Compute `blake3::hash(&data[..HEADER_SIZE + payload_length])` and compare bytes; on mismatch return `MessageError::ChecksumMismatch`. Use `subtle`-style constant-time compare or simple `!=` on `[u8; 32]` (acceptable here — the 4-byte header check already short-circuits non-constant-time).
5. In `Message::read_from_stream`, extend the read buffer to `HEADER_SIZE + payload_length + BLAKE3_CHECKSUM_SIZE` so the BLAKE3 trailer is read off the wire before delegating to `deserialize`.
6. Add `use blake3;` (or call `blake3::hash` via fully-qualified path) at the top of the file. `blake3 = "1.7"` is already in `Cargo.toml`.
7. In the existing `#[cfg(test)] mod tests` block, add:
   - `fn checksum_round_trip()` — build a `Message`, serialize, deserialize, assert `message_type` equality and `Ok(_)`.
   - `fn tamper_rejected()` — serialize a message, flip one byte inside the BLAKE3 trailer (last 32 bytes of the buffer), assert `Err(MessageError::ChecksumMismatch)`. Add a second flip inside the padded-payload region and assert *either* `InvalidChecksum` (header SHA256d catches it first) *or* `ChecksumMismatch` — keep the test focused on trailer tamper to be precise.
8. Audit existing tests in the same module that hand-craft or splice serialized buffers (`test_checksum_validation`, `test_magic_bytes_validation`, `test_message_padding`) — they all serialize via `Message::serialize` and only mutate the header, so they keep working with the trailer present. Verify the `MIN_MESSAGE_SIZE + HEADER_SIZE` lower-bound assertion in `test_message_padding` still passes (it will: trailer makes serialized output 32 bytes longer, never shorter).

## Files
- `src/networking/message.rs` -- add `BLAKE3_CHECKSUM_SIZE` constant, `MessageError::ChecksumMismatch` variant + `Display` arm, append BLAKE3 trailer in `serialize`, verify in `deserialize`, extend `read_from_stream` byte count, add `checksum_round_trip` and `tamper_rejected` tests.

## Risks
- **Wire-format break.** Adding a 32-byte trailer changes the serialized frame; any peer running an older build will fail to parse and vice versa. There is no protocol versioning gate around this. Acceptable for a single-repo, no-deployed-network change but flag it loudly in the commit message.
- **`read_from_stream` underflow.** If the `payload_length` byte-count change is missed, the trailer read will short-read or block on a half-frame. Step 5 covers this; double-check after edit.
- **Downstream consumers.** `p2p.rs`, `block_propagation.rs`, `padding.rs`, `protocol_morphing.rs`, `traffic_obfuscation.rs` all use `Message`/`MessageError` but go through `serialize`/`deserialize`, so they should be transparent. If any matches `MessageError` exhaustively without a wildcard, the new variant breaks compile — handle by adding wildcard arms or matching the new variant.
- **Existing `InvalidChecksum` tests.** `test_checksum_validation` corrupts byte 12 (the SHA256d header checksum) and expects `InvalidChecksum`. That still fires before the BLAKE3 check because the header-checksum verification runs first. No change needed.
- **Padding interaction.** The legacy padding path mutates the payload before the trailer is computed, so the trailer covers the padded form — round-trips will still match because deserialize hashes the same `data[..HEADER_SIZE + payload_length]` bytes it was given.

## Verify
```
cargo build --lib
cargo test --lib message::tests::checksum_round_trip
cargo test --lib message::tests::tamper_rejected
cargo test --lib networking::message
```

## Assumptions
- "Every `Message` variant" refers to every serialized `Message` instance (the `Message` type is a struct with a `MessageType` discriminant, not a Rust `enum`). Routing all messages through the single `serialize`/`deserialize` path satisfies "every variant".
- The BLAKE3 trailer is **additional** to the existing 4-byte SHA256d header checksum, not a replacement. The todo says "appended" and the existing checksum is in the header, not appended. Removing the SHA256d would break `test_checksum_validation` and is out of scope.
- The trailer covers the entire prior frame (magic + type + length + sha256-checksum + padded payload). This gives the strongest tamper coverage; the alternative of hashing only the payload duplicates what the SHA256d checksum already does.
- Constant-time comparison is not required for this trailer — the existing 4-byte check already runs in non-constant time, and the threat model here is integrity, not key-equality side channels.
- Tests live in the existing inline `#[cfg(test)] mod tests` block at `src/networking/message.rs:357`, matching the `message::tests::*` paths in the verify spec.
- `blake3 = "1.7"` is already in `Cargo.toml` (confirmed line 62) so no dependency change is needed.
- Downstream `MessageError` matches use wildcards; if any compile failures surface from the new variant, add `_ => ...` or explicit arms as part of the same commit.

## Blockers
Blockers: none

## Summary
Append a BLAKE3-256 trailer to every serialized `Message` and reject mismatches on deserialize via a new `MessageError::ChecksumMismatch`, pinned by two new round-trip / tamper tests.
