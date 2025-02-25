use crate::blockchain::Transaction;
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;

pub fn generate_keypair() -> Option<Keypair> {
    let mut csprng = OsRng;
    Some(Keypair::generate(&mut csprng))
}

pub fn serialize_keypair(keypair: &Keypair) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(keypair.public.as_bytes());
    bytes.extend_from_slice(&keypair.secret.to_bytes());
    bytes
}

pub fn deserialize_keypair(bytes: &[u8]) -> Option<Keypair> {
    if bytes.len() != 64 {
        return None;
    }

    let public_key = &bytes[0..32];
    let secret_key = &bytes[32..64];

    Keypair::from_bytes(&[secret_key, public_key].concat()).ok()
}

pub fn encrypt_keypair(keypair: &Keypair, password: &[u8]) -> Vec<u8> {
    let serialized = serialize_keypair(keypair);
    let mut encrypted = serialized.clone();

    // Simple XOR encryption (NOT secure for production!)
    for (i, byte) in encrypted.iter_mut().enumerate() {
        *byte ^= password[i % password.len()];
    }

    encrypted
}

pub fn decrypt_keypair(encrypted: &[u8], password: &[u8]) -> Option<Keypair> {
    let mut decrypted = encrypted.to_vec();

    // Simple XOR decryption (NOT secure for production!)
    for (i, byte) in decrypted.iter_mut().enumerate() {
        *byte ^= password[i % password.len()];
    }

    deserialize_keypair(&decrypted)
}

pub fn hash_transaction(tx: &Transaction) -> [u8; 32] {
    tx.hash()
}

pub fn calculate_hash_difficulty(hash: &[u8; 32]) -> u32 {
    // Convert first 4 bytes of hash to u32 in big-endian order
    let mut value = 0u32;
    value |= (hash[0] as u32) << 24;
    value |= (hash[1] as u32) << 16;
    value |= (hash[2] as u32) << 8;
    value |= hash[3] as u32;
    // For a hash of all zeros (best possible), this returns 0
    // For a hash of all ones (worst possible), this returns 0xFFFFFFFF
    value
}

pub fn validate_hash_difficulty(hash: &[u8; 32], target: u32) -> bool {
    let hash_value = calculate_hash_difficulty(hash);
    // For PoW, lower hash values are better (need to be below target)
    hash_value <= target
}

#[cfg(test)]
mod tests {
    use super::*;
    mod hash_tests;
    mod key_tests;
}
