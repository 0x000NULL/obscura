// Simple test for RngAdapter
// Run with: rustc test_rng.rs && ./test_rng

use rand::rngs::OsRng;

fn main() {
    println!("Testing RngAdapter with rand_core version conflict");

    // Test direct access to OsRng
    let mut os_rng = OsRng;
    println!("Direct OsRng u32: {}", os_rng.next_u32());
    
    let mut bytes = [0u8; 8];
    os_rng.fill_bytes(&mut bytes);
    println!("Direct OsRng bytes: {:?}", bytes);
    
    // Test with our adapter
    let mut adapter = RngAdapter(OsRng);
    println!("Via adapter u32: {}", adapter.next_u32());
    
    adapter.fill_bytes(&mut bytes);
    println!("Via adapter bytes: {:?}", bytes);
    
    let result = adapter.try_fill_bytes(&mut bytes);
    match result {
        Ok(_) => println!("try_fill_bytes succeeded: {:?}", bytes),
        Err(e) => println!("try_fill_bytes error: {:?}", e),
    }
    
    println!("Test completed successfully");
}

// Define our adapter
struct RngAdapter(OsRng);

// Implement RngCore
impl rand_core::RngCore for RngAdapter {
    fn next_u32(&mut self) -> u32 {
        // Use a safer approach that works with rand 0.7's OsRng
        let mut buf = [0u8; 4];
        self.0.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }
    
    fn next_u64(&mut self) -> u64 {
        // Use a safer approach that works with rand 0.7's OsRng
        let mut buf = [0u8; 8];
        self.0.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
    
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.try_fill_bytes(dest).expect("RNG should not fail")
    }
    
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        // Delegate to the wrapped RNG's try_fill_bytes
        self.0.try_fill_bytes(dest)
    }
}

// Mark as CryptoRng
impl rand_core::CryptoRng for RngAdapter {} 