use rand::rngs::OsRng;
use rand_core::RngCore;

fn main() {
    println!("Minimal RngAdapter test");

    // Test OsRng directly
    let mut os_rng = OsRng;
    let random_u32 = os_rng.next_u32();
    println!("Direct OsRng next_u32: {}", random_u32);

    // Create our adapter
    let mut adapter = RngAdapter(OsRng);
    let random_u32_via_adapter = adapter.next_u32();
    println!("Via RngAdapter next_u32: {}", random_u32_via_adapter);

    // Test fill_bytes
    let mut bytes = [0u8; 16];
    adapter.fill_bytes(&mut bytes);
    println!("RngAdapter fill_bytes: {:?}", bytes);

    // Test try_fill_bytes
    let result = adapter.try_fill_bytes(&mut bytes);
    match result {
        Ok(_) => println!("try_fill_bytes worked correctly: {:?}", bytes),
        Err(e) => println!("try_fill_bytes error: {:?}", e),
    }

    println!("Test completed successfully!");
}

// A minimal RngAdapter that wraps OsRng
struct RngAdapter(OsRng);

// Implement rand_core::RngCore for RngAdapter
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

// Also implement CryptoRng marker trait
impl rand_core::CryptoRng for RngAdapter {}
