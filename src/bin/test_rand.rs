use rand::rngs::OsRng;
use rand_core::{RngCore, Error};

// Directly specify the import to see which version we get
use rand_core::impls::fill_bytes_via_next;

// Create an adapter using the same pattern as in your actual code
struct RngAdapter(OsRng);

impl RngCore for RngAdapter {
    fn next_u32(&mut self) -> u32 {
        println!("Called next_u32");
        // Use a safer approach that works with rand 0.7's OsRng
        let mut buf = [0u8; 4];
        self.0.try_fill_bytes(&mut buf).expect("RNG should not fail");
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        println!("Called next_u64");
        // Use a safer approach that works with rand 0.7's OsRng
        let mut buf = [0u8; 8];
        self.0.try_fill_bytes(&mut buf).expect("RNG should not fail");
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        println!("Called fill_bytes");
        self.0.try_fill_bytes(dest).expect("RNG should not fail")
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        println!("Called try_fill_bytes");
        // This is the fix we've been implementing - use fill_bytes and return Ok
        self.0.try_fill_bytes(dest).expect("RNG should not fail");
        Ok(())
    }
}

fn main() {
    println!("Starting OsRng direct test");
    
    let mut rng = OsRng;
    
    // Test direct OsRng methods
    println!("OsRng next_u32: {}", rng.next_u32());
    println!("OsRng next_u64: {}", rng.next_u64());
    
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    println!("OsRng fill_bytes: {:?}", bytes);
    
    match rng.try_fill_bytes(&mut bytes) {
        Ok(_) => println!("OsRng try_fill_bytes success: {:?}", bytes),
        Err(e) => println!("OsRng try_fill_bytes error: {:?}", e),
    }
    
    println!("\nTesting RngAdapter");
    
    let mut adapter = RngAdapter(OsRng);
    
    println!("RngAdapter next_u32: {}", adapter.next_u32());
    println!("RngAdapter next_u64: {}", adapter.next_u64());
    
    let mut adapter_bytes = [0u8; 16];
    adapter.fill_bytes(&mut adapter_bytes);
    println!("RngAdapter fill_bytes: {:?}", adapter_bytes);
    
    match adapter.try_fill_bytes(&mut adapter_bytes) {
        Ok(_) => println!("RngAdapter try_fill_bytes success: {:?}", adapter_bytes),
        Err(e) => println!("RngAdapter try_fill_bytes error: {:?}", e),
    }
    
    println!("Test completed successfully!");
} 
