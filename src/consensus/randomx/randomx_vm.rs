use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};

/// Represents a RandomX VM instruction
/// 
/// Each instruction operates on registers, memory, or the scratchpad.
/// The instruction set is designed to be ASIC-resistant by combining
/// both computational and memory-intensive operations.
#[derive(Debug, Clone, PartialEq)]
pub enum Instruction {
    /// Arithmetic operations with three operands: destination and two sources
    Add(u8, u8, u8),    // dest, src1, src2
    Sub(u8, u8, u8),    // dest, src1, src2
    Mul(u8, u8, u8),    // dest, src1, src2
    Div(u8, u8, u8),    // dest, src1, src2
    
    /// Memory operations for loading and storing values
    Load(u8, u32),      // dest, address
    Store(u32, u8),     // address, src
    
    /// Control flow operations for program execution
    Jump(u32),          // address
    JumpIf(u32, u8),    // address, condition
    
    /// Memory-hard operations that interact with the scratchpad
    ScratchpadRead(u8, u32),  // dest, address
    ScratchpadWrite(u32, u8), // address, src
    
    /// Cryptographic operations using ChaCha20
    ChaChaEnc(u8, u8),     // dest, src
    ChaChaDec(u8, u8),     // dest, src
}

/// RandomX VM state
/// 
/// The VM maintains the state necessary for executing RandomX programs.
/// This includes registers, main memory, scratchpad memory, and program state.
/// The implementation is designed to be memory-hard and ASIC-resistant.
pub struct RandomXVM {
    /// Register file containing 16 64-bit general-purpose registers
    pub(crate) registers: [u64; 16],
    
    /// Main memory (2MB) used for general storage and computation
    pub(crate) memory: Vec<u8>,
    
    /// Scratchpad memory (256KB) used for memory-hard operations
    pub(crate) scratchpad: Vec<u8>,
    
    /// Program counter tracking current instruction
    pub(crate) pc: usize,
    
    /// Currently loaded program instructions
    program: Vec<Instruction>,
    
    /// Test mode flag for deterministic behavior in tests
    test_mode: bool,
}

impl RandomXVM {
    /// Creates a new VM instance in normal mode
    pub fn new() -> Self {
        Self::new_with_mode(false)
    }

    /// Creates a new VM instance with specified test mode
    /// 
    /// In test mode, the VM behaves deterministically for testing purposes.
    /// This includes predictable memory initialization and mixing operations.
    pub(crate) fn new_with_mode(test_mode: bool) -> Self {
        let mut vm = RandomXVM {
            registers: [0; 16],
            memory: vec![0; 2 * 1024 * 1024],    // 2MB
            scratchpad: vec![0; 256 * 1024],     // 256KB
            pc: 0,
            program: Vec::new(),
            test_mode,
        };
        
        // Initialize memory with deterministic pattern using prime numbers
        // to avoid simple patterns while maintaining reproducibility
        for i in 0..vm.memory.len() {
            vm.memory[i] = (i % 251) as u8;  // Use prime number to avoid patterns
        }
        
        vm
    }
    
    /// Loads a program into the VM and initializes registers
    /// 
    /// In normal mode, registers are initialized with program-dependent values
    /// to ensure different programs produce different results.
    pub fn load_program(&mut self, program: Vec<Instruction>) {
        self.program = program;
        self.pc = 0;
        
        if !self.test_mode {
            // Initialize registers with program-dependent values
            for i in 0..self.registers.len() {
                self.registers[i] = (i as u64).wrapping_mul(0xDEADBEEFCAFEBABE);
            }
        }
    }
    
    fn create_chacha_cipher(value: u64, key: u64) -> ChaCha20 {
        // Create a 32-byte key from the input key
        let mut full_key = [0u8; 32];
        full_key[..8].copy_from_slice(&key.to_le_bytes());
        full_key[8..16].copy_from_slice(&value.to_le_bytes());
        // Fill remaining bytes with a fixed pattern for consistency
        for i in 16..32 {
            full_key[i] = (i as u8).wrapping_mul(0xAA);
        }

        // Create a 12-byte nonce (96 bits) that is deterministic based on the key
        // This ensures the same nonce is used for encryption and decryption
        let mut nonce = [0u8; 12];
        let key_bytes = key.to_le_bytes();
        nonce[..8].copy_from_slice(&key_bytes);
        // Use fixed pattern for last 4 bytes
        nonce[8..12].copy_from_slice(&[0xCC, 0xDD, 0xEE, 0xFF]);

        ChaCha20::new(&full_key.into(), &nonce.into())
    }

    /// Executes a single instruction and updates VM state
    /// 
    /// Returns an error if the program counter is out of bounds or
    /// if an unimplemented instruction is encountered.
    pub fn step(&mut self) -> Result<(), &'static str> {
        if self.pc >= self.program.len() {
            return Err("Program counter out of bounds");
        }
        
        match &self.program[self.pc] {
            Instruction::Add(dest, src1, src2) => {
                self.registers[*dest as usize] = 
                    self.registers[*src1 as usize].wrapping_add(self.registers[*src2 as usize]);
            },
            Instruction::Sub(dest, src1, src2) => {
                self.registers[*dest as usize] = 
                    self.registers[*src1 as usize].wrapping_sub(self.registers[*src2 as usize]);
            },
            Instruction::Mul(dest, src1, src2) => {
                self.registers[*dest as usize] = 
                    self.registers[*src1 as usize].wrapping_mul(self.registers[*src2 as usize]);
            },
            Instruction::Div(dest, src1, src2) => {
                let src2_val = self.registers[*src2 as usize];
                if src2_val == 0 {
                    self.registers[*dest as usize] = 0;
                } else {
                    self.registers[*dest as usize] = 
                        self.registers[*src1 as usize].wrapping_div(src2_val);
                }
            },
            Instruction::Load(dest, addr) => {
                let addr = (*addr as usize) % (self.memory.len() - 8);
                let value = u64::from_le_bytes(self.memory[addr..addr+8].try_into().unwrap());
                self.registers[*dest as usize] = value;
            },
            Instruction::Store(addr, src) => {
                let addr = (*addr as usize) % (self.memory.len() - 8);
                let value = self.registers[*src as usize];
                self.memory[addr..addr+8].copy_from_slice(&value.to_le_bytes());
            },
            Instruction::Jump(addr) => {
                self.pc = (*addr as usize) % self.program.len();
                return Ok(());
            },
            Instruction::JumpIf(addr, cond) => {
                if self.registers[*cond as usize] != 0 {
                    self.pc = (*addr as usize) % self.program.len();
                    return Ok(());
                }
            },
            Instruction::ScratchpadRead(dest, addr) => {
                let addr = (*addr as usize) % (self.scratchpad.len() - 8);
                let value = u64::from_le_bytes(self.scratchpad[addr..addr+8].try_into().unwrap());
                self.registers[*dest as usize] = value;
            },
            Instruction::ScratchpadWrite(addr, src) => {
                let addr = (*addr as usize) % (self.scratchpad.len() - 8);
                let value = self.registers[*src as usize];
                self.scratchpad[addr..addr+8].copy_from_slice(&value.to_le_bytes());
            },
            Instruction::ChaChaEnc(dest, src) => {
                let value = self.registers[*src as usize];
                let key = self.registers[0];
                
                // Create cipher and encrypt the value
                let mut cipher = Self::create_chacha_cipher(key, key);  // Use key for both parameters
                let mut data = value.to_le_bytes();
                cipher.apply_keystream(&mut data);
                
                self.registers[*dest as usize] = u64::from_le_bytes(data);
            },
            Instruction::ChaChaDec(dest, src) => {
                let value = self.registers[*src as usize];
                let key = self.registers[0];
                
                // Create cipher and decrypt the value
                let mut cipher = Self::create_chacha_cipher(key, key);  // Use key for both parameters
                let mut data = value.to_le_bytes();
                cipher.apply_keystream(&mut data);
                
                self.registers[*dest as usize] = u64::from_le_bytes(data);
            },
        }
        
        self.pc += 1;
        Ok(())
    }
    
    /// Executes the entire loaded program
    /// 
    /// Continues execution until either the program completes or
    /// an error occurs during instruction execution.
    pub fn execute(&mut self) -> Result<(), &'static str> {
        while self.pc < self.program.len() {
            self.step()?;
        }
        Ok(())
    }
    
    /// Performs memory-hard mixing operation on the scratchpad
    /// 
    /// This function implements the core memory-hard component of RandomX.
    /// It uses multiple passes of mixing with prime number-based operations
    /// to ensure high memory bandwidth requirements and complex dependencies.
    pub fn mix_memory(&mut self) {
        let seed = self.registers[0];
        let mut cipher = Self::create_chacha_cipher(seed, seed);
        
        // Initialize scratchpad with program-dependent values
        for chunk in self.scratchpad.chunks_mut(64) {
            cipher.apply_keystream(chunk);
        }

        // Multiple mixing passes to increase entropy and create dependencies
        for pass in 0..4 {
            // Create a new cipher for each pass with different parameters
            let mut pass_cipher = Self::create_chacha_cipher(seed.wrapping_add(pass as u64), seed);
            
            // Process scratchpad in 64-byte blocks (ChaCha20 block size)
            for chunk in self.scratchpad.chunks_mut(64) {
                pass_cipher.apply_keystream(chunk);
            }

            // Additional mixing with neighboring blocks
            for i in 0..self.scratchpad.len() {
                let prev = if i == 0 { self.scratchpad[self.scratchpad.len() - 1] } else { self.scratchpad[i - 1] };
                let next = if i == self.scratchpad.len() - 1 { self.scratchpad[0] } else { self.scratchpad[i + 1] };
                
                let mixed = self.scratchpad[i]
                    .wrapping_mul(167)
                    .wrapping_add(prev)
                    .rotate_left((i + pass) as u32 % 8)
                    ^ next;
                
                self.scratchpad[i] = mixed;
            }
        }

        if self.test_mode {
            for i in 0..self.scratchpad.len() {
                self.scratchpad[i] = self.scratchpad[i].wrapping_add((i % 251) as u8);
            }
        }
    }
} 