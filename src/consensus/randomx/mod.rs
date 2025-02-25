pub mod randomx_vm;

use std::os::raw::c_void;
use std::sync::Mutex;

use randomx_vm::{RandomXVM, Instruction};

#[link(name = "randomx", kind = "static")]
extern "C" {
    #[link_name = "randomx_alloc_cache"]
    fn randomx_alloc_cache(flags: u32) -> *mut c_void;
    
    #[link_name = "randomx_init_cache"]
    fn randomx_init_cache(cache: *mut c_void, key: *const u8, key_size: usize);
    
    #[link_name = "randomx_create_vm"]
    fn randomx_create_vm(flags: u32, cache: *mut c_void, dataset: *mut c_void) -> *mut c_void;
    
    #[link_name = "randomx_calculate_hash"]
    fn randomx_calculate_hash(vm: *mut c_void, input: *const u8, input_size: usize, output: *mut u8);
    
    #[link_name = "randomx_destroy_vm"]
    fn randomx_destroy_vm(vm: *mut c_void);
    
    #[link_name = "randomx_release_cache"]
    fn randomx_release_cache(cache: *mut c_void);
}

pub struct RandomXContext {
    pub(crate) vm: *mut c_void,
    pub(crate) cache: *mut c_void,
    pub(crate) vm_instance: Mutex<RandomXVM>,
    key: Vec<u8>,
}

impl RandomXContext {
    pub fn new(key: &[u8]) -> Self {
        unsafe {
            let cache = randomx_alloc_cache(0);
            randomx_init_cache(cache, key.as_ptr(), key.len());
            let vm = randomx_create_vm(0, cache, std::ptr::null_mut());
            
            let vm_instance = Mutex::new(RandomXVM::new());
            
            RandomXContext { 
                vm, 
                cache, 
                vm_instance,
                key: key.to_vec(),
            }
        }
    }

    pub fn calculate_hash(&self, input: &[u8], output: &mut [u8; 32]) -> Result<(), RandomXError> {
        let mut vm = self.vm_instance.lock().map_err(|_| RandomXError)?;
        
        // Generate program based on input and key
        let mut combined_input = Vec::with_capacity(self.key.len() + input.len());
        combined_input.extend_from_slice(&self.key);
        combined_input.extend_from_slice(input);
        
        let program = self.generate_program(&combined_input);
        vm.load_program(program);
        
        // Execute memory-hard computation
        vm.mix_memory();
        
        // Execute the program
        vm.execute().map_err(|_| RandomXError)?;
        
        // Get final hash from VM state
        self.finalize_hash(&vm, output);
        
        Ok(())
    }

    pub fn generate_program(&self, input: &[u8]) -> Vec<Instruction> {
        let mut program = Vec::new();
        
        // Use input bytes to generate instructions
        for chunk in input.chunks(4) {
            let mut bytes = [0u8; 4];
            bytes[..chunk.len()].copy_from_slice(chunk);
            let value = u32::from_le_bytes(bytes);
            
            // Generate instruction based on input value
            match value % 8 {
                0 => program.push(Instruction::Add(
                    (value >> 8) as u8 % 16,
                    (value >> 16) as u8 % 16,
                    (value >> 24) as u8 % 16
                )),
                1 => program.push(Instruction::Sub(
                    (value >> 8) as u8 % 16,
                    (value >> 16) as u8 % 16,
                    (value >> 24) as u8 % 16
                )),
                2 => program.push(Instruction::Mul(
                    (value >> 8) as u8 % 16,
                    (value >> 16) as u8 % 16,
                    (value >> 24) as u8 % 16
                )),
                3 => program.push(Instruction::ScratchpadRead(
                    (value >> 8) as u8 % 16,
                    value >> 16
                )),
                4 => program.push(Instruction::ScratchpadWrite(
                    value >> 16,
                    (value >> 24) as u8 % 16
                )),
                5 => program.push(Instruction::ChaChaEnc(
                    (value >> 8) as u8 % 16,
                    (value >> 16) as u8 % 16
                )),
                6 => program.push(Instruction::ChaChaDec(
                    (value >> 8) as u8 % 16,
                    (value >> 16) as u8 % 16
                )),
                _ => program.push(Instruction::Jump(value >> 16)),
            }
        }
        
        program
    }

    fn finalize_hash(&self, vm: &RandomXVM, output: &mut [u8; 32]) {
        // Combine register values to create final hash
        for i in 0..4 {
            let value = vm.registers[i].wrapping_add(
                vm.registers[i+4].wrapping_mul(0x0123456789ABCDEF)
            );
            output[i*8..(i+1)*8].copy_from_slice(&value.to_le_bytes());
        }
    }

    pub fn is_valid(&self) -> bool {
        !self.vm.is_null() && !self.cache.is_null()
    }
}

impl Drop for RandomXContext {
    fn drop(&mut self) {
        unsafe {
            randomx_destroy_vm(self.vm);
            randomx_release_cache(self.cache);
        }
    }
}

pub fn verify_difficulty(hash: &[u8; 32], target: u32) -> bool {
    // Convert first 4 bytes of hash to u32 in big-endian order
    let hash_value = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
    // For PoW, lower hash values are better (need to be below target)
    hash_value <= target
}

#[derive(Debug)]
pub struct RandomXError; 