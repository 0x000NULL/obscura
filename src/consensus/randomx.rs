use std::os::raw::c_void;

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
}

impl RandomXContext {
    pub fn new(key: &[u8]) -> Self {
        unsafe {
            let cache = randomx_alloc_cache(0);
            randomx_init_cache(cache, key.as_ptr(), key.len());
            let vm = randomx_create_vm(0, cache, std::ptr::null_mut());
            
            RandomXContext { vm, cache }
        }
    }

    pub fn calculate_hash(&self, input: &[u8], output: &mut [u8; 32]) -> Result<(), RandomXError> {
        unsafe {
            randomx_calculate_hash(
                self.vm,
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr()
            );
        }
        Ok(())
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