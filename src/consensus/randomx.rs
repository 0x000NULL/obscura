use std::ffi::c_void;

#[link(name = "randomx")]
extern "C" {
    fn randomx_alloc_cache(flags: u32) -> *mut c_void;
    fn randomx_init_cache(cache: *mut c_void, key: *const u8, key_size: usize);
    fn randomx_create_vm(flags: u32, cache: *mut c_void, dataset: *mut c_void) -> *mut c_void;
    fn randomx_calculate_hash(vm: *mut c_void, input: *const u8, input_size: usize, output: *mut u8);
    fn randomx_destroy_vm(vm: *mut c_void);
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
    let difficulty_bytes = target.to_be_bytes();
    let hash_start = &hash[0..4];
    hash_start <= &difficulty_bytes
}

#[derive(Debug)]
pub struct RandomXError; 