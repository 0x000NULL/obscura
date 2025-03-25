use crate::utils::memory::{aligned_malloc, aligned_free};
use std::os::raw::{c_void, c_int};

// Define the C symbols that RandomX is looking for
#[no_mangle]
pub unsafe extern "C" fn _aligned_malloc(size: usize, alignment: usize) -> *mut c_void {
    aligned_malloc(size, alignment) as *mut c_void
}

#[no_mangle]
pub unsafe extern "C" fn _aligned_free(ptr: *mut c_void) {
    // Use a common alignment value - this is a limitation but should work in most cases
    aligned_free(ptr as *mut u8, 16);
}

// If we need to provide additional functions for RandomX, add them here

// This module can be extended with additional RandomX wrapper functionality as needed 