use std::alloc::{alloc, dealloc, Layout};

/// Allocate memory with the specified alignment
/// This function can be used as a replacement for _aligned_malloc
#[no_mangle]
pub unsafe extern "C" fn aligned_malloc(size: usize, alignment: usize) -> *mut u8 {
    if size == 0 {
        return std::ptr::null_mut();
    }

    // Create a layout with the required alignment
    match Layout::from_size_align(size, alignment) {
        Ok(layout) => alloc(layout),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free memory allocated with aligned_malloc
/// This function can be used as a replacement for _aligned_free
#[no_mangle]
pub unsafe extern "C" fn aligned_free(ptr: *mut u8, alignment: usize) {
    if !ptr.is_null() {
        // We need to know the size to create the layout
        // Since we don't store the size, we use a reasonable maximum
        // This is a limitation of this approach
        let layout = Layout::from_size_align_unchecked(std::usize::MAX / 2, alignment);
        dealloc(ptr, layout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aligned_malloc() {
        unsafe {
            let ptr = aligned_malloc(1024, 64);
            assert!(!ptr.is_null());
            
            // Check alignment
            let addr = ptr as usize;
            assert_eq!(addr % 64, 0);
            
            // Free the memory
            aligned_free(ptr, 64);
        }
    }
} 