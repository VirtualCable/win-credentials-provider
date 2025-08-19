use std::{ffi::OsStr, os::windows::ffi::OsStrExt, ptr};
use windows::Win32::System::Com::CoTaskMemAlloc; // , CoTaskMemFree};
use windows::core::*;

#[allow(dead_code)]
pub fn alloc_pwstr(s: &str) -> PWSTR {
    let wide: Vec<u16> = OsStr::new(s).encode_wide().chain(Some(0)).collect();
    unsafe {
        let size_bytes = wide.len() * std::mem::size_of::<u16>();
        let mem = CoTaskMemAlloc(size_bytes) as *mut u16;
        if mem.is_null() {
            return PWSTR::null();
        }
        ptr::copy_nonoverlapping(wide.as_ptr(), mem, wide.len());
        PWSTR(mem)
    }
}

/// Helper Function to Convert Any Type to a Byte Slice
pub fn as_u8_slice<T>(val: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(val as *const T as *const u8, std::mem::size_of::<T>()) }
}

// Implements From<&str> for PWSTR
