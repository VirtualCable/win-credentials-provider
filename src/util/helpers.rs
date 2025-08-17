use std::{ffi::OsStr, os::windows::ffi::OsStrExt, ptr};
use windows::Win32::System::Com::{CoTaskMemAlloc, CoTaskMemFree};
use windows::core::PWSTR;

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
fn as_u8_slice<T>(val: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(val as *const T as *const u8, std::mem::size_of::<T>()) }
}

#[derive(Debug)]
pub struct WinHandle {
    ptr: *mut std::ffi::c_void,
}

impl WinHandle {
    pub fn from_ptr(ptr: *mut std::ffi::c_void) -> Result<Self> {
        // If null, raise an error
        if ptr.is_null() {
            // Get windows last error
            let last_error = unsafe { GetLastError().0 };
            return Err(anyhow::anyhow!(
                "Null pointer passed to WinHttpHandle: {last_error}"
            ));
        }
        Ok(Self { ptr })
    }

    pub fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.ptr
    }
}

impl Drop for WinHandle {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                // Simply ignore close handle errors. Maybe log them in a future?
                WinHttpCloseHandle(self.ptr)
                    .ok()
                    .context("WinHttpCloseHandle failed")
                    .unwrap_or_default();
            }
            self.ptr = std::ptr::null_mut();
        }
    }
}
