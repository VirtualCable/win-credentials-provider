use windows::Win32::System::WindowsProgramming::GetComputerNameW;
use windows::core::{PCWSTR, PWSTR}; // o *mut i8 si quieres seguir el estilo C

// Helper
#[inline]
pub const fn make_int_resource(id: u16) -> PCWSTR {
    PCWSTR(id as usize as *const u16)
}
/// Helper Function to Convert Any Type to a Byte Slice
#[inline]
pub fn as_u8_slice<T>(val: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(val as *const T as *const u8, std::mem::size_of::<T>()) }
}

// Helper to get computer name
pub fn get_computer_name() -> String {
    let mut buffer = [0u16; 64];  // Max computer name should be 15, 30 with widechars + 1 = 31, but give twice as much space
    let mut size = buffer.len() as u32;
    match unsafe { GetComputerNameW(Some(PWSTR(buffer.as_mut_ptr())), &mut size) } {
        Ok(_) => String::from_utf16_lossy(&buffer[..size as usize]),
        Err(_) => ".".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_computer_name() {
        let name = get_computer_name();
        assert!(!name.is_empty());
        // Should not be "." under normal circumstances
        assert_ne!(name, "");
    }
}
