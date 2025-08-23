use windows::core::PCWSTR; // o *mut i8 si quieres seguir el estilo C

// Helper
#[inline]
pub const fn make_int_resource_a(id: u16) -> PCWSTR {
    PCWSTR(id as usize as *const u16)
}
/// Helper Function to Convert Any Type to a Byte Slice
#[inline]
pub fn as_u8_slice<T>(val: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(val as *const T as *const u8, std::mem::size_of::<T>()) }
}
