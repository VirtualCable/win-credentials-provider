use std::{mem, ptr};
use widestring::U16CString;

use windows::{
    Win32::System::Com::{CoCreateInstance, CoTaskMemAlloc, IGlobalInterfaceTable},
    core::{GUID, IUnknown, Interface, PCWSTR, PWSTR},
};

pub const CLSID_STD_GLOBAL_INTERFACE_TABLE: GUID =
    GUID::from_u128(0x00000323_0000_0000_C000_000000000046);

#[derive(Debug)]
pub enum AllocPwstrError {
    InvalidString,
    AllocationFailed,
}

#[allow(dead_code)]
pub fn alloc_pwstr(s: &str) -> Result<PWSTR, AllocPwstrError> {
    let wide = U16CString::from_str(s).map_err(|_| AllocPwstrError::InvalidString)?;
    let len = wide.len();

    unsafe {
        let mem = CoTaskMemAlloc(len * mem::size_of::<u16>()) as *mut u16;
        if mem.is_null() {
            return Err(AllocPwstrError::AllocationFailed);
        }
        ptr::copy_nonoverlapping(wide.as_ptr(), mem, len);
        Ok(PWSTR(mem))
    }
}

pub fn pcwstr_to_string(pcwstr: PCWSTR) -> String {
    if pcwstr.is_null() {
        return String::new();
    }

    unsafe {
        // Interpreta el puntero como una U16CStr terminada en 0
        let u16_cstr = widestring::U16CStr::from_ptr_str(pcwstr.0);
        // Convierte directamente a String (UTF‑8), con reemplazo si hay caracteres inválidos
        u16_cstr.to_string_lossy()
    }
}

/// Retrieves the process-wide Global Interface Table (GIT) instance.
///
/// # Requirements
/// - COM must be initialized on the current thread before calling.
/// - Returns an `IGlobalInterfaceTable` ready to register, revoke, or retrieve interfaces.
pub fn get_git() -> windows::core::Result<IGlobalInterfaceTable> {
    unsafe {
        CoCreateInstance(
            &CLSID_STD_GLOBAL_INTERFACE_TABLE,
            None,
            windows::Win32::System::Com::CLSCTX_INPROC_SERVER,
        )
    }
}

/// Registers a COM interface in the Global Interface Table (GIT).
///
/// # Type Parameters
/// - `T`: Any COM interface type that implements `Interface`.
///
/// # Parameters
/// - `interface`: The COM interface instance to register.
///
/// # Returns
/// A `u32` "cookie" that uniquely identifies the registered interface in the GIT.
/// This cookie must be used later to revoke or retrieve the interface.
///
/// # Notes
/// - COM must be initialized before calling.
/// - The caller is responsible for revoking the interface when it is no longer needed.
pub fn register_in_git<T: Interface>(interface: T) -> windows::core::Result<u32> {
    let git = get_git()?;
    let iunk = interface.cast::<IUnknown>()?;
    let cookie = unsafe { git.RegisterInterfaceInGlobal(&iunk, &T::IID)? };
    Ok(cookie)
}

/// Removes a previously registered interface from the Global Interface Table.
///
/// # Parameters
/// - `cookie`: The registration cookie returned by `register_in_git`.
///
/// # Notes
/// - Once revoked, the cookie is no longer valid and cannot be used to retrieve the interface.
pub fn unregister_from_git(cookie: u32) -> windows::core::Result<()> {
    let git = get_git()?;
    unsafe { git.RevokeInterfaceFromGlobal(cookie)? };
    Ok(())
}

/// Retrieves a COM interface from the Global Interface Table using its cookie.
///
/// # Type Parameters
/// - `T`: The expected COM interface type.
///
/// # Parameters
/// - `cookie`: The registration cookie returned by `register_in_git`.
///
/// # Returns
/// The requested COM interface instance.
///
/// # Safety
/// - The caller must ensure the cookie refers to a still‑valid interface of type `T`.
/// - COM must be initialized before calling.
pub fn get_from_git<T: Interface>(cookie: u32) -> windows::core::Result<T> {
    let mut ptr = std::ptr::null_mut();
    let git = get_git()?;
    unsafe { git.GetInterfaceFromGlobal(cookie, &T::IID, &mut ptr)? };
    Ok(unsafe { T::from_raw(ptr as _) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_pwstr() {
        let s = "Hello, world!";
        let pwstr = alloc_pwstr(s).expect("Failed to allocate PWSTR");
        let converted = pcwstr_to_string(PCWSTR(pwstr.0));
        assert_eq!(s, converted);
        unsafe {
            windows::Win32::System::Com::CoTaskMemFree(Some(pwstr.0 as _));
        }
    }
}
