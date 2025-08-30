use std::{mem, ptr};
use widestring::U16CString;

use windows::{
    Win32::System::Com::{
        COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx, CoTaskMemAlloc, CoTaskMemFree,
        CoUninitialize, IGlobalInterfaceTable,
    },
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
    let len = wide.len() + 1;

    unsafe {
        // Allow for null terminator
        let mem = CoTaskMemAlloc(len * mem::size_of::<u16>()) as *mut u16;
        if mem.is_null() {
            return Err(AllocPwstrError::AllocationFailed);
        }
        ptr::copy_nonoverlapping(wide.as_ptr(), mem, len);
        Ok(PWSTR(mem))
    }
}

pub fn free_pcwstr(pcwstr: PCWSTR) {
    unsafe {
        if !pcwstr.is_null() {
            CoTaskMemFree(Some(pcwstr.0 as _));
        }
    }
}

pub fn pcwstr_to_string(pcwstr: PCWSTR) -> String {
    if pcwstr.is_null() {
        return String::new();
    }

    unsafe {
        // Interpret the pointer as a U16CStr terminated in 0
        let u16_cstr = widestring::U16CStr::from_ptr_str(pcwstr.0);
        // Convert directly to String (UTF‑8), with replacement if there are invalid characters
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
/// - COM must be initialized before calling. (This is ensured if we use this in a Com impl)
pub fn get_from_git<T: Interface>(cookie: u32) -> windows::core::Result<T> {
    let mut ptr = std::ptr::null_mut();
    let git = get_git()?;
    unsafe { git.GetInterfaceFromGlobal(cookie, &T::IID, &mut ptr)? };
    Ok(unsafe { T::from_raw(ptr as _) })
}

pub struct ComInitializer;

impl ComInitializer {
    pub fn new() -> Self {
        unsafe {
            _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        }
        Self
    }
}

impl Default for ComInitializer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ComInitializer {
    fn drop(&mut self) {
        unsafe {
            CoUninitialize();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use windows::{
        Win32::System::Com::{COINIT_APARTMENTTHREADED, IPersist, IPersist_Impl},
        core::{GUID, implement},
    };

    use super::*;

    // Simple interface for testing register/unregister
    #[derive(Clone)]
    #[implement(IPersist)]
    struct TestCom {
        guid: Arc<RwLock<Option<GUID>>>,
    }

    impl IPersist_Impl for TestCom_Impl {
        fn GetClassID(&self) -> windows_core::Result<windows_core::GUID> {
            // Set a new guid, se we know it hase benn invoked correctly
            self.guid
                .write()
                .unwrap()
                .replace(GUID::from_u128(0x12345678_1234_1234_1234_1234567890ab));

            Ok(self.guid.read().unwrap().unwrap())
        }
    }

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

    #[test]
    fn test_register_get_unregister() {
        let _com_init = ComInitializer::new();
        unsafe {
            CoInitializeEx(None, COINIT_APARTMENTTHREADED)
                .map(|| ())
                .unwrap()
        };

        let com = TestCom {
            guid: Arc::new(RwLock::new(None)),
        };
        assert_eq!(*com.guid.read().unwrap(), None);
        let com_impl: IUnknown = com.clone().into();
        let cookie = register_in_git(com_impl).expect("Failed to register COM object");
        let retrieved: IPersist = get_from_git(cookie).expect("Failed to get COM object");
        let guid = unsafe { retrieved.GetClassID().expect("Failed to get class ID") };
        assert_eq!(
            guid,
            GUID::from_u128(0x12345678_1234_1234_1234_1234567890ab)
        );
        assert_eq!(
            com.guid.read().unwrap().unwrap(),
            GUID::from_u128(0x12345678_1234_1234_1234_1234567890ab)
        );

        unregister_from_git(cookie).expect("Failed to unregister COM object");

        assert!(
            get_from_git::<IPersist>(cookie).is_err(),
            "Expected error when getting unregistered COM object"
        );
    }
}
