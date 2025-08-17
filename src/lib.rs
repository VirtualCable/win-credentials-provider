use windows::core::{HRESULT, GUID};

mod util;
mod interfaces;
// mod dll;

mod uds_credential_provider;

mod udscredential;
mod udscredential_filter;

mod classfactory;


#[unsafe(no_mangle)] 
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    windows::Win32::Foundation::S_OK
}

#[unsafe(no_mangle)]
pub extern "system" fn DllGetClassObject(
    _clsid: *const GUID,
    _iid: *const GUID,
    _ppv: *mut *mut core::ffi::c_void,
) -> HRESULT {
    windows::Win32::Foundation::E_NOTIMPL
}
