use windows::core::{Interface, GUID, HRESULT};
use windows::Win32::Foundation::BOOL;

// GUIDs de credentialprovider.h
pub const IID_ICredentialProviderFilter: GUID = GUID::from_u128(0xa5da...);

#[repr(transparent)]
pub struct ICredentialProviderFilter(windows::core::IUnknown);

unsafe impl Interface for ICredentialProviderFilter {
    type Vtable = ICredentialProviderFilter_Vtbl;
    const IID: GUID = IID_ICredentialProviderFilter;
}

#[repr(C)]
pub struct ICredentialProviderFilter_Vtbl {
    pub base__: windows::core::IUnknown_Vtbl,
    pub Filter: unsafe extern "system" fn(
        this: *mut core::ffi::c_void,
        cpus: u32,
        dwFlags: u32,
        rgclsidProviders: *mut GUID,
        rgbAllow: *mut BOOL,
        cProviders: u32,
    ) -> HRESULT,
    pub UpdateRemoteCredential: unsafe extern "system" fn(
        this: *mut core::ffi::c_void,
        in_serial: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        out_serial: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> HRESULT,
}
