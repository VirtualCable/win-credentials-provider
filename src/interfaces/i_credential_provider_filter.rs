// src/interfaces/i_credential_provider_filter.rs

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use windows::core::*;
use super::types::*;

// ICredentialProviderFilter COM interface
pub const CLSID_CREDENTIAL_PROVIDER_FILTER: GUID =
    GUID::from_u128(0xa5da53f9_d475_4080_a120_910c4a739880);

#[interface("a5da53f9-d475-4080-a120-910c4a739880")]
pub unsafe trait ICredentialProviderFilter: IUnknown {
    unsafe fn Filter(
        &self,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        dwFlags: u32,
        rgclsidProviders: *const GUID,
        rgbAllow: *mut BOOL,
        cProviders: u32,
    ) -> HRESULT;

    unsafe fn UpdateRemoteCredential(
        &self,
        pcpcsIn: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        pcpcsOut: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> HRESULT;
}
