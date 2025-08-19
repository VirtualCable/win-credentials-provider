use windows::core::*;

use crate::com::i_credential_provider_filter::{
    ICredentialProviderFilter, ICredentialProviderFilter_Impl,
};
use crate::com::types::*;

#[implement(ICredentialProviderFilter)]
pub struct UDSCredentialsFilter {}

impl UDSCredentialsFilter {
    pub fn new() -> Self {
        Self {}
    }
}

#[allow(non_snake_case)]
impl ICredentialProviderFilter_Impl for UDSCredentialsFilter_Impl {
    unsafe fn Filter(
        &self,
        _cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        _dwFlags: u32,
        _rgclsidProviders: *const GUID,
        _rgbAllow: *mut BOOL,
        _cProviders: u32,
    ) -> HRESULT {
        return HRESULT(0);
    }

    unsafe fn UpdateRemoteCredential(
        &self,
        _pcpcsIn: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        _pcpcsOut: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> HRESULT {
        return HRESULT(0);
    }
}
