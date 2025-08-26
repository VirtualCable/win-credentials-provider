use windows::{
    Win32::UI::Shell::{
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        ICredentialProviderFilter, ICredentialProviderFilter_Impl,
    },
    core::*,
};

#[implement(ICredentialProviderFilter)]
pub struct UDSCredentialsFilter {}

impl UDSCredentialsFilter {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for UDSCredentialsFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(non_snake_case)]
impl ICredentialProviderFilter_Impl for UDSCredentialsFilter_Impl {
    fn Filter(
        &self,
        _cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        _dwflags: u32,
        _rgclsidproviders: *const windows::core::GUID,
        _rgballow: *mut windows::core::BOOL,
        _cproviders: u32,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn UpdateRemoteCredential(
        &self,
        _pcpcsin: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        _pcpcsout: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> windows::core::Result<()> {
        Ok(())
    }
}
