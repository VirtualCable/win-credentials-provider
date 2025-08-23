use windows::{
    Win32::Foundation::E_INVALIDARG,
    Win32::UI::Shell::{
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR,
        CREDENTIAL_PROVIDER_USAGE_SCENARIO, ICredentialProvider, ICredentialProvider_Impl,
        ICredentialProviderCredential, ICredentialProviderEvents,
    },
    core::*,
};

pub const CLSID_UDS_CREDENTIAL_PROVIDER: GUID =
    GUID::from_u128(0x6e3b975c_2cf3_11e6_88a9_10feed05884b);

#[implement(ICredentialProvider)]
pub struct UDSCredentialsProvider {}

impl UDSCredentialsProvider {
    pub fn new() -> Self {
        Self {}
    }
}

impl ICredentialProvider_Impl for UDSCredentialsProvider_Impl {
    fn SetUsageScenario(
        &self,
        _cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        _dwflags: u32,
    ) -> windows_core::Result<()> {
        Ok(())
    }
    fn SetSerialization(
        &self,
        _pcpcs: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> windows_core::Result<()> {
        Ok(())
    }
    fn Advise(
        &self,
        _pcpe: windows_core::Ref<'_, ICredentialProviderEvents>,
        _upadvisecontext: usize,
    ) -> windows_core::Result<()> {
        Ok(())
    }
    fn UnAdvise(&self) -> windows_core::Result<()> {
        Ok(())
    }
    fn GetFieldDescriptorCount(&self) -> windows_core::Result<u32> {
        Ok(0)
    }
    fn GetFieldDescriptorAt(
        &self,
        _dwindex: u32,
    ) -> windows_core::Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        Ok(std::ptr::null_mut())
    }
    fn GetCredentialCount(
        &self,
        _pdwcount: *mut u32,
        _pdwdefault: *mut u32,
        _pbautologonwithdefault: *mut windows_core::BOOL,
    ) -> windows_core::Result<()> {
        Ok(())
    }
    fn GetCredentialAt(&self, _dwindex: u32) -> Result<ICredentialProviderCredential> {
        Err(windows_core::Error::from_hresult(E_INVALIDARG))
    }
}
