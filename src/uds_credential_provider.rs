use windows::core::*;

use crate::interfaces::types::{
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO,
};

use crate::interfaces::{
    i_credential_provider::{ICredentialProvider, ICredentialProvider_Impl},
    i_credential_provider_credential::ICredentialProviderCredential,
    i_credential_provider_events::ICredentialProviderEvents,
};

#[implement(ICredentialProvider)]
pub struct UDSCredentialsProvider {
}

impl UDSCredentialsProvider {
    pub fn new() -> Self {
        Self {}
    }
}

#[allow(non_snake_case)]
impl ICredentialProvider_Impl for UDSCredentialsProvider_Impl {
    unsafe fn SetUsageScenario(
        &self,
        _cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        _dw_flags: u32,
    ) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn SetSerialization(
        &self,
        _pcpcs: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn Advise(&self, _pcpe: *const ICredentialProviderEvents, _ctx: usize) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn UnAdvise(&self) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn GetFieldDescriptorCount(&self, _pdw_count: *mut u32) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn GetFieldDescriptorAt(
        &self,
        _idx: u32,
        _ppfd: *mut *mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR,
    ) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn GetCredentialCount(
        &self,
        _pdw_count: *mut u32,
        _pdw_default: *mut u32,
        _pb_auto: *mut BOOL,
    ) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn GetCredentialAt(
        &self,
        _idx: u32,
        _ppcpc: *mut *mut ICredentialProviderCredential,
    ) -> HRESULT {
        HRESULT(0)
    }
}
