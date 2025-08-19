// src/interfaces/i_credential_provider.rs

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use windows::core::*;

use super::types::*;
use super::i_credential_provider_events::ICredentialProviderEvents;
use super::i_credential_provider_credential::ICredentialProviderCredential;

//
// SDK types: credential serialization, usage scenario, field types/descriptor
//


//
// ICredentialProvider COM interface
//

#[interface("d27c3481-5a1c-45b2-8aaa-c20ebbe8229e")]
pub unsafe trait ICredentialProvider: IUnknown {
    unsafe fn SetUsageScenario(&self, cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO, dwFlags: u32) -> HRESULT;

    unsafe fn SetSerialization(
        &self,
        pcpcs: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> HRESULT;

    unsafe fn Advise(&self, pcpe: *const ICredentialProviderEvents, upAdviseContext: usize) -> HRESULT;

    unsafe fn UnAdvise(&self) -> HRESULT;

    unsafe fn GetFieldDescriptorCount(&self, pdwCount: *mut u32) -> HRESULT;

    unsafe fn GetFieldDescriptorAt(
        &self,
        dwIndex: u32,
        ppcpfd: *mut *mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR,
    ) -> HRESULT;

    unsafe fn GetCredentialCount(
        &self,
        pdwCount: *mut u32,
        pdwDefault: *mut u32,
        pbAutoLogonWithDefault: *mut BOOL,
    ) -> HRESULT;

    unsafe fn GetCredentialAt(
        &self,
        dwIndex: u32,
        ppcpc: *mut *mut ICredentialProviderCredential,
    ) -> HRESULT;
}
