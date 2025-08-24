use std::{cell::RefCell, sync::{Mutex, Arc}};

use windows::{
    Win32::{
        Foundation::E_INVALIDARG,
        UI::Shell::{
            CPUS_CHANGE_PASSWORD, CPUS_CREDUI, CPUS_LOGON, CPUS_UNLOCK_WORKSTATION,
            CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR,
            CREDENTIAL_PROVIDER_USAGE_SCENARIO, ICredentialProvider, ICredentialProvider_Impl,
            ICredentialProviderCredential, ICredentialProviderEvents,
        },
    },
    core::*,
};

use crate::debug_dev;

use super::credential::UDSCredential;

pub const CLSID_UDS_CREDENTIAL_PROVIDER: GUID =
    GUID::from_u128(0x6e3b975c_2cf3_11e6_88a9_10feed05884b);

#[implement(ICredentialProvider)]
pub struct UDSCredentialsProvider {
    credential: Arc<Mutex<UDSCredential>>,
    cred_prov_events: Arc<Mutex<Option<ICredentialProviderEvents>>>,
}

impl UDSCredentialsProvider {
    pub fn new() -> Self {
        Self {
            credential: Arc::new(Mutex::new(UDSCredential::new())),
            cred_prov_events: Arc::new(Mutex::new(None)),
        }
    }
}

impl ICredentialProvider_Impl for UDSCredentialsProvider_Impl {
    fn SetUsageScenario(
        &self,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        dwflags: u32,
    ) -> windows::core::Result<()> {
        debug_dev!("SetUsageScenario called: {:?} {}", cpus, dwflags);
        match cpus {
            CPUS_LOGON | CPUS_UNLOCK_WORKSTATION => {
                self.credential.lock().unwrap().reset();
                self.credential.lock().unwrap().set_usage_scenario(cpus);
                Ok(())
            }
            CPUS_CREDUI | CPUS_CHANGE_PASSWORD => Ok(()),
            _ => Err(E_INVALIDARG.into()),
        }
    }

    fn SetSerialization(
        &self,
        _pcpcs: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn Advise(
        &self,
        pcpe: windows::core::Ref<'_, ICredentialProviderEvents>,
        _upadvisecontext: usize,
    ) -> windows::core::Result<()> {
        // Store for using later
        *self.cred_prov_events.lock().unwrap() = pcpe.clone();
        Ok(())
    }
    fn UnAdvise(&self) -> windows::core::Result<()> {
        *self.cred_prov_events.lock().unwrap() = None;
        Ok(())
    }
    fn GetFieldDescriptorCount(&self) -> windows::core::Result<u32> {
        Ok(0)
    }
    fn GetFieldDescriptorAt(
        &self,
        _dwindex: u32,
    ) -> windows::core::Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        Ok(std::ptr::null_mut())
    }
    fn GetCredentialCount(
        &self,
        _pdwcount: *mut u32,
        _pdwdefault: *mut u32,
        _pbautologonwithdefault: *mut windows::core::BOOL,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn GetCredentialAt(&self, dwindex: u32) -> Result<ICredentialProviderCredential> {
        if dwindex == 0 {
            Ok(self.credential.lock().unwrap().clone().into())
        } else {
            Err(windows::core::Error::from_hresult(E_INVALIDARG))
        }
    }
}
