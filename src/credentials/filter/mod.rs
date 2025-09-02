use std::sync::RwLock;

use windows::{
    Win32::{
        Foundation::{E_INVALIDARG, E_NOTIMPL},
        UI::Shell::{
            CPUS_CHANGE_PASSWORD, CPUS_CREDUI, CPUS_LOGON, CPUS_UNLOCK_WORKSTATION,
            CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_USAGE_SCENARIO,
            ICredentialProviderFilter, ICredentialProviderFilter_Impl,
        },
    },
    core::*,
};

use crate::{
    credentials::types,
    debug_dev, debug_flow,
    utils::{lsa},
};

static RECV_CRED: RwLock<Option<types::Credential>> = RwLock::new(None);

#[implement(ICredentialProviderFilter)]
pub struct UDSCredentialsFilter {}

impl UDSCredentialsFilter {
    pub fn new() -> Self {
        debug_flow!("UDSCredentialsFilter::new");
        Self {}
    }

    /// Gets and consumes the received credential
    pub fn get_received_credential() -> Option<types::Credential> {
        let mut recv_guard = RECV_CRED.write().unwrap();
        let cred = recv_guard.take();
        cred.clone()
    }

    // Check if we have received a credential, but do not consume it
    pub fn has_received_credential() -> bool {
        let recv_guard = RECV_CRED.read().unwrap();
        recv_guard.is_some()
    }

    pub fn set_received_credential(cred: Option<types::Credential>) {
        let mut recv_guard: std::sync::RwLockWriteGuard<'_, Option<types::Credential>> =
            RECV_CRED.write().unwrap();
        *recv_guard = cred;
    }

    fn filter(
        &self,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        dwflags: u32,
        rgclsidproviders: *const windows::core::GUID,
        rgballow: *mut windows::core::BOOL,
        cproviders: u32,
    ) -> windows::core::Result<()> {
        // If we come from a remote session, and we have a valid UDS credential 
        let is_rdp = UDSCredentialsFilter::has_received_credential();

        debug_dev!("Filter called. is_rdp: {} {} {:?}", is_rdp, dwflags, cpus);

        match cpus {
            CPUS_LOGON | CPUS_UNLOCK_WORKSTATION => {
                if !is_rdp {
                    debug_dev!("Not an RDP session, leaving the providers list as is");
                    // If not RDP, keep the rgballow as is
                    return Ok(());
                }
                // In logon or unlock workstation, we only allow our provider if it's not an RDP session
                for i in 0..cproviders as isize {
                    unsafe {
                        let clsid = *rgclsidproviders.offset(i);
                        let allow = clsid == crate::globals::CLSID_UDS_CREDENTIAL_PROVIDER;
                        *rgballow.offset(i) = allow.into();
                        debug_dev!("Filter: provider: {:?}, allow: {}", clsid, allow);
                    }
                }
            }
            CPUS_CREDUI | CPUS_CHANGE_PASSWORD => {
                return Err(E_NOTIMPL.into());
            }
            _ => {
                return Err(E_INVALIDARG.into());
            }
        }

        Ok(())
    }

    fn update_remote_credential(
        &self,
        pcpcsin: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        _pcpcsout: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> windows::core::Result<()> {
        debug_dev!("UpdateRemoteCredential called. {:?}", pcpcsin);
        #[cfg(debug_assertions)]
        {
            unsafe {
                let mut rgb_serialization = vec![0; (*pcpcsin).cbSerialization as usize];
                // Copy the serialization data
                rgb_serialization.copy_from_slice(std::slice::from_raw_parts(
                    (*pcpcsin).rgbSerialization,
                    (*pcpcsin).cbSerialization as usize,
                ));
                // Convert to KERB_INTERACTIVE_UNLOCK_LOGON using lsa utils. Note that is "in_place"
                // so logon points to the same memory as the packed structure
                let logon = lsa::kerb_interactive_unlock_logon_unpack_in_place(
                    rgb_serialization.as_ptr() as _,
                );
                // Username should be our token, password our shared_secret with our server
                // and domain is simply ignored :)
                let username = lsa::lsa_unicode_string_to_string(&logon.Logon.UserName);
                let password = lsa::lsa_unicode_string_to_string(&logon.Logon.Password);
                let domain = lsa::lsa_unicode_string_to_string(&logon.Logon.LogonDomainName);

                debug_dev!(
                    "UpdateRemoteCredential: username: {}, password: {}, domain: {}",
                    username,
                    password,
                    domain
                );
                if let Some((ticket, key)) = crate::broker::transform_broker_credential(&username) {
                    UDSCredentialsFilter::set_received_credential(Some(
                        types::Credential::with_credentials(&ticket, &key),
                    ));
                }
            }
        }

        Ok(())
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
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        dwflags: u32,
        rgclsidproviders: *const windows::core::GUID,
        rgballow: *mut windows::core::BOOL,
        cproviders: u32,
    ) -> windows::core::Result<()> {
        debug_flow!("ICredentialProviderFilter::Filter");
        self.filter(cpus, dwflags, rgclsidproviders, rgballow, cproviders)
    }

    /// Only invoked when the user is logging in and NLA is enabled
    fn UpdateRemoteCredential(
        &self,
        pcpcsin: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        pcpcsout: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> windows::core::Result<()> {
        // After some tests, the data obtanined from this will be provided to the selected Credential Provider
        // We can simply return transformer credential here, an treat them on our Provider SetSerialzation
        // But the result will be the same.
        debug_flow!("ICredentialProviderFilter::UpdateRemoteCredential");

        self.update_remote_credential(pcpcsin, pcpcsout)
    }
}

#[cfg(test)]
mod tests;
