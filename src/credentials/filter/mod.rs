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
    debug_dev, debug_flow,
    utils::{helpers, lsa},
};

#[implement(ICredentialProviderFilter)]
pub struct UDSCredentialsFilter {}

impl UDSCredentialsFilter {
    pub fn new() -> Self {
        debug_flow!("UDSCredentialsFilter::new");
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
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // COM need the signature as is. Cannot mark as unsafe
    fn Filter(
        &self,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        dwflags: u32,
        rgclsidproviders: *const windows::core::GUID,
        rgballow: *mut windows::core::BOOL,
        cproviders: u32,
    ) -> windows::core::Result<()> {
        debug_flow!("ICredentialProviderFilter::Filter");
        let is_rdp = helpers::is_rdp_session();

        debug_dev!("Filter called. is_rdp: {} {}", is_rdp, dwflags);

        match cpus {
            CPUS_LOGON | CPUS_UNLOCK_WORKSTATION => {
                // In logon or unlock workstation, we only allow our provider if it's not an RDP session
                for i in 0..cproviders as isize {
                    unsafe {
                        let clsid = *rgclsidproviders.offset(i);
                        let allow =
                            clsid == crate::globals::CLSID_UDS_CREDENTIAL_PROVIDER && !is_rdp;
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
    ///
    /// Update the remote credential serialization
    /// Only invoked when the user is logging in and NLA is enabled
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // COM need the signature as is. Cannot mark as unsafe
    fn UpdateRemoteCredential(
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
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests;
