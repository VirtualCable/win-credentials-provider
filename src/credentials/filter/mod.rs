use windows::{
    Win32::UI::Shell::{
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        ICredentialProviderFilter, ICredentialProviderFilter_Impl,
    },
    core::*,
};

use crate::{debug_dev, util::lsa};

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
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // COM need the signature as is. Cannot mark as unsafe
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
            let mut rgb_serialization = vec![0; unsafe { *pcpcsin }.cbSerialization as usize];
            // Copy the serialization data
            rgb_serialization.copy_from_slice(unsafe {
                std::slice::from_raw_parts(
                    (*pcpcsin).rgbSerialization,
                    (*pcpcsin).cbSerialization as usize,
                )
            });
            // Convert to KERB_INTERACTIVE_UNLOCK_LOGON using lsa utils. Note that is "in_place"
            // so logon points to the same memory as the packed structure
            let logon = unsafe {
                lsa::kerb_interactive_unlock_logon_unpack_in_place(rgb_serialization.as_ptr() as _)
            };
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
        Ok(())
    }
}
