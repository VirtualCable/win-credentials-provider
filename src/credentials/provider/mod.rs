use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
};

use windows::{
    Win32::{
        Foundation::{E_INVALIDARG, E_NOTIMPL},
        UI::Shell::{
            CPUS_CHANGE_PASSWORD, CPUS_CREDUI, CPUS_LOGON, CPUS_PLAP, CPUS_UNLOCK_WORKSTATION,
            CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR,
            CREDENTIAL_PROVIDER_NO_DEFAULT, CREDENTIAL_PROVIDER_USAGE_SCENARIO,
            ICredentialProvider, ICredentialProvider_Impl, ICredentialProviderCredential,
            ICredentialProviderEvents,
        },
    },
    core::*,
};

use log::error;
use zeroize::Zeroize;

use crate::debug_dev;
use crate::{credentials::credential::UDSCredential, util::lsa};

#[implement(ICredentialProvider)]
#[derive(Clone)]
pub struct UDSCredentialsProvider {
    credential: Arc<RwLock<UDSCredential>>,
    cookie: Arc<RwLock<Option<u32>>>,
    up_advise_context: Arc<RwLock<Option<usize>>>,
    stop_flag: Arc<AtomicBool>,
}

impl UDSCredentialsProvider {
    pub fn new() -> Self {
        let me = Self {
            credential: Arc::new(RwLock::new(UDSCredential::new())),
            cookie: Arc::new(RwLock::new(None)),
            up_advise_context: Arc::new(RwLock::new(None)),
            stop_flag: Arc::new(AtomicBool::new(false)),
        };
        // Start the async credentials receiver by the pipe processor
        me.async_creds_processor();
        me
    }

    pub fn on_data_arrived(
        &self,
        msg: crate::messages::auth::AuthRequest,
    ) -> windows::core::Result<()> {
        // Update credentials
        self.credential
            .write()
            .unwrap()
            .set_credentials(&msg.username, &msg.password, &msg.domain);

        // If we have a cookie, retrieve the interface from the GIT
        if let Some(cookie) = *self.cookie.read().unwrap() {
            unsafe {
                let events: ICredentialProviderEvents = crate::util::com::get_from_git(cookie)?;

                // NOTE: The second parameter (upAdviseContext) is the one you received in Advise
                //       If you don't have it stored, you can keep it along with the cookie.
                events.CredentialsChanged(self.up_advise_context.read().unwrap().unwrap())?;
            }
        }

        Ok(())
    }

    fn async_creds_processor(&self) {
        let cred_provider = self.clone();
        let auth_token: String = crate::globals::get_auth_token().unwrap_or_default();
        std::thread::spawn(move || {
            let (thread_handle, channel_server) =
                match crate::messages::channel::ChannelServer::run(&auth_token) {
                    Ok((thread_handle, channel_server)) => (thread_handle, channel_server),
                    Err(e) => {
                        error!("Failed to start ChannelServer: {:?}", e);
                        return;
                    }
                };
            while !cred_provider.stop_flag.load(Ordering::Relaxed) {
                if let Some(request) = channel_server.get_request() {
                    cred_provider
                        .on_data_arrived(request)
                        .unwrap_or_else(|e| error!("on_data_arrived failed: {:?}", e));
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(1000));
                }
            }
            // Flag channel server to stop
            channel_server.stop();
            thread_handle.join().unwrap_or_else(|e| {
                error!("ChannelServer thread join failed: {:?}", e);
            });
        });
    }

    fn set_usage_scenario(
        &self,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        dwflags: u32,
    ) -> windows::core::Result<()> {
        debug_dev!("SetUsageScenario called: {:?} {}", cpus, dwflags);
        match cpus {
            CPUS_LOGON | CPUS_UNLOCK_WORKSTATION => {
                self.credential.write().unwrap().reset();
                self.credential.write().unwrap().set_usage_scenario(cpus);
                Ok(())
            }
            CPUS_CREDUI | CPUS_CHANGE_PASSWORD | CPUS_PLAP => Err(E_NOTIMPL.into()),
            _ => Err(E_INVALIDARG.into()),
        }
    }

    // This will receive the credentials provided by the user
    // In case of RDP (our initial implementation will be for RDP)
    // The username, password and domain will be those present on the logon request by the user
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // COM need the signature as is. Cannot mark as unsafe
    fn serialize(
        &self,
        pcpcs: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> windows::core::Result<()> {
        unsafe {
            if (*pcpcs).clsidCredentialProvider != crate::globals::CLSID_UDS_CREDENTIAL_PROVIDER {
                return Err(E_INVALIDARG.into());
            }
            debug_dev!("SetSerialization called with our CLSID");
            let mut rgb_serialization = vec![0; (*pcpcs).cbSerialization as usize];
            // Copy the serialization data
            rgb_serialization.copy_from_slice(std::slice::from_raw_parts(
                (*pcpcs).rgbSerialization,
                (*pcpcs).cbSerialization as usize,
            ));
            // Convert to KERB_INTERACTIVE_UNLOCK_LOGON using lsa utils. Note that is "in_place"
            // so logon points to the same memory as the packed structure
            let logon =
                lsa::kerb_interactive_unlock_logon_unpack_in_place(rgb_serialization.as_ptr() as _);

            // Username should be our token, password our shared_secret with our server
            // and domain is simply ignored :)
            let username = lsa::lsa_unicode_string_to_string(&logon.Logon.UserName);
            let password = lsa::lsa_unicode_string_to_string(&logon.Logon.Password);
            let domain = lsa::lsa_unicode_string_to_string(&logon.Logon.LogonDomainName);

            if !crate::broker::is_broker_credential(&username) {
                return Err(E_INVALIDARG.into());
            }

            match crate::broker::get_credentials_from_broker(&username, &password, &domain) {
                Ok((username, mut password, domain)) => {
                    self.credential
                        .write()
                        .unwrap()
                        .set_credentials(&username, &password, &domain);

                    debug_dev!(
                        "SetSerialization extracted credentials: {}\\{}",
                        domain,
                        username
                    );
                    // Clean up retrieved password
                    password.zeroize();
                }
                Err(e) => {
                    error!("Failed to get credentials from broker: {:?}", e);
                }
            };

            rgb_serialization.zeroize(); // Clean up OUR packed data also
        }

        Ok(())
    }

    fn register_event_manager(
        &self,
        pcpe: ICredentialProviderEvents,
        upadvisecontext: usize,
    ) -> windows::core::Result<()> {
        // Store for using later
        let cookie = crate::util::com::register_in_git(pcpe)?;
        *self.cookie.write().unwrap() = Some(cookie);
        // Context used with ICredentialProviderEvents
        *self.up_advise_context.write().unwrap() = Some(upadvisecontext);
        Ok(())
    }

    fn unregister_event_manager(&self) -> windows::core::Result<()> {
        if let Some(cookie) = *self.cookie.write().unwrap() {
            crate::util::com::unregister_from_git(cookie)?;
            *self.cookie.write().unwrap() = None;
            *self.up_advise_context.write().unwrap() = None;
        }
        Ok(())
    }

    fn number_of_fields(&self) -> u32 {
        crate::credentials::types::UdsFieldId::NumFields as u32
    }

    fn get_field_descriptor_at(
        &self,
        index: u32,
    ) -> windows::core::Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        if index >= self.number_of_fields() {
            return Err(windows::core::Error::from_hresult(E_INVALIDARG));
        }
        crate::credentials::fields::CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS[index as usize]
            .into_com_alloc()
    }

    fn get_credential_count(&self) -> windows::core::Result<(u32, u32, BOOL)> {
        // If we have redirected credentials, SetSerialization will be invoked prior us
        // If not, we allow interactive logon
        let is_rdp = crate::util::helpers::is_rdp_session();
        let has_valid_creds = self.credential.read().unwrap().is_ready()
            && crate::broker::is_broker_credential(&self.credential.read().unwrap().username());

        debug_dev!(
            "GetCredentialCount called. is_rdp: {} has_creds: {}",
            is_rdp,
            has_valid_creds
        );

        let pdwcount = 1; // If 0, our provider will not be shown

        let (pwdefault, pwautologonwithdefault) = if is_rdp && has_valid_creds {
            (0, true.into())
        } else {
            (CREDENTIAL_PROVIDER_NO_DEFAULT, false.into())
        };
        Ok((pdwcount, pwdefault, pwautologonwithdefault))
    }

    fn get_credential_at(
        &self,
        index: u32,
    ) -> windows::core::Result<ICredentialProviderCredential> {
        if index == 0 {
            Ok(self.credential.read().unwrap().clone().into())
        } else {
            Err(windows::core::Error::from_hresult(E_INVALIDARG))
        }
    }

    // Thread for running channel server and
}

impl Default for UDSCredentialsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for UDSCredentialsProvider {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        // Unregister from GIT if needed
        if let Some(cookie) = *self.cookie.read().unwrap()
            && let Err(e) = crate::util::com::unregister_from_git(cookie)
        {
            error!("Failed to unregister from GIT: {:?}", e);
        }
    }
}

impl ICredentialProvider_Impl for UDSCredentialsProvider_Impl {
    fn SetUsageScenario(
        &self,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        dwflags: u32,
    ) -> windows::core::Result<()> {
        self.set_usage_scenario(cpus, dwflags)
    }

    // This will receive the credentials provided by the user
    // In case of RDP (our initial implementation will be for RDP)
    // The username, password and domain will be those present on the logon request by the user
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // COM need the signature as is. Cannot mark as unsafe
    fn SetSerialization(
        &self,
        pcpcs: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> windows::core::Result<()> {
        self.serialize(pcpcs)
    }

    fn Advise(
        &self,
        pcpe: windows::core::Ref<'_, ICredentialProviderEvents>,
        upadvisecontext: usize,
    ) -> windows::core::Result<()> {
        self.register_event_manager(pcpe.unwrap().clone(), upadvisecontext)
    }

    fn UnAdvise(&self) -> windows::core::Result<()> {
        self.unregister_event_manager()
    }

    fn GetFieldDescriptorCount(&self) -> windows::core::Result<u32> {
        Ok(self.number_of_fields())
    }

    fn GetFieldDescriptorAt(
        &self,
        dwindex: u32,
    ) -> windows::core::Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        self.get_field_descriptor_at(dwindex)
    }

    #[allow(clippy::not_unsafe_ptr_arg_deref)] // COM need the signature as is. Cannot mark as unsafe
    fn GetCredentialCount(
        &self,
        pdwcount: *mut u32,
        pdwdefault: *mut u32,
        pbautologonwithdefault: *mut windows::core::BOOL,
    ) -> windows::core::Result<()> {
        // If we have redirected credentials, SetSerialization will be invoked prior us
        // If not, we allow interactive logon
        unsafe { (*pdwcount, *pdwdefault, *pbautologonwithdefault) = self.get_credential_count()? };
        Ok(())
    }

    fn GetCredentialAt(&self, dwindex: u32) -> Result<ICredentialProviderCredential> {
        self.get_credential_at(dwindex)
    }
}

#[cfg(test)]
mod tests;
