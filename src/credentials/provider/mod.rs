#[cfg(debug_assertions)]
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

use zeroize::Zeroize;

use crate::{
    credentials::credential::UDSCredential,
    debug_flow,
    utils::{log, log::error, lsa},
};
use crate::{debug_dev, globals};

// Only available in tests
#[cfg(test)]
use std::sync::OnceLock;

#[cfg(test)]
static ASYNC_CREDS_HANDLE: OnceLock<RwLock<Option<std::thread::JoinHandle<()>>>> = OnceLock::new();

#[implement(ICredentialProvider)]
#[derive(Clone)]
pub struct UDSCredentialsProvider {
    credential: Arc<RwLock<UDSCredential>>,
    cookie: Arc<RwLock<Option<u32>>>,
    up_advise_context: Arc<RwLock<usize>>,
    stop_flag: Arc<AtomicBool>,
}

impl UDSCredentialsProvider {
    pub fn new() -> Self {
        // Ensure flow counter is reset on debug
        log::reset_flow_counter();

        debug_flow!("UDSCredentialsProvider::new");
        let me: UDSCredentialsProvider = Self {
            credential: Arc::new(RwLock::new(UDSCredential::new())),
            cookie: Arc::new(RwLock::new(None)),
            up_advise_context: Arc::new(RwLock::new(0)),
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

        // If we have an event manager, notify it of the credential change
        if let Some(event_manager) = self.get_event_manager()? {
            unsafe { event_manager.CredentialsChanged(*self.up_advise_context.read().unwrap())? };
        }

        Ok(())
    }

    fn async_creds_processor(&self) {
        let cred_provider = self.clone();
        let auth_token: String = crate::globals::get_auth_token().unwrap_or_default();
        let pipe_name = globals::get_pipe_name();
        debug_dev!(
            "Starting async credentials receiver with pipe name: {}",
            pipe_name
        );
        let _thread_handle = std::thread::spawn(move || {
            let (thread_handle, channel_server) =
                match crate::messages::channel::ChannelServer::run_with_pipe(
                    &auth_token,
                    Some(pipe_name.as_str()),
                ) {
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
        #[cfg(test)]
        {
            ASYNC_CREDS_HANDLE
                .get_or_init(|| RwLock::new(None))
                .write()
                .unwrap()
                .replace(_thread_handle);
        }
    }

    fn set_usage_scenario(
        &self,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
    ) -> windows::core::Result<()> {
        match cpus {
            CPUS_LOGON | CPUS_UNLOCK_WORKSTATION => {
                self.credential.write().unwrap().reset_credentials();
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
    fn unserialize(
        &self,
        pcpcs: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> windows::core::Result<()> {
        unsafe {
            if (*pcpcs).clsidCredentialProvider != crate::globals::CLSID_UDS_CREDENTIAL_PROVIDER {
                return Err(E_INVALIDARG.into());
            }
            debug_dev!("SetSerialization called with our CLSID");
            let mut rgb_serialization = vec![0; (*pcpcs).cbSerialization as usize];
            // Copy the data to unserialize
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

            if !crate::broker::is_broker_credential(&username, &password) {
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
                    return Err(E_INVALIDARG.into());
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
        let cookie = crate::utils::com::register_in_git(pcpe)?;
        *self.cookie.write().unwrap() = Some(cookie);
        // Context used with ICredentialProviderEvents
        *self.up_advise_context.write().unwrap() = upadvisecontext;
        Ok(())
    }

    fn unregister_event_manager(&self) -> windows::core::Result<()> {
        let cookie_opt = {
            let guard = self.cookie.read().unwrap();
            *guard
        };
        if let Some(cookie) = cookie_opt {
            crate::utils::com::unregister_from_git(cookie)?;
            *self.cookie.write().unwrap() = None;
            *self.up_advise_context.write().unwrap() = 0;
        }
        Ok(())
    }

    fn get_event_manager(&self) -> windows::core::Result<Option<ICredentialProviderEvents>> {
        if let Some(cookie) = *self.cookie.read().unwrap() {
            Ok(Some(crate::utils::com::get_from_git(cookie)?))
        } else {
            Ok(None)
        }
    }

    fn get_number_of_fields(&self) -> u32 {
        crate::credentials::types::UdsFieldId::NumFields as u32
    }

    fn get_field_descriptor_at(
        &self,
        index: u32,
    ) -> windows::core::Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        if index >= self.get_number_of_fields() {
            return Err(windows::core::Error::from_hresult(E_INVALIDARG));
        }
        crate::credentials::fields::CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS[index as usize]
            .into_com_alloc()
    }

    fn get_credential_count(&self) -> windows::core::Result<(u32, u32, BOOL)> {
        // If we have redirected credentials, SetSerialization will be invoked prior us
        // If not, we allow interactive logon
        let is_rdp = crate::utils::helpers::is_rdp_session();
        let has_valid_creds = self.credential.read().unwrap().is_ready();

        debug_dev!(
            "get_credential_count called. is_rdp: {} has_creds: {}",
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
        let cookie_opt = {
            let guard = self.cookie.read().unwrap();
            *guard
        };
        if let Some(cookie) = cookie_opt
            && let Err(e) = crate::utils::com::unregister_from_git(cookie)
        {
            error!("Failed to unregister from GIT: {:?}", e);
        }
    }
}

impl ICredentialProvider_Impl for UDSCredentialsProvider_Impl {
    fn SetUsageScenario(
        &self,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        _dwflags: u32,
    ) -> windows::core::Result<()> {
        debug_flow!("ICredentialProvider::SetUsageScenario");
        debug_dev!("SetUsageScenario called: {:?} {}", cpus, _dwflags);
        self.set_usage_scenario(cpus)
    }

    // This will receive the credentials provided by the user
    // In case of RDP (our initial implementation will be for RDP)
    // The username, password and domain will be those present on the logon request by the user
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // COM need the signature as is. Cannot mark as unsafe
    fn SetSerialization(
        &self,
        pcpcs: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> windows::core::Result<()> {
        debug_flow!("ICredentialProvider::SetSerialization");
        self.unserialize(pcpcs)
    }

    fn Advise(
        &self,
        pcpe: windows::core::Ref<'_, ICredentialProviderEvents>,
        upadvisecontext: usize,
    ) -> windows::core::Result<()> {
        debug_flow!("ICredentialProvider::Advise");
        self.register_event_manager(pcpe.unwrap().clone(), upadvisecontext)
    }

    fn UnAdvise(&self) -> windows::core::Result<()> {
        debug_flow!("ICredentialProvider::UnAdvise");
        self.unregister_event_manager()
    }

    fn GetFieldDescriptorCount(&self) -> windows::core::Result<u32> {
        debug_flow!("ICredentialProvider::GetFieldDescriptorCount");
        Ok(self.get_number_of_fields())
    }

    fn GetFieldDescriptorAt(
        &self,
        dwindex: u32,
    ) -> windows::core::Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        debug_flow!("ICredentialProvider::GetFieldDescriptorAt");
        self.get_field_descriptor_at(dwindex)
    }

    #[allow(clippy::not_unsafe_ptr_arg_deref)] // COM need the signature as is. Cannot mark as unsafe
    fn GetCredentialCount(
        &self,
        pdwcount: *mut u32,
        pdwdefault: *mut u32,
        pbautologonwithdefault: *mut windows::core::BOOL,
    ) -> windows::core::Result<()> {
        debug_flow!("ICredentialProvider::GetCredentialCount");
        // If we have redirected credentials, SetSerialization will be invoked prior us
        // If not, we allow interactive logon
        unsafe { (*pdwcount, *pdwdefault, *pbautologonwithdefault) = self.get_credential_count()? };
        Ok(())
    }

    fn GetCredentialAt(&self, dwindex: u32) -> Result<ICredentialProviderCredential> {
        debug_flow!("ICredentialProvider::GetCredentialAt");
        self.get_credential_at(dwindex)
    }
}

#[cfg(test)]
mod tests;
