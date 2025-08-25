use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
};

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

use log::error;

use crate::credential::credential::UDSCredential;
use crate::debug_dev;

pub const CLSID_UDS_CREDENTIAL_PROVIDER: GUID =
    GUID::from_u128(0x6e3b975c_2cf3_11e6_88a9_10feed05884b);

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
        std::thread::spawn(move || {
            let (thread_handle, channel_server) =
                match crate::messages::channel::ChannelServer::run("") {
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

    // Thread for running channel server and
}

impl Drop for UDSCredentialsProvider {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        // Unregister from GIT if needed
        if let Some(cookie) = *self.cookie.read().unwrap() {
            if let Err(e) = crate::util::com::unregister_from_git(cookie) {
                error!("Failed to unregister from GIT: {:?}", e);
            }
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
                self.credential.write().unwrap().reset();
                self.credential.write().unwrap().set_usage_scenario(cpus);
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
        upadvisecontext: usize,
    ) -> windows::core::Result<()> {
        // Store for using later
        let cookie = crate::util::com::register_in_git(pcpe.clone().unwrap())?;
        *self.cookie.write().unwrap() = Some(cookie);
        *self.up_advise_context.write().unwrap() = Some(upadvisecontext);
        Ok(())
    }
    fn UnAdvise(&self) -> windows::core::Result<()> {
        if let Some(cookie) = *self.cookie.write().unwrap() {
            crate::util::com::unregister_from_git(cookie)?;
            *self.cookie.write().unwrap() = None;
            *self.up_advise_context.write().unwrap() = None;
        }
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
            Ok(self.credential.read().unwrap().clone().into())
        } else {
            Err(windows::core::Error::from_hresult(E_INVALIDARG))
        }
    }
}
