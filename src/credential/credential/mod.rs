use std::sync::{Arc, RwLock};

use log::{debug, error, info};

use windows::{
    Win32::{
        Foundation::{E_INVALIDARG, E_NOTIMPL, NTSTATUS},
        Graphics::Gdi::HBITMAP,
        Security::Authentication::Identity::{
            KERB_INTERACTIVE_LOGON, KERB_INTERACTIVE_UNLOCK_LOGON, KerbInteractiveLogon,
            KerbWorkstationUnlockLogon,
        },
        System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance, IGlobalInterfaceTable},
        UI::{
            Shell::{
                CPGSR_RETURN_CREDENTIAL_FINISHED, CPUS_LOGON, CPUS_UNLOCK_WORKSTATION,
                CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
                CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE, CREDENTIAL_PROVIDER_FIELD_STATE,
                CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE, CREDENTIAL_PROVIDER_STATUS_ICON,
                CREDENTIAL_PROVIDER_USAGE_SCENARIO, ICredentialProviderCredential,
                ICredentialProviderCredential_Impl, ICredentialProviderCredentialEvents,
            },
            WindowsAndMessaging::{IMAGE_BITMAP, LR_CREATEDIBSECTION, LR_DEFAULTCOLOR, LoadImageW},
        },
    },
    core::*,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{credential::provider::CLSID_UDS_CREDENTIAL_PROVIDER, debug_dev, dll, util::com};

use super::{fields::CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS, lsa, types::UdsFieldId};

#[derive(Debug, Clone)]
struct Creds {
    username: String,
    password: Zeroizing<Vec<u8>>,
    domain: String,
}

#[allow(dead_code)]
#[implement(ICredentialProviderCredential)]
#[derive(Clone)]
pub struct UDSCredential {
    cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
    values: Arc<RwLock<Vec<String>>>, // Array containing the values of the fields
    credential: Arc<RwLock<Creds>>,   // Actual credentials
    cookie: Arc<RwLock<Option<u32>>>,
}

impl Drop for UDSCredential {
    fn drop(&mut self) {
        let mut credential = self.credential.write().unwrap();
        credential.password.zeroize(); // Clear the password on drop
    }
}

impl UDSCredential {
    pub fn new() -> Self {
        Self {
            cpus: CPUS_LOGON,
            values: Arc::new(RwLock::new(vec![
                String::new();
                UdsFieldId::NumFields as usize
            ])),
            credential: Arc::new(RwLock::new(Creds {
                username: String::new(),
                password: Zeroizing::new(Vec::new()),
                domain: String::new(),
            })),
            cookie: Arc::new(RwLock::new(None)),
        }
    }
    pub fn reset(&mut self) {
        let mut credential = self.credential.write().unwrap();
        credential.username.clear();
        credential.password.zeroize();
        credential.domain.clear();
        let mut values = self.values.write().unwrap();
        for v in values.iter_mut() {
            v.clear();
        }
    }

    pub fn set_credentials(&mut self, username: &str, password: &str, domain: &str) {
        // If no domain, use GetComputerNameW
        // Ensure previous password is cleared with zero values before
        let mut credential = self.credential.write().unwrap();
        credential.password.zeroize();
        let temp = password.as_bytes().to_vec();
        credential.password = Zeroizing::new(temp);

        if domain.is_empty() {
            credential.domain = crate::util::helpers::get_computer_name();
        } else {
            credential.domain = domain.to_string();
        }

        credential.username = username.to_string();
        let mut values = self.values.write().unwrap();
        *values = (0..UdsFieldId::NumFields as usize)
            .map(|i| match i {
                x if x == UdsFieldId::SubmitButton as usize => "Submit".into(),
                x if x == UdsFieldId::Username as usize => credential.username.clone(),
                _ => String::new(),
            })
            .collect();
    }

    pub fn set_usage_scenario(&mut self, cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO) {
        self.cpus = cpus;
    }

    pub fn get_icredential_provider_credential_event(
        &self,
    ) -> Option<ICredentialProviderCredentialEvents> {
        if let Some(cookie) = *self.cookie.read().unwrap() {
            return com::get_from_git(cookie).ok();
        }
        None
    }
}

impl ICredentialProviderCredential_Impl for UDSCredential_Impl {
    // By this method, LogonUI gives us a callback so we can notify it of changes
    // If we need to update the UI, we can call the appropriate methods on the events object
    fn Advise(
        &self,
        pcpce: windows::core::Ref<'_, ICredentialProviderCredentialEvents>,
    ) -> windows::core::Result<()> {
        debug_dev!("Advising credential provider events");
        let cookie = com::register_in_git(pcpce.unwrap().clone())?;
        *self.cookie.write().unwrap() = Some(cookie);
        Ok(())
    }

    // Release the callback
    fn UnAdvise(&self) -> windows::core::Result<()> {
        debug_dev!("Unadvising credential provider events");
        if let Some(cookie) = *self.cookie.write().unwrap() {
            com::unregister_from_git(cookie)?;
            *self.cookie.write().unwrap() = None;
        }
        Ok(())
    }

    // Invoked when our tile is selected.
    // We do not heed any special here, Just inform to not autologon
    fn SetSelected(&self) -> windows::core::Result<windows::core::BOOL> {
        // If we have an username, copy it to values
        let username: String = {
            let credential = self.credential.read().unwrap();
            if credential.username.is_empty() {
                "".to_string()
            } else {
                // If we have domain and has a point, set username to username@domain
                // else, if we have domain, set domain\username
                if !credential.domain.is_empty() {
                    if credential.domain.contains('.') {
                        format!("{}@{}", credential.username, credential.domain)
                    } else {
                        format!("{}\\{}", credential.domain, credential.username)
                    }
                } else {
                    credential.username.clone()
                }
            }
        };
        if username.len() > 0 {
            self.values.write().unwrap()[UdsFieldId::Username as usize] = username;
        }
        Ok(false.into())
    }

    // Our tile is deselected, clear the password value
    // To do not keep it in memory
    fn SetDeselected(&self) -> windows::core::Result<()> {
        // If values[<index>] is the password field, clear it
        let mut values = self.values.write().unwrap();
        if !values[UdsFieldId::Password as usize].is_empty() {
            values[UdsFieldId::Password as usize].zeroize(); // Clear the password field
        }
        let cred_prov_events = self.get_icredential_provider_credential_event();
        if let Some(events) = cred_prov_events {
            let icred: ICredentialProviderCredential = (*self).clone().into();
            unsafe {
                events.SetFieldString(
                    &icred,
                    UdsFieldId::Password as u32,
                    windows::core::PCWSTR::null(), // Empty string
                )
            }?;
        }
        Ok(())
    }

    /// Retrieves the state of a field.
    fn GetFieldState(
        &self,
        dwfieldid: u32,
        pcpfs: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        pcpfis: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    ) -> windows::core::Result<()> {
        if dwfieldid as usize >= CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS.len() {
            return Err(E_INVALIDARG.into());
        }
        unsafe {
            *pcpfs = CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS[dwfieldid as usize].state;
            *pcpfis = CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS[dwfieldid as usize].interactive_state;
        }
        Ok(())
    }

    /// Retrieves the string value of a field.
    fn GetStringValue(&self, dwfieldid: u32) -> windows::core::Result<PWSTR> {
        if dwfieldid as usize >= CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS.len() {
            return Err(E_INVALIDARG.into());
        }
        let values = self.values.read().unwrap();
        let value = values[dwfieldid as usize].as_str();
        debug!(
            "GetStringValue called for field ID: {}; {}",
            dwfieldid, value
        );

        match crate::util::com::alloc_pwstr(value) {
            Ok(pwstr) => Ok(pwstr),
            Err(_) => Err(E_INVALIDARG.into()),
        }
    }

    // Get the bitmap shown on the user tile
    fn GetBitmapValue(&self, dwfieldid: u32) -> windows::core::Result<HBITMAP> {
        if dwfieldid == UdsFieldId::TileImage as u32 {
            unsafe {
                LoadImageW(
                    Some(dll::get_instance()),
                    crate::util::helpers::make_int_resource(101),
                    IMAGE_BITMAP,
                    0,
                    0,
                    LR_CREATEDIBSECTION | LR_DEFAULTCOLOR,
                )
                .map(|hbmp_handle| HBITMAP(hbmp_handle.0))
            }
        } else {
            Err(E_INVALIDARG.into())
        }
    }

    fn GetCheckboxValue(
        &self,
        _dwfieldid: u32,
        _pbchecked: *mut windows::core::BOOL,
        _ppszlabel: *mut PWSTR,
    ) -> windows::core::Result<()> {
        Err(E_NOTIMPL.into())
    }

    // This returns the field id that will have the submit button next to it
    fn GetSubmitButtonValue(&self, dwfieldid: u32) -> windows::core::Result<u32> {
        if dwfieldid == UdsFieldId::SubmitButton as u32 {
            return Ok(UdsFieldId::Password as u32);
        } else {
            Err(E_INVALIDARG.into())
        }
    }

    fn GetComboBoxValueCount(
        &self,
        _dwfieldid: u32,
        _pcitems: *mut u32,
        _pdwselecteditem: *mut u32,
    ) -> windows::core::Result<()> {
        Err(E_NOTIMPL.into())
    }
    fn GetComboBoxValueAt(&self, _dwfieldid: u32, _dwitem: u32) -> windows::core::Result<PWSTR> {
        Err(E_NOTIMPL.into())
    }

    fn SetStringValue(
        &self,
        dwfieldid: u32,
        psz: &windows::core::PCWSTR,
    ) -> windows::core::Result<()> {
        debug_dev!(
            "SetStringValue called for field ID: {}; {:?}",
            dwfieldid,
            psz
        );
        if (dwfieldid as usize) < CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS.len() {
            let descriptor = &CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS[dwfieldid as usize];
            debug_dev!("Field descriptor: {:?}", descriptor);
            if descriptor.is_text_field() {
                let new_value = crate::util::com::pcwstr_to_string(*psz);
                debug_dev!("New value: {}", new_value);
                self.values.write().unwrap()[dwfieldid as usize] = new_value;
                return Ok(());
            } else {
                debug_dev!("Field is not a text field");
            }
        }

        return Err(E_INVALIDARG.into());
    }

    fn SetCheckboxValue(
        &self,
        _dwfieldid: u32,
        _bchecked: windows::core::BOOL,
    ) -> windows::core::Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn SetComboBoxSelectedValue(
        &self,
        _dwfieldid: u32,
        _dwselecteditem: u32,
    ) -> windows::core::Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn CommandLinkClicked(&self, _dwfieldid: u32) -> windows::core::Result<()> {
        Err(E_NOTIMPL.into())
    }

    // Collects the necessary data for serialization for the correct usage scenario
    // Logon passes back this credentials to the system to log on.
    fn GetSerialization(
        &self,
        pcpgsr: *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        pcpcs: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        _ppszoptionalstatustext: *mut PWSTR,
        _pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> windows::core::Result<()> {
        debug_dev!("GetSerialization called");

        // Store LSA strings and ensure they live long enough
        let lsa_username =
            crate::util::com::LsaUnicodeString::new(&self.credential.read().unwrap().username);
        let lsa_password = crate::util::com::LsaUnicodeString::new(&String::from_utf8_lossy(
            &self.credential.read().unwrap().password,
        ));
        let lsa_domain =
            crate::util::com::LsaUnicodeString::new(&self.credential.read().unwrap().domain);

        let interactive_logon = KERB_INTERACTIVE_UNLOCK_LOGON {
            Logon: KERB_INTERACTIVE_LOGON {
                MessageType: if self.cpus == CPUS_UNLOCK_WORKSTATION {
                    KerbWorkstationUnlockLogon
                } else {
                    KerbInteractiveLogon
                },
                LogonDomainName: *lsa_domain.as_lsa(),
                UserName: *lsa_username.as_lsa(),
                Password: *lsa_password.as_lsa(),
            },
            LogonId: Default::default(),
        };
        let (pkiul_out, cb_total) = lsa::kerb_interactive_unlock_logon_pack(&interactive_logon)?;
        debug_dev!(
            "Packed KERB_INTERACTIVE_UNLOCK_LOGON: {:?}: {}",
            pkiul_out,
            cb_total
        );

        unsafe { *pcpcs }.rgbSerialization = pkiul_out;
        unsafe { *pcpcs }.cbSerialization = cb_total;

        unsafe { *pcpcs }.ulAuthenticationPackage = match lsa::retrieve_negotiate_auth_package() {
            Ok(package) => package,
            Err(err) => {
                error!("Failed to retrieve negotiate auth package: {}", err);
                return Err(err);
            }
        };
        unsafe { *pcpcs }.clsidCredentialProvider = CLSID_UDS_CREDENTIAL_PROVIDER;
        unsafe { *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED };

        Ok(())
    }

    fn ReportResult(
        &self,
        ntsstatus: NTSTATUS,
        ntssubstatus: NTSTATUS,
        _ppszoptionalstatustext: *mut PWSTR,
        _pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> windows::core::Result<()> {
        if ntsstatus.is_err() || ntssubstatus.is_err() {
            error!("Login failed: {} {}", ntsstatus.0, ntssubstatus.0);
        } else {
            info!("Login succeeded: {} {}", ntsstatus.0, ntssubstatus.0);
        }
        Ok(())
    }
}
