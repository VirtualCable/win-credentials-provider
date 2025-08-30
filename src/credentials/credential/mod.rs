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

use crate::{
    debug_dev, globals,
    globals::CLSID_UDS_CREDENTIAL_PROVIDER,
    util::{com, lsa},
};

use super::{fields::CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS, types::UdsFieldId};

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
    pub fn reset_credentials(&mut self) {
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

    /// Returns true if the credential is ready to be used
    pub fn is_ready(&self) -> bool {
        let credential = self.credential.read().unwrap();
        // Domain is optional
        !credential.username.is_empty() && !credential.password.is_empty()
    }

    pub fn username(&self) -> String {
        let credential = self.credential.read().unwrap();
        credential.username.clone()
    }

    pub fn password(&self) -> Zeroizing<Vec<u8>> {
        let credential = self.credential.read().unwrap();
        Zeroizing::new(credential.password.to_vec())
    }

    pub fn domain(&self) -> String {
        let credential = self.credential.read().unwrap();
        credential.domain.clone()
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

    // Private methods
    fn register_event_manager(
        &self,
        manager: ICredentialProviderCredentialEvents,
    ) -> windows::core::Result<()> {
        debug_dev!("Registering credential provider events");
        let cookie = com::register_in_git(manager).unwrap();
        *self.cookie.write().unwrap() = Some(cookie);
        Ok(())
    }

    fn unregister_event_manager(&self) -> windows::core::Result<()> {
        debug_dev!("Unregistering credential provider events");
        if let Some(cookie) = *self.cookie.write().unwrap() {
            com::unregister_from_git(cookie)?;
            *self.cookie.write().unwrap() = None;
        }
        Ok(())
    }

    fn update_value_from_username(&self) {
        debug_dev!("Updating value from username");

        let username: Option<String> = {
            let credential = self.credential.read().unwrap();
            if credential.username.is_empty() {
                None
            } else {
                // If we have domain and has a point, set username to username@domain
                // else, if we have domain, set domain\username
                Some(if !credential.domain.is_empty() {
                    if credential.domain.contains('.') {
                        format!("{}@{}", credential.username, credential.domain)
                    } else {
                        format!("{}\\{}", credential.domain, credential.username)
                    }
                } else {
                    credential.username.clone()
                })
            }
        };
        if let Some(username) = username {
            self.values.write().unwrap()[UdsFieldId::Username as usize] = username;
        }
    }

    fn clear_password_value(&self) -> windows::core::Result<()> {
        debug_dev!("Clearing password field");

        let mut values: std::sync::RwLockWriteGuard<'_, Vec<String>> = self.values.write().unwrap();
        if !values[UdsFieldId::Password as usize].is_empty() {
            values[UdsFieldId::Password as usize].zeroize(); // Clear the password field
        }
        let cred_prov_events = self.get_icredential_provider_credential_event();
        if let Some(events) = cred_prov_events {
            debug_dev!("Notifying LogonUI to clear the password field");
            let icred: ICredentialProviderCredential = (*self).clone().into();
            unsafe {
                events.SetFieldString(
                    &icred,
                    UdsFieldId::Password as u32,
                    PCWSTR::null(), // Empty string
                )
            }?;
        }
        Ok(())
    }

    unsafe fn get_field_state(
        &self,
        field_id: u32,
        pcpfs: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        pcpfis: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    ) -> windows::core::Result<()> {
        if field_id as usize >= CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS.len() {
            return Err(E_INVALIDARG.into());
        }
        let field = &CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS[field_id as usize];
        unsafe {
            *pcpfs = field.state;
            *pcpfis = field.interactive_state;
        }
        Ok(())
    }

    fn get_string_value(&self, field_id: u32) -> windows::core::Result<PWSTR> {
        if field_id as usize >= CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS.len() {
            return Err(E_INVALIDARG.into());
        }
        let values = self.values.read().unwrap();
        let value = values[field_id as usize].as_str();
        debug!(
            "GetStringValue called for field ID: {}; {}",
            field_id, value
        );

        match crate::util::com::alloc_pwstr(value) {
            Ok(pwstr) => Ok(pwstr),
            Err(_) => Err(E_INVALIDARG.into()),
        }
    }

    fn set_string_value(&self, field_id: u32, psz: &PCWSTR) -> windows::core::Result<()> {
        debug_dev!(
            "set_string_value called for field ID: {}; {:?}",
            field_id,
            psz
        );
        if (field_id as usize) < CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS.len() {
            let descriptor = &CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS[field_id as usize];
            debug_dev!("Field descriptor: {:?}", descriptor);
            if descriptor.is_text_field() {
                let new_value = crate::util::com::pcwstr_to_string(*psz);
                debug_dev!("New value: {}", new_value);
                self.values.write().unwrap()[field_id as usize] = new_value;
                return Ok(());
            } else {
                debug_dev!("Field is not a text field");
            }
        }

        Err(E_INVALIDARG.into())
    }

    fn get_bitmap_value(&self, field_id: u32) -> windows::core::Result<HBITMAP> {
        if field_id == UdsFieldId::TileImage as u32 {
            unsafe {
                LoadImageW(
                    Some(globals::get_instance()),
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

    fn serialize(
        &self,
        pcpgsr: *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        pcpcs: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> windows::core::Result<()> {
        debug_dev!(
            "Serialization called: location of pcpcs: {:?}",
            pcpcs as *const _
        );

        // Store LSA strings and ensure they live long enough
        let lsa_username = lsa::LsaUnicodeString::new(&self.credential.read().unwrap().username);
        let lsa_password = lsa::LsaUnicodeString::new(&String::from_utf8_lossy(
            &self.credential.read().unwrap().password,
        ));
        let lsa_domain = lsa::LsaUnicodeString::new(&self.credential.read().unwrap().domain);

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
        let (pkiul_out, cb_total) =
            unsafe { lsa::kerb_interactive_unlock_logon_pack(&interactive_logon)? };
        debug_dev!(
            "Packed KERB_INTERACTIVE_UNLOCK_LOGON: {:?}: {}",
            pkiul_out,
            cb_total
        );

        unsafe {
            (*pcpcs).rgbSerialization = pkiul_out;
            (*pcpcs).cbSerialization = cb_total;
            (*pcpcs).ulAuthenticationPackage = match lsa::retrieve_negotiate_auth_package() {
                Ok(package) => package,
                Err(err) => {
                    error!("Failed to retrieve negotiate auth package: {}", err);
                    return Err(err);
                }
            };
            (*pcpcs).clsidCredentialProvider = CLSID_UDS_CREDENTIAL_PROVIDER;
            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED
        };

        Ok(())
    }
}

impl Default for UDSCredential {
    fn default() -> Self {
        Self::new()
    }
}

impl ICredentialProviderCredential_Impl for UDSCredential_Impl {
    // By this method, LogonUI gives us a callback so we can notify it of changes
    // If we need to update the UI, we can call the appropriate methods on the events object
    fn Advise(
        &self,
        pcpce: windows::core::Ref<'_, ICredentialProviderCredentialEvents>,
    ) -> windows::core::Result<()> {
        self.register_event_manager(pcpce.unwrap().clone())
    }

    // Release the callback
    fn UnAdvise(&self) -> windows::core::Result<()> {
        self.unregister_event_manager()
    }

    // Invoked when our tile is selected.
    // We do not heed any special here, Just inform to not autologon
    fn SetSelected(&self) -> windows::core::Result<BOOL> {
        // If we have an username, copy it to values
        self.update_value_from_username();

        // true --> Focus on our main credential field
        // false --> do not focus
        Ok(false.into())
    }

    // Our tile is deselected, clear the password value
    // To do not keep it in memory
    fn SetDeselected(&self) -> windows::core::Result<()> {
        // If values[<index>] is the password field, clear it
        self.clear_password_value()
    }

    /// Retrieves the state of a field.
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // COM need the signature as is. Cannot mark as unsafe
    fn GetFieldState(
        &self,
        dwfieldid: u32,
        pcpfs: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        pcpfis: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    ) -> windows::core::Result<()> {
        unsafe { self.get_field_state(dwfieldid, pcpfs, pcpfis) }
    }

    /// Retrieves the string value of a field.
    fn GetStringValue(&self, dwfieldid: u32) -> windows::core::Result<PWSTR> {
        self.get_string_value(dwfieldid)
    }

    // Get the bitmap shown on the user tile
    fn GetBitmapValue(&self, dwfieldid: u32) -> windows::core::Result<HBITMAP> {
        self.get_bitmap_value(dwfieldid)
    }

    fn GetCheckboxValue(
        &self,
        _dwfieldid: u32,
        _pbchecked: *mut BOOL,
        _ppszlabel: *mut PWSTR,
    ) -> windows::core::Result<()> {
        Err(E_NOTIMPL.into())
    }

    // This returns the field id that will have the submit button next to it
    fn GetSubmitButtonValue(&self, dwfieldid: u32) -> windows::core::Result<u32> {
        if dwfieldid == UdsFieldId::SubmitButton as u32 {
            Ok(UdsFieldId::Password as u32)
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

    fn SetStringValue(&self, dwfieldid: u32, psz: &PCWSTR) -> windows::core::Result<()> {
        self.set_string_value(dwfieldid, psz)
    }

    fn SetCheckboxValue(&self, _dwfieldid: u32, _bchecked: BOOL) -> windows::core::Result<()> {
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
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // COM need the signature as is. Cannot mark as unsafe
    fn GetSerialization(
        &self,
        pcpgsr: *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        pcpcs: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        _ppszoptionalstatustext: *mut PWSTR,
        _pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> windows::core::Result<()> {
        self.serialize(pcpgsr, pcpcs)
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

#[cfg(test)]
mod tests;
