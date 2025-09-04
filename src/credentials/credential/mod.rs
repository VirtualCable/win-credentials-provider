// Copyright (c) 2026 Virtual Cable S.L.U.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
//    * Redistributions of source code must retain the above copyright notice,
//      this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above copyright notice,
//      this list of conditions and the following disclaimer in the documentation
//      and/or other materials provided with the distribution.
//    * Neither the name of Virtual Cable S.L.U. nor the names of its contributors
//      may be used to endorse or promote products derived from this software
//      without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
/*!
Author: Adolfo Gómez, dkmaster at dkmon dot com
*/
use std::sync::{Arc, RwLock};

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
            WindowsAndMessaging::{IMAGE_BITMAP, LR_CREATEDIBSECTION, LoadImageW},
        },
    },
    core::*,
};
use zeroize::Zeroize;

use crate::{
    broker,
    credentials::{filter::UDSCredentialsFilter, types},
    debug_dev, debug_flow,
    globals::{self, CLSID_UDS_CREDENTIAL_PROVIDER},
    utils::{
        com, helpers,
        log::{debug, error, info},
        lsa,
    },
};

use super::{fields::CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS, types::UdsFieldId};

#[allow(dead_code)]
#[implement(ICredentialProviderCredential)]
#[derive(Clone)]
pub struct UDSCredential {
    cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
    values: Arc<RwLock<Vec<String>>>, // Array containing the values of the fields
    credential: Arc<RwLock<types::Credential>>, // Actual credentials
    cookie: Arc<RwLock<Option<u32>>>,
}

impl UDSCredential {
    pub fn new() -> Self {
        debug_flow!("UDSCredential::new");
        Self {
            cpus: CPUS_LOGON,
            values: Arc::new(RwLock::new(vec![
                String::new();
                UdsFieldId::NumFields as usize
            ])),
            credential: Arc::new(RwLock::new(Default::default())),
            cookie: Arc::new(RwLock::new(None)),
        }
    }
    pub fn reset_credential(&mut self) {
        self.credential.write().unwrap().reset();

        // let mut values = self.values.write().unwrap();
        // for v in values.iter_mut() {
        //     v.clear();
        // }
    }

    pub fn has_valid_credential(&self) -> bool {
        self.credential.read().unwrap().is_valid()
    }

    pub fn set_credential(&mut self, ticket: &str, key: &str) {
        // If no domain, use GetComputerNameW
        // Ensure previous password is cleared with zero values before
        let mut credential = self.credential.write().unwrap();
        credential.set_credential(ticket, key);
    }

    pub fn ticket(&self) -> String {
        self.credential.read().unwrap().ticket().to_string()
    }

    pub fn key(&self) -> String {
        self.credential.read().unwrap().key().to_string()
    }

    pub fn set_values(&self, username: &str, password: &str, domain: &str) {
        self.values.write().unwrap()[UdsFieldId::Username as usize] =
            helpers::username_with_domain(username, domain);
        self.values.write().unwrap()[UdsFieldId::Password as usize] = password.to_string();
    }

    pub fn credential(&self) -> types::Credential {
        self.credential.read().unwrap().clone()
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
        let cookie_opt = *self.cookie.read().unwrap();
        if let Some(cookie) = cookie_opt {
            com::unregister_from_git(cookie)?;
            *self.cookie.write().unwrap() = None;
        }
        Ok(())
    }

    fn clear_password(&self) -> windows::core::Result<()> {
        debug_dev!("Clearing password field");

        let mut values_guard: std::sync::RwLockWriteGuard<'_, Vec<String>> =
            self.values.write().unwrap();
        if !values_guard[UdsFieldId::Password as usize].is_empty() {
            values_guard[UdsFieldId::Password as usize].zeroize(); // Clear the password field
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

        match crate::utils::com::alloc_pwstr(value) {
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
                let new_value = unsafe { (*psz).to_string().unwrap_or_default() };
                debug_dev!("New value: {}", new_value);
                self.values.write().unwrap()[field_id as usize] = new_value.clone();
                debug_assert!(self.values.read().unwrap()[field_id as usize] == new_value);
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
                    crate::utils::helpers::make_int_resource(101),
                    IMAGE_BITMAP,
                    0,
                    0,
                    LR_CREATEDIBSECTION,
                )
                .map(|hbmp_handle| HBITMAP(hbmp_handle.0))
            }
        } else {
            Err(E_INVALIDARG.into())
        }
    }

    fn get_submit_button_value(&self, field_id: u32) -> windows::core::Result<u32> {
        if field_id == UdsFieldId::SubmitButton as u32 {
            Ok(UdsFieldId::Password as u32)
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

        // Our first option is use the credential received into cred
        let cred = self.credential();
        let cred = if !cred.is_valid() {
            debug_dev!(
                "No valid credentials found in our creds. Looking for filter credentials..."
            );
            // Second, is use the credential from the filter, that is OUR credential
            // This credential has been alread filtered, so it's valid and ours.
            // The get_received_credential cleans the filter credential
            if let Some(filter_credential) = UDSCredentialsFilter::get_received_credential() {
                debug_dev!("Using filter credentials: {:?}", filter_credential);
                filter_credential
            } else {
                cred
            }
        } else {
            debug_dev!("Using valid credentials found in our creds: {:?}", cred);
            cred
        };

        // If no valid credentials, fallback to interactive
        let (username, password, domain) = if !cred.is_valid() {
            debug_dev!("No valid credentials, fallback to interactive");
            let values_guard = self.values.read().unwrap();
            let (username, domain) = helpers::split_username_domain(
                &values_guard[UdsFieldId::Username as usize].clone(),
            );
            let password = values_guard[UdsFieldId::Password as usize].clone();
            (username, password, domain)
        } else {
            // Get from broker or fail, because are our credentials and must be valid
            debug_dev!("Getting credentials from broker using ticket and key");
            let response = broker::get_credentials_from_broker(cred.ticket(), cred.key())?;

            (response.0, response.1, response.2)
        };

        let lsa_username = lsa::LsaUnicodeString::new(&username);
        let lsa_password = lsa::LsaUnicodeString::new(&password);
        let lsa_domain = lsa::LsaUnicodeString::new(&domain);

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
            // Clean up the pcpcs
            std::ptr::write_bytes(pcpcs, 0, 1);
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
        debug_flow!("ICredentialProviderCredential::Advise");
        self.register_event_manager(pcpce.unwrap().clone())
    }

    // Release the callback
    fn UnAdvise(&self) -> windows::core::Result<()> {
        debug_flow!("ICredentialProviderCredential::UnAdvise");
        self.unregister_event_manager()
    }

    // Invoked when our tile is selected.
    // We do not heed any special here, Just inform to not autologon
    fn SetSelected(&self) -> windows::core::Result<BOOL> {
        debug_flow!("ICredentialProviderCredential::SetSelected");

        // true --> Focus on our main credential field
        // false --> do not focus
        Ok(false.into())
    }

    // Our tile is deselected, clear the password value
    // To do not keep it in memory
    fn SetDeselected(&self) -> windows::core::Result<()> {
        debug_flow!("ICredentialProviderCredential::SetDeselected");
        // If values[<index>] is the password field, clear it
        self.clear_password()
    }

    /// Retrieves the state of a field.
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // COM need the signature as is. Cannot mark as unsafe
    fn GetFieldState(
        &self,
        dwfieldid: u32,
        pcpfs: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        pcpfis: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    ) -> windows::core::Result<()> {
        debug_flow!("ICredentialProviderCredential::GetFieldState");
        unsafe { self.get_field_state(dwfieldid, pcpfs, pcpfis) }
    }

    /// Retrieves the string value of a field.
    fn GetStringValue(&self, dwfieldid: u32) -> windows::core::Result<PWSTR> {
        debug_flow!("ICredentialProviderCredential::GetStringValue");
        self.get_string_value(dwfieldid)
    }

    // Get the bitmap shown on the user tile
    fn GetBitmapValue(&self, dwfieldid: u32) -> windows::core::Result<HBITMAP> {
        debug_flow!("ICredentialProviderCredential::GetBitmapValue");
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
        debug_flow!("ICredentialProviderCredential::GetSubmitButtonValue");
        if dwfieldid == UdsFieldId::SubmitButton as u32 {
            Ok(UdsFieldId::Password as u32)
        } else {
            self.get_submit_button_value(dwfieldid)
        }
    }

    fn GetComboBoxValueCount(
        &self,
        _dwfieldid: u32,
        _pcitems: *mut u32,
        _pdwselecteditem: *mut u32,
    ) -> windows::core::Result<()> {
        debug_flow!("ICredentialProviderCredential::GetComboBoxValueCount");
        Err(E_NOTIMPL.into())
    }
    fn GetComboBoxValueAt(&self, _dwfieldid: u32, _dwitem: u32) -> windows::core::Result<PWSTR> {
        debug_flow!("ICredentialProviderCredential::GetComboBoxValueAt");
        Err(E_NOTIMPL.into())
    }

    fn SetStringValue(&self, dwfieldid: u32, psz: &PCWSTR) -> windows::core::Result<()> {
        debug_flow!("ICredentialProviderCredential::SetStringValue");
        self.set_string_value(dwfieldid, psz)
    }

    fn SetCheckboxValue(&self, _dwfieldid: u32, _bchecked: BOOL) -> windows::core::Result<()> {
        debug_flow!("ICredentialProviderCredential::SetCheckboxValue");
        Err(E_NOTIMPL.into())
    }

    fn SetComboBoxSelectedValue(
        &self,
        _dwfieldid: u32,
        _dwselecteditem: u32,
    ) -> windows::core::Result<()> {
        debug_flow!("ICredentialProviderCredential::SetComboBoxSelectedValue");
        Err(E_NOTIMPL.into())
    }

    fn CommandLinkClicked(&self, _dwfieldid: u32) -> windows::core::Result<()> {
        debug_flow!("ICredentialProviderCredential::CommandLinkClicked");
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
        debug_flow!("ICredentialProviderCredential::GetSerialization");
        self.serialize(pcpgsr, pcpcs)
    }

    fn ReportResult(
        &self,
        ntsstatus: NTSTATUS,
        ntssubstatus: NTSTATUS,
        _ppszoptionalstatustext: *mut PWSTR,
        _pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> windows::core::Result<()> {
        debug_flow!("ICredentialProviderCredential::ReportResult");
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
