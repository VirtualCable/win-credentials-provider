use log::debug;

use windows::{
    core::*, Win32::{
        Foundation::{E_INVALIDARG, NTSTATUS},
        Graphics::Gdi::{LoadBitmapW, HBITMAP},
        UI::Shell::{
            ICredentialProviderCredential, ICredentialProviderCredentialEvents, ICredentialProviderCredential_Impl, CPUS_LOGON, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE, CREDENTIAL_PROVIDER_FIELD_STATE, CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE, CREDENTIAL_PROVIDER_STATUS_ICON, CREDENTIAL_PROVIDER_USAGE_SCENARIO
        },
    }
};

use crate::dll;

use super::{fields::CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS, types::UdsFieldId};

#[allow(dead_code)]
#[implement(ICredentialProviderCredential)]
pub struct UDSCredential {
    cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
    values: Vec<String>, // Array containing the values of the fields
    cred_prov_events: Option<ICredentialProviderCredentialEvents>, // Optional events for the credential provider
    username: String,                                              // Username for the credential
    password: String,                                              // Password for the credential
    domain: String,                                                // Domain for the credential
}

impl UDSCredential {
    pub fn new() -> Self {
        Self {
            cpus: CPUS_LOGON,
            values: Vec::new(),
            cred_prov_events: None,
            username: String::new(),
            password: String::new(),
            domain: String::new(),
        }
    }
}

impl ICredentialProviderCredential_Impl for UDSCredential_Impl {
    fn Advise(
        &self,
        _pcpce: windows_core::Ref<'_, ICredentialProviderCredentialEvents>,
    ) -> windows_core::Result<()> {
        Ok(())
    }
    fn UnAdvise(&self) -> windows_core::Result<()> {
        Ok(())
    }
    fn SetSelected(&self) -> windows_core::Result<windows_core::BOOL> {
        Ok(windows_core::BOOL(1))
    }
    fn SetDeselected(&self) -> windows_core::Result<()> {
        Ok(())
    }

    /// Retrieves the state of a field.
    fn GetFieldState(
        &self,
        dwfieldid: u32,
        pcpfs: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        pcpfis: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    ) -> windows_core::Result<()> {
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
    fn GetStringValue(&self, dwfieldid: u32) -> windows_core::Result<PWSTR> {
        if dwfieldid as usize >= CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS.len() {
            return Err(E_INVALIDARG.into());
        }
        let value = self.values[dwfieldid as usize].as_str();
        debug!("GetStringValue called for field ID: {}; {}", dwfieldid, value);
        match crate::util::comstr::alloc_pwstr(value) {
            Ok(pwstr) => Ok(pwstr),
            Err(_) => Err(E_INVALIDARG.into()),
        }
    }

    // Get the bitmap shown on the user tile
    fn GetBitmapValue(&self, dwfieldid: u32) -> windows_core::Result<HBITMAP> {
        if dwfieldid == UdsFieldId::TileImage as u32 {
            // #define MAKEINTRESOURCEA(i) ((LPSTR)((ULONG_PTR)((WORD)(i))))
            unsafe {
                let hbmp = LoadBitmapW(Some(dll::get_instance()), crate::util::helpers::make_int_resource_a(101));
                Ok(hbmp)
            }
        } else {
            Err(E_INVALIDARG.into())
        }
    }
    fn GetCheckboxValue(
        &self,
        _dwfieldid: u32,
        _pbchecked: *mut windows_core::BOOL,
        _ppszlabel: *mut PWSTR,
    ) -> windows_core::Result<()> {
        Ok(())
    }
    fn GetSubmitButtonValue(&self, _dwfieldid: u32) -> windows_core::Result<u32> {
        Ok(0)
    }
    fn GetComboBoxValueCount(
        &self,
        _dwfieldid: u32,
        _pcitems: *mut u32,
        _pdwselecteditem: *mut u32,
    ) -> windows_core::Result<()> {
        Ok(())
    }
    fn GetComboBoxValueAt(&self, _dwfieldid: u32, _dwitem: u32) -> windows_core::Result<PWSTR> {
        Ok(PWSTR::null())
    }
    fn SetStringValue(
        &self,
        _dwfieldid: u32,
        _psz: &windows_core::PCWSTR,
    ) -> windows_core::Result<()> {
        Ok(())
    }
    fn SetCheckboxValue(
        &self,
        _dwfieldid: u32,
        _bchecked: windows_core::BOOL,
    ) -> windows_core::Result<()> {
        Ok(())
    }
    fn SetComboBoxSelectedValue(
        &self,
        _dwfieldid: u32,
        _dwselecteditem: u32,
    ) -> windows_core::Result<()> {
        Ok(())
    }
    fn CommandLinkClicked(&self, _dwfieldid: u32) -> windows_core::Result<()> {
        Ok(())
    }
    fn GetSerialization(
        &self,
        _pcpgsr: *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        _pcpcs: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        _ppszoptionalstatustext: *mut PWSTR,
        _pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> windows_core::Result<()> {
        Ok(())
    }
    fn ReportResult(
        &self,
        _ntsstatus: NTSTATUS,
        _ntssubstatus: NTSTATUS,
        _ppszoptionalstatustext: *mut PWSTR,
        _pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> windows_core::Result<()> {
        Ok(())
    }
}
