use windows::{
    Win32::Foundation::NTSTATUS,
    Win32::Graphics::Gdi::HBITMAP,
    Win32::UI::Shell::{
        CPUS_LOGON, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
        CREDENTIAL_PROVIDER_FIELD_STATE, CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        CREDENTIAL_PROVIDER_STATUS_ICON, CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        ICredentialProviderCredential, ICredentialProviderCredential_Impl,
        ICredentialProviderCredentialEvents,
    },
    core::*,
};

use crate::fields;

#[allow(dead_code)]
#[implement(ICredentialProviderCredential)]
pub struct UDSCredential {
    cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
    descriptors: [CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR; fields::UdsFieldId::NumFields as usize], // An array holding  the type and name of each field
    states: [fields::FieldStatePair; fields::UdsFieldId::NumFields as usize], // State of each field in the tile
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
            descriptors: Default::default(),
            states: Default::default(),
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
    fn GetFieldState(
        &self,
        _dwfieldid: u32,
        _pcpfs: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        _pcpfis: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    ) -> windows_core::Result<()> {
        Ok(())
    }
    fn GetStringValue(&self, _dwfieldid: u32) -> windows_core::Result<PWSTR> {
        Ok(PWSTR::null())
    }
    fn GetBitmapValue(&self, _dwfieldid: u32) -> windows_core::Result<HBITMAP> {
        Ok(HBITMAP::default())
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
