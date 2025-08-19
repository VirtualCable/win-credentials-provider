use windows::{Win32::Graphics::Gdi::HBITMAP, core::*};

use crate::com::i_credential_provider_credential::{
    ICredentialProviderCredential, ICredentialProviderCredential_Impl,
    ICredentialProviderCredentialEvents,
};
use crate::com::types::*;
use crate::com::fields::*;

#[implement(ICredentialProviderCredential)]
pub struct UDSCredential {
    cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,  
    descriptors: [CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR; UdsFieldId::NumFields as usize],  // An array holding  the type and name of each field
    states: [FieldStatePair; UdsFieldId::NumFields as usize],  // State of each field in the tile
    values: Vec<String>,  // Array containing the values of the fields
    cred_prov_events: Option<ICredentialProviderCredentialEvents>,  // Optional events for the credential provider
    username: String,  // Username for the credential
    password: String,  // Password for the credential
    domain: String,  // Domain for the credential
}

impl UDSCredential {
    pub fn new() -> Self {
        Self {
            cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO::CPUS_LOGON,
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

#[allow(dead_code)]
#[allow(non_snake_case)]
impl ICredentialProviderCredential_Impl for UDSCredential_Impl {
    unsafe fn Advise(&self, _pcpce: *const ICredentialProviderCredentialEvents) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn UnAdvise(&self) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn SetSelected(&self, _pbAutoLogon: *mut BOOL) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn SetDeselected(&self) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn GetFieldState(
        &self,
        _dwFieldID: u32,
        _pcpfs: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        _pcpfis: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    ) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn GetStringValue(&self, _dwFieldID: u32, _ppsz: *mut PWSTR) -> HRESULT {
        HRESULT(0)
    }

    // HBITMAP as isize
    unsafe fn GetBitmapValue(&self, _dwFieldID: u32, _phbmp: *mut HBITMAP) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn GetCheckboxValue(
        &self,
        _dwFieldID: u32,
        _pbChecked: *mut BOOL,
        _ppszLabel: *mut PWSTR,
    ) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn GetSubmitButtonValue(&self, _dwFieldID: u32, _pdwAdjacentTo: *mut u32) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn GetComboBoxValueCount(
        &self,
        _dwFieldID: u32,
        _pcItems: *mut u32,
        _pdwSelectedItem: *mut u32,
    ) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn GetComboBoxValueAt(
        &self,
        _dwFieldID: u32,
        _dwItem: u32,
        _ppszItem: *mut PWSTR,
    ) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn SetStringValue(&self, _dwFieldID: u32, _psz: PCWSTR) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn SetCheckboxValue(&self, _dwFieldID: u32, _bChecked: BOOL) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn SetComboBoxSelectedValue(&self, _dwFieldID: u32, _dwSelectedItem: u32) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn CommandLinkClicked(&self, _dwFieldID: u32) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn GetSerialization(
        &self,
        _pcpgsr: *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        _pcpcs: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        _ppszOptionalStatusText: *mut PWSTR,
        _pcpsiOptionalStatusIcon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn ReportResult(
        &self,
        _ntsStatus: i32, // NTSTATUS como i32
        _ntsSubstatus: i32,
        _ppszOptionalStatusText: *mut PWSTR,
        _pcpsiOptionalStatusIcon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> HRESULT {
        HRESULT(0)
    }
}
