use windows::core::*;
use windows::{core::*, Win32::Foundation::HWND, Win32::Graphics::Gdi::HBITMAP};

use crate::interfaces::types::*;
use crate::interfaces::i_credential_provider_credential::{ICredentialProviderCredential, ICredentialProviderCredential_Impl, ICredentialProviderCredentialEvents};

#[implement(ICredentialProviderCredential)]
pub struct UDSCredential {

}

impl UDSCredential {
    pub fn new() -> Self {
        Self {}
    }
}

#[allow(non_snake_case)]
impl ICredentialProviderCredential_Impl for UDSCredential_Impl {
    unsafe fn Advise(&self, pcpce: *const ICredentialProviderCredentialEvents) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn UnAdvise(&self) -> HRESULT {
        HRESULT(0)
    }

    unsafe fn SetSelected(&self, pbAutoLogon: *mut BOOL) -> HRESULT {
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