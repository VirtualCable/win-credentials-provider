// src/interfaces/i_credential_provider_credential.rs

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use windows::{core::*, Win32::Foundation::HWND, Win32::Graphics::Gdi::HBITMAP};
use super::types::*;

#[interface("fa6fa76b-66b7-4b11-95f1-86171118e816")]
pub unsafe trait ICredentialProviderCredentialEvents: IUnknown {
    fn SetFieldState(
        &self,
        pcpc: *const ICredentialProviderCredential,
        dwFieldID: u32,
        cpfs: CREDENTIAL_PROVIDER_FIELD_STATE,
    ) -> HRESULT;

    fn SetFieldInteractiveState(
        &self,
        pcpc: *const ICredentialProviderCredential,
        dwFieldID: u32,
        cpfis: CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    ) -> HRESULT;

    fn SetFieldString(
        &self,
        pcpc: *const ICredentialProviderCredential,
        dwFieldID: u32,
        psz: PCWSTR,
    ) -> HRESULT;

    fn SetFieldCheckbox(
        &self,
        pcpc: *const ICredentialProviderCredential,
        dwFieldID: u32,
        bChecked: BOOL,
        pszLabel: PCWSTR,
    ) -> HRESULT;

    fn SetFieldBitmap(
        &self,
        pcpc: *const ICredentialProviderCredential,
        dwFieldID: u32,
        hbmp: HBITMAP,
    ) -> HRESULT;

    fn SetFieldComboBoxSelectedItem(
        &self,
        pcpc: *const ICredentialProviderCredential,
        dwFieldID: u32,
        dwSelectedItem: u32,
    ) -> HRESULT;

    fn DeleteFieldComboBoxItem(
        &self,
        pcpc: *const ICredentialProviderCredential,
        dwFieldID: u32,
        dwItem: u32,
    ) -> HRESULT;

    fn AppendFieldComboBoxItem(
        &self,
        pcpc: *const ICredentialProviderCredential,
        dwFieldID: u32,
        pszItem: PCWSTR,
    ) -> HRESULT;

    fn SetFieldSubmitButton(
        &self,
        pcpc: *const ICredentialProviderCredential,
        dwFieldID: u32,
        dwAdjacentTo: u32,
    ) -> HRESULT;

    fn OnCreatingWindow(
        &self,
        phwndOwner: *mut HWND,
    ) -> HRESULT;
}

//
// Definición de la interfaz COM ICredentialProviderCredential
//

#[windows::core::interface("63913A93-40C1-481A-818D-4072FF8C70CC")]
pub unsafe trait ICredentialProviderCredential: IUnknown {
    unsafe fn Advise(&self, pcpce: *const ICredentialProviderCredentialEvents) -> HRESULT;

    unsafe fn UnAdvise(&self) -> HRESULT;

    unsafe fn SetSelected(&self, pbAutoLogon: *mut BOOL) -> HRESULT;

    unsafe fn SetDeselected(&self) -> HRESULT;

    unsafe fn GetFieldState(
        &self,
        dwFieldID: u32,
        pcpfs: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        pcpfis: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    ) -> HRESULT;

    unsafe fn GetStringValue(&self, dwFieldID: u32, ppsz: *mut PWSTR) -> HRESULT;

    unsafe fn GetBitmapValue(&self, dwFieldID: u32, phbmp: *mut isize) -> HRESULT; // HBITMAP como isize

    unsafe fn GetCheckboxValue(
        &self,
        dwFieldID: u32,
        pbChecked: *mut BOOL,
        ppszLabel: *mut PWSTR,
    ) -> HRESULT;

    unsafe fn GetSubmitButtonValue(&self, dwFieldID: u32, pdwAdjacentTo: *mut u32) -> HRESULT;

    unsafe fn GetComboBoxValueCount(
        &self,
        dwFieldID: u32,
        pcItems: *mut u32,
        pdwSelectedItem: *mut u32,
    ) -> HRESULT;

    unsafe fn GetComboBoxValueAt(
        &self,
        dwFieldID: u32,
        dwItem: u32,
        ppszItem: *mut PWSTR,
    ) -> HRESULT;

    unsafe fn SetStringValue(&self, dwFieldID: u32, psz: PCWSTR) -> HRESULT;

    unsafe fn SetCheckboxValue(&self, dwFieldID: u32, bChecked: BOOL) -> HRESULT;

    unsafe fn SetComboBoxSelectedValue(&self, dwFieldID: u32, dwSelectedItem: u32) -> HRESULT;

    unsafe fn CommandLinkClicked(&self, dwFieldID: u32) -> HRESULT;

    unsafe fn GetSerialization(
        &self,
        pcpgsr: *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        pcpcs: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        ppszOptionalStatusText: *mut PWSTR,
        pcpsiOptionalStatusIcon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> HRESULT;

    unsafe fn ReportResult(
        &self,
        ntsStatus: i32, // NTSTATUS como i32
        ntsSubstatus: i32,
        ppszOptionalStatusText: *mut PWSTR,
        pcpsiOptionalStatusIcon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> HRESULT;
}
