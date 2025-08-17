#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use windows::core::{GUID, PWSTR};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION {
    pub ulAuthenticationPackage: u32, // ULONG
    pub clsidCredentialProvider: GUID,
    pub cbSerialization: u32,      // ULONG
    pub rgbSerialization: *mut u8, // byte*
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CREDENTIAL_PROVIDER_USAGE_SCENARIO {
    CPUS_INVALID = 0,
    CPUS_LOGON = 1,
    CPUS_UNLOCK_WORKSTATION = 2,
    CPUS_CHANGE_PASSWORD = 3,
    CPUS_CREDUI = 4,
    CPUS_PLAP = 5,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CREDENTIAL_PROVIDER_FIELD_TYPE {
    CPFT_INVALID = 0,
    CPFT_LARGE_TEXT = 1,
    CPFT_SMALL_TEXT = 2,
    CPFT_COMMAND_LINK = 3,
    CPFT_EDIT_TEXT = 4,
    CPFT_PASSWORD_TEXT = 5,
    CPFT_TILE_IMAGE = 6,
    CPFT_CHECKBOX = 7,
    CPFT_COMBOBOX = 8,
    CPFT_SUBMIT_BUTTON = 9,
    CPFT_NUM_FIELDS = 10,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR {
    pub dwFieldID: u32,                       // DWORD
    pub cpft: CREDENTIAL_PROVIDER_FIELD_TYPE, // enum
    pub pszLabel: PWSTR,                      // LPWSTR
    pub guidFieldType: GUID,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CREDENTIAL_PROVIDER_FIELD_STATE {
    CPFS_HIDDEN = 0,
    CPFS_DISPLAY_IN_SELECTED_TILE = 1,
    CPFS_DISPLAY_IN_DESELECTED_TILE = 2,
    CPFS_DISPLAY_IN_BOTH = 3,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE {
    CPFIS_NONE = 0,
    CPFIS_READONLY = 1,
    CPFIS_DISABLED = 2,
    CPFIS_FOCUSED = 3,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE {
    CPGSR_NO_CREDENTIAL_NOT_FINISHED = 0,
    CPGSR_NO_CREDENTIAL_FINISHED = 1,
    CPGSR_RETURN_CREDENTIAL_FINISHED = 2,
    CPGSR_RETURN_NO_CREDENTIAL_FINISHED = 3,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CREDENTIAL_PROVIDER_STATUS_ICON {
    CPSI_NONE = 0,
    CPSI_ERROR = 1,
    CPSI_WARNING = 2,
    CPSI_SUCCESS = 3,
}
