// Author: Adolfo Gómez <dkmaster@dkmon.com>

use windows::{
    Win32::UI::Shell::{
        CPFIS_FOCUSED, CPFIS_NONE, CPFS_DISPLAY_IN_BOTH, CPFS_DISPLAY_IN_SELECTED_TILE,
        CPFT_TILE_IMAGE,
    },
    core::*,
};

use super::types::*;

pub static CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS: [CredentialFieldDescriptor;
    UdsFieldId::NumFields as usize] = [
    CredentialFieldDescriptor {
        field_id: UdsFieldId::TileImage as u32,
        field_type: CPFT_TILE_IMAGE,
        label: "UDS Provider",
        guid: GUID::zeroed(),
        state: CPFS_DISPLAY_IN_BOTH,
        interactive_state: CPFIS_NONE,
    },
    CredentialFieldDescriptor {
        field_id: UdsFieldId::Username as u32,
        field_type: windows::Win32::UI::Shell::CPFT_EDIT_TEXT,
        label: "Username",
        guid: GUID::zeroed(),
        state: CPFS_DISPLAY_IN_BOTH,
        interactive_state: CPFIS_NONE,
    },
    CredentialFieldDescriptor {
        field_id: UdsFieldId::Password as u32,
        field_type: windows::Win32::UI::Shell::CPFT_PASSWORD_TEXT,
        label: "Password",
        guid: GUID::zeroed(),
        state: CPFS_DISPLAY_IN_SELECTED_TILE,
        interactive_state: CPFIS_FOCUSED,
    },
    CredentialFieldDescriptor {
        field_id: UdsFieldId::SubmitButton as u32,
        field_type: windows::Win32::UI::Shell::CPFT_SUBMIT_BUTTON,
        label: "Submit",
        guid: GUID::zeroed(),
        state: CPFS_DISPLAY_IN_SELECTED_TILE,
        interactive_state: CPFIS_NONE,
    },
];
