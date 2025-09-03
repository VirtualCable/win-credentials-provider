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
