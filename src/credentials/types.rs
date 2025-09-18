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
use std::mem;
use windows::Win32::{
    System::Com::{CoTaskMemAlloc, CoTaskMemFree},
    UI::Shell::{
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
        CREDENTIAL_PROVIDER_FIELD_STATE, CREDENTIAL_PROVIDER_FIELD_TYPE, SHStrDupW,
    },
};
use windows::core::{GUID, PWSTR};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone)]
pub struct CredentialFieldDescriptor {
    pub field_id: u32,
    pub field_type: CREDENTIAL_PROVIDER_FIELD_TYPE,
    pub label: &'static str,
    pub guid: GUID,
    pub state: CREDENTIAL_PROVIDER_FIELD_STATE,
    pub interactive_state: CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
}

impl CredentialFieldDescriptor {
    pub fn into_com_alloc(
        &self,
    ) -> windows::core::Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        unsafe {
            let ptr = CoTaskMemAlloc(mem::size_of::<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>())
                as *mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR;

            if ptr.is_null() {
                return Err(windows::core::Error::from_thread());
            }

            (*ptr).dwFieldID = self.field_id;
            (*ptr).cpft = self.field_type;

            let wide_label = match widestring::U16CString::from_str(self.label) {
                Ok(w) => w,
                Err(_) => {
                    // Log, fallback, o abortar según el caso
                    return Err(windows::core::Error::from_thread());
                }
            };
            match SHStrDupW(PWSTR(wide_label.as_ptr() as _)) {
                Ok(s) => (*ptr).pszLabel = s,
                Err(e) => {
                    CoTaskMemFree(Some(ptr as _));
                    return Err(e);
                }
            }

            (*ptr).guidFieldType = self.guid;

            Ok(ptr)
        }
    }

    pub fn is_text_field(&self) -> bool {
        self.field_type == windows::Win32::UI::Shell::CPFT_EDIT_TEXT
            || self.field_type == windows::Win32::UI::Shell::CPFT_PASSWORD_TEXT
    }

    pub fn is_image_field(&self) -> bool {
        self.field_type == windows::Win32::UI::Shell::CPFT_TILE_IMAGE
    }

    pub fn is_submit_button(&self) -> bool {
        self.field_type == windows::Win32::UI::Shell::CPFT_SUBMIT_BUTTON
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UdsFieldId {
    TileImage = 0,
    Username,
    Password,
    SubmitButton,
    NumFields, // Note: if new fields are added, keep NumFields last.  This is used as a count of the number of fields
}

#[derive(Debug, Clone)]
pub struct Credential {
    ticket: String,
    key: String,
}

impl Credential {
    pub fn new() -> Self {
        Self {
            ticket: String::new(),
            key: String::new(),
        }
    }

    pub fn with_credential(ticket: &str, key: &str) -> Self {
        Self {
            ticket: ticket.to_string(),
            key: key.to_string(),
        }
    }

    pub fn set_credential(&mut self, ticket: &str, key: &str) {
        self.ticket = ticket.to_string();
        self.key = key.to_string();
    }

    pub fn ticket(&self) -> &str {
        &self.ticket
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn reset(&mut self) {
        self.ticket.clear();
        self.key.clear();
    }

    pub fn is_valid(&self) -> bool {
        !self.ticket.is_empty() && !self.key.is_empty()
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        // Zeroize the sensitive data
        let mut token = Zeroizing::new(self.ticket.clone());
        let mut key = Zeroizing::new(self.key.clone());
        token.zeroize();
        key.zeroize();
    }
}

impl Default for Credential {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use windows::Win32::UI::Shell::{CPFIS_NONE, CPFS_DISPLAY_IN_SELECTED_TILE, CPFT_EDIT_TEXT};

    use super::*;

    #[test]
    fn test_credential_field_descriptor() {
        let field = CredentialFieldDescriptor {
            field_id: 1,
            field_type: CPFT_EDIT_TEXT,
            label: "Username",
            guid: GUID::from_u128(32),
            state: CPFS_DISPLAY_IN_SELECTED_TILE,
            interactive_state: CPFIS_NONE,
        };

        let com_ptr = field.into_com_alloc();
        assert!(com_ptr.is_ok());
        let com_ptr = com_ptr.unwrap();
        assert!(unsafe { *com_ptr }.dwFieldID == 1);
        assert!(unsafe { *com_ptr }.cpft == CPFT_EDIT_TEXT);
        let string: String = unsafe { (*com_ptr).pszLabel.to_string().unwrap_or_default() };
        assert!(string == "Username");
        assert!(unsafe { *com_ptr }.guidFieldType == GUID::from_u128(32));
    }
}
