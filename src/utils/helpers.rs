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
use windows::Win32::{
    Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE},
    Security::{
        ACL, ACL_REVISION, AddAccessAllowedAce, GetTokenInformation, InitializeAcl,
        InitializeSecurityDescriptor, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        SECURITY_DESCRIPTOR, SetSecurityDescriptorDacl, TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    System::{
        SystemServices::SECURITY_DESCRIPTOR_REVISION,
        Threading::{GetCurrentProcess, OpenProcessToken},
        WindowsProgramming::GetComputerNameW,
    },
    UI::WindowsAndMessaging::{GetSystemMetrics, SM_REMOTESESSION},
};
use windows::core::*;

// Helper
#[inline]
pub const fn make_int_resource(id: u16) -> PCWSTR {
    PCWSTR(id as usize as *const u16)
}
/// Helper Function to Convert Any Type to a Byte Slice
#[inline]
pub fn as_u8_slice<T>(val: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(val as *const T as *const u8, std::mem::size_of::<T>()) }
}

// Helper to get computer name
pub fn get_computer_name() -> String {
    let mut buffer = [0u16; 64]; // Max computer name should be 15, 30 with widechars + 1 = 31, but give twice as much space
    let mut size = buffer.len() as u32;
    match unsafe { GetComputerNameW(Some(PWSTR(buffer.as_mut_ptr())), &mut size) } {
        Ok(_) => String::from_utf16_lossy(&buffer[..size as usize]),
        Err(_) => ".".into(),
    }
}

// Helper to get current user SID
pub fn current_user_sid() -> Result<PSID> {
    unsafe {
        let mut token: HANDLE = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;

        // Get the size needed for the buffer
        let mut size_needed = 0;
        GetTokenInformation(token, TokenUser, None, 0, &mut size_needed)?;

        // Now allocate and fill the buffer
        let mut buf = vec![0u8; size_needed as usize];
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            size_needed,
            &mut size_needed,
        )?;
        let token_user = &*buf.as_ptr().cast::<TOKEN_USER>();
        Ok(token_user.User.Sid)
    }
}

pub struct SecurityAttributes {
    attrs: SECURITY_ATTRIBUTES,
    _sec_desc_sentry: SECURITY_DESCRIPTOR,
    _acl_buf: Vec<u8>,
}

impl SecurityAttributes {
    pub fn as_ptr(&self) -> *const SECURITY_ATTRIBUTES {
        &self.attrs as *const _
    }
}

// Helper to get security attrs for acces only by a sid
pub fn sec_attrs_for_sid(sid: PSID) -> Result<SecurityAttributes> {
    unsafe {
        let mut sec_desc = SECURITY_DESCRIPTOR::default();
        let p_sec_dec = PSECURITY_DESCRIPTOR(&mut sec_desc as *mut _ as _);
        InitializeSecurityDescriptor(p_sec_dec, SECURITY_DESCRIPTOR_REVISION)?;

        // Create an ACL
        let mut acl_buf = vec![0u8; 1024];
        let acl = acl_buf.as_mut_ptr() as *mut ACL;
        InitializeAcl(acl, acl_buf.len() as u32, ACL_REVISION)?;

        AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_READ.0 | GENERIC_WRITE.0, sid)?;

        SetSecurityDescriptorDacl(p_sec_dec, true, Some(acl), false)?;

        Ok(SecurityAttributes {
            attrs: SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: p_sec_dec.0,
                bInheritHandle: false.into(),
            },
            _sec_desc_sentry: sec_desc,
            _acl_buf: acl_buf,
        })
    }
}

// Compose, given an username and a domain, username\domain, username@domain or, if domain is empty username@get_computer_name
pub fn username_with_domain(username: &str, domain: &str) -> String {
    if domain.is_empty() {
        format!("{}@{}", username, get_computer_name())
    } else if domain.contains('.') {
        format!("{}@{}", username, domain)
    } else {
        format!("{}\\{}", domain, username)
    }
}

// Extract domain from username, domain\\username, username@domain o usename (no domain, will return get_computer_name)
// Returns (username, domain)
pub fn split_username_domain(username: &str) -> (String, String) {
    if username.contains('@') {
        let parts: Vec<&str> = username.split('@').collect();
        if parts.len() == 2 {
            return (parts[0].to_string(), parts[1].to_string());
        }
    } else if username.contains('\\') {
        let parts: Vec<&str> = username.split('\\').collect();
        if parts.len() == 2 {
            return (parts[1].to_string(), parts[0].to_string());
        }
    }
    (username.to_string(), get_computer_name())
}

pub fn is_rdp_session() -> bool {
    unsafe { GetSystemMetrics(SM_REMOTESESSION) != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_computer_name() {
        let name = get_computer_name();
        assert!(!name.is_empty());
        // Should not be "." under normal circumstances
        assert_ne!(name, "");
    }
}
