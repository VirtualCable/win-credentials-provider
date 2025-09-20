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
use std::sync::RwLock;

use windows::{
    Win32::{
        Foundation::{E_INVALIDARG, E_NOTIMPL},
        UI::Shell::{
            CPUS_CHANGE_PASSWORD, CPUS_CREDUI, CPUS_LOGON, CPUS_UNLOCK_WORKSTATION,
            CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_USAGE_SCENARIO,
            ICredentialProviderFilter, ICredentialProviderFilter_Impl,
        },
    },
    core::*,
};

use crate::{broker, credentials::types, debug_dev, debug_flow, utils::lsa};

static RECV_CRED: RwLock<Option<types::Credential>> = RwLock::new(None);

#[implement(ICredentialProviderFilter)]
pub struct UDSCredentialsFilter {}

impl UDSCredentialsFilter {
    pub fn new() -> Self {
        debug_flow!("UDSCredentialsFilter::new");
        Self {}
    }

    /// Gets and consumes the received credential
    pub fn get_received_credential() -> Option<types::Credential> {
        let mut recv_guard = RECV_CRED.write().unwrap();
        let cred = recv_guard.take();
        cred.clone()
    }

    // Check if we have received a credential, but do not consume it
    pub fn has_received_credential() -> bool {
        let recv_guard = RECV_CRED.read().unwrap();
        recv_guard.is_some()
    }

    pub fn set_received_credential(cred: Option<types::Credential>) {
        debug_dev!("Setting received credential: {:?}", cred);
        let mut recv_guard: std::sync::RwLockWriteGuard<'_, Option<types::Credential>> =
            RECV_CRED.write().unwrap();
        *recv_guard = cred;
    }

    fn filter(
        &self,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        dwflags: u32,
        rgclsidproviders: *const windows::core::GUID,
        rgballow: *mut windows::core::BOOL,
        cproviders: u32,
    ) -> windows::core::Result<()> {
        // If we come from a remote session, and we have a valid UDS credential, and we can contact with UDS Broker
        let is_our_credential =
            UDSCredentialsFilter::has_received_credential() && broker::get_broker_info().is_valid();

        debug_dev!(
            "Filter called. must_be_our_cred: {} && {} = {}  dwflags: {}  cpus: {:?}",
            UDSCredentialsFilter::has_received_credential(),
            broker::get_broker_info().is_valid(),
            is_our_credential,
            dwflags,
            cpus
        );

        match cpus {
            CPUS_LOGON | CPUS_UNLOCK_WORKSTATION => {
                if !is_our_credential {
                    debug_dev!("Not an RDP session, leaving the providers list as is");
                    // do not filter anything, just return
                    return Ok(());
                }
                // In logon or unlock workstation, we only allow our provider if it's not an RDP session
                for i in 0..cproviders as isize {
                    unsafe {
                        let clsid = *rgclsidproviders.offset(i);
                        let allow = clsid == crate::globals::CLSID_UDS_CREDENTIAL_PROVIDER;
                        *rgballow.offset(i) = allow.into();
                        debug_dev!("Filter: provider: {:?}, allow: {}", clsid, allow);
                    }
                }
            }
            CPUS_CREDUI | CPUS_CHANGE_PASSWORD => {
                return Err(E_NOTIMPL.into());
            }
            _ => {
                return Err(E_INVALIDARG.into());
            }
        }

        Ok(())
    }

    fn update_remote_credential(
        &self,
        pcpcsin: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        _pcpcsout: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> windows::core::Result<()> {
        debug_dev!("UpdateRemoteCredential called. {:?}", unsafe { &*pcpcsin });

        unsafe {
            let mut rgb_serialization = vec![0; (*pcpcsin).cbSerialization as usize];
            // Copy the serialization data
            rgb_serialization.copy_from_slice(std::slice::from_raw_parts(
                (*pcpcsin).rgbSerialization,
                (*pcpcsin).cbSerialization as usize,
            ));
            // Convert to KERB_INTERACTIVE_UNLOCK_LOGON using lsa utils. Note that is "in_place"
            // so logon points to the same memory as the packed structure
            let logon =
                lsa::kerb_interactive_unlock_logon_unpack_in_place(rgb_serialization.as_ptr() as _);

            // Username should be our token, password our shared_secret with our server
            // and domain is simply ignored :)
            let username = lsa::lsa_unicode_string_to_string(&logon.Logon.UserName);
            // Note that credential can be unprotected or protected, so we use our utils to unprotect if needed
            // let password = lsa::unprotect_credential(logon.Logon.Password)?;
            let domain = lsa::lsa_unicode_string_to_string(&logon.Logon.LogonDomainName);

            debug_dev!(
                "UpdateRemoteCredential: username: {}, domain: {}",
                username,
                domain
            );
            if let Some((ticket, key)) = crate::broker::transform_broker_credential(&username) {
                UDSCredentialsFilter::set_received_credential(Some(
                    types::Credential::with_credential(&ticket, &key),
                ));
            } else {
                return Err(E_INVALIDARG.into());  // Not recognized credential
            }
        }

        Ok(())
    }
}

impl Default for UDSCredentialsFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(non_snake_case)]
impl ICredentialProviderFilter_Impl for UDSCredentialsFilter_Impl {
    fn Filter(
        &self,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        dwflags: u32,
        rgclsidproviders: *const windows::core::GUID,
        rgballow: *mut windows::core::BOOL,
        cproviders: u32,
    ) -> windows::core::Result<()> {
        debug_flow!("ICredentialProviderFilter::Filter");

        self.filter(cpus, dwflags, rgclsidproviders, rgballow, cproviders)
    }

    /// Only invoked when the user is logging in and NLA is enabled
    fn UpdateRemoteCredential(
        &self,
        pcpcsin: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        pcpcsout: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> windows::core::Result<()> {
        // After some tests, the data obtanined from this will be provided to the selected Credential Provider
        // We can simply return transformer credential here, an treat them on our Provider SetSerialzation
        // But the result will be the same.
        debug_flow!("ICredentialProviderFilter::UpdateRemoteCredential");

        self.update_remote_credential(pcpcsin, pcpcsout)
    }
}

#[cfg(test)]
mod tests;
