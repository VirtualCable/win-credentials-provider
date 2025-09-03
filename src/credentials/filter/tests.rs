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
use super::*;

use crate::{
    globals,
    test_utils::{self, TEST_BROKER_TICKET, TEST_ENCRYPTION_KEY},
};

#[test]
fn test_uds_credentials_filter_credentials() -> Result<()> {
    // Cleaan
    UDSCredentialsFilter::set_received_credential(None);
    // Retrieve
    let creds = UDSCredentialsFilter::get_received_credential();

    // No credentials received
    assert!(!UDSCredentialsFilter::has_received_credential());

    // Should be none
    assert!(creds.is_none());
    UDSCredentialsFilter::set_received_credential(Some(types::Credential::with_credential(
        "user", "pass",
    )));
    // Credential is available
    assert!(UDSCredentialsFilter::has_received_credential());

    // Retrieve
    let creds = UDSCredentialsFilter::get_received_credential();

    // Should be some
    assert!(creds.is_some());

    // But if retrieved again, should be None
    let creds = UDSCredentialsFilter::get_received_credential();

    // Should be none
    assert!(creds.is_none());

    Ok(())
}

// fn Filter(
//     &self,
//     cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
//     dwflags: u32,
//     rgclsidproviders: *const windows::core::GUID,
//     rgballow: *mut windows::core::BOOL,
//     cproviders: u32,
// ) -> windows::core::Result<()> {

#[test]
#[serial_test::serial(rdp)]
fn test_uds_credential_filter_no_rdp() -> Result<()> {
    crate::utils::log::setup_logging("debug");
    let filter = UDSCredentialsFilter::new();

    let list_of_clids: Vec<GUID> = (0..10)
        .map(GUID::from_u128)
        .chain(std::iter::once(globals::CLSID_UDS_CREDENTIAL_PROVIDER))
        .chain((11..=20).map(GUID::from_u128))
        .collect();

    // Make list even false, odd true for better testing that is not modified
    let mut list_of_allows = (0..list_of_clids.len())
        .map(|i| BOOL(i as i32 % 2))
        .collect::<Vec<BOOL>>();

    for cpus in [
        CPUS_LOGON,
        CPUS_UNLOCK_WORKSTATION,
        CPUS_CREDUI,
        CPUS_CHANGE_PASSWORD,
    ] {
        let res = filter.filter(
            cpus,
            0,
            list_of_clids.as_ptr(),
            list_of_allows.as_mut_ptr(),
            list_of_clids.len() as u32,
        );
        if cpus == CPUS_LOGON || cpus == CPUS_UNLOCK_WORKSTATION {
            assert!(res.is_ok());
        } else {
            assert!(res.is_err());
        }
        for (i, val) in list_of_allows.iter().enumerate() {
            assert_eq!(*val, BOOL(i as i32 % 2));
        }
    }

    Ok(())
}

#[test]
#[serial_test::serial(broker, rdp)]
fn test_uds_credential_filter_rdp() -> Result<()> {
    crate::utils::log::setup_logging("debug");

    let filter = UDSCredentialsFilter::new();

    UDSCredentialsFilter::set_received_credential(Some(types::Credential::with_credential(
        TEST_BROKER_TICKET,
        TEST_ENCRYPTION_KEY,
    )));

    let list_of_clids: Vec<GUID> = (0..10)
        .map(GUID::from_u128)
        .chain(std::iter::once(globals::CLSID_UDS_CREDENTIAL_PROVIDER))
        .chain((11..=20).map(GUID::from_u128))
        .collect();

    for cpus in [
        CPUS_LOGON,
        CPUS_UNLOCK_WORKSTATION,
        CPUS_CREDUI,
        CPUS_CHANGE_PASSWORD,
    ] {
        // Make list even false, odd true for better testing that is not modified
        let mut list_of_allows = (0..list_of_clids.len())
            .map(|i| BOOL(i as i32 % 2))
            .collect::<Vec<BOOL>>();

        let res = filter.filter(
            cpus,
            0,
            list_of_clids.as_ptr(),
            list_of_allows.as_mut_ptr(),
            list_of_clids.len() as u32,
        );
        if cpus == CPUS_LOGON || cpus == CPUS_UNLOCK_WORKSTATION {
            assert!(res.is_ok());
            // Only ours should be TRUE, the rest, must be FALSE
            for (i, val) in list_of_allows.iter().enumerate() {
                if i == 10 {
                    assert_eq!(*val, BOOL::from(true));
                } else {
                    assert_eq!(*val, BOOL::from(false));
                }
            }
        } else {
            assert!(res.is_err());
            for (i, val) in list_of_allows.iter().enumerate() {
                assert_eq!(*val, BOOL(i as i32 % 2));
            }
        }
    }

    Ok(())
}

#[test]
fn test_update_remote_credentials() -> Result<()> {
    crate::utils::log::setup_logging("debug");
    let filter = UDSCredentialsFilter::new();

    let cred_serial_in = test_utils::create_credential_serialization(
        "username",
        "password",
        "domain",
        globals::CLSID_UDS_CREDENTIAL_PROVIDER,
    )?;
    let mut cred_serial_out = test_utils::create_credential_serialization(
        "username",
        "password",
        "domain",
        globals::CLSID_UDS_CREDENTIAL_PROVIDER,
    )?;

    // Cred serial out is not used, as us not our format, will not has_received_credential
    filter.update_remote_credential(&cred_serial_in, &mut cred_serial_out)?;

    assert!(!UDSCredentialsFilter::has_received_credential());

    // With our format, should set it
    let cred_serial_in = test_utils::create_credential_serialization(
        test_utils::TEST_BROKER_CREDENTIAL,
        "",
        "",
        globals::CLSID_UDS_CREDENTIAL_PROVIDER,
    )?;

    // With our format, should set it
    filter.update_remote_credential(&cred_serial_in, &mut cred_serial_out)?;

    assert!(UDSCredentialsFilter::has_received_credential());

    Ok(())
}
