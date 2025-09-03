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
#![cfg(windows)]

use win_cred_provider::{
    credentials::types,
    globals,
    utils::{com, helpers::username_with_domain, log, log::info, lsa},
};
use windows::{
    Win32::UI::Shell::{
        CPSI_NONE, CPUS_LOGON, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE, CREDENTIAL_PROVIDER_NO_DEFAULT,
        CREDENTIAL_PROVIDER_STATUS_ICON, ICredentialProviderCredentialEvents,
        ICredentialProviderEvents,
    },
    core::*,
};

mod utils;

use utils::test_utils;

#[test]
#[serial_test::serial(remote_logon, rdp)]
fn test_remote_logon_ok_cred() -> Result<()> {
    do_test_remote_logon(true)
}

#[test]
#[serial_test::serial(remote_logon, rdp)]
fn test_remote_logon_invalid_cred() -> Result<()> {
    do_test_remote_logon(false)
}

fn do_test_remote_logon(valid_cred: bool) -> Result<()> {
    // Set the UDSCP_FORCE_RDP to force system recognizes as RDP
    unsafe { std::env::set_var("UDSCP_FORCE_RDP", "1") };
    unsafe { std::env::set_var("UDSCP_FAKE_CREDENTIALS", "username:password:domain") };
    unsafe { std::env::set_var("UDSCP_ENABLE_FLOW_LOG", "1") };

    let (username, password, domain) = if valid_cred {
        (test_utils::TEST_BROKER_CREDENTIAL, "", "")
    } else {
        ("username", "password", "domain")  // Must match UDSCP_FAKE_CREDENTIALS for invalid_cred test to work
    };
    log::setup_logging("debug");

    let factory = utils::com::ClassFactoryTest::new()?;
    // The drop on end, will force the Channel stop
    let provider = factory.create_provider()?;
    let filter = factory.create_filter()?;

    // First invoked is filter of Filter
    let list_of_clids: Vec<GUID> = (0..10)
        .map(GUID::from_u128)
        .chain(std::iter::once(globals::CLSID_UDS_CREDENTIAL_PROVIDER))
        .chain((11..=20).map(GUID::from_u128))
        .collect();

    // Make list even false, odd true for better testing that is not modified
    let mut list_of_allows = (0..list_of_clids.len())
        .map(|i| BOOL(i as i32 % 2))
        .collect::<Vec<BOOL>>();

    unsafe {
        filter.Filter(
            CPUS_LOGON,
            0,
            list_of_clids.as_ptr(),
            list_of_allows.as_mut_ptr(),
            list_of_clids.len() as u32,
        )
    }?;

    // Now UpdateRemoteCredential with the RDP Logon Info on filter
    let cred_serial_in = crate::utils::test_utils::create_credential_serialization(
        username,
        password,
        domain,
        globals::CLSID_UDS_CREDENTIAL_PROVIDER,
    )?;
    let mut cred_serial_out = crate::utils::test_utils::create_credential_serialization(
        "",
        "",
        "",
        globals::CLSID_UDS_CREDENTIAL_PROVIDER,
    )?;

    // Cred serial out is not used right now, should set the RECV_CRED global on filter
    unsafe { filter.UpdateRemoteCredential(&cred_serial_in, &mut cred_serial_out)? };
    assert_eq!(
        win_cred_provider::credentials::filter::UDSCredentialsFilter::has_received_credential(),
        valid_cred
    );

    unsafe { provider.SetUsageScenario(CPUS_LOGON, 0)? };

    let test_cred_serial = crate::utils::test_utils::create_credential_serialization(
        username,
        password,
        domain,
        globals::CLSID_UDS_CREDENTIAL_PROVIDER,
    )?;

    let res = unsafe { provider.SetSerialization(&test_cred_serial) };
    // Credential provider should not process the credentials at all
    assert!(res.is_ok());

    let credential_provider_events: utils::com::TestingCredentialProviderEvents =
        utils::com::TestingCredentialProviderEvents::default();
    let icredential_provider_events: ICredentialProviderEvents =
        credential_provider_events.clone().into();

    unsafe { provider.Advise(&icredential_provider_events, 0x120909)? };

    let field_descriptor_count = unsafe { provider.GetFieldDescriptorCount()? };

    info!("Field descriptor count: {}", field_descriptor_count);

    let mut fields = Vec::new();
    for fld in 0..field_descriptor_count {
        // Returned value is a comm allocated memory
        let field_descriptor = unsafe { provider.GetFieldDescriptorAt(fld)? };
        info!("Field descriptor {}: {:?}", fld, field_descriptor);
        fields.push(field_descriptor);
    }
    let mut cred_count: u32 = 0;
    let mut cred_default: u32 = 0;
    let mut autologon: BOOL = false.into();
    unsafe {
        provider.GetCredentialCount(&mut cred_count, &mut cred_default, &mut autologon)?;
    }

    info!(
        "Credential count: {}, default: {}, autologon: {}",
        cred_count,
        cred_default,
        autologon.as_bool()
    );

    // Autologon should be TRUE with valid cdeds
    assert_eq!(autologon.as_bool(), valid_cred);

    // As this is a rdp redirected scenario, we expect 1 credential, no default and autologon to be true
    assert_eq!(cred_count, 1);
    assert_eq!(
        cred_default,
        if valid_cred {
            0
        } else {
            CREDENTIAL_PROVIDER_NO_DEFAULT
        }
    );
    assert_eq!(
        autologon,
        if valid_cred {
            BOOL::from(true)
        } else {
            BOOL::from(false)
        }
    );

    // Get the Credential interface
    let credential = unsafe { provider.GetCredentialAt(0)? };
    info!("Credential: {:?}", credential);

    // Advise
    let credential_provider_credential_events =
        utils::com::TestingCredentialProviderCredentialEvents::new();
    let icredential_provider_credential_events: ICredentialProviderCredentialEvents =
        credential_provider_credential_events.clone().into();
    unsafe { credential.Advise(&icredential_provider_credential_events)? };

    // If invalid credentials, simulate the input of fields
    if !valid_cred {
        let pwstr_username = com::alloc_pcwstr(&username_with_domain(username, domain)).unwrap();
        let pwstr_password = com::alloc_pcwstr(password).unwrap();
        unsafe {
            credential.SetStringValue(types::UdsFieldId::Username as u32, pwstr_username)?;
            credential.SetStringValue(types::UdsFieldId::Password as u32, pwstr_password)?;
        }
        com::free_pcwstr(pwstr_username);
        com::free_pcwstr(pwstr_password);
    }

    // GetSerialization needs a bit more setup
    let mut pcpgsr = CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE(-1);
    let mut pcpcs = CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION {
        ulAuthenticationPackage: 0,
        clsidCredentialProvider: windows_core::GUID::zeroed(),
        cbSerialization: 0,
        rgbSerialization: std::ptr::null_mut(),
    };
    let mut null_pwstr: PWSTR = PWSTR::null();
    let mut cred_prov_icon: CREDENTIAL_PROVIDER_STATUS_ICON = CPSI_NONE;

    let res = unsafe {
        credential.GetSerialization(
            &mut pcpgsr,
            &mut pcpcs as *mut _,
            &mut null_pwstr,
            &mut cred_prov_icon,
        )
    };
    assert!(res.is_ok());
    assert!(!pcpcs.rgbSerialization.is_null());
    assert!(pcpcs.cbSerialization > 0);

    unsafe { credential.UnAdvise()? };

    let res = unsafe { provider.SetSerialization(&pcpcs) };
    // SetSerialization does nothing in fact
    assert!(res.is_ok());

    // End of credential part,UnAdvise provider
    unsafe { provider.UnAdvise()? };

    // The values should be present on rgbSerialization, same as we set them
    let unserial =
        unsafe { lsa::kerb_interactive_unlock_logon_unpack_in_place(pcpcs.rgbSerialization) };
    assert_eq!(
        lsa::lsa_unicode_string_to_string(&unserial.Logon.UserName),
        "username"
    );
    assert_eq!(
        lsa::lsa_unicode_string_to_string(&unserial.Logon.Password),
        "password"
    );
    assert_eq!(
        lsa::lsa_unicode_string_to_string(&unserial.Logon.LogonDomainName),
        "domain"
    );

    // Free the rgbSerialization, not needed anymore
    com::alloc_free(pcpcs.rgbSerialization);

    // Free fields also
    for field in fields {
        com::alloc_free(field);
    }

    unsafe { std::env::remove_var("UDSCP_FORCE_RDP") };
    unsafe { std::env::remove_var("UDSCP_FAKE_CREDENTIALS") };

    Ok(())
}
