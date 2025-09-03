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

use crate::{test_utils, utils::log::setup_logging};

#[test]
fn test_uds_credential_new() {
    setup_logging("debug");
    let credential = UDSCredential::new();
    let cred = credential.credential.read().unwrap();
    assert!(cred.ticket().is_empty());
    assert!(cred.key().is_empty());
}

#[test]
fn test_uds_credential_into_impl() {
    setup_logging("debug");
    let credential = UDSCredential::new();
    let _cred_impl: ICredentialProviderCredential = credential.into();
    // If we reach here, is all fine :)
}

// Bitmap test is on integrations tests, because needs the dll to read the resource

#[test]
fn test_password_clean() {
    setup_logging("debug");
    let credential = UDSCredential::new();
    credential.values.write().unwrap()[UdsFieldId::Password as usize] = "test".to_string();
    credential.clear_password().unwrap();
    let values = credential.values.read().unwrap();

    assert_eq!(values[UdsFieldId::Password as usize], "");
}

#[test]
fn test_get_field_state() {
    setup_logging("debug");
    let credential = UDSCredential::new();
    for field in CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS.iter() {
        let mut pcpfs = CREDENTIAL_PROVIDER_FIELD_STATE(-1);
        let mut pcpfis = CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE(-1);
        unsafe { credential.get_field_state(field.field_id, &mut pcpfs, &mut pcpfis) }.unwrap();
        assert!(field.state == pcpfs);
        assert!(field.interactive_state == pcpfis);
    }
}

#[test]
fn test_get_string_value() {
    setup_logging("debug");
    let credential = UDSCredential::new();
    for field_id in 0..UdsFieldId::NumFields as u32 {
        credential.values.write().unwrap()[field_id as usize] = format!("value{}", field_id);
        let val: PWSTR = credential.get_string_value(field_id).unwrap();
        let value = unsafe { val.to_string().unwrap_or_default() };
        assert_eq!(credential.values.read().unwrap()[field_id as usize], value);
    }
}

#[test]
fn test_set_string_value() {
    setup_logging("debug");
    let credential = UDSCredential::new();
    for field_id in 0..UdsFieldId::NumFields as u32 {
        let value = format!("value{}", field_id);
        let pcwstr: PCWSTR = crate::utils::com::alloc_pcwstr(&value).unwrap();
        let descriptor = &CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS[field_id as usize];
        let res = credential.set_string_value(field_id, &pcwstr);
        if descriptor.is_text_field() {
            assert!(res.is_ok());
            assert_eq!(credential.values.read().unwrap()[field_id as usize], value);
        } else {
            assert!(res.is_err());
        }
        crate::utils::com::free_pcwstr(pcwstr);
    }
}

enum SerializeTestMode {
    Broker,
    Values,
    Filter,
}

#[test]
#[serial_test::serial(broker, rdp)]
fn test_serialization_logon_with_values() {
    do_test_serialization_logon("username", "password", "domain", SerializeTestMode::Values)
        .unwrap();
}

#[test]
#[serial_test::serial(broker, rdp)]
fn test_serialization_logon_with_broker() {
    do_test_serialization_logon(
        test_utils::TEST_BROKER_CREDENTIAL,
        test_utils::TEST_ENCRYPTION_KEY,
        "not_used",
        SerializeTestMode::Broker,
    )
    .unwrap();
}

#[test]
#[serial_test::serial(broker, rdp)]
fn test_serialization_logon_with_filter() {
    do_test_serialization_logon(
        test_utils::TEST_BROKER_CREDENTIAL,
        test_utils::TEST_ENCRYPTION_KEY,
        "not_used",
        SerializeTestMode::Filter,
    )
    .unwrap();
}

#[allow(dead_code)]
fn do_test_serialization_logon(
    ticket_or_username: &str,
    key_or_password: &str,
    domain: &str,
    mode: SerializeTestMode,
) -> Result<()> {
    setup_logging("debug");

    // On new, all fields are empty
    let credential = UDSCredential::new();

    // Create a fake broker, so the call to get credentials from broker does not fail
    // when testing the serialization
    let (_url, _server, mock) = crate::test_utils::create_fake_broker();

    match mode {
        SerializeTestMode::Broker => {
            credential
                .credential
                .write()
                .unwrap()
                .set_credential(ticket_or_username, key_or_password);
        }
        SerializeTestMode::Values => {
            let mut values_guard = credential.values.write().unwrap();
            values_guard[UdsFieldId::Username as usize] =
                helpers::username_with_domain(ticket_or_username, domain);
            values_guard[UdsFieldId::Password as usize] = key_or_password.to_string();
        }
        SerializeTestMode::Filter => {
            let cred = types::Credential::with_credential(ticket_or_username, key_or_password);
            UDSCredentialsFilter::set_received_credential(Some(cred));
        }
    }
    let mut pcpgsr = CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE(-1);
    let mut pcpcs = CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION {
        ulAuthenticationPackage: 0,
        clsidCredentialProvider: windows_core::GUID::zeroed(),
        cbSerialization: 0,
        rgbSerialization: std::ptr::null_mut(),
    };
    debug_dev!("memory loc of pcpcs: {:?}", &pcpcs as *const _);
    let res = credential.serialize(&mut pcpgsr, &mut pcpcs as *mut _);
    assert!(res.is_ok());
    assert!(!pcpcs.rgbSerialization.is_null());
    assert!(pcpcs.cbSerialization > 0);

    let base = pcpcs.rgbSerialization;

    // Deseralize data again and see that all is fine
    let unserial =
        unsafe { crate::utils::lsa::kerb_interactive_unlock_logon_unpack_in_place(base) };

    let _recv_username = lsa::lsa_unicode_string_to_string(&unserial.Logon.UserName);
    let _recv_password = lsa::lsa_unicode_string_to_string(&unserial.Logon.Password);
    let _recv_domain = lsa::lsa_unicode_string_to_string(&unserial.Logon.LogonDomainName);

    match mode {
        SerializeTestMode::Broker | SerializeTestMode::Filter => {
            assert_eq!(_recv_username, test_utils::VALID_CREDS.0);
            assert_eq!(_recv_password, test_utils::VALID_CREDS.1);
            assert_eq!(_recv_domain, test_utils::VALID_CREDS.2);
            mock.assert();
        }
        SerializeTestMode::Values => {
            assert_eq!(_recv_username, ticket_or_username);
            assert_eq!(_recv_password, key_or_password);
            assert_eq!(_recv_domain, domain);
        }
    }

    Ok(())
}
