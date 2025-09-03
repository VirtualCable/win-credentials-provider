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
use std::{sync::atomic::AtomicU32, time::Instant};

use windows::Win32::UI::Shell::ICredentialProviderEvents_Impl;

use super::*;

use crate::{
    credentials::filter,
    utils::{com::ComInitializer, log::setup_logging},
};

// Every UDSCredentialProvider creates a different pipe for our tests
// BUT as the provider reads the pipe name from globals, we must serialize them

static CREATED_CRED_COUNT: OnceLock<AtomicU32> = OnceLock::new();

// Creates a provider, and stop the channel thread instantly
fn create_provider() -> UDSCredentialsProvider {
    let cred_number = CREATED_CRED_COUNT.get_or_init(AtomicU32::default);
    cred_number.fetch_add(1, Ordering::Relaxed);
    // Store it again
    CREATED_CRED_COUNT
        .set(AtomicU32::new(cred_number.load(Ordering::Relaxed)))
        .ok();

    let pipe_prefix = format!("{:04}", cred_number.load(Ordering::Relaxed));

    setup_logging("debug");
    globals::set_pipe_name(&("\\\\.\\pipe\\TestCom".to_string() + &pipe_prefix));
    let provider = UDSCredentialsProvider::new();
    provider.stop_flag.store(true, Ordering::Relaxed);
    provider
}

fn create_provider_with_channel() -> UDSCredentialsProvider {
    setup_logging("info");
    let cred_number = CREATED_CRED_COUNT.get_or_init(AtomicU32::default);
    cred_number.fetch_add(1, Ordering::Relaxed);
    // Store it again
    CREATED_CRED_COUNT
        .set(AtomicU32::new(cred_number.load(Ordering::Relaxed)))
        .ok();

    let pipe_prefix = format!("{:04}", cred_number.load(Ordering::Relaxed));

    globals::set_pipe_name(&("\\\\.\\pipe\\TestCom".to_string() + &pipe_prefix));
    UDSCredentialsProvider::new()
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_uds_credential_provider_new() -> Result<()> {
    // Wait a bit to ensure previous test closed the pipe
    // In fact, rest of tasks, even with the thead creation "failed"
    // Is not problematic, because they are designed so
    let provider = create_provider_with_channel();
    std::thread::sleep(std::time::Duration::from_millis(222));
    // Should have the ASYNC_CREDS_HANDLE sent with a handle
    assert!(ASYNC_CREDS_HANDLE.get().is_some());
    assert!(ASYNC_CREDS_HANDLE.get().unwrap().read().unwrap().is_some());
    // Wait a bit, not needed for this test, but allows to fully start channel
    std::thread::sleep(std::time::Duration::from_millis(222));

    assert!(
        !ASYNC_CREDS_HANDLE
            .get()
            .unwrap()
            .write()
            .unwrap()
            .as_ref()
            .unwrap()
            .is_finished()
    );
    // Stop the task
    provider.stop_flag.store(true, Ordering::Relaxed);

    // Task should stop in a while, just wait
    let task_handle = ASYNC_CREDS_HANDLE
        .get()
        .unwrap()
        .write()
        .unwrap()
        .take()
        .unwrap(); // Fails is no handle

    let start = Instant::now();
    loop {
        if task_handle.is_finished() {
            task_handle.join().unwrap();
            break;
        }
        if start.elapsed().as_secs() > 3 {
            panic!("Task did not stop in 3 seconds");
        }
    }
    Ok(())
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_on_data_arrived() -> Result<()> {
    let provider = create_provider();
    // Simulate incoming data
    let auth_request = crate::messages::auth::AuthRequest {
        protocol_version: 1,
        auth_token: "auth_token".into(),
        broker_credential: crate::test_utils::TEST_BROKER_CREDENTIAL.into(),
    };
    provider.on_data_arrived(auth_request)?;

    let credential_guard = provider.credential.read().unwrap();
    assert!(credential_guard.has_valid_credentials());

    Ok(())
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_set_usage_scenario_logon() -> Result<()> {
    let provider = create_provider();
    // Setup credential so we can check they are cleaned
    provider
        .credential
        .write()
        .unwrap()
        .set_token("token", "key");

    provider.set_usage_scenario(CPUS_LOGON)?;
    // Ensure credentials are reset
    assert!(!provider.credential.read().unwrap().has_valid_credentials());
    assert!(provider.credential.read().unwrap().token().is_empty());
    assert!(provider.credential.read().unwrap().key().is_empty());

    Ok(())
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_set_usage_scenario_unlock() -> Result<()> {
    let provider = create_provider();
    // Setup credential so we can check they are cleaned
    provider
        .credential
        .write()
        .unwrap()
        .set_token("token", "key");
    provider.set_usage_scenario(CPUS_UNLOCK_WORKSTATION)?;
    // Ensure credentials are reset
    assert!(!provider.credential.read().unwrap().has_valid_credentials());
    assert!(provider.credential.read().unwrap().token().is_empty());
    assert!(provider.credential.read().unwrap().key().is_empty());

    Ok(())
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_set_usage_scenario_cred_ui() -> Result<()> {
    let provider = create_provider();
    // Setup credential so we can check they are cleaned
    assert!(provider.set_usage_scenario(CPUS_CREDUI).is_err());

    Ok(())
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_set_usage_scenario_change_password() -> Result<()> {
    let provider = create_provider();
    // Setup credential so we can check they are cleaned
    assert!(provider.set_usage_scenario(CPUS_CHANGE_PASSWORD).is_err());

    Ok(())
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_set_usage_scenario_plap() -> Result<()> {
    let provider = create_provider();
    // Setup credential so we can check they are cleaned
    assert!(provider.set_usage_scenario(CPUS_PLAP).is_err());

    Ok(())
}

// fn get_credential_serialization(
//     username: &str,
//     password: &str,
//     domain: &str,
//     guid: GUID,
// ) -> Result<CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION> {
//     let _lsa_user = LsaUnicodeString::new(username);
//     let _lsa_pass = LsaUnicodeString::new(password);
//     let _lsa_domain = LsaUnicodeString::new(domain);

//     let logon = KERB_INTERACTIVE_UNLOCK_LOGON {
//         Logon: KERB_INTERACTIVE_LOGON {
//             MessageType: KerbInteractiveLogon,
//             LogonDomainName: *_lsa_domain.as_lsa(),
//             UserName: *_lsa_user.as_lsa(),
//             Password: *_lsa_pass.as_lsa(),
//         },
//         LogonId: Default::default(),
//     };
//     // Pack the logon
//     let (packed, size) = unsafe { crate::utils::lsa::kerb_interactive_unlock_logon_pack(&logon)? };

//     Ok(CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION {
//         ulAuthenticationPackage: 0,
//         clsidCredentialProvider: guid,
//         cbSerialization: size,
//         rgbSerialization: packed,
//     })
// }

#[derive(Clone)]
// Fake ICredentialProviderEvents for tests
#[implement(ICredentialProviderEvents)]
struct TestingCredentialProviderEvents {
    up_advise_context: Arc<RwLock<usize>>,
}

impl Default for TestingCredentialProviderEvents {
    fn default() -> Self {
        Self {
            up_advise_context: Arc::new(RwLock::new(0)),
        }
    }
}

impl ICredentialProviderEvents_Impl for TestingCredentialProviderEvents_Impl {
    fn CredentialsChanged(&self, upadvisecontext: usize) -> windows_core::Result<()> {
        let mut context = self.up_advise_context.write().unwrap();
        *context = upadvisecontext;
        Ok(())
    }
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_register_get_unregister_event_manager() -> Result<()> {
    // This is a test, we do not have CoInitialize called in our thread
    let _com_init = ComInitializer::new();

    let provider = create_provider();
    let events = TestingCredentialProviderEvents::default();
    let event_impl: ICredentialProviderEvents = events.clone().into();
    provider.register_event_manager(event_impl, 0x120909)?;

    assert!(provider.cookie.read().unwrap().is_some());
    assert!(*provider.up_advise_context.read().unwrap() == 0x120909);

    // Invoke it
    let event_manager = provider.get_event_manager()?;
    unsafe { event_manager.unwrap().CredentialsChanged(0xdeadbeef)? };

    assert_eq!(*events.up_advise_context.read().unwrap(), 0xdeadbeef);

    // Unregister
    provider.unregister_event_manager()?;

    assert!(provider.cookie.read().unwrap().is_none());
    assert!(*provider.up_advise_context.read().unwrap() == 0);

    Ok(())
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_number_of_fields() -> Result<()> {
    let provider = create_provider();
    assert_eq!(
        provider.get_number_of_fields(),
        crate::credentials::types::UdsFieldId::NumFields as u32
    );

    Ok(())
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_get_field_descriptor_at() -> Result<()> {
    let provider = create_provider();
    for i in 0..provider.get_number_of_fields() {
        let field_descriptor = provider.get_field_descriptor_at(i);
        match field_descriptor {
            Ok(desc) => {
                let orig =
                    &crate::credentials::fields::CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS[i as usize];
                unsafe {
                    assert_eq!((*desc).dwFieldID, orig.field_id);
                    assert_eq!((*desc).cpft, orig.field_type);
                    assert_eq!((*desc).guidFieldType, orig.guid);
                    let label = (*desc).pszLabel.to_string().unwrap_or_default();
                    assert_eq!(label, orig.label);
                }
                crate::utils::com::alloc_free(desc as *mut _);
            }
            Err(e) => {
                debug_dev!("Failed to get field descriptor at index {}: {}", i, e);
                return Err(e);
            }
        }
    }
    Ok(())
}

#[test]
#[serial_test::serial(CredentialProvider, rdp)]
fn test_get_credential_count_with_creds() -> Result<()> {
    let provider = create_provider();
    provider
        .credential
        .write()
        .unwrap()
        .set_token("token", "key");
    let cred_count = provider.get_credential_count().unwrap();
    assert_eq!(cred_count, (1u32, 0u32, true.into())); // One credential

    Ok(())
}

#[test]
#[serial_test::serial(CredentialProvider, rdp)]
fn test_get_credential_count_with_filter_creds() -> Result<()> {
    let provider = create_provider();
    crate::credentials::filter::UDSCredentialsFilter::set_received_credential(Some(
        crate::credentials::types::Credential::with_credentials("token", "key"),
    ));
    let cred_count = provider.get_credential_count().unwrap();
    assert_eq!(cred_count, (1u32, 0u32, true.into())); // One credential

    Ok(())
}

#[test]
#[serial_test::serial(CredentialProvider, rdp)]
fn test_get_credential_count_no_creds() -> Result<()> {
    let provider = create_provider();
    provider.credential.write().unwrap().reset_token();
    filter::UDSCredentialsFilter::set_received_credential(None);
    let cred_count = provider.get_credential_count().unwrap();
    assert_eq!(
        cred_count,
        (1u32, CREDENTIAL_PROVIDER_NO_DEFAULT, false.into())
    ); // No credentials

    // Just to ensure that the problem was the creds
    provider
        .credential
        .write()
        .unwrap()
        .set_token("token", "key");
    let cred_count = provider.get_credential_count().unwrap();
    assert_eq!(cred_count, (1u32, 0u32, true.into())); // One credential
    Ok(())
}

#[test]
#[serial_test::serial(CredentialProvider, rdp)]
fn test_get_credential_count_no_rdp() -> Result<()> {
    let provider = create_provider();
    provider
        .credential
        .write()
        .unwrap()
        .set_token("token", "key");

    let cred_count = provider.get_credential_count().unwrap();
    assert_eq!(
        cred_count,
        (1u32, 0, true.into())
    ); // Has credentials. Only can come from RDP or our channel

    Ok(())
}

#[test]
#[serial_test::serial(broker_info)]
fn test_get_credential_at_ok() {
    let provider = create_provider();
    let result = provider.get_credential_at(0);
    assert!(result.is_ok());
}

#[test]
#[serial_test::serial(broker_info)]
fn test_get_credential_at_err() {
    let provider = create_provider();
    let result = provider.get_credential_at(1);
    assert!(result.is_err());
}
