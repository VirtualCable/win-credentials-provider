use std::time::Instant;

use rand::{Rng, distr};
use windows::Win32::{
    Security::Authentication::Identity::{
        KERB_INTERACTIVE_LOGON, KERB_INTERACTIVE_UNLOCK_LOGON, KerbInteractiveLogon,
    },
    UI::Shell::ICredentialProviderEvents_Impl,
};
use zeroize::Zeroizing;

use super::*;

use crate::util::{com::ComInitializer, logger::setup_logging, lsa::LsaUnicodeString};

// Every UDSCredentialProvider creates a different pipe for our tests
// BUT as the provider reads the pipe name from globals, we must serialize them

// Creates a provider, and stop the channel thread instantly
fn create_provider(pipe_prefix: &str) -> UDSCredentialsProvider {
    setup_logging("info");
    globals::set_pipe_name(&("\\\\.\\pipe\\TestCom".to_string() + pipe_prefix));
    let provider = UDSCredentialsProvider::new();
    provider.stop_flag.store(true, Ordering::Relaxed);
    provider
}

fn create_provider_with_channel(pipe_prefix: &str) -> UDSCredentialsProvider {
    setup_logging("info");
    globals::set_pipe_name(&("\\\\.\\pipe\\TestComCh".to_string() + pipe_prefix));
    UDSCredentialsProvider::new()
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_uds_credential_provider_new() -> Result<()> {
    // Wait a bit to ensure previous test closed the pipe
    // In fact, rest of tasks, even with the thead creation "failed"
    // Is not problematic, because they are designed so
    let provider = create_provider_with_channel("001");
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
    let provider = create_provider("00x2");
    // Simulate incoming data
    let auth_request = crate::messages::auth::AuthRequest {
        protocol_version: 1,
        auth_token: "auth_token".into(),
        username: "username".into(),
        password: "password".into(),
        domain: "domain".into(),
    };
    provider.on_data_arrived(auth_request)?;

    assert!(provider.credential.read().unwrap().is_ready());
    assert!(provider.credential.read().unwrap().username() == "username");
    assert!(provider.credential.read().unwrap().password() == Zeroizing::new("password".into()));
    assert!(provider.credential.read().unwrap().domain() == "domain");
    Ok(())
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_set_usage_scenario_logon() -> Result<()> {
    let provider = create_provider("003");
    // Setup credential so we can check they are cleaned
    provider
        .credential
        .write()
        .unwrap()
        .set_credentials("username", "password", "domain");

    provider.set_usage_scenario(CPUS_LOGON)?;
    // Ensure credentials are reset
    assert!(!provider.credential.read().unwrap().is_ready());
    assert!(provider.credential.read().unwrap().username().is_empty());
    assert!(provider.credential.read().unwrap().password().is_empty());
    assert!(provider.credential.read().unwrap().domain().is_empty());

    Ok(())
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_set_usage_scenario_unlock() -> Result<()> {
    let provider = create_provider("004");
    // Setup credential so we can check they are cleaned
    provider
        .credential
        .write()
        .unwrap()
        .set_credentials("username", "password", "domain");
    provider.set_usage_scenario(CPUS_UNLOCK_WORKSTATION)?;
    // Ensure credentials are reset
    assert!(!provider.credential.read().unwrap().is_ready());
    assert!(provider.credential.read().unwrap().username().is_empty());
    assert!(provider.credential.read().unwrap().password().is_empty());
    assert!(provider.credential.read().unwrap().domain().is_empty());

    Ok(())
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_set_usage_scenario_cred_ui() -> Result<()> {
    let provider = create_provider("005");
    // Setup credential so we can check they are cleaned
    assert!(provider.set_usage_scenario(CPUS_CREDUI).is_err());

    Ok(())
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_set_usage_scenario_change_password() -> Result<()> {
    let provider = create_provider("006");
    // Setup credential so we can check they are cleaned
    assert!(provider.set_usage_scenario(CPUS_CHANGE_PASSWORD).is_err());

    Ok(())
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_set_usage_scenario_plap() -> Result<()> {
    let provider = create_provider("007");
    // Setup credential so we can check they are cleaned
    assert!(provider.set_usage_scenario(CPUS_PLAP).is_err());

    Ok(())
}

fn generate_broker_username() -> String {
    // Calc user name that comply with rules on crate::broker
    // const BROKER_CREDENTIAL_PREFIX  // Broker credential prefix
    // const BROKER_CREDENTIAL_SIZE    // Broker credential size
    format!(
        "{}{}",
        crate::broker::BROKER_CREDENTIAL_PREFIX,
        rand::rng()
            .sample_iter(&rand::distr::Alphanumeric)
            .take(
                crate::broker::BROKER_CREDENTIAL_SIZE
                    - crate::broker::BROKER_CREDENTIAL_PREFIX.len()
            )
            .map(char::from)
            .collect::<String>()
    )
}

fn get_credential_serialization(
    username: &str,
    password: &str,
    domain: &str,
    guid: GUID,
) -> Result<CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION> {
    let _lsa_user = LsaUnicodeString::new(&username);
    let _lsa_pass = LsaUnicodeString::new(password);
    let _lsa_domain = LsaUnicodeString::new(domain);

    let logon = KERB_INTERACTIVE_UNLOCK_LOGON {
        Logon: KERB_INTERACTIVE_LOGON {
            MessageType: KerbInteractiveLogon,
            LogonDomainName: *_lsa_domain.as_lsa(),
            UserName: *_lsa_user.as_lsa(),
            Password: *_lsa_pass.as_lsa(),
        },
        LogonId: Default::default(),
    };
    // Pack the logon
    let (packed, size) = unsafe { crate::util::lsa::kerb_interactive_unlock_logon_pack(&logon)? };

    Ok(CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION {
        ulAuthenticationPackage: 0,
        clsidCredentialProvider: guid,
        cbSerialization: size,
        rgbSerialization: packed,
    })
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_unserialize_ok() -> Result<()> {
    let provider = create_provider("008");
    let username = generate_broker_username();
    let cred_serial = get_credential_serialization(
        &username,
        "password",
        "domain",
        crate::globals::CLSID_UDS_CREDENTIAL_PROVIDER,
    )?;

    provider.unserialize(&cred_serial).unwrap(); // If fails will stop here

    Ok(())
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_unserialize_bad_guid() -> Result<()> {
    let provider = create_provider("008");
    let cred_serial = get_credential_serialization(
        &generate_broker_username(),
        "password",
        "domain",
        GUID::from(9),
    )?;

    // Should fail
    assert!(provider.unserialize(&cred_serial).is_err());

    Ok(())
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_unserialize_invalid_username() -> Result<()> {
    let provider = create_provider("008");
    let cred_serial = get_credential_serialization(
        "username",
        "password",
        "domain",
        crate::globals::CLSID_UDS_CREDENTIAL_PROVIDER,
    )?;

    // Should fail
    assert!(provider.unserialize(&cred_serial).is_err());

    Ok(())
}

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

    let provider = create_provider("009");
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
