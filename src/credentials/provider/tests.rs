use std::time::Instant;

use zeroize::Zeroizing;

use super::*;

use crate::util::logger::setup_logging;

// Every UDSCredentialProvider creates a different pipe for our tests
// BUT as the provider reads the pipe name from globals, we must serializea

fn create_provider(pipe_prefix: &str) -> UDSCredentialsProvider {
    setup_logging("info");
    globals::set_pipe_name(&("\\\\.\\pipe\\UDSCredsComms".to_string() + pipe_prefix));
    UDSCredentialsProvider::new()
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_uds_credential_provider_new() -> Result<()> {
    // Wait a bit to ensure previous test closed the pipe
    // In fact, rest of tasks, even with the thead creation "failed"
    // Is not problematic, because they are designed so
    let provider = create_provider("_test_uds_credential_provider_new");
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
    provider.stop_flag.store(true, Ordering::SeqCst);

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
    let provider = create_provider("_test_on_data_arrived");
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
    let provider = create_provider("_test_set_usage_scenario_logon");
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
    let provider = create_provider("_test_set_usage_scenario_unlock");
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
    let provider = create_provider("_test_set_usage_scenario_cred_ui");
    // Setup credential so we can check they are cleaned
    assert!(provider.set_usage_scenario(CPUS_CREDUI).is_err());

    Ok(())
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_set_usage_scenario_change_password() -> Result<()> {
    let provider = create_provider("_test_set_usage_scenario_change_password");
    // Setup credential so we can check they are cleaned
    assert!(provider.set_usage_scenario(CPUS_CHANGE_PASSWORD).is_err());

    Ok(())
}

#[test]
#[serial_test::serial(CredentialProvider)]
fn test_set_usage_scenario_plap() -> Result<()> {
    let provider = create_provider("_test_set_usage_scenario_plap");
    // Setup credential so we can check they are cleaned
    assert!(provider.set_usage_scenario(CPUS_PLAP).is_err());

    Ok(())
}
