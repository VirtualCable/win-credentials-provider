use std::time::Instant;

use zeroize::Zeroizing;

use super::*;

use crate::util::logger::setup_logging;

#[test]
fn test_uds_credential_provider_new() -> Result<()> {
    setup_logging("info");
    let provider = UDSCredentialsProvider::new();
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
fn test_on_data_arrived() -> Result<()> {
    setup_logging("info");
    let provider = UDSCredentialsProvider::new();
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
