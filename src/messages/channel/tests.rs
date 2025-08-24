#[cfg(test)]
use super::*;

use log::info;
use prost::Message;
use rand::{Rng, distr};
use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};

use crate::{messages::auth::*, util::logger::setup_logging};

#[test]
fn test_create_destroy_create() {
    setup_logging("debug");
    let token = gen_auth_token();
    let (_server_thread, server) =
        ChannelServer::run_with_pipe(&token, Some("\\\\.\\pipe\\ChanTest1")).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(500)); // Wait for start

    server.stop();
    _server_thread.join().expect("Server thread panicked");

    let (_server_thread, server) =
        ChannelServer::run_with_pipe(&token, Some("\\\\.\\pipe\\ChanTest1")).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(500)); // Wait for start
    server.stop();
    _server_thread.join().expect("Server thread panicked");
    std::thread::sleep(std::time::Duration::from_secs(3));
}

#[test]
fn test_server_waits_without_client() {
    const PIPE_NAME: &str = "\\\\.\\pipe\\ChanTestTimeout";
    setup_logging("debug");
    let token = gen_auth_token();

    let (_server_thread, server) = ChannelServer::run_with_pipe(&token, Some(PIPE_NAME)).unwrap();

    // Esperamos un tiempo razonable sin conectar ningún cliente
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Verificamos que no se ha recibido ninguna petición
    assert!(
        server.get_request().is_none(),
        "No debería haber ninguna AuthRequest sin cliente"
    );

    // Detenemos el servidor
    server.stop();
    _server_thread.join().expect("Server thread panicked");
}

#[test]
fn test_send_valid_auth_request() {
    setup_logging("debug");
    const PIPE_NAME: &str = "\\\\.\\pipe\\ChanTest2";
    let token = gen_auth_token();
    let (_server_thread, server) = ChannelServer::run_with_pipe(&token, Some(PIPE_NAME)).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(500)); // Wait for start

    let pipe_handle = open_client_pipe(PIPE_NAME);

    write_pipe_auth_request(&pipe_handle, &token).unwrap();
    let _ = check_auth_request(&server, &token);
    server.stop();
    _server_thread.join().expect("Server thread panicked");
}

#[test]
fn test_rapid_close_auth_request() {
    const PIPE_NAME: &str = "\\\\.\\pipe\\ChanTestRapidClose";
    setup_logging("debug");
    let token = gen_auth_token();

    let (_server_thread, server) = ChannelServer::run_with_pipe(&token, Some(PIPE_NAME)).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(500)); // Wait for start

    let pipe_handle = open_client_pipe(PIPE_NAME);

    write_pipe_auth_request(&pipe_handle, &token).unwrap();
    pipe_handle.close();
    let _ = check_auth_request(&server, &token);
    server.stop();
    _server_thread.join().expect("Server thread panicked");
}

#[test]
fn test_only_one_client_allowed() {
    const PIPE_NAME: &str = "\\\\.\\pipe\\ChanTest3";
    setup_logging("debug");
    let token = gen_auth_token();
    let (_server_thread, server) = ChannelServer::run_with_pipe(&token, Some(PIPE_NAME)).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(1000)); // Wait for start

    let pipe_handle = open_client_pipe(PIPE_NAME);
    assert!(pipe_handle.is_valid(), "Failed to open client pipe");

    // A second one, should fail
    let second_pipe_handle = open_client(PIPE_NAME);
    assert!(!second_pipe_handle.is_valid());

    // Stop the server
    server.stop();
    _server_thread.join().expect("Server thread panicked");
}

#[test]
fn test_invalid_auth_request() {
    const PIPE_NAME: &str = "\\\\.\\pipe\\ChanTest4";
    setup_logging("debug");
    let token = gen_auth_token();
    let (_server_thread, server) = ChannelServer::run_with_pipe(&token, Some(PIPE_NAME)).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(500)); // Wait for start

    let pipe_handle = open_client_pipe(PIPE_NAME);

    let mut buf = rand::rng()
        .sample_iter(&distr::Alphanumeric)
        .take(1024)
        .map(char::from)
        .collect::<String>()
        .encode_to_vec();

    let mut len_buf = Vec::new();
    len_buf.write_u32::<LittleEndian>(buf.len() as u32).unwrap();

    let mut written = 0u32;
    unsafe {
        WriteFile(
            pipe_handle.get(),
            Some(&mut len_buf),
            Some(&mut written),
            None,
        )
        .unwrap();
        WriteFile(pipe_handle.get(), Some(&mut buf), Some(&mut written), None).unwrap();
    }

    // Should not have any request in a timeout
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert!(server.get_request().is_none());

    server.stop();
    _server_thread.join().expect("Server thread panicked");
}

#[test]
fn test_invalid_structure_auth_request() {
    const PIPE_NAME: &str = "\\\\.\\pipe\\ChanTest5";
    setup_logging("debug");
    let token = gen_auth_token();
    let (_server_thread, server) = ChannelServer::run_with_pipe(&token, Some(PIPE_NAME)).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(500)); // Wait for start

    let pipe_handle = open_client_pipe(PIPE_NAME);
    write_pipe_auth_request_with_auth_req(
        &pipe_handle,
        &AuthRequest {
            protocol_version: 0xDEADBEEF,          // Incorrect protocol
            auth_token: "short_token".to_string(), // Too short
            username: "".to_string(),              // Empty username
            password: "p".repeat(129),             // Too long
            domain: "test.local".to_string(),
        },
    )
    .unwrap();

    server.stop();
    _server_thread.join().expect("Server thread panicked");
}

#[test]
fn test_client_connects_but_sends_nothing() {
    const PIPE_NAME: &str = "\\\\.\\pipe\\ChanTestNoSend";
    setup_logging("debug");
    let token = gen_auth_token();

    let (_server_thread, server) = ChannelServer::run_with_pipe(&token, Some(PIPE_NAME)).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(500)); // Esperamos a que el servidor esté listo

    // Cliente abre el pipe pero no escribe nada
    let pipe_handle = open_client_pipe(PIPE_NAME);
    assert!(pipe_handle.is_valid(), "Client should be able to connect");

    // Esperamos un poco para ver si el servidor se bloquea o lanza errores
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Verificamos que no se ha recibido ninguna petición
    assert!(
        server.get_request().is_none(),
        "No debería haber ninguna AuthRequest si el cliente no envía datos"
    );

    // Cerramos el servidor
    server.stop();
    _server_thread.join().expect("Server thread panicked");
}

#[test]
fn test_message_too_large() {
    const PIPE_NAME: &str = "\\\\.\\pipe\\ChanTest6";
    setup_logging("debug");
    let token = gen_auth_token();
    let (_server_thread, server) = ChannelServer::run_with_pipe(&token, Some(PIPE_NAME)).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(500)); // Wait for start

    let pipe_handle = open_client_pipe(PIPE_NAME);

    // Mensaje de tamaño excesivo
    let mut oversized_payload = vec![b'A'; consts::MAX_MESSAGE_SIZE + 100];
    let mut len_buf = Vec::new();
    len_buf
        .write_u32::<LittleEndian>(oversized_payload.len() as u32)
        .unwrap();

    let mut written = 0u32;
    unsafe {
        WriteFile(
            pipe_handle.get(),
            Some(&mut len_buf),
            Some(&mut written),
            None,
        )
        .unwrap();
        let result = WriteFile(
            pipe_handle.get(),
            Some(&mut oversized_payload),
            Some(&mut written),
            None,
        );
        // Should return an 0x00E9 Error because server closed our conn
        assert!(
            result.is_err(),
            "WriteFile should fail with oversized payload"
        );
        assert_eq!(
            written, 0,
            "No bytes should be written for oversized payload"
        );
        assert_eq!(result.unwrap_err().code().0 as u32 & 0xFFFF, 0x00E9);
    }
    server.stop();
    _server_thread.join().expect("Server thread panicked");
}

#[test]
pub fn test_cannot_dos_auth_request() {
    const PIPE_NAME: &str = r"\\.\pipe\ChanTest7";
    setup_logging("debug");
    let token = gen_auth_token();
    let (_server_thread, server) = ChannelServer::run_with_pipe(&token, Some(PIPE_NAME)).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(500)); // Wait for start

    let pipe_handle = open_client_pipe(PIPE_NAME);

    let mut oversized_payload = vec![b'A'; consts::MAX_MESSAGE_SIZE + 100];
    let mut len_buf = Vec::new();
    len_buf
        .write_u32::<LittleEndian>(oversized_payload.len() as u32)
        .unwrap();

    let mut written = 0u32;
    unsafe {
        WriteFile(
            pipe_handle.get(),
            Some(&mut len_buf),
            Some(&mut written),
            None,
        )
        .unwrap();
        let result = WriteFile(
            pipe_handle.get(),
            Some(&mut oversized_payload),
            Some(&mut written),
            None,
        );
        // Should return an 0x00E9 Error because server closed our conn
        assert!(
            result.is_err(),
            "WriteFile should fail with oversized payload"
        );
        assert_eq!(
            written, 0,
            "No bytes should be written for oversized payload"
        );
        assert_eq!(result.unwrap_err().code().0 as u32 & 0xFFFF, 0x00E9);
    }

    let pipe_handle = open_client_pipe(PIPE_NAME);
    write_pipe_auth_request_with_auth_req(
        &pipe_handle,
        &AuthRequest {
            protocol_version: consts::MAGIC_HEADER,
            auth_token: token.clone(),
            username: "adolfo".to_string(),
            password: "supersecret".to_string(),
            domain: "test.local".to_string(),
        },
    )
    .unwrap();

    check_auth_request(&server, &token);

    server.stop();
    _server_thread.join().expect("Server thread panicked");
}

#[test]
fn test_client_inactivity_triggers_pipe_reset() {
    const PIPE_NAME: &str = r"\\.\pipe\test_pipe_inactivity";
    let token = gen_auth_token();

    // Start the server
    let (_handle, server) = ChannelServer::run_with_pipe(&token, Some(PIPE_NAME)).unwrap();

    // Give the server time to create the pipe
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Connect as client
    let handle: SafeHandle = open_client_pipe(PIPE_NAME);
    assert!(handle.is_valid(), "Client failed to connect to pipe");

    // Wait 2 seconds to trigger server timeout
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Try to write something
    let msg = b"hello";
    let mut written = 0u32;
    let res = unsafe { WriteFile(handle.get(), Some(msg), Some(&mut written), None) };

    // The server must be alive
    let new_handle = open_client_pipe(PIPE_NAME);
    assert!(
        new_handle.is_valid(),
        "Server should accept new clients after reset"
    );

    // Expect failure because server should have disconnected
    assert!(res.is_err(), "Expected write to fail after inactivity");

    server.stop();
}

// ***********
// ==Helpers**
// ***********

// 64 char token for testing
fn gen_auth_token() -> String {
    rand::rng()
        .sample_iter(&distr::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

fn open_client_pipe(pipe_name: &str) -> SafeHandle {
    for _ in 0..10 {
        let pipe_handle = open_client(pipe_name);
        if pipe_handle.is_valid() {
            return pipe_handle;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    SafeHandle::invalid()
}

fn open_client(pipe_name: &str) -> SafeHandle {
    let pipe_wide = widestring::U16CString::from_str(pipe_name).unwrap();
    let pipe_handle = SafeHandle::new(
        match unsafe {
            CreateFileW(
                PCWSTR::from_raw(pipe_wide.as_ptr()),
                (GENERIC_WRITE | GENERIC_READ).0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES::default(),
                None,
            )
        } {
            Ok(handle) => handle,
            Err(e) => {
                info!("Failed to open client pipe: {}", e);
                INVALID_HANDLE_VALUE
            }
        },
    );

    pipe_handle
}

fn write_pipe_auth_request_with_auth_req(handle: &SafeHandle, msg: &AuthRequest) -> Result<()> {
    let mut buf = Vec::new();
    msg.encode(&mut buf)?;

    let mut len_buf = Vec::new();
    len_buf.write_u32::<LittleEndian>(buf.len() as u32)?;

    let mut written = 0u32;
    unsafe {
        WriteFile(handle.get(), Some(&mut len_buf), Some(&mut written), None)
            .ok()
            .context("Failed to write message length")?;
        WriteFile(handle.get(), Some(&mut buf), Some(&mut written), None)
            .ok()
            .context("Failed to write message body")?;
    }

    Ok(())
}

fn write_pipe_auth_request(handle: &SafeHandle, auth_token: &str) -> Result<()> {
    let msg = AuthRequest {
        protocol_version: consts::MAGIC_HEADER,
        auth_token: auth_token.to_string(),
        username: "adolfo".to_string(),
        password: "supersecret".to_string(),
        domain: "test.local".to_string(),
    };
    write_pipe_auth_request_with_auth_req(handle, &msg)
}

fn check_auth_request(server: &ChannelServer, expected_token: &str) -> AuthRequest {
    let mut count = 0;
    let request = loop {
        if count > 10 {
            panic!("Timeout waiting for auth request");
        }
        count += 1;
        let req = server.get_request();
        if req.is_some() {
            break req.unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    };
    assert!(
        request.protocol_version == consts::MAGIC_HEADER,
        "Invalid protocol version"
    );
    assert!(request.auth_token == expected_token, "Invalid auth token");
    assert!(!request.username.is_empty(), "Username should not be empty");
    assert!(!request.password.is_empty(), "Password should not be empty");
    assert!(!request.domain.is_empty(), "Domain should not be empty");
    request
}
