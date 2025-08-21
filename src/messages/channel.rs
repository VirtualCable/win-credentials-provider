use log::error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::Pipes::*;
use windows::core::PCWSTR;

use crate::debug_dev;

use crate::messages::{
    auth::{AuthRequest, AuthResponse},
    consts,
};
use crate::util::safe::SafeHandle;

#[derive(Debug, Clone)]
pub struct ChannelServer {
    handle: SafeHandle,
    stop_flag: Arc<AtomicBool>,
    request: Arc<Mutex<Option<AuthRequest>>>,
}

impl AuthRequest {
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != consts::MAGIC_HEADER {
            return Err(anyhow::anyhow!("Invalid protocol version"));
        }
        // auth_token should be 64 bytes exactly
        if self.auth_token.len() != 64 {
            return Err(anyhow::anyhow!("Invalid auth_token length"));
        }
        // Username and password must be provided and be less than 128 bytes
        if self.username.is_empty() || self.password.is_empty() {
            return Err(anyhow::anyhow!("Username and password must be provided"));
        }
        if self.username.len() > 128 || self.password.len() > 128 {
            return Err(anyhow::anyhow!(
                "Username and password must be less than 128 bytes"
            ));
        }
        Ok(())
    }
}

#[allow(dead_code)]
impl ChannelServer {
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }

    pub fn is_stopped(&self) -> bool {
        self.stop_flag.load(Ordering::SeqCst)
    }

    pub fn run_with_pipe(
        auth_token: &str,
        pipe_name: Option<&str>,
    ) -> Result<(std::thread::JoinHandle<()>, ChannelServer)> {
        let server = ChannelServer::create(pipe_name)
            .ok()
            .context("Failed to create ChannelServer")?;

        let cloned_server = server.clone();
        let auth_token = auth_token.to_string();
        Ok((
            std::thread::spawn(move || {
                while !server.is_stopped() {
                    match server.read_message::<AuthRequest>() {
                        Ok(msg) => match msg {
                            Some(msg) => {
                                debug_dev!("Received AuthRequest: {:?}", msg);
                                server.process_msg(msg, &auth_token);
                                server.disconnect_pipe(false);
                            }
                            None => {
                                std::thread::sleep(std::time::Duration::from_secs(1));
                            }
                        },
                        Err(e) => {
                            let _ = server.write_message(&AuthResponse {
                                protocol_version: consts::MAGIC_HEADER,
                                status_code: 1, // 1 = Invalid
                                error_message: format!("Failed to read message: {}", e),
                            });
                            server.disconnect_pipe(false);
                        }
                    }
                }
            }),
            cloned_server,
        ))
    }

    pub fn run(auth_token: &str) -> Result<(std::thread::JoinHandle<()>, ChannelServer)> {
        Self::run_with_pipe(auth_token, None)
    }

    fn create(name: Option<&str>) -> Result<Self> {
        let pipe_wide = widestring::U16CString::from_str(name.unwrap_or(consts::PIPE_NAME))?;
        let pipe_wide_ptr = PCWSTR::from_raw(pipe_wide.as_ptr());

        let handle = unsafe {
            CreateNamedPipeW(
                pipe_wide_ptr,
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT,
                1, // we do not need PIPE_UNLIMITED_INSTANCES, because we will sequentially process a single message
                consts::PIPE_BUFFER,
                consts::PIPE_BUFFER,
                0,
                None,
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            error!("Failed to create named pipe {}", consts::PIPE_NAME);
            return Err(anyhow::anyhow!("Failed to create named pipe"));
        }

        Ok(Self {
            handle: SafeHandle::new(handle), // We will take care of releasing it on drop
            stop_flag: Arc::new(AtomicBool::new(false)),
            request: std::sync::Arc::new(std::sync::Mutex::new(None)),
        })
    }

    fn read_message<T: prost::Message + Default>(&self) -> Result<Option<T>> {
        let mut len_buf = [0u8; 4];
        let mut read = 0u32;

        let res = unsafe { ReadFile(self.handle.get(), Some(&mut len_buf), Some(&mut read), None) };

        debug_dev!("Read message length: {:?}, res: {:?}", &len_buf[..], res);

        match res {
            Ok(_) => {}
            Err(e) => {
                let code = (e.code().0 as u32) & 0xFFFF;
                // if error, can be ERROR_PIPE_LISTENING (536) --> Other side not connected, so we cannot read
                // or ERROR_NO_DATA (232) --> No data to read
                if matches!(code, 232 | 233 | 536) {
                    debug_dev!("No data to read or pipe not connected: {}", code);
                    return Ok(None); // No data to read
                }
                return Err(anyhow::anyhow!("Failed to read message length: {}", e));
            }
        }

        let msg_len = (&len_buf[..]).read_u32::<LittleEndian>()? as usize;
        if msg_len > consts::MAX_MESSAGE_SIZE {
            // Disconnect here, will do it again later, but no problem (will return an error that will not interfere with )
            self.disconnect_pipe(true);
            return Err(anyhow::anyhow!("Message too large: {} bytes", msg_len));
        }

        let mut buf = vec![0u8; msg_len];
        unsafe {
            ReadFile(self.handle.get(), Some(&mut buf), Some(&mut read), None)
                .ok()
                .context("Failed to read message body")?;
        }

        let msg = T::decode(&*buf).ok().context("Failed to decode message")?;
        Ok(Some(msg))
    }

    fn write_message<T: prost::Message>(&self, msg: &T) -> Result<()> {
        let mut buf = Vec::new();
        msg.encode(&mut buf)?;

        if buf.len() > consts::MAX_MESSAGE_SIZE {
            return Err(anyhow::anyhow!("Message too large to send"));
        }

        let mut len_buf = Vec::with_capacity(4);
        len_buf.write_u32::<LittleEndian>(buf.len() as u32)?;

        let mut written = 0u32;

        unsafe {
            WriteFile(
                self.handle.get(),
                Some(&mut len_buf),
                Some(&mut written),
                None,
            )
            .ok()
            .context("Failed to write message length")?;
            // Ensure the entire length header is written
            if written != len_buf.len() as u32 {
                return Err(anyhow::anyhow!("Failed to write complete message length"));
            }

            WriteFile(self.handle.get(), Some(&mut buf), Some(&mut written), None)
                .ok()
                .context("Failed to write message body")?;
            // Ensure the entire message is written
            if written != buf.len() as u32 {
                return Err(anyhow::anyhow!("Failed to write complete message body"));
            }
        }

        Ok(())
    }

    fn send_invalid_message(&self, error_message: &str) {
        let _ = self.write_message(&AuthResponse {
            protocol_version: consts::MAGIC_HEADER,
            status_code: 1, // 1 = Invalid
            error_message: error_message.to_string(),
        });
    }

    fn process_msg(&self, msg: AuthRequest, auth_token: &str) {
        // Process the message, an if not valid simply discards it
        // Validate the message
        if let Err(e) = msg.validate() {
            error!("AuthRequest validation failed: {}", e);
            // Send an error response
            self.send_invalid_message(format!("AuthRequest validation failed: {}", e).as_str());

            return;
        }
        if msg.auth_token != auth_token {
            error!("Invalid auth token: {}", msg.auth_token);
            self.send_invalid_message(format!("Invalid auth token: {}", msg.auth_token).as_str());
            return;
        }

        // Here you would typically process the authentication request
        // For now, we will just return a dummy response
        let response = AuthResponse {
            protocol_version: consts::MAGIC_HEADER,
            status_code: 0, // 0 = OK
            error_message: String::new(),
        };

        // Store so it can be processed later
        self.request.lock().unwrap().replace(msg);

        if let Err(e) = self.write_message(&response) {
            error!("Failed to send AuthResponse: {}", e);
        }
    }

    fn disconnect_pipe(&self, force: bool) {
        // Disconnect the client, but do not destroy the Pipe itself
        if force {
            debug_dev!("Disconnecting named pipe");
            let _ = unsafe { FlushFileBuffers(self.handle.get()) };
        }
        debug_dev!("Flushed file buffers");
        let _ = unsafe { DisconnectNamedPipe(self.handle.get()) };
        debug_dev!("Disconnected named pipe");
    }

    // function that will run a thread that will process incomming messages until stopped
}

impl Drop for ChannelServer {
    fn drop(&mut self) {
        debug_dev!("Dropping ChannelServer, cleaning up resources");
        self.handle.clear(); // Early drop
    }
}

#[cfg(test)]
mod tests {
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

        std::thread::sleep(std::time::Duration::from_millis(1000)); // Wait for start

        server.stop();
        _server_thread.join().expect("Server thread panicked");

        let (_server_thread, server) =
            ChannelServer::run_with_pipe(&token, Some("\\\\.\\pipe\\ChanTest1")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1000)); // Wait for start
        server.stop();
        _server_thread.join().expect("Server thread panicked");
        std::thread::sleep(std::time::Duration::from_secs(3));
    }

    #[test]
    fn test_send_valid_auth_request() {
        setup_logging("debug");
        const PIPE_NAME: &str = "\\\\.\\pipe\\ChanTest2";
        let token = gen_auth_token();
        let (_server_thread, server) =
            ChannelServer::run_with_pipe(&token, Some(PIPE_NAME)).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(1000)); // Wait for start

        let pipe_handle = open_client_pipe(PIPE_NAME);

        // If not valid, unwrap of CreateFileW already panics
        write_pipe_auth_request(&pipe_handle, &token).unwrap();
        let response = read_pipe_auth_response(&pipe_handle).unwrap();
        server.stop();
        _server_thread.join().expect("Server thread panicked");

        assert_eq!(response.protocol_version, consts::MAGIC_HEADER);
        std::thread::sleep(std::time::Duration::from_secs(3));
    }

    #[test]
    fn test_only_one_client_allowed() {
        const PIPE_NAME: &str = "\\\\.\\pipe\\ChanTest3";
        setup_logging("debug");
        let token = gen_auth_token();
        let (_server_thread, server) =
            ChannelServer::run_with_pipe(&token, Some(PIPE_NAME)).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(1000)); // Wait for start

        let pipe_handle = open_client_pipe(PIPE_NAME);
        assert!(pipe_handle.is_valid(), "Failed to open client pipe");

        // A second one, should fail
        let second_pipe_handle = open_client_pipe(PIPE_NAME);
        assert!(!second_pipe_handle.is_valid());

        // Stop the server
        server.stop();
        _server_thread.join().expect("Server thread panicked");
        std::thread::sleep(std::time::Duration::from_secs(3));
    }

    #[test]
    fn test_invalid_auth_request() {
        const PIPE_NAME: &str = "\\\\.\\pipe\\ChanTest4";
        setup_logging("debug");
        let token = gen_auth_token();
        let (_server_thread, server) =
            ChannelServer::run_with_pipe(&token, Some(PIPE_NAME)).unwrap();

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

        // Wait for response, but don't block to process timeout
        let mut response_buf = Vec::new();
        let mut response_len = [0u8; 4];
        let mut read = 0u32;

        unsafe {
            ReadFile(
                pipe_handle.get(),
                Some(&mut response_len),
                Some(&mut read),
                None,
            )
            .unwrap();
            assert_eq!(read, 4);
            let msg_len = (&response_len[..]).read_u32::<LittleEndian>().unwrap() as usize;
            response_buf.resize(msg_len, 0);
            ReadFile(
                pipe_handle.get(),
                Some(&mut response_buf),
                Some(&mut read),
                None,
            )
            .unwrap();
            assert_eq!(read, msg_len as u32);
        }

        std::thread::sleep(std::time::Duration::from_secs(1));
        server.stop();
        _server_thread.join().expect("Server thread panicked");

        let response = AuthResponse::decode(&*response_buf).unwrap();
        assert_eq!(response.protocol_version, consts::MAGIC_HEADER);
        assert_eq!(response.status_code, 1);

        std::thread::sleep(std::time::Duration::from_secs(3));
    }

    #[test]
    fn test_invalid_structure_auth_request() {
        const PIPE_NAME: &str = "\\\\.\\pipe\\ChanTest5";
        setup_logging("debug");
        let token = gen_auth_token();
        let (_server_thread, server) =
            ChannelServer::run_with_pipe(&token, Some(PIPE_NAME)).unwrap();

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

        let response = read_pipe_auth_response(&pipe_handle).unwrap();
        assert_eq!(response.status_code, 1);
        assert!(response.error_message.contains("validation failed"));

        server.stop();
        _server_thread.join().expect("Server thread panicked");
    }

    #[test]
    fn test_message_too_large() {
        const PIPE_NAME: &str = "\\\\.\\pipe\\ChanTest6";
        setup_logging("debug");
        let token = gen_auth_token();
        let (_server_thread, server) =
            ChannelServer::run_with_pipe(&token, Some(PIPE_NAME)).unwrap();

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

    fn read_pipe_auth_response(handle: &SafeHandle) -> Result<AuthResponse> {
        let mut response_buf = Vec::new();
        let mut response_len = [0u8; 4];
        let mut read = 0u32;

        unsafe {
            ReadFile(handle.get(), Some(&mut response_len), Some(&mut read), None)
                .ok()
                .context("Failed to read response length")?;
            assert_eq!(read, 4);
            let msg_len = (&response_len[..])
                .read_u32::<LittleEndian>()
                .ok()
                .context("Failed to read message length")? as usize;
            response_buf.resize(msg_len, 0);
            ReadFile(handle.get(), Some(&mut response_buf), Some(&mut read), None)
                .ok()
                .context("Failed to read response body")?;
            assert_eq!(read, msg_len as u32);
        }
        let response = AuthResponse::decode(&*response_buf)
            .ok()
            .context("Failed to decode AuthResponse")?;

        Ok(response)
    }
}
