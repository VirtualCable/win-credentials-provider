use anyhow::{Context, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::Pipes::*;
use windows::core::PCWSTR;

use crate::debug_dev;

use crate::messages::{auth::AuthRequest, consts};
use crate::utils::{
    log::{debug, error},
    safe::SafeHandle,
};

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

#[derive(Debug, Clone)]
pub struct ChannelServer {
    pipe_handle: SafeHandle,
    stop_flag: Arc<AtomicBool>,
    request: Arc<RwLock<Option<AuthRequest>>>,
    no_data_since: Arc<RwLock<Option<Instant>>>,
}

#[allow(dead_code)]
impl ChannelServer {
    pub fn new() -> Self {
        Self {
            pipe_handle: SafeHandle::new(INVALID_HANDLE_VALUE),
            stop_flag: Arc::new(AtomicBool::new(true)),
            request: std::sync::Arc::new(std::sync::RwLock::new(None)),
            no_data_since: Arc::new(RwLock::new(None)),
        }
    }

    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }

    pub fn is_stopped(&self) -> bool {
        self.stop_flag.load(Ordering::Relaxed)
    }

    pub fn get_request(&self) -> Option<AuthRequest> {
        let mut request_guard = self.request.write().unwrap();
        request_guard.take() // Take the request, leaving None in the mutex
    }

    pub fn run_with_pipe(
        auth_token: &str,
        pipe_name: Option<&str>,
    ) -> Result<(std::thread::JoinHandle<()>, ChannelServer)> {
        let pipe_name = pipe_name.unwrap_or(consts::PIPE_NAME).to_string();
        debug_dev!("Using pipe name: {}", &pipe_name);
        let server = ChannelServer::create(&pipe_name)
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
                                server.disconnect_pipe();
                            }
                            None => {
                                std::thread::sleep(std::time::Duration::from_secs(1));
                            }
                        },
                        Err(e) => {
                            error!("Failed to read message: {}", e);
                            server.disconnect_pipe();
                            // Regenerate named pipe to avoid being blocked
                            // And close the named pipe, and open it again
                            server.pipe_handle.clear(); // Ensure handle is cleared/closed
                            server
                                .pipe_handle
                                .set(Self::create_pipe(&pipe_name).unwrap());
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

    fn create_pipe(name: &str) -> Result<HANDLE> {
        use crate::messages::consts;

        let pipe_wide = widestring::U16CString::from_str(name)?;
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
            let err = unsafe { GetLastError() };
            error!("Failed to create named pipe {}: {}", name, err.0);
            return Err(anyhow::anyhow!(format!(
                "Failed to create named pipe {}: {}",
                name, err.0
            )));
        }

        Ok(handle)
    }

    fn create(name: &str) -> Result<Self> {
        let handle = Self::create_pipe(name)?;

        Ok(Self {
            pipe_handle: SafeHandle::new(handle), // We will take care of releasing it on drop
            stop_flag: Arc::new(AtomicBool::new(false)),
            request: std::sync::Arc::new(std::sync::RwLock::new(None)),
            no_data_since: Arc::new(RwLock::new(None)),
        })
    }

    fn read_message<T: prost::Message + Default>(&self) -> Result<Option<T>> {
        let mut len_buf = [0u8; 4];
        let mut read = 0u32;

        let res = unsafe {
            ReadFile(
                self.pipe_handle.get(),
                Some(&mut len_buf),
                Some(&mut read),
                None,
            )
        };

        match res {
            Ok(_) => {
                if read != 4 {
                    return Err(anyhow::anyhow!("Failed to read message length"));
                }
                self.no_data_since.write().unwrap().take(); // Clear no_data_since on successful read
            }
            Err(e) => {
                let code = (e.code().0 as u32) & 0xFFFF;
                if code == 232 {
                    // ERROR_NO_DATA (232) --> No data to read, but client connected
                    let mut no_data_guard = self.no_data_since.write().unwrap();
                    let now = std::time::Instant::now();
                    match *no_data_guard {
                        Some(start) if now.duration_since(start) > Duration::from_secs(1) => {
                            // Set data to None again
                            *no_data_guard = None;
                            error!("No data read for more than 1 second, disconnecting pipe");
                            return Err(anyhow::anyhow!(
                                "No data read for more than 1 second, disconnecting pipe"
                            ));
                        }
                        None => {
                            *no_data_guard = Some(now);
                            debug_dev!("No data read, setting no_data_since to {:?}", now);
                        }
                        _ => {
                            debug_dev!(
                                "No data read, but within 1 second, keeping connection alive"
                            );
                        }
                    }
                    return Ok(None); // No data to read, but client connected
                }
                // if error, can be ERROR_PIPE_LISTENING (536) --> Other side not connected, so we cannot read
                if matches!(code, 233 | 536) {
                    return Ok(None); // No data to read
                }
                return Err(anyhow::anyhow!("Failed to read message"));
            }
        }

        let msg_len = (&len_buf[..]).read_u32::<LittleEndian>()? as usize;
        if msg_len > consts::MAX_MESSAGE_SIZE {
            // Disconnect here, will do it again later, but no problem (will return an error that will not interfere with )
            return Err(anyhow::anyhow!("Message too large: {} bytes", msg_len));
        }

        let mut buf = vec![0u8; msg_len];
        unsafe {
            ReadFile(
                self.pipe_handle.get(),
                Some(&mut buf),
                Some(&mut read),
                None,
            )
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
                self.pipe_handle.get(),
                Some(&len_buf),
                Some(&mut written),
                None,
            )
            .ok()
            .context("Failed to write message length")?;
            // Ensure the entire length header is written
            if written != len_buf.len() as u32 {
                return Err(anyhow::anyhow!("Failed to write complete message length"));
            }

            WriteFile(self.pipe_handle.get(), Some(&buf), Some(&mut written), None)
                .ok()
                .context("Failed to write message body")?;
            // Ensure the entire message is written
            if written != buf.len() as u32 {
                return Err(anyhow::anyhow!("Failed to write complete message body"));
            }
        }

        Ok(())
    }

    fn process_msg(&self, msg: AuthRequest, auth_token: &str) {
        // Process the message, an if not valid simply discards it
        // Validate the message
        if let Err(e) = msg.validate() {
            error!("AuthRequest validation failed: {}", e);
            return;
        }
        if msg.auth_token != auth_token {
            error!("Invalid auth token: {}", msg.auth_token);
            return;
        }

        // Store so it can be processed later
        self.request.write().unwrap().replace(msg);
    }

    fn disconnect_pipe(&self) {
        // Disconnect the client, but do not destroy the Pipe itself
        unsafe {
            let _ = DisconnectNamedPipe(self.pipe_handle.get());
        }
        debug_dev!("Disconnected named pipe");
    }

    // function that will run a thread that will process incomming messages until stopped
}

impl Default for ChannelServer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ChannelServer {
    fn drop(&mut self) {
        // Not really needed, but better safe than sorry :)
        if self.pipe_handle.is_valid() {
            debug!("Dropping ChannelServer, cleaning up resources");
            self.pipe_handle.clear(); // Early drop
        }
    }
}

#[cfg(test)]
mod tests;
