use log::{error, info};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

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

static STOP_FLAG: OnceLock<AtomicBool> = OnceLock::new();

pub struct NamedPipe {
    handle: SafeHandle,
    auth_token: String,
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
impl NamedPipe {
    pub fn create(auth_token: &str) -> Result<Self> {
        let pipe_wide = widestring::U16CString::from_str(consts::PIPE_NAME)?;
        let pipe_wide_ptr = PCWSTR::from_raw(pipe_wide.as_ptr());

        let handle = unsafe {
            CreateNamedPipeW(
                pipe_wide_ptr,
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT,
                PIPE_UNLIMITED_INSTANCES,
                consts::PIPE_BUFFER,
                consts::PIPE_BUFFER,
                0,
                None,
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return Err(anyhow::anyhow!("Failed to create named pipe"));
        }

        Ok(Self {
            handle: SafeHandle::new(handle),
            auth_token: auth_token.to_string(),
        })
    }

    pub fn read_message<T: prost::Message + Default>(&self) -> Result<Option<T>> {
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
                if code == 232 || code == 536 {
                    return Ok(None); // No data to read
                }
                return Err(anyhow::anyhow!("Failed to read message length: {}", e));
            }
        }

        let msg_len = (&len_buf[..]).read_u32::<LittleEndian>()? as usize;
        if msg_len > consts::MAX_MESSAGE_SIZE {
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

    pub fn write_message<T: prost::Message>(&self, msg: &T) -> Result<()> {
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

            WriteFile(self.handle.get(), Some(&mut buf), Some(&mut written), None)
                .ok()
                .context("Failed to write message body")?;
        }

        Ok(())
    }

    pub fn process_msg(&self, msg: AuthRequest) {
        // Process the message, an if not valid simply discards it
        // Validate the message
        if let Err(e) = msg.validate() {
            error!("AuthRequest validation failed: {}", e);
            return;
        }

        // Here you would typically process the authentication request
        // For now, we will just return a dummy response
        let response = AuthResponse {
            protocol_version: consts::MAGIC_HEADER,
            status_code: 0, // 0 = OK
            error_message: String::new(),
        };

        // TODO: Insert the message in a processing queue

        if let Err(e) = self.write_message(&response) {
            error!("Failed to send AuthResponse: {}", e);
        }
    }

        

    // function that will run a thread that will process incomming messages until stopped
    pub fn start_message_processing(auth_token: &str) -> Option<std::thread::JoinHandle<()>> {
        let pipe = match NamedPipe::create(auth_token) {
            Ok(p) => p,
            Err(e) => {
                error!("Cannot create named pipe: {}", e);
                return None;
            }
        };
        let stop_flag = STOP_FLAG.get_or_init(|| AtomicBool::new(false));
        Some(std::thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match pipe.read_message::<AuthRequest>() {
                    Ok(msg) => {
                        match msg {
                            Some(msg) => {
                                debug_dev!("Received AuthRequest: {:?}", msg);
                                pipe.process_msg(msg);
                            }
                            None => {
                                std::thread::sleep(std::time::Duration::from_secs(1));
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error reading message: {}", e);
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                }
                // Process incoming messages
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, distr};

    use crate::{messages::auth::*, util::logger::setup_logging};

    // 64 char token for testing
    fn gen_auth_token() -> String {
        rand::rng()
            .sample_iter(&distr::Alphanumeric)
            .take(64)
            .map(char::from)
            .collect()
    }

    #[test]
    fn test_read_named_pipe_no_data() {
        setup_logging("debug");
        let token = gen_auth_token();
        let pipe = NamedPipe::create(&token).expect("Failed to create named pipe");
        match pipe.read_message::<AuthRequest>() {
            Ok(msg) => {
                if let Some(msg) = msg {
                    // Process the message
                    debug_dev!("Received AuthRequest: {:?}", msg);
                    match msg.validate() {
                        Ok(_) => {
                            debug_dev!("AuthRequest is valid");
                        }
                        Err(e) => {
                            debug_dev!("AuthRequest validation failed: {}", e);
                        }
                    }
                } else {
                    // No message received
                    debug_dev!("No AuthRequest received");
                }
            }
            Err(e) => {
                error!("Error reading message: {}", e);
                // Fail test
                panic!("Test failed because: {}", e);
            }
        }
    }

    #[test]
    fn test_start_message_processing_stops() {
        setup_logging("debug");
        let token = gen_auth_token();
        let thread_handle = NamedPipe::start_message_processing(&token).unwrap(); // fail on None
        std::thread::sleep(std::time::Duration::from_secs(1));
        STOP_FLAG.get().unwrap().store(true, Ordering::Relaxed);
        // In a couple of second at most should have stopped processing messages
        // Wait with a timeout
        use std::sync::Arc;
        let flag = Arc::new(AtomicBool::new(false));
        flag.store(false, Ordering::Relaxed);
        let flag_clone = Arc::clone(&flag);
        let control_thread = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(2));
            if !flag_clone.load(Ordering::Relaxed) {
                error!("Message processing thread did not stop in time");
                panic!("Test failed: Message processing thread did not stop in time");
            } else {
                info!("Message processing thread stopped as expected");
            }
        });
        thread_handle.join().expect("Thread panicked");
        flag.store(true, Ordering::Relaxed);
        control_thread.join().expect("Control thread panicked");
    }
}
