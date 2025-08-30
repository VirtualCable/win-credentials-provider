use std::sync::{
    OnceLock, RwLock,
    atomic::{AtomicU32, Ordering},
};

use windows::{Win32::Foundation::HINSTANCE, core::GUID};

use crate::debug_dev;

pub const CLSID_UDS_CREDENTIAL_PROVIDER: GUID =
    GUID::from_u128(0x6e3b975c_2cf3_11e6_88a9_10feed05884b);

// Gobal DLL References counter
pub static DLL_REF_COUNT: AtomicU32 = AtomicU32::new(0);

// Global HINSTANCE of the DLL
static DLL_INSTANCE: std::sync::OnceLock<SafeHInstance> = std::sync::OnceLock::new();

// Auth token
static AUTHTOKEN: OnceLock<RwLock<Option<String>>> = OnceLock::new();

// Broker info
static BROKER_INFO: OnceLock<RwLock<Option<BrokerInfo>>> = OnceLock::new();

// PIPE NAME
static PIPE_NAME: OnceLock<RwLock<Option<String>>> = OnceLock::new();

#[derive(Clone, Copy)]
struct SafeHInstance(HINSTANCE);

// I promise that HINSTANCE is safe for being shared across threads :)
unsafe impl Sync for SafeHInstance {}
unsafe impl Send for SafeHInstance {}

// Only invoked once (Uses OnceLock)
pub fn set_instance(h: HINSTANCE) {
    DLL_INSTANCE.set(SafeHInstance(h)).ok();
}

pub fn get_instance() -> HINSTANCE {
    DLL_INSTANCE.get().expect("DLL_INSTANCE not initialized").0
}

/// Increments the global DLL reference count
pub fn dll_add_ref() {
    DLL_REF_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Decrements the global DLL reference count
pub fn dll_release() {
    DLL_REF_COUNT.fetch_sub(1, Ordering::SeqCst);
}

pub fn set_auth_token(token: String) {
    AUTHTOKEN
        .get_or_init(|| RwLock::new(Some(String::new())))
        .write()
        .unwrap()
        .replace(token);
}

pub fn get_auth_token() -> Option<String> {
    AUTHTOKEN
        .get()
        .and_then(|lock| lock.read().unwrap().clone())
}

#[derive(Clone)]
pub struct BrokerInfo {
    url: String,
    verify_ssl: bool,
}

impl BrokerInfo {
    pub fn new(url: String, verify_ssl: bool) -> Self {
        Self { url, verify_ssl }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn verify_ssl(&self) -> bool {
        self.verify_ssl
    }
}

impl Default for BrokerInfo {
    fn default() -> Self {
        Self {
            url: String::new(),
            verify_ssl: true,
        }
    }
}

pub fn set_broker_info(url: &str, verify_ssl: bool) {
    BROKER_INFO
        .get_or_init(|| RwLock::new(Some(BrokerInfo::default())))
        .write()
        .unwrap()
        .replace(BrokerInfo::new(url.to_string(), verify_ssl));
}

pub fn get_broker_info() -> Option<BrokerInfo> {
    BROKER_INFO
        .get()
        .and_then(|lock| lock.read().unwrap().clone())
}

#[cfg(test)]
pub fn reset_broker_info() {
    BROKER_INFO
        .get_or_init(|| RwLock::new(Some(BrokerInfo::default())))
        .write()
        .unwrap()
        .take();
}

pub fn get_pipe_name() -> String {
    let name = PIPE_NAME
        .get()
        .and_then(|lock| lock.read().unwrap().clone())
        .unwrap_or(crate::messages::consts::PIPE_NAME.to_string());
    debug_dev!("Using pipe name: {}", name);
    name
}

pub fn set_pipe_name(name: &str) {
    debug_dev!("Setting pipe name: {}", name);
    // If PIPE_NAME is not initialized, set it
    PIPE_NAME
        .get_or_init(|| RwLock::new(Some(String::new())))
        .write()
        .unwrap()
        .replace(name.to_string());
}
