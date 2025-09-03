use std::sync::{
    OnceLock, RwLock,
    atomic::{AtomicU32, Ordering},
};

use windows::{
    Win32::{
        Foundation::HINSTANCE,
        System::Registry::{HKEY, HKEY_LOCAL_MACHINE},
    },
    core::*,
};

use crate::debug_dev;

pub const CLSID_UDS_CREDENTIAL_PROVIDER: GUID =
    GUID::from_u128(0x6e3b975c_2cf3_11e6_88a9_10feed05884b);

pub const UDSACTOR_REG_HKEY: HKEY = HKEY_LOCAL_MACHINE;
pub const UDSACTOR_REG_PATH: PCWSTR = w!("SOFTWARE\\UDSActor");

pub const BROKER_CREDENTIAL_PREFIX: &str = "uds-"; // Broker credential prefix
pub const BROKER_CREDENTIAL_TOKEN_SIZE: usize = 48;
pub const BROKER_CREDENTIAL_KEY_SIZE: usize = 32;
pub const BROKER_CREDENTIAL_SIZE: usize =
    4 + BROKER_CREDENTIAL_TOKEN_SIZE + BROKER_CREDENTIAL_KEY_SIZE; // Broker credential size, "uds-" + ticket(48) + key(32)

// Global DLL References counter
pub static DLL_REF_COUNT: AtomicU32 = AtomicU32::new(0);

// Global HINSTANCE of the DLL
static DLL_INSTANCE: std::sync::OnceLock<SafeHInstance> = std::sync::OnceLock::new();

// Auth token
static AUTHTOKEN: OnceLock<RwLock<Option<String>>> = OnceLock::new();

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
