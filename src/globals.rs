use std::sync::{
    OnceLock, RwLock,
    atomic::{AtomicU32, Ordering},
};

use windows::Win32::Foundation::HINSTANCE;

// Gobal DLL References counter
pub static DLL_REF_COUNT: AtomicU32 = AtomicU32::new(0);

// Global HINSTANCE of the DLL
#[derive(Clone, Copy)]
struct SafeHInstance(HINSTANCE);

// I promise that HINSTANCE is safe for being shared across threads :)
unsafe impl Sync for SafeHInstance {}
unsafe impl Send for SafeHInstance {}

static DLL_INSTANCE: std::sync::OnceLock<SafeHInstance> = std::sync::OnceLock::new();

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

// Configuration parameters
static CONFIG_AUTHTOKEN: OnceLock<RwLock<Option<String>>> = OnceLock::new();

pub fn set_auth_token(token: String) {
    CONFIG_AUTHTOKEN.get_or_init(|| RwLock::new(Some(token)));
}

pub fn get_auth_token() -> Option<String> {
    CONFIG_AUTHTOKEN
        .get()
        .and_then(|lock| lock.read().unwrap().clone())
}
