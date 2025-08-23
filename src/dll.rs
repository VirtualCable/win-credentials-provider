use std::sync::atomic::{AtomicU32, Ordering};

use windows::Win32::Foundation::HINSTANCE;

// Contador global del servidor COM
pub static DLL_REF_COUNT: AtomicU32 = AtomicU32::new(0);
// Global HINSTANCE of the DLL

#[derive(Clone, Copy)]
struct SafeHInstance(HINSTANCE);

// Tú garantizas que acceder a este puntero desde varios hilos es seguro:
unsafe impl Sync for SafeHInstance {}
unsafe impl Send for SafeHInstance {}

static DLL_INSTANCE: std::sync::OnceLock<SafeHInstance> = std::sync::OnceLock::new();

pub fn set_instance(h: HINSTANCE) {
    DLL_INSTANCE.set(SafeHInstance(h)).ok();
}

pub fn get_instance() -> HINSTANCE {
    DLL_INSTANCE.get().expect("DLL_INSTANCE no inicializado").0
}

/// Incrementa el contador global
pub fn dll_add_ref() {
    DLL_REF_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Decrementa el contador global
pub fn dll_release() {
    DLL_REF_COUNT.fetch_sub(1, Ordering::SeqCst);
}
