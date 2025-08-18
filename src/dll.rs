use std::sync::atomic::{AtomicU32, Ordering};

// Contador global del servidor COM
pub static DLL_REF_COUNT: AtomicU32 = AtomicU32::new(0);

/// Incrementa el contador global
pub fn dll_add_ref() {
    DLL_REF_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Decrementa el contador global
pub fn dll_release() {
    DLL_REF_COUNT.fetch_sub(1, Ordering::SeqCst);
}
