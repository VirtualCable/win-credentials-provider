#![cfg(windows)]

mod common;

use windows::Win32::Foundation::S_OK;
use windows::core::HRESULT;

#[test]
fn can_load_and_call_dll_can_unload_now() {
    let lib = common::dll_load();

    unsafe {
        let dll_can_unload_now =
            common::dll_get::<unsafe extern "system" fn() -> HRESULT>(&lib, "DllCanUnloadNow");

        // Llama y valida
        let hr = dll_can_unload_now();
        assert_eq!(hr, S_OK, "Unexpected HRESULT from DllCanUnloadNow: {hr:?}");
    }
}
