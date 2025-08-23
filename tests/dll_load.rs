#![cfg(windows)]

mod utils;

use windows::Win32::Foundation::S_OK;

#[test]
fn can_load_and_call_dll_can_unload_now() {
    let lib = utils::dll::load();

    unsafe {
        let dll_can_unload_now = utils::dll::get_symbol(&lib, "DllCanUnloadNow").unwrap();

        // Llama y valida
        let hr = dll_can_unload_now();
        assert_eq!(hr, S_OK, "Unexpected HRESULT from DllCanUnloadNow: {hr:?}");
    }
}
