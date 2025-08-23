use std::sync::atomic::Ordering;

use windows::Win32::Foundation::{CLASS_E_CLASSNOTAVAILABLE, HINSTANCE, S_FALSE, S_OK};
use windows::Win32::System::Com::IClassFactory;
use windows::Win32::System::LibraryLoader::DisableThreadLibraryCalls;
use windows::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH,
};
use windows::core::*;

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(
    hinst_dll: HINSTANCE,
    fdw_reason: u32,
    _lp_reserved: *mut core::ffi::c_void,
) -> BOOL {
    // Store the instance for later retrieval
    dll::set_instance(hinst_dll);
    unsafe {
        match fdw_reason {
            DLL_PROCESS_ATTACH => {
                let _ = DisableThreadLibraryCalls(hinst_dll.into());
                // Aquí podrías poner setup_logging("info") si quieres logs desde el arranque
            }
            DLL_PROCESS_DETACH => {
                // Limpieza si aplica
            }
            DLL_THREAD_ATTACH => {}
            DLL_THREAD_DETACH => {}
            _ => {}
        }
    }
    BOOL::from(true)
}

#[unsafe(no_mangle)]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    if crate::dll::DLL_REF_COUNT.load(Ordering::SeqCst) == 0 {
        S_OK
    } else {
        S_FALSE
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut core::ffi::c_void,
) -> HRESULT {
    util::logger::setup_logging("info");
    unsafe {
        if *rclsid != crate::credential::provider::CLSID_UDS_CREDENTIAL_PROVIDER {
            return CLASS_E_CLASSNOTAVAILABLE;
        }

        // Instanciamos el objeto COM que implementa IClassFactory
        let factory: IClassFactory = crate::classfactory::ClassFactory::new().into();
        factory.query(riid, ppv)
    }
}

// ======== Modules ========
// Public to use them in the integration tests
pub mod classfactory;
pub mod credential;
pub mod dll;
pub mod messages;
pub mod util;
