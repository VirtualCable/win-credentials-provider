// dll.rs
use std::sync::atomic::{AtomicU32, Ordering};

use windows::core::{GUID, HRESULT, IUnknown};
use windows::Win32::Foundation::{
    CLASS_E_CLASSNOTAVAILABLE, E_NOINTERFACE, E_POINTER, S_FALSE, S_OK,
};
use windows::Win32::System::Com::IClassFactory;

use crate::{classfactory::ClassFactory, udscredential_filter, uds_credential_provider};

// Contador global del servidor COM (para LockServer / DllCanUnloadNow)
static DLL_REF_COUNT: AtomicU32 = AtomicU32::new(0);

/// Incrementa el contador global
pub fn dll_add_ref() {
    DLL_REF_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Decrementa el contador global
pub fn dll_release() {
    DLL_REF_COUNT.fetch_sub(1, Ordering::SeqCst);
}

/// Export COM: consulta si se puede descargar la DLL
#[unsafe(no_mangle)]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    if DLL_REF_COUNT.load(Ordering::SeqCst) == 0 {
        S_OK
    } else {
        S_FALSE
    }
}

/// Export COM: devuelve una IClassFactory para el CLSID soportado
#[unsafe(no_mangle)]
pub extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut core::ffi::c_void,
) -> HRESULT {
    unsafe {
        // Validación básica de punteros y saneo de out-param
        if ppv.is_null() {
            return E_POINTER;
        }
        *ppv = core::ptr::null_mut();
        if rclsid.is_null() || riid.is_null() {
            return E_POINTER;
        }

        let clsid = *rclsid;

        // Sustituye por tus constantes reales de CLSID
        let soportado = clsid == uds_credential_provider::CLSID || clsid == udscredential_filter::CLSID;

        if !soportado {
            return CLASS_E_CLASSNOTAVAILABLE;
        }

        // Crea la factory (gracias al #[implement(IClassFactory)] puedes hacer into())
        let factory: IClassFactory = ClassFactory::new().into();

        if *riid == IClassFactory::IID {
            let ptr = factory.as_raw();
            std::mem::forget(factory); // transferimos propiedad al cliente
            *ppv = ptr as *mut _;
            return S_OK;
        }

        if *riid == IUnknown::IID {
            match factory.cast::<IUnknown>() {
                Ok(u) => {
                    let ptr = u.as_raw();
                    std::mem::forget(u);
                    *ppv = ptr as *mut _;
                    S_OK
                }
                Err(e) => e.code(),
            }
        } else {
            E_NOINTERFACE
        }
    }
}
