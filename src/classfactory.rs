// classfactory.rs
use windows::{
    Win32::Foundation::{CLASS_E_NOAGGREGATION, E_INVALIDARG, E_NOINTERFACE},
    Win32::System::Com::{IClassFactory, IClassFactory_Impl},
    Win32::UI::Shell::{ICredentialProvider, ICredentialProviderFilter},
    core::*,
};

use crate::dll::{dll_add_ref, dll_release};

// Implementaciones concretas
use crate::credential::provider::UDSCredentialsProvider;
use crate::credential::filter::UDSCredentialsFilter;

#[implement(IClassFactory)]
pub struct ClassFactory;

impl ClassFactory {
    pub fn new() -> Self {
        Self
    }
}

#[allow(non_snake_case)]
impl IClassFactory_Impl for ClassFactory_Impl {
    fn CreateInstance(
        &self,
        punkouter: Ref<'_, IUnknown>,
        riid: *const GUID,
        ppvobject: *mut *mut core::ffi::c_void,
    ) -> Result<()> {
        unsafe {
            // Agregación no soportada
            if !punkouter.is_null() {
                return Err(CLASS_E_NOAGGREGATION.into());
            }
            // Validación de punteros
            if ppvobject.is_null() || riid.is_null() {
                return Err(E_INVALIDARG.into());
            }
            *ppvobject = core::ptr::null_mut();

            if *riid == ICredentialProvider::IID {
                // Instantiate the Credential Provider
                let iface: IUnknown = UDSCredentialsProvider::new().into();
                let ptr = iface.as_raw();
                core::mem::forget(iface); // transferimos la propiedad al caller
                *ppvobject = ptr as *mut _;
                return Ok(());
            }

            if *riid == ICredentialProviderFilter::IID {
                // Instantiate a ICredentialProviderFilter
                let iface: IUnknown = UDSCredentialsFilter::new().into();
                let ptr = iface.as_raw();
                core::mem::forget(iface);
                *ppvobject = ptr as *mut _;
                return Ok(());
            }

            Err(E_NOINTERFACE.into())
        }
    }

    fn LockServer(&self, f_lock: BOOL) -> Result<()> {
        if f_lock.as_bool() {
            dll_add_ref();
        } else {
            dll_release();
        }
        Ok(())
    }
}
