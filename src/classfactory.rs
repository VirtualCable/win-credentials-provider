// classfactory.rs
use windows::core::*;
use windows::Win32::Foundation::{CLASS_E_NOAGGREGATION, E_INVALIDARG, E_NOINTERFACE};
use windows::Win32::System::Com::{IClassFactory, IClassFactory_Impl};

use crate::dll::{dll_add_ref, dll_release};

// Interfaces (tus bindings)
use crate::com::i_credential_provider::ICredentialProvider;
use crate::com::i_credential_provider_filter::ICredentialProviderFilter;

// Implementaciones concretas
use crate::uds_credential_provider::UDSCredentialsProvider;
use crate::udscredential_filter::UDSCredentialsFilter;

#[implement(IClassFactory)]
pub struct ClassFactory;

impl ClassFactory {
    pub fn new() -> Self { Self }
}

#[allow(non_snake_case)]
impl IClassFactory_Impl for ClassFactory_Impl  {
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

            // Igual que en el C++: decidir por IID qué objeto se instancia
            if *riid == ICredentialProvider::IID {
                // Instanciar el Credential Provider y devolverlo como ICredentialProvider
                let iface: ICredentialProvider = UDSCredentialsProvider::new().into();
                let ptr = iface.as_raw();
                core::mem::forget(iface); // transferimos la propiedad al caller
                *ppvobject = ptr as *mut _;
                return Ok(());
            }

            if *riid == ICredentialProviderFilter::IID {
                // Instanciar el Credential Filter y devolverlo como ICredentialProviderFilter
                let iface: ICredentialProviderFilter = UDSCredentialsFilter::new().into();
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
