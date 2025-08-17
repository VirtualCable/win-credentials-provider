// classfactory.rs
use windows::core::{implement, GUID, HRESULT, Interface, IUnknown, Result, Ref, BOOL};
use windows::Win32::System::Com::{IClassFactory, IClassFactory_Impl};
use windows::Win32::Foundation::{
    S_OK, E_NOINTERFACE, CLASS_E_NOAGGREGATION,
    // S_FALSE, CLASS_E_CLASSNOTAVAILABLE,  // si los necesitas
};

use crate::{uds_credential_provider, udscredential, udscredential_filter};

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
        // Ref representa un puntero COM que puede venir nulo en llamadas COM.
        // Si tu Ref tiene .is_null(), úsalo para detectar agregación.
        if punkouter.is_null() {
            // sin agregación: OK, seguimos
        } else {
            return Err(CLASS_E_NOAGGREGATION.into());
        }

        unsafe {
            // Limpia siempre el out param por seguridad
            *ppvobject = core::ptr::null_mut();

            // if *riid == udsprovider::UDSProvider::IID {
            //     let hr: HRESULT = udsprovider::UDSProvider::new().query_interface(riid, ppvobject);
            //     return if hr == S_OK { Ok(()) } else { Err(hr.into()) };
            // }

            // if *riid == udscredential_filter::UDSCredentialFilter::IID {
            //     let hr: HRESULT = udscredential_filter::UDSCredentialFilter::new().query_interface(riid, ppvobject);
            //     return if hr == S_OK { Ok(()) } else { Err(hr.into()) };
            // }
        }

        Err(E_NOINTERFACE.into())
    }

    fn LockServer(&self, f_lock: BOOL) -> Result<()> {
        // if f_lock.as_bool() {
        //     dll_add_ref();
        // } else {
        //     dll_release();
        // }
        Ok(())
    }
}
