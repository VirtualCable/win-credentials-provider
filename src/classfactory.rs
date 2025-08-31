// classfactory.rs
use windows::{
    Win32::Foundation::{CLASS_E_NOAGGREGATION, E_INVALIDARG, E_NOINTERFACE},
    Win32::System::Com::{IClassFactory, IClassFactory_Impl},
    Win32::UI::Shell::{ICredentialProvider, ICredentialProviderFilter},
    core::*,
};

use crate::globals::{dll_add_ref, dll_release};

// Implementaciones concretas
use crate::credentials::filter::UDSCredentialsFilter;
use crate::credentials::provider::UDSCredentialsProvider;

#[implement(IClassFactory)]
pub struct ClassFactory;

impl ClassFactory {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ClassFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(non_snake_case)]
impl IClassFactory_Impl for ClassFactory_Impl {
    // COM need the signature as is. Cannot mark as unsafe
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn CreateInstance(
        &self,
        punkouter: Ref<'_, IUnknown>,
        riid: *const GUID,
        ppvobject: *mut *mut core::ffi::c_void,
    ) -> Result<()> {
        // Aggregation not supported
        if !punkouter.is_null() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }
        // Pointer validation
        if ppvobject.is_null() || riid.is_null() {
            return Err(E_INVALIDARG.into());
        }
        unsafe {
            *ppvobject = core::ptr::null_mut();

            match *riid {
                ICredentialProvider::IID => {
                    let provider: ICredentialProvider = UDSCredentialsProvider::new().into();
                    *ppvobject = std::mem::transmute::<ICredentialProvider, *mut core::ffi::c_void>(
                        provider,
                    );
                    Ok(())
                }
                ICredentialProviderFilter::IID => {
                    let filter: ICredentialProviderFilter = UDSCredentialsFilter::new().into();
                    // `transmute()` is needed to return the real object
                    *ppvobject = std::mem::transmute::<
                        ICredentialProviderFilter,
                        *mut core::ffi::c_void,
                    >(filter);
                    Ok(())
                }
                _ => Err(E_NOINTERFACE.into()),
            }
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
