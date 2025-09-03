// Copyright (c) 2026 Virtual Cable S.L.U.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
//    * Redistributions of source code must retain the above copyright notice,
//      this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above copyright notice,
//      this list of conditions and the following disclaimer in the documentation
//      and/or other materials provided with the distribution.
//    * Neither the name of Virtual Cable S.L.U. nor the names of its contributors
//      may be used to endorse or promote products derived from this software
//      without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
/*!
Author: Adolfo Gómez, dkmaster at dkmon dot com
*/
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
                    // into_raw of Interface copies and transmutes the object, forgetting drop.
                    // So we transfer the property of hte object, that is on the Heap, to COM
                    *ppvobject = provider.into_raw();
                    Ok(())
                }
                ICredentialProviderFilter::IID => {
                    let filter: ICredentialProviderFilter = UDSCredentialsFilter::new().into();
                    // into_raw of Interface copies and transmutes the object, forgetting drop.
                    // So we transfer the property of the object, that is on the Heap, to COM
                    *ppvobject = filter.into_raw();
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
