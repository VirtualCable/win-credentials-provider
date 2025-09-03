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
    globals::set_instance(hinst_dll);
    unsafe {
        match fdw_reason {
            DLL_PROCESS_ATTACH => {
                let _ = DisableThreadLibraryCalls(hinst_dll.into());
                utils::log::setup_logging("info");
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
    if crate::globals::DLL_REF_COUNT.load(Ordering::SeqCst) == 0 {
        S_OK
    } else {
        S_FALSE
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)] // System calls cannot be unsafe :)
#[unsafe(no_mangle)]
pub extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut core::ffi::c_void,
) -> HRESULT {
    unsafe {
        if *rclsid != crate::globals::CLSID_UDS_CREDENTIAL_PROVIDER {
            return CLASS_E_CLASSNOTAVAILABLE;
        }

        // Instanciamos el objeto COM que implementa IClassFactory
        let factory: IClassFactory = crate::classfactory::ClassFactory::new().into();
        factory.query(riid, ppv)
    }
}

// ======== Modules ========
// Public to use them in the integration tests
pub mod broker;
pub mod classfactory;
pub mod credentials;
pub mod globals;
pub mod messages;
pub mod utils;

#[cfg(test)]
pub mod test_utils;
