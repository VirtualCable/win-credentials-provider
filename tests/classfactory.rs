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
#![cfg(windows)]
// Integration tests for COM class factory

mod utils;

use windows::{core::*, Win32::UI::Shell::{ICredentialProviderCredential, CPUS_LOGON}};

#[test]
fn test_class_factory_instantiates_provider() -> windows::core::Result<()> {
    let factory = utils::com::ClassFactoryTest::new()?;
    let provider = factory.create_provider()?;

    // Should work correctly if the class was correctly created..
    unsafe { provider.SetUsageScenario(CPUS_LOGON, 0) }?;

    Ok(())
}

#[test]
fn test_class_instantiates_filter() -> windows::core::Result<()> {
    let factory = utils::com::ClassFactoryTest::new()?;
    factory.create_filter()?;
    // let mut rgballow = BOOL(0);
    // let clsids = [CLSID_UDS_CREDENTIAL_PROVIDER];
    // let _ = unsafe { filter.Filter(Default::default(), 0, clsids.as_ptr(), &mut rgballow, 1) };

    Ok(())
}

#[test]
fn test_class_fails_other() -> windows::core::Result<()> {
    let factory = utils::com::ClassFactoryTest::new()?;
    let provider: Result<ICredentialProviderCredential> = factory.create_instance();
    assert!(provider.is_err());
    Ok(())
}
