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
use std::mem::zeroed;
use windows::Win32::Graphics::Gdi::{BITMAP, GetObjectW};

mod utils;
use win_cred_provider::credentials::types::UdsFieldId;


#[test]
fn test_get_bitmap_correct_field() -> windows::core::Result<()> {
    let factory = utils::com::ClassFactoryTest::new()?;
    let credential = factory.create_credential()?;

    let bitmap = unsafe { credential.GetBitmapValue(UdsFieldId::TileImage as u32) }?;

    let mut bmp: BITMAP = unsafe { zeroed() };

    unsafe {
        GetObjectW(
            bitmap.into(), // converts HBITMAP → HGDIOBJ
            std::mem::size_of::<BITMAP>() as i32,
            Some(&mut bmp as *mut _ as *mut core::ffi::c_void), // pointer as Option<*mut core::ffi::c_void>
        );
    }

    assert!(bmp.bmWidth == 128);
    assert!(bmp.bmHeight == 128);
    assert!(bmp.bmPlanes == 1);

    Ok(())
}

#[test]
fn test_get_bitmap_incorrect_field() -> windows::core::Result<()> {
    let factory = utils::com::ClassFactoryTest::new()?;
    let credential = factory.create_credential()?;

    let result = unsafe { credential.GetBitmapValue(9999) }; // Invalid field ID

    assert!(result.is_err());
    Ok(())
}
