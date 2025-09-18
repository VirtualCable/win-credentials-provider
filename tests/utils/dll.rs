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
// The allow dead_codes is to prevent warnings about unused functions, because these are only
// used on integration tests

use windows::{
    Win32::{
        Foundation::HMODULE,
        System::LibraryLoader::{GetProcAddress, LoadLibraryW},
    },
    core::*,
};

use std::path::{Path, PathBuf};

/// DLL Name from package name (replaces '-' with '_')
fn dll_filename() -> String {
    format!("{}.dll", env!("CARGO_PKG_NAME").replace('-', "_"))
}

/// Returns the path to target/{debug|release}/{crate}.dll
fn dll_path() -> PathBuf {
    let mut path = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("target"));

    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push(dll_filename());
    path
}

#[allow(dead_code)]
pub fn load() -> HMODULE {
    let dll_file = dll_path();
    assert_file_exists(&dll_file);

    let wide_path = widestring::U16CString::from_str(dll_file.as_os_str().to_string_lossy())
        .expect("Could not convert DLL path to wide string");

    unsafe { LoadLibraryW(PCWSTR::from_raw(wide_path.as_ptr())).unwrap() }
}

#[allow(dead_code)]
pub fn get_symbol(module: &HMODULE, name: &str) -> Result<unsafe extern "system" fn() -> HRESULT> {
    let cstr = match std::ffi::CString::new(name) {
        Ok(cstr) => cstr,
        Err(_) => return Err(Error::from_thread()),
    };
    let pcstr = PCSTR::from_raw(cstr.as_ptr() as *const u8);

    if let Some(addr) = unsafe { GetProcAddress(*module, pcstr) } {
        #[allow(clippy::missing_transmute_annotations)]
        Ok(unsafe { std::mem::transmute(addr) })
    } else {
        Err(Error::from_thread())
    }
}

/// Asserts that a file exists at the given path.
fn assert_file_exists(path: &Path) {
    assert!(
        path.exists(),
        "Could not find the DLL in {:?}. Compile with `cargo build` or run `cargo test{}`",
        path,
        if cfg!(debug_assertions) {
            ""
        } else {
            " --release"
        }
    );
}
