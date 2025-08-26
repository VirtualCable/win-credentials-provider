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
        Err(_) => return Err(Error::from_win32()),
    };
    let pcstr = PCSTR::from_raw(cstr.as_ptr() as *const u8);

    if let Some(addr) = unsafe { GetProcAddress(*module, pcstr) } {
        #[allow(clippy::missing_transmute_annotations)]
        Ok(unsafe { std::mem::transmute(addr) })
    } else {
        Err(Error::from_win32())
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
