#![cfg(windows)]

use std::path::{Path, PathBuf};

use libloading::{Library, Symbol};

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

pub fn load() -> Library {
    let dll_file = dll_path();
    assert_file_exists(&dll_file);

    unsafe {
        Library::new(&dll_file).unwrap_or_else(|e| panic!("Could not find DLL {:?}: {e}", dll_file))
    }
}

pub fn get<'a, T>(lib: &'a Library, name: &str) -> Symbol<'a, T> {
    unsafe {
        lib.get(name.as_bytes())
            .unwrap_or_else(|e| panic!("Could not find '{name}' in the DLL: {e}"))
    }
}

/// Friendly error message if the file does not exist
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
