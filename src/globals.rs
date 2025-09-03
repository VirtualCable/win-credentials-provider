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

use std::sync::{
    OnceLock, RwLock,
    atomic::{AtomicU32, Ordering},
};

use windows::{
    Win32::{
        Foundation::HINSTANCE,
        System::Registry::{HKEY, HKEY_LOCAL_MACHINE},
    },
    core::*,
};

use crate::debug_dev;

pub const CLSID_UDS_CREDENTIAL_PROVIDER: GUID =
    GUID::from_u128(0x6e3b975c_2cf3_11e6_88a9_10feed05884b);

pub const UDSACTOR_REG_HKEY: HKEY = HKEY_LOCAL_MACHINE;
pub const UDSACTOR_REG_PATH: PCWSTR = w!("SOFTWARE\\UDSActor");

pub const BROKER_CREDENTIAL_PREFIX: &str = "uds-"; // Broker credential prefix
// The ticket length must match the one defined on UDSBroker
pub const BROKER_CREDENTIAL_TICKET_SIZE: usize = 48;
pub const BROKER_CREDENTIAL_KEY_SIZE: usize = 32;
pub const BROKER_CREDENTIAL_SIZE: usize =
    4 + BROKER_CREDENTIAL_TICKET_SIZE + BROKER_CREDENTIAL_KEY_SIZE; // Broker credential size, "uds-" + ticket(48) + key(32)
pub const BROKER_URL_PATH: &str = "/uds/rest/actor/v3/ticket";

// Global DLL References counter
pub static DLL_REF_COUNT: AtomicU32 = AtomicU32::new(0);

// Global HINSTANCE of the DLL
static DLL_INSTANCE: std::sync::OnceLock<SafeHInstance> = std::sync::OnceLock::new();

// PIPE NAME
static PIPE_NAME: OnceLock<RwLock<Option<String>>> = OnceLock::new();

#[derive(Clone, Copy)]
struct SafeHInstance(HINSTANCE);

// I promise that HINSTANCE is safe for being shared across threads :)
unsafe impl Sync for SafeHInstance {}
unsafe impl Send for SafeHInstance {}

// Only invoked once (Uses OnceLock)
pub fn set_instance(h: HINSTANCE) {
    DLL_INSTANCE.set(SafeHInstance(h)).ok();
}

pub fn get_instance() -> HINSTANCE {
    DLL_INSTANCE.get().expect("DLL_INSTANCE not initialized").0
}

/// Increments the global DLL reference count
pub fn dll_add_ref() {
    DLL_REF_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Decrements the global DLL reference count
pub fn dll_release() {
    DLL_REF_COUNT.fetch_sub(1, Ordering::SeqCst);
}

pub fn get_pipe_name() -> String {
    let name = PIPE_NAME
        .get()
        .and_then(|lock| lock.read().unwrap().clone())
        .unwrap_or(crate::messages::consts::PIPE_NAME.to_string());
    debug_dev!("Using pipe name: {}", name);
    name
}

pub fn set_pipe_name(name: &str) {
    debug_dev!("Setting pipe name: {}", name);
    // If PIPE_NAME is not initialized, set it
    PIPE_NAME
        .get_or_init(|| RwLock::new(Some(String::new())))
        .write()
        .unwrap()
        .replace(name.to_string());
}
