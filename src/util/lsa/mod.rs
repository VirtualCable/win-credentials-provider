use widestring::U16CString;
use windows::{
    Win32::{
        Foundation::{E_OUTOFMEMORY, HANDLE},
        Security::Authentication::Identity::{
            KERB_INTERACTIVE_UNLOCK_LOGON, LSA_STRING, LSA_UNICODE_STRING, LsaConnectUntrusted,
            LsaDeregisterLogonProcess, LsaLookupAuthenticationPackage, NEGOSSP_NAME_A,
        },
        System::Com::CoTaskMemAlloc,
    },
    core::*,
};

use crate::debug_dev;

pub struct LsaUnicodeString {
    _keepalive: U16CString,  // Dueño de la cadena UTF‑16 + terminador
    lsa: LSA_UNICODE_STRING, // Estructura con puntero a `wide`
}

impl LsaUnicodeString {
    pub fn new(s: &str) -> Self {
        let wide = U16CString::from_str(s).expect("UTF‑16 inválido");
        let len_bytes = (wide.len() * 2) as u16; // len() does not count the null terminator
        let lsa = LSA_UNICODE_STRING {
            Length: len_bytes,
            MaximumLength: len_bytes,
            Buffer: PWSTR(wide.as_ptr() as *mut _),
        };
        Self {
            _keepalive: wide,
            lsa,
        }
    }

    pub fn from_pcwstr(pwstr: PCWSTR) -> Self {
        // Look for length of PWSTR before anything, to ensure we can use it
        {
            let mut len = 0;
            while unsafe { *pwstr.0.add(len) } != 0 && len < u16::MAX as usize {
                len += 1;
            }
            len
        };
        let wide = unsafe { U16CString::from_ptr_str(pwstr.0) };
        let len_bytes = (wide.len() * 2) as u16; // len() does not count the null terminator
        let lsa = LSA_UNICODE_STRING {
            Length: len_bytes,
            MaximumLength: len_bytes,
            Buffer: PWSTR(wide.as_ptr() as *mut _),
        };
        Self {
            _keepalive: wide,
            lsa,
        }
    }

    pub fn as_lsa(&self) -> &LSA_UNICODE_STRING {
        &self.lsa
    }
}

pub struct LsaString {
    _keepalive: String,
    lsa: LSA_STRING,
}

impl LsaString {
    pub fn new(s: &str) -> Self {
        let keepalive = s.to_string();
        let len = keepalive.len() as u16;
        let lsa = LSA_STRING {
            Length: len,
            MaximumLength: len,
            Buffer: PSTR(keepalive.as_ptr() as *mut u8),
        };
        Self {
            _keepalive: keepalive,
            lsa,
        }
    }

    pub fn from_pcstr(pcstr: PCSTR) -> Self {
        let mut len = 0;
        while unsafe { *pcstr.0.add(len) } != 0 && len < u16::MAX as usize {
            len += 1;
        }
        let slice = unsafe { std::slice::from_raw_parts(pcstr.0, len) };
        let keepalive = String::from_utf8_lossy(slice).to_string();
        let len = keepalive.len() as u16;
        let lsa = LSA_STRING {
            Length: len,
            MaximumLength: len,
            Buffer: PSTR(keepalive.as_ptr() as *mut u8),
        };
        Self {
            _keepalive: keepalive,
            lsa,
        }
    }

    pub fn as_lsa(&self) -> &LSA_STRING {
        &self.lsa
    }
}

pub fn lsa_unicode_string_to_string(lsa: &LSA_UNICODE_STRING) -> String {
    if lsa.Length == 0 || lsa.Buffer.is_null() {
        return String::new();
    }
    let len_u16 = (lsa.Length / 2) as usize; // Length en bytes → chars
    unsafe {
        let slice = std::slice::from_raw_parts(lsa.Buffer.0, len_u16);
        // Creamos una copia con terminador
        let mut vec = slice.to_vec();
        vec.push(0); // null terminator UTF‑16

        widestring::U16CString::from_vec(vec)
            .unwrap_or_default()
            .to_string_lossy()
    }
}

/// Packs a `KERB_INTERACTIVE_UNLOCK_LOGON` struct and its strings into a single buffer allocation.
///
/// WinLogon and LSA consume "packed" KERB_INTERACTIVE_UNLOCK_LOGONs.
/// This is basically the struct + all strings concatenated on a single buffer alloc.
///
/// # Safety
/// The caller must ensure that the provided `logon` reference is valid and that the returned pointer is properly managed and freed.
/// Normally, the returned value should be used as output to COM so COM will release it.
pub unsafe fn kerb_interactive_unlock_logon_pack(
    logon: &KERB_INTERACTIVE_UNLOCK_LOGON,
) -> windows::core::Result<(*mut u8, u32)> {
    let pkil_in = &logon.Logon;

    // Total length: struct + length of each string (in bytes)
    let cb_total = std::mem::size_of::<KERB_INTERACTIVE_UNLOCK_LOGON>()
        + pkil_in.UserName.Length as usize
        + pkil_in.Password.Length as usize
        + pkil_in.LogonDomainName.Length as usize;

    let pkiul_out = unsafe { CoTaskMemAlloc(cb_total).cast::<KERB_INTERACTIVE_UNLOCK_LOGON>() };
    if pkiul_out.is_null() {
        return Err(E_OUTOFMEMORY.into());
    }
    // 0xFF mem for easier debug in case of problems
    unsafe {
        std::ptr::write_bytes(pkiul_out.cast::<u8>(), 0xFF, cb_total);
    }

    // ZeroMemory(&pkiulOut->LogonId, sizeof(LUID));
    unsafe { (*pkiul_out).LogonId = Default::default() };

    // Cursor for copying strings at the end of the struct
    let mut pb_buffer = unsafe {
        (pkiul_out.cast::<u8>()).add(std::mem::size_of::<KERB_INTERACTIVE_UNLOCK_LOGON>())
    };

    // Basic copy of fixed fields
    unsafe {
        (*pkiul_out).Logon.MessageType = pkil_in.MessageType;
    }

    // Internal helper to copy an LSA_UNICODE_STRING
    fn copy_and_update_ref(
        src: &LSA_UNICODE_STRING,
        dst_struct: &mut LSA_UNICODE_STRING,
        base: *mut u8,
        buf_cursor: &mut *mut u8,
    ) {
        // Copy bytes of the string
        unsafe {
            std::ptr::copy_nonoverlapping(
                src.Buffer.0,
                *buf_cursor as *mut u16,
                (src.Length / 2) as usize,
            )
        };
        debug_assert!(src.Length as usize <= src.MaximumLength as usize);
        debug_assert!(src.Length & 1 == 0); // Is even

        *dst_struct = *src;
        // Offset relative to the start of the struct
        dst_struct.Buffer = PWSTR(unsafe { (*buf_cursor).offset_from(base) as *mut u16 });

        debug_assert!(!dst_struct.Buffer.is_null());

        // Advance the cursor
        *buf_cursor = unsafe { (*buf_cursor).add(src.Length as usize) };
    }

    // Copy the three strings
    copy_and_update_ref(
        &pkil_in.LogonDomainName,
        unsafe { &mut (*pkiul_out).Logon.LogonDomainName },
        pkiul_out.cast(),
        &mut pb_buffer,
    );
    copy_and_update_ref(
        &pkil_in.UserName,
        unsafe { &mut (*pkiul_out).Logon.UserName },
        pkiul_out.cast(),
        &mut pb_buffer,
    );
    copy_and_update_ref(
        &pkil_in.Password,
        unsafe { &mut (*pkiul_out).Logon.Password },
        pkiul_out.cast(),
        &mut pb_buffer,
    );

    // pb_buffer should be point to base + cb_total
    debug_assert!(pb_buffer as usize == (pkiul_out as usize + cb_total));

    Ok((pkiul_out.cast(), cb_total as u32))
}

// As de documentation and samples says, the struct received comes as we pack it
/// Unpacks a packed `KERB_INTERACTIVE_UNLOCK_LOGON` struct in place, updating string pointers to point to their actual locations within the buffer.
///
/// # Safety
/// The caller must ensure that `base` points to a valid buffer containing a packed `KERB_INTERACTIVE_UNLOCK_LOGON` struct,
pub unsafe fn kerb_interactive_unlock_logon_unpack_in_place<'a>(
    base: *mut u8,
) -> &'a mut KERB_INTERACTIVE_UNLOCK_LOGON {
    let pkiul = base.cast::<KERB_INTERACTIVE_UNLOCK_LOGON>();

    unsafe {
        if !(*pkiul).Logon.LogonDomainName.Buffer.is_null() {
            debug_dev!(
                "Unpacking LogonDomainName; {:?}",
                (*pkiul).Logon.LogonDomainName.Buffer
            );
            (*pkiul).Logon.LogonDomainName.Buffer = PWSTR(
                base.add((*pkiul).Logon.LogonDomainName.Buffer.0 as usize)
                    .cast(),
            );
            debug_dev!(
                "Unpacking LogonDomainName After; {:?}",
                (*pkiul).Logon.LogonDomainName.Buffer
            );
        }
        if !(*pkiul).Logon.UserName.Buffer.is_null() {
            (*pkiul).Logon.UserName.Buffer =
                PWSTR(base.add((*pkiul).Logon.UserName.Buffer.0 as usize).cast());
        }
        if !(*pkiul).Logon.Password.Buffer.is_null() {
            (*pkiul).Logon.Password.Buffer =
                PWSTR(base.add((*pkiul).Logon.Password.Buffer.0 as usize).cast());
        }
    }
    unsafe { &mut *pkiul }
}

pub fn retrieve_negotiate_auth_package() -> windows::core::Result<u32> {
    let mut lsahandle = HANDLE::default();
    let status = unsafe { LsaConnectUntrusted(&mut lsahandle) };

    if status.to_hresult().is_err() {
        return Err(status.into());
    }
    let kerb_name = LsaString::from_pcstr(NEGOSSP_NAME_A);

    let mut authenticationpackage = 0u32;
    // Convert LSA_UNICODE_STRING to LSA_STRING
    let status = unsafe {
        LsaLookupAuthenticationPackage(lsahandle, kerb_name.as_lsa(), &mut authenticationpackage)
    };
    _ = unsafe { LsaDeregisterLogonProcess(lsahandle) };
    if status.to_hresult().is_err() {
        Err(status.into())
    } else {
        Ok(authenticationpackage)
    }
}

#[cfg(test)]
mod tests;
