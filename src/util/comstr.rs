use std::{mem, ptr};
use widestring::U16CString;

use windows::{
    Win32::{
        Security::Authentication::Identity::{LSA_STRING, LSA_UNICODE_STRING},
        System::Com::CoTaskMemAlloc,
    },
    core::{PCSTR, PCWSTR, PSTR, PWSTR},
};

#[derive(Debug)]
pub enum AllocPwstrError {
    InvalidString,
    AllocationFailed,
}

#[allow(dead_code)]
pub fn alloc_pwstr(s: &str) -> Result<PWSTR, AllocPwstrError> {
    let wide = U16CString::from_str(s).map_err(|_| AllocPwstrError::InvalidString)?;
    let len = wide.len();

    unsafe {
        let mem = CoTaskMemAlloc(len * mem::size_of::<u16>()) as *mut u16;
        if mem.is_null() {
            return Err(AllocPwstrError::AllocationFailed);
        }
        ptr::copy_nonoverlapping(wide.as_ptr(), mem, len);
        Ok(PWSTR(mem))
    }
}

pub fn pcwstr_to_string(pcwstr: PCWSTR) -> String {
    if pcwstr.is_null() {
        return String::new();
    }

    unsafe {
        // Interpreta el puntero como una U16CStr terminada en 0
        let u16_cstr = widestring::U16CStr::from_ptr_str(pcwstr.0);
        // Convierte directamente a String (UTF‑8), con reemplazo si hay caracteres inválidos
        u16_cstr.to_string_lossy()
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_pwstr() {
        let s = "Hello, world!";
        let pwstr = alloc_pwstr(s).expect("Failed to allocate PWSTR");
        let converted = pcwstr_to_string(PCWSTR(pwstr.0));
        assert_eq!(s, converted);
        unsafe {
            windows::Win32::System::Com::CoTaskMemFree(Some(pwstr.0 as _));
        }
    }

    #[test]
    fn test_lsa_unicode_string_owned() {
        let s = "Test String";
        let lsa_owned = LsaUnicodeString::new(s);
        let lsa_ref = lsa_owned.as_lsa();
        let converted = lsa_unicode_string_to_string(lsa_ref);
        assert_eq!(s, converted);
    }
}
