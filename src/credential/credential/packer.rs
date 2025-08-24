use windows::{
    Win32::{
        Foundation::E_OUTOFMEMORY,
        Security::Authentication::Identity::{KERB_INTERACTIVE_UNLOCK_LOGON, LSA_UNICODE_STRING},
        System::Com::CoTaskMemAlloc,
    },
    core::*,
};

use crate::debug_dev;

// As the documentation:
// WinLogon and LSA consume "packed" KERB_INTERACTIVE_UNLOCK_LOGONs
// This is basically the struct + all strings concatenated on a single buffer alloc
pub fn kerb_interactive_unlock_logon_pack(
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
    // 0xFF mem for easier debug
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
    unsafe { (*pkiul_out).Logon.MessageType = (*pkil_in).MessageType; }

    // Internal helper to copy an LSA_UNICODE_STRING
    fn copy_unicode_string(
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

        *dst_struct = *src;
        // Offset relative to the start of the struct
        dst_struct.Buffer = PWSTR(unsafe { (*buf_cursor).offset_from(base) as isize as *mut u16 });

        // Advance the cursor
        *buf_cursor = unsafe { (*buf_cursor).add(src.Length as usize) };
    }

    // Copy the three strings
    copy_unicode_string(
        &pkil_in.LogonDomainName,
        unsafe { &mut (*pkiul_out).Logon.LogonDomainName },
        pkiul_out.cast(),
        &mut pb_buffer,
    );
    copy_unicode_string(
        &pkil_in.UserName,
        unsafe { &mut (*pkiul_out).Logon.UserName },
        pkiul_out.cast(),
        &mut pb_buffer,
    );
    copy_unicode_string(
        &pkil_in.Password,
        unsafe { &mut (*pkiul_out).Logon.Password },
        pkiul_out.cast(),
        &mut pb_buffer,
    );

    // pb_buffer should be point to base + cb_total
    debug_assert!(pb_buffer as usize == (pkiul_out as usize + cb_total));

    Ok((pkiul_out.cast(), cb_total as u32))
}

// As de documentation and samples sayas, the struct received comes as we pack it
pub fn kerb_interactive_unlock_logon_unpack_in_place(pkiul: *mut KERB_INTERACTIVE_UNLOCK_LOGON) {
    let base = pkiul.cast::<u8>();

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
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::util::{
        comstr::{LsaUnicodeStringOwned, lsa_unicode_string_to_string},
        logger::setup_logging,
    };

    use windows::Win32::Security::Authentication::Identity::{
        KERB_INTERACTIVE_LOGON, KerbInteractiveLogon,
    };

    #[test]
    fn test_kerb_interactive_unlock_logon_pack() {
        let _lsa_user = LsaUnicodeStringOwned::new("user5");
        let _lsa_pass = LsaUnicodeStringOwned::new("passw6");
        let _lsa_domain = LsaUnicodeStringOwned::new("dom4");
        // Create a sample KERB_INTERACTIVE_UNLOCK_LOGON
        let logon = KERB_INTERACTIVE_UNLOCK_LOGON {
            Logon: KERB_INTERACTIVE_LOGON {
                MessageType: KerbInteractiveLogon,
                LogonDomainName: *_lsa_domain.as_lsa(),
                UserName: *_lsa_user.as_lsa(),
                Password: *_lsa_pass.as_lsa(),
            },
            LogonId: Default::default(),
        };

        // Pack the logon
        let (packed, size) = kerb_interactive_unlock_logon_pack(&logon).unwrap();

        assert!(!packed.is_null());

        // Cast to a KERB_INTERACTIVE_UNLOCK_LOGON
        let packed = unsafe { &*(packed.cast::<KERB_INTERACTIVE_UNLOCK_LOGON>()) };

        assert!(packed.Logon.MessageType == KerbInteractiveLogon);

        // Validate the packed data
        assert!(
            size == (std::mem::size_of::<KERB_INTERACTIVE_UNLOCK_LOGON>() as u32
                + logon.Logon.LogonDomainName.Length as u32
                + logon.Logon.UserName.Length as u32
                + logon.Logon.Password.Length as u32),
        );
    }

    #[test]
    fn test_kerb_interactive_unlock_logon_unpack_in_place() {
        setup_logging("debug");
        // Create a sample KERB_INTERACTIVE_UNLOCK_LOGON
        let _lsa_user = LsaUnicodeStringOwned::new("usr4");
        let _lsa_pass = LsaUnicodeStringOwned::new("pass5");
        let _lsa_domain = LsaUnicodeStringOwned::new("domai6");

        let logon = KERB_INTERACTIVE_UNLOCK_LOGON {
            Logon: KERB_INTERACTIVE_LOGON {
                MessageType: KerbInteractiveLogon,
                LogonDomainName: *_lsa_domain.as_lsa(),
                UserName: *_lsa_user.as_lsa(),
                Password: *_lsa_pass.as_lsa(),
            },
            LogonId: Default::default(),
        };

        // Pack the logon
        let (packed, _) = kerb_interactive_unlock_logon_pack(&logon).unwrap();

        let packed_kerb = packed as *mut KERB_INTERACTIVE_UNLOCK_LOGON;

        // Unpack the logon
        kerb_interactive_unlock_logon_unpack_in_place(packed_kerb);

        // Validate the unpacked data
        let unpacked = unsafe { &*packed_kerb };
        assert_eq!(unpacked.Logon.MessageType, KerbInteractiveLogon);
        assert_eq!(unpacked.Logon.UserName.Length, 8);
        assert_eq!(unpacked.Logon.Password.Length, 10);
        assert_eq!(unpacked.Logon.LogonDomainName.Length, 12);

        assert_eq!(
            lsa_unicode_string_to_string(&unpacked.Logon.UserName).as_str(),
            "usr4"
        );
        assert_eq!(
            lsa_unicode_string_to_string(&unpacked.Logon.Password).as_str(),
            "pass5"
        );
        assert_eq!(
            lsa_unicode_string_to_string(&unpacked.Logon.LogonDomainName).as_str(),
            "domai6"
        );
    }
}
