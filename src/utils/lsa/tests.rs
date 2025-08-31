use super::*;

use crate::utils::log::setup_logging;

use windows::Win32::Security::Authentication::Identity::{
    KERB_INTERACTIVE_LOGON, KerbInteractiveLogon,
};

fn kerb_interactive_unlock_test(username: &str, password: &str, domain: &str) {
    setup_logging("debug");
    let _lsa_user = LsaUnicodeString::new(username);
    let _lsa_pass = LsaUnicodeString::new(password);
    let _lsa_domain = LsaUnicodeString::new(domain);
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
    let (packed, size) = unsafe { kerb_interactive_unlock_logon_pack(&logon) }.unwrap();

    assert!(!packed.is_null());

    // Cast to a KERB_INTERACTIVE_UNLOCK_LOGON
    let packed = packed.cast::<KERB_INTERACTIVE_UNLOCK_LOGON>();

    // Compose an HEX string of the packed data, with the size "size"
    // To help debugging if needed
    let hex_string = unsafe {
        std::slice::from_raw_parts(packed as *const _ as *const u8, size as usize)
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .join(" ")
    };
    debug_dev!("Packed KERB_INTERACTIVE_UNLOCK_LOGON: {}", hex_string);

    assert!(unsafe { *packed }.Logon.MessageType == KerbInteractiveLogon);

    // Validate the packed data
    assert!(
        size == (std::mem::size_of::<KERB_INTERACTIVE_UNLOCK_LOGON>() as u32
            + logon.Logon.LogonDomainName.Length as u32
            + logon.Logon.UserName.Length as u32
            + logon.Logon.Password.Length as u32),
    );
    assert!(
        unsafe { (*packed).Logon.LogonDomainName.Length } == logon.Logon.LogonDomainName.Length
    );
    assert!(unsafe { (*packed).Logon.UserName.Length } == logon.Logon.UserName.Length);
    assert!(unsafe { (*packed).Logon.Password.Length } == logon.Logon.Password.Length);
    assert!(unsafe { (*packed).LogonId } == logon.LogonId);
}

#[test]
fn test_kerb_interactive_unlock_logon_pack() {
    setup_logging("debug");
    kerb_interactive_unlock_test("user5", "passw6", "dom4");
}

#[test]
fn test_kerb_interactive_unlock_logon_pack_empty_strs() {
    setup_logging("debug");
    kerb_interactive_unlock_test("", "", "");
}

#[test]
fn test_kerb_interactive_unlock_logon_unpack_in_place() {
    setup_logging("debug");
    // This is the expected packed data for:
    // KERB_INTERACTIVE_UNLOCK_LOGON {
    //   Logon: KERB_INTERACTIVE_LOGON {
    //     MessageType: KerbInteractiveLogon,
    //     LogonDomainName: L"dom4",
    //     UserName: L"user5",
    //     Password: L"passw6",
    //   },
    //   LogonId: <LogonId>,
    // }

    let data: Vec<u8> = vec![
        0x02, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x0A, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x0C, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x6D, 0x00, 0x34, 0x00, 0x75, 0x00, 0x73,
        0x00, 0x65, 0x00, 0x72, 0x00, 0x35, 0x00, 0x70, 0x00, 0x61, 0x00, 0x73, 0x00, 0x73, 0x00,
        0x77, 0x00, 0x36, 0x00,
    ];

    // Unpack the logon
    let logon = unsafe { kerb_interactive_unlock_logon_unpack_in_place(data.as_ptr() as *mut u8) };

    // Validate the unpacked data
    assert_eq!(logon.Logon.MessageType, KerbInteractiveLogon);
    assert_eq!(logon.Logon.LogonDomainName.Length, 8);
    assert_eq!(logon.Logon.UserName.Length, 10);
    assert_eq!(logon.Logon.Password.Length, 12);

    assert_eq!(
        lsa_unicode_string_to_string(&logon.Logon.LogonDomainName).as_str(),
        "dom4"
    );
    assert_eq!(
        lsa_unicode_string_to_string(&logon.Logon.UserName).as_str(),
        "user5"
    );
    assert_eq!(
        lsa_unicode_string_to_string(&logon.Logon.Password).as_str(),
        "passw6"
    );
}

#[test]
fn test_retrieve_negotiate_auth_package() {
    setup_logging("debug");
    let package = retrieve_negotiate_auth_package().unwrap();
    debug_dev!("Negotiate Auth Package: {}", package);
}

#[test]
fn test_lsa_unicode_string_owned() {
    let s = "Test String";
    let lsa_owned = LsaUnicodeString::new(s);
    let lsa_ref = lsa_owned.as_lsa();
    let converted = lsa_unicode_string_to_string(lsa_ref);
    assert_eq!(s, converted);
}
