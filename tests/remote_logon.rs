#![cfg(windows)]

use win_cred_provider::{
    utils::{com, log, log::info, lsa},
};
use windows::{
    Win32::{
        Foundation::E_INVALIDARG,
        Security::Authentication::Identity::{
            KERB_INTERACTIVE_LOGON, KERB_INTERACTIVE_UNLOCK_LOGON, KerbInteractiveLogon,
        },
        UI::Shell::{
            CPSI_NONE, CPUS_LOGON, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
            CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
            CREDENTIAL_PROVIDER_STATUS_ICON, ICredentialProviderCredentialEvents,
            ICredentialProviderEvents,
        },
    },
    core::*,
};

mod utils;

#[test]
#[serial_test::serial(remote_logon)]
fn test_remote_logon_ok_cred() -> Result<()> {
    do_test_remote_logon(true)
}

#[test]
#[serial_test::serial(remote_logon)]
fn test_remote_logon_invalid_cred() -> Result<()> {
    do_test_remote_logon(false)
}

fn do_test_remote_logon(valid_cred: bool) -> Result<()> {
    // Set the UDSCP_FORCE_RDP to force system recognizes as RDP
    unsafe { std::env::set_var("UDSCP_FORCE_RDP", "1") };
    unsafe { std::env::set_var("UDSCP_FAKE_CREDENTIALS", "username:password:domain") };
    unsafe { std::env::set_var("UDSCP_ENABLE_FLOW_LOG", "1") };

    let (username, password, domain) = if valid_cred {
        (
            "uds-12345678901234567890123456789012345678901234",
            "123456789012345678901234567890123456789012345678",
            "",
        )
    } else {
        ("normaluser", "normalpassword", "normaldomain")
    };
    log::setup_logging("debug");

    let factory = utils::com::ClassFactoryTest::new()?;
    // The drop on end, will force the Channel stop
    let provider = factory.create_provider()?;

    unsafe { provider.SetUsageScenario(CPUS_LOGON, 0)? };

    let _lsa_user = lsa::LsaUnicodeString::new(username);
    let _lsa_pass = lsa::LsaUnicodeString::new(password);
    let _lsa_domain = lsa::LsaUnicodeString::new(domain);

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
    let (packed, size) = unsafe { lsa::kerb_interactive_unlock_logon_pack(&logon)? };

    let test_cred_serial = CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION {
        ulAuthenticationPackage: 0,
        clsidCredentialProvider: win_cred_provider::globals::CLSID_UDS_CREDENTIAL_PROVIDER,
        cbSerialization: size,
        rgbSerialization: packed,
    };

    let res = unsafe { provider.SetSerialization(&test_cred_serial) };
    assert!(res.is_ok() == valid_cred); 

    // If valid_cred is false, the rest of the process is the same as it was on local logon
    // because credentials were not recognized
    if !valid_cred {
        return Ok(());  // End here
    }

    let credential_provider_events: utils::com::TestingCredentialProviderEvents =
        utils::com::TestingCredentialProviderEvents::default();
    let icredential_provider_events: ICredentialProviderEvents =
        credential_provider_events.clone().into();

    unsafe { provider.Advise(&icredential_provider_events, 0x120909)? };

    let field_descriptor_count = unsafe { provider.GetFieldDescriptorCount()? };

    info!("Field descriptor count: {}", field_descriptor_count);

    let mut fields = Vec::new();
    for fld in 0..field_descriptor_count {
        // Returned value is a comm allocated memory
        let field_descriptor = unsafe { provider.GetFieldDescriptorAt(fld)? };
        info!("Field descriptor {}: {:?}", fld, field_descriptor);
        fields.push(field_descriptor);
    }
    let mut cred_count: u32 = 0;
    let mut cred_default: u32 = 0;
    let mut autologon: BOOL = false.into();
    unsafe {
        provider.GetCredentialCount(&mut cred_count, &mut cred_default, &mut autologon)?;
    }
    info!(
        "Credential count: {}, default: {}, autologon: {}",
        cred_count,
        cred_default,
        autologon.as_bool()
    );

    // As this is a rdp redirected scenario, we expect 1 credential, no default and autologon to be true
    assert_eq!(cred_count, 1);
    assert_eq!(cred_default, 0);
    assert_eq!(autologon, BOOL::from(true));

    // Get the Credential interface
    let credential = unsafe { provider.GetCredentialAt(0)? };
    info!("Credential: {:?}", credential);

    // Advise
    let credential_provider_credential_events =
        utils::com::TestingCredentialProviderCredentialEvents::new();
    let icredential_provider_credential_events: ICredentialProviderCredentialEvents =
        credential_provider_credential_events.clone().into();
    unsafe { credential.Advise(&icredential_provider_credential_events)? };

    // GetSerialization needs a bit more setup
    let mut pcpgsr = CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE(-1);
    let mut pcpcs = CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION {
        ulAuthenticationPackage: 0,
        clsidCredentialProvider: windows_core::GUID::zeroed(),
        cbSerialization: 0,
        rgbSerialization: std::ptr::null_mut(),
    };
    let mut null_pwstr: PWSTR = PWSTR::null();
    let mut cred_prov_icon: CREDENTIAL_PROVIDER_STATUS_ICON = CPSI_NONE;

    let res = unsafe {
        credential.GetSerialization(
            &mut pcpgsr,
            &mut pcpcs as *mut _,
            &mut null_pwstr,
            &mut cred_prov_icon,
        )
    };
    assert!(res.is_ok());
    assert!(!pcpcs.rgbSerialization.is_null());
    assert!(pcpcs.cbSerialization > 0);

    unsafe { credential.UnAdvise()? };

    let res = unsafe { provider.SetSerialization(&pcpcs) };
    assert!(res.is_err()); // Should return E_INVALIDARG
    assert_eq!(res.err().unwrap().code(), E_INVALIDARG);

    // End of credential part,UnAdvise provider
    unsafe { provider.UnAdvise()? };

    // The values should be present on rgbSerialization, same as we set them
    let unserial =
        unsafe { lsa::kerb_interactive_unlock_logon_unpack_in_place(pcpcs.rgbSerialization) };
    assert_eq!(
        lsa::lsa_unicode_string_to_string(&unserial.Logon.UserName),
        "username"
    );
    assert_eq!(
        lsa::lsa_unicode_string_to_string(&unserial.Logon.Password),
        "password"
    );
    assert_eq!(
        lsa::lsa_unicode_string_to_string(&unserial.Logon.LogonDomainName),
        "domain"
    );

    // Free the rgbSerialization, not needed anymore
    com::alloc_free(pcpcs.rgbSerialization);

    // Free fields also
    for field in fields {
        com::alloc_free(field);
    }

    unsafe { std::env::remove_var("UDSCP_FORCE_RDP") };
    unsafe { std::env::remove_var("UDSCP_FAKE_CREDENTIALS") };

    Ok(())
}
