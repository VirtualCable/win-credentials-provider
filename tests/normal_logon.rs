#![cfg(windows)]

use win_cred_provider::{
    credentials::fields,
    debug_dev,
    utils::{com, logger, traits::To},
};
use windows::{
    Win32::UI::Shell::{
        CPUS_LOGON, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE, CREDENTIAL_PROVIDER_FIELD_STATE,
        CREDENTIAL_PROVIDER_NO_DEFAULT, ICredentialProviderCredentialEvents,
        ICredentialProviderEvents,
    },
    core::*,
};

mod utils;

#[test]
fn test_normal_logon() -> Result<()> {
    logger::setup_logging("debug");
    let factory = utils::com::ClassFactoryTest::new()?;
    // The drop on end, will force the Channel stop
    let provider = factory.create_provider()?;

    unsafe { provider.SetUsageScenario(CPUS_LOGON, 0)? };

    let credential_provider_events: utils::com::TestingCredentialProviderEvents =
        utils::com::TestingCredentialProviderEvents::default();
    let icredential_provider_events: ICredentialProviderEvents =
        credential_provider_events.clone().into();

    unsafe { provider.Advise(&icredential_provider_events, 0x120909)? };

    let field_descriptor_count = unsafe { provider.GetFieldDescriptorCount()? };

    debug_dev!("Field descriptor count: {}", field_descriptor_count);

    let mut fields = Vec::new();
    for fld in 0..field_descriptor_count {
        // Returned value is a comm allocated memory
        let field_descriptor = unsafe { provider.GetFieldDescriptorAt(fld)? };
        debug_dev!("Field descriptor {}: {:?}", fld, field_descriptor);
        fields.push(field_descriptor);
    }
    let mut cred_count: u32 = 0;
    let mut cred_default: u32 = 0;
    let mut autologon: BOOL = false.into();
    unsafe {
        provider.GetCredentialCount(&mut cred_count, &mut cred_default, &mut autologon)?;
    }
    debug_dev!(
        "Credential count: {}, default: {}, autologon: {}",
        cred_count,
        cred_default,
        autologon.as_bool()
    );

    // As this is a "normal", should have return that do not autologon, 1 cred_Count and no default
    assert_eq!(cred_count, 1);
    assert_eq!(cred_default, CREDENTIAL_PROVIDER_NO_DEFAULT);
    assert_eq!(autologon, BOOL::from(false));

    // Get the Credential interface
    let credential = unsafe { provider.GetCredentialAt(0)? };
    debug_dev!("Credential: {:?}", credential);

    // Advise
    let credential_provider_credential_events =
        utils::com::TestingCredentialProviderCredentialEvents::new();
    let icredential_provider_credential_events: ICredentialProviderCredentialEvents =
        credential_provider_credential_events.clone().into();
    unsafe { credential.Advise(&icredential_provider_credential_events)? };

    #[derive(Debug)]
    struct Field {
        _id: u32,
        _state: CREDENTIAL_PROVIDER_FIELD_STATE,
        _interactive_state: CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
        _value: String,
    }

    // Credential part flow
    let mut fields_data: Vec<Field> = Vec::new();
    for fld in fields.iter() {
        let field = unsafe { **fld };

        // Field state
        let dwfieldid = field.dwFieldID;
        let mut pcpfs = CREDENTIAL_PROVIDER_FIELD_STATE::default();
        let mut pcpfis = CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE::default();
        unsafe { credential.GetFieldState(dwfieldid, &mut pcpfs, &mut pcpfis)? };
        debug_dev!(
            "Field ID {}: Type: {:?}, State: {:?}, Interactive State: {:?}",
            dwfieldid,
            field.cpft,
            pcpfs,
            pcpfis
        );

        // Field value
        let orig_fld = &fields::CREDENTIAL_PROVIDER_FIELD_DESCRIPTORS[field.dwFieldID as usize];
        if orig_fld.is_text_field() {
            // Com allocated, convert an release
            let pwstr = unsafe { credential.GetStringValue(dwfieldid)? };
            let str_value = win_cred_provider::utils::com::pcwstr_to_string(pwstr.to());
            com::free_pcwstr(pwstr.to());
            fields_data.push(Field {
                _id: dwfieldid,
                _state: pcpfs,
                _interactive_state: pcpfis,
                _value: str_value,
            });
        } else if orig_fld.is_image_field() {
            // Image field, get the bitmap handle
            let bitmap = unsafe { credential.GetBitmapValue(dwfieldid)? };
            fields_data.push(Field {
                _id: dwfieldid,
                _state: pcpfs,
                _interactive_state: pcpfis,
                _value: format!("HBMP: {:#X}", bitmap.0 as isize),
            });
        } else if orig_fld.is_submit_button() {
            let button = unsafe { credential.GetSubmitButtonValue(dwfieldid)? };
            fields_data.push(Field {
                _id: dwfieldid,
                _state: pcpfs,
                _interactive_state: pcpfis,
                _value: format!("SUBMIT: {}", button),
            });
        }
        debug_dev!("Field data: {:?}", fields_data.last().unwrap());
    }

    // Simulate user filling fields
    for field in fields_data.iter_mut() {
        if field._id == win_cred_provider::credentials::types::UdsFieldId::Username as u32 {
            let username = com::alloc_pwstr("username").unwrap().to();
            unsafe { credential.SetStringValue(field._id, username)? };
            com::free_pcwstr(username);
        } else if field._id == win_cred_provider::credentials::types::UdsFieldId::Password as u32 {
            let password = com::alloc_pwstr("password").unwrap().to();
            unsafe { credential.SetStringValue(field._id, password)? };
            com::free_pcwstr(password);
        }
    }
    // Regetting the fields, shold contain the values stored
    let username: PCWSTR = unsafe {
        credential
            .GetStringValue(win_cred_provider::credentials::types::UdsFieldId::Username as u32)?
    }
    .to();
    let password = unsafe {
        credential
            .GetStringValue(win_cred_provider::credentials::types::UdsFieldId::Password as u32)?
    }
    .to();
    assert_eq!(com::pcwstr_to_string(username), "username");
    assert_eq!(com::pcwstr_to_string(password), "password");

    // Free COM strings
    com::free_pcwstr(username);
    com::free_pcwstr(password);

    // TODO:
    // GetSerialization from credential,
    // UnAdvise from credential

    // End of credential part,UnAdvise provider
    unsafe { provider.UnAdvise()? };

    // TODO:
    // SetSerialization from provider

    // Release fields from com memory
    for field in fields {
        com::alloc_free(field);
    }

    Ok(())
}
