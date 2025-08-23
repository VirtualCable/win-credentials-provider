#![cfg(windows)]
// Integration tests for COM class factory

mod utils;

use windows::{Win32::UI::Shell::ICredentialProviderCredential, core::*};

#[test]
fn test_class_factory_instantiates_provider() -> windows::core::Result<()> {
    let factory = utils::com::ClassFactoryTest::new()?;
    factory.create_provider()?;
    // let _ = unsafe { provider.SetUsageScenario(Default::default(), 0) };

    Ok(())
}

#[test]
fn test_class_instantiates_filter() -> windows::core::Result<()> {
    let factory = utils::com::ClassFactoryTest::new()?;
    factory.create_filter()?;
    // let mut rgballow = BOOL(0);
    // let clsids = [CLSID_UDS_CREDENTIAL_PROVIDER];
    // let _ = unsafe { filter.Filter(Default::default(), 0, clsids.as_ptr(), &mut rgballow, 1) };

    Ok(())
}

#[test]
fn test_class_fails_other() -> windows::core::Result<()> {
    let factory = utils::com::ClassFactoryTest::new()?;
    let provider: Result<ICredentialProviderCredential> = factory.create_instance();
    assert!(provider.is_err());
    Ok(())
}
