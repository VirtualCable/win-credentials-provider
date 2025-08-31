#![cfg(windows)]

use windows::{Win32::UI::Shell::CPUS_LOGON, core::*};

mod utils;

#[test]
fn test_normal_logon() -> Result<()> {
    let factory = utils::com::ClassFactoryTest::new()?;
    let provider = factory.create_provider()?;

    unsafe { provider.SetUsageScenario(CPUS_LOGON, 0)? };
    

    Ok(())
}
