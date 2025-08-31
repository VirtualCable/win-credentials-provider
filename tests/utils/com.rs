use std::sync::{Arc, RwLock};
use windows::{
    Win32::{
        Foundation::{FreeLibrary, HMODULE},
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
            CoRegisterClassObject, CoRevokeClassObject, CoUninitialize, IClassFactory,
            REGCLS_MULTIPLEUSE,
        },
        UI::Shell::{
            CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE, CREDENTIAL_PROVIDER_FIELD_STATE,
            ICredentialProvider, ICredentialProviderCredential,
            ICredentialProviderCredentialEvents, ICredentialProviderCredentialEvents_Impl,
            ICredentialProviderEvents, ICredentialProviderEvents_Impl, ICredentialProviderFilter,
        },
    },
    core::*,
};

use win_cred_provider::{
    classfactory::ClassFactory, credentials::credential::UDSCredential, globals,
};

const CLSID_TEST_FACTORY: GUID = GUID::from_u128(0x12481020_4080_1002_0040_080012345678);

pub struct ClassFactoryTest {
    _factory: IClassFactory,
    fake_dll: HMODULE,
    cookie: u32,
}

// Only used on tests, disable analyzer warnings
#[allow(dead_code)]
impl ClassFactoryTest {
    pub fn new() -> Result<Self> {
        unsafe {
            // Initialize COM
            CoInitializeEx(None, COINIT_APARTMENTTHREADED).map(|| ())?;

            // Register our ClassFactory temporarily in the COM table for this process
            let factory: IClassFactory = ClassFactory::new().into();
            let cookie = CoRegisterClassObject(
                &CLSID_TEST_FACTORY,
                &factory,
                CLSCTX_INPROC_SERVER,
                REGCLS_MULTIPLEUSE,
            )
            .expect("CoRegisterClassObject failed");

            // Lets load the dll, so the resources are available for the tests
            let fake_dll = super::dll::load();
            globals::set_instance(fake_dll.into());

            // Keep factory object alive
            // Also the dll. Anyway, the dll has no Drop impl
            // But I prefer keeping lifetimes under control even if it means more boilerplate :)
            Ok(Self {
                _factory: factory,
                fake_dll,
                cookie,
            })
        }
    }

    pub fn create_instance<T: Interface>(&self) -> Result<T> {
        unsafe {
            let ins: Result<T> = CoCreateInstance(&CLSID_TEST_FACTORY, None, CLSCTX_INPROC_SERVER);
            ins
        }
    }

    pub fn create_provider(&self) -> Result<ICredentialProvider> {
        self.create_instance()
    }

    pub fn create_filter(&self) -> Result<ICredentialProviderFilter> {
        self.create_instance()
    }

    pub fn create_credential(&self) -> Result<ICredentialProviderCredential> {
        let cred = UDSCredential::new();
        Ok(cred.into())
    }
}

impl Drop for ClassFactoryTest {
    fn drop(&mut self) {
        unsafe {
            // Clean up temporary registration and close COM
            CoRevokeClassObject(self.cookie).expect("CoRevokeClassObject failed");
            CoUninitialize();
            if !self.fake_dll.is_invalid() {
                let _ = FreeLibrary(self.fake_dll);
            }
        }
    }
}

#[derive(Clone)]
// Fake ICredentialProviderEvents for tests
#[implement(ICredentialProviderEvents)]
pub struct TestingCredentialProviderEvents {
    pub up_advise_context: Arc<RwLock<usize>>,
}

impl Default for TestingCredentialProviderEvents {
    fn default() -> Self {
        Self {
            up_advise_context: Arc::new(RwLock::new(0)),
        }
    }
}

impl ICredentialProviderEvents_Impl for TestingCredentialProviderEvents_Impl {
    fn CredentialsChanged(&self, upadvisecontext: usize) -> windows::core::Result<()> {
        let mut context = self.up_advise_context.write().unwrap();
        *context = upadvisecontext;
        Ok(())
    }
}

#[derive(Clone)]
// Fake ICredentialProviderCredentialEvents for tests
#[implement(ICredentialProviderCredentialEvents)]
pub struct TestingCredentialProviderCredentialEvents;

impl TestingCredentialProviderCredentialEvents {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TestingCredentialProviderCredentialEvents {
    fn default() -> Self {
        Self::new()
    }
}

impl ICredentialProviderCredentialEvents_Impl for TestingCredentialProviderCredentialEvents_Impl {
    fn SetFieldState(
        &self,
        _pcpc: windows::core::Ref<'_, ICredentialProviderCredential>,
        _dwfieldid: u32,
        _cpfs: CREDENTIAL_PROVIDER_FIELD_STATE,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn SetFieldInteractiveState(
        &self,
        _pcpc: windows::core::Ref<'_, ICredentialProviderCredential>,
        _dwfieldid: u32,
        _cpfis: CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn SetFieldString(
        &self,
        _pcpc: windows::core::Ref<'_, ICredentialProviderCredential>,
        _dwfieldid: u32,
        _psz: &windows::core::PCWSTR,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn SetFieldCheckbox(
        &self,
        _pcpc: windows::core::Ref<'_, ICredentialProviderCredential>,
        _dwfieldid: u32,
        _bchecked: windows::core::BOOL,
        _pszlabel: &windows::core::PCWSTR,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn SetFieldBitmap(
        &self,
        _pcpc: windows::core::Ref<'_, ICredentialProviderCredential>,
        _dwfieldid: u32,
        _hbmp: windows::Win32::Graphics::Gdi::HBITMAP,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn SetFieldComboBoxSelectedItem(
        &self,
        _pcpc: windows::core::Ref<'_, ICredentialProviderCredential>,
        _dwfieldid: u32,
        _dwselecteditem: u32,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn DeleteFieldComboBoxItem(
        &self,
        _pcpc: windows::core::Ref<'_, ICredentialProviderCredential>,
        _dwfieldid: u32,
        _dwitem: u32,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn AppendFieldComboBoxItem(
        &self,
        _pcpc: windows::core::Ref<'_, ICredentialProviderCredential>,
        _dwfieldid: u32,
        _pszitem: &windows::core::PCWSTR,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn SetFieldSubmitButton(
        &self,
        _pcpc: windows::core::Ref<'_, ICredentialProviderCredential>,
        _dwfieldid: u32,
        _dwadjacentto: u32,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn OnCreatingWindow(&self) -> windows::core::Result<windows::Win32::Foundation::HWND> {
        Ok(windows::Win32::Foundation::HWND(0 as _))
    }
}
