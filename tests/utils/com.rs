use windows::{
    Win32::{
        Foundation::{FreeLibrary, HMODULE},
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
            CoRegisterClassObject, CoRevokeClassObject, CoUninitialize, IClassFactory,
            REGCLS_MULTIPLEUSE,
        },
        UI::Shell::{
            ICredentialProvider, ICredentialProviderCredential, ICredentialProviderFilter,
        },
    },
    core::*,
};

use win_cred_provider::{classfactory::ClassFactory, credential::credential::UDSCredential, dll};

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
            let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED).map(|| ())?;

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
            dll::set_instance(fake_dll.into());

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
