use windows::{
    Win32::{
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
            CoRegisterClassObject, CoRevokeClassObject, CoUninitialize, IClassFactory,
            REGCLS_MULTIPLEUSE,
        },
        UI::Shell::{ICredentialProvider, ICredentialProviderFilter},
    },
    core::*,
};

use win_cred_provider::classfactory::ClassFactory;

const CLSID_TEST_FACTORY: GUID = GUID::from_u128(0x12481020_4080_1002_0040_080012345678);

pub struct ClassFactoryTest {
    _factory: IClassFactory,
    cookie: u32,
}

impl ClassFactoryTest {
    pub fn new() -> Result<Self> {
        unsafe {
            // Initialize COM
            let res = CoInitializeEx(None, COINIT_APARTMENTTHREADED).map(|| ())?;

            // Register our ClassFactory temporarily in the COM table for this process
            let factory: IClassFactory = ClassFactory::new().into();
            let cookie = CoRegisterClassObject(
                &CLSID_TEST_FACTORY,
                &factory,
                CLSCTX_INPROC_SERVER,
                REGCLS_MULTIPLEUSE,
            )
            .expect("CoRegisterClassObject failed");

            // Keep factory object alive
            Ok(Self {
                _factory: factory,
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
}

impl Drop for ClassFactoryTest {
    fn drop(&mut self) {
        unsafe {
            // Clean up temporary registration and close COM
            CoRevokeClassObject(self.cookie).expect("CoRevokeClassObject failed");
            CoUninitialize();
        }
    }
}
