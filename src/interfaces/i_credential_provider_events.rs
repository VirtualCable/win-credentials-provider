
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use windows::core::*;

// ICredentialProviderEvents COM interface

#[interface("34201e5a-a787-41a3-a5a4-bd6dcf2a854e")]
pub unsafe trait ICredentialProviderEvents: IUnknown {
    unsafe fn CredentialsChanged(
        &self,
        upAdviseContext: usize,
    ) -> HRESULT;
}
