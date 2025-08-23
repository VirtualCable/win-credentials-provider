use windows::Win32::{
    System::Com::CoTaskMemAlloc,
    UI::Shell::CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR,
};
use std::{mem, ptr};

pub struct FieldDescriptor(pub CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR);

impl FieldDescriptor {
    pub fn into_com_alloc(self) -> *mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR {
        unsafe {
            let ptr = CoTaskMemAlloc(mem::size_of::<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>())
                as *mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR;
            if !ptr.is_null() {
                *ptr = self.0;
            }
            ptr
        }
    }
}