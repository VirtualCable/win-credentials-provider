use std::mem;
use windows::Win32::{
    System::Com::{CoTaskMemAlloc, CoTaskMemFree},
    UI::Shell::{
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
        CREDENTIAL_PROVIDER_FIELD_STATE, CREDENTIAL_PROVIDER_FIELD_TYPE, SHStrDupW,
    },
};
use windows::core::{GUID, PWSTR};

#[derive(Debug, Clone)]
pub struct CredentialFieldDescriptor {
    pub field_id: u32,
    pub field_type: CREDENTIAL_PROVIDER_FIELD_TYPE,
    pub label: &'static str,
    pub guid: GUID,
    pub state: CREDENTIAL_PROVIDER_FIELD_STATE,
    pub interactive_state: CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
}

impl CredentialFieldDescriptor {
    pub fn into_com_alloc(
        &self,
    ) -> windows::core::Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        unsafe {
            let ptr = CoTaskMemAlloc(mem::size_of::<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>())
                as *mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR;

            if ptr.is_null() {
                return Err(windows::core::Error::from_win32());
            }

            (*ptr).dwFieldID = self.field_id;
            (*ptr).cpft = self.field_type;

            let wide_label = match widestring::U16CString::from_str(self.label) {
                Ok(w) => w,
                Err(_) => {
                    // Log, fallback, o abortar según el caso
                    return Err(windows::core::Error::from_win32());
                }
            };
            match SHStrDupW(PWSTR(wide_label.as_ptr() as _)) {
                Ok(s) => (*ptr).pszLabel = s,
                Err(e) => {
                    CoTaskMemFree(Some(ptr as _));
                    return Err(e);
                }
            }

            (*ptr).guidFieldType = self.guid;

            Ok(ptr)
        }
    }

    pub fn is_text_field(&self) -> bool {
        self.field_type == windows::Win32::UI::Shell::CPFT_EDIT_TEXT
            || self.field_type == windows::Win32::UI::Shell::CPFT_PASSWORD_TEXT
    }
}

#[allow(dead_code)]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UdsFieldId {
    TileImage = 0,
    Username,
    Password,
    SubmitButton,
    NumFields, // Note: if new fields are added, keep NumFields last.  This is used as a count of the number of fields
}

#[cfg(test)]
mod tests {
    use windows::Win32::UI::Shell::{CPFIS_NONE, CPFS_DISPLAY_IN_SELECTED_TILE, CPFT_EDIT_TEXT};
    use crate::util::traits::To;

    use super::*;

    #[test]
    fn test_credential_field_descriptor() {
        let field = CredentialFieldDescriptor {
            field_id: 1,
            field_type: CPFT_EDIT_TEXT,
            label: "Username",
            guid: GUID::from_u128(32),
            state: CPFS_DISPLAY_IN_SELECTED_TILE,
            interactive_state: CPFIS_NONE,
        };

        let com_ptr = field.into_com_alloc();
        assert!(com_ptr.is_ok());
        let com_ptr = com_ptr.unwrap();
        assert!(unsafe { *com_ptr }.dwFieldID == 1);
        assert!(unsafe { *com_ptr }.cpft == CPFT_EDIT_TEXT);
        let string: String = unsafe { *com_ptr }.pszLabel.to();
        assert!(string == "Username");
        assert!(unsafe { *com_ptr }.guidFieldType == GUID::from_u128(32));
    }
}
