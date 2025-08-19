use crate::com::types::{
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE, CREDENTIAL_PROVIDER_FIELD_STATE,
};

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UdsFieldId {
    TileImage = 0,
    Username,
    Password,
    SubmitButton,
    NumFields, // Note: if new fields are added, keep NumFields last.  This is used as a count of the number of fields
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FieldStatePair {
    pub state: CREDENTIAL_PROVIDER_FIELD_STATE,
    pub interactive_state: CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
}

impl Default for FieldStatePair {
    fn default() -> Self {
        Self {
            state: CREDENTIAL_PROVIDER_FIELD_STATE::CPFS_DISPLAY_IN_SELECTED_TILE,
            interactive_state: CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE::CPFIS_NONE,
        }
    }
}