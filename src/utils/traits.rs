use windows_core::{PCWSTR, PWSTR};

/// Generic trait for converting a type to another type.
pub trait To<T> {
    /// Converts self to type T.
    fn to(&self) -> T;
}

/// Implements conversion from PWSTR to PCWSTR.
impl To<PCWSTR> for PWSTR {
    /// Converts PWSTR to PCWSTR by wrapping the pointer.
    fn to(&self) -> PCWSTR {
        PCWSTR(self.0)
    }
}

/// Implements conversion from PCWSTR to String.
impl To<String> for PCWSTR {
    /// Converts PCWSTR to String using a utility function.
    fn to(&self) -> String {
        crate::utils::com::pcwstr_to_string(*self)
    }
}

/// Implements conversion from PWSTR to String.
impl To<String> for PWSTR {
    /// Converts PWSTR to String by first converting to PCWSTR, then to String.
    fn to(&self) -> String {
        crate::utils::com::pcwstr_to_string(self.to())
    }
}
