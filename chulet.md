# 🗂 Chuleta Visual — Credential Provider & `CoTaskMemAlloc`

> Leyenda:  
> ✅ = Requiere asignar con `CoTaskMemAlloc` (Windows la liberará con `CoTaskMemFree`)  
> ❌ = No requiere asignación COM (usa tipos nativos o punteros a interfaces)  
> 🎨 = Devuelve `HBITMAP` u otro handle, no se libera con `CoTaskMemFree`

---

## **ICredentialProvider**

| Método                    | Necesita `CoTaskMemAlloc` | Tipo devuelto                                      | Notas |
|---------------------------|---------------------------|----------------------------------------------------|-------|
| `GetFieldDescriptorCount` | ❌                        | `DWORD` (count)                                    | Solo un número |
| `GetFieldDescriptorAt`    | ✅                        | `CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*`            | Asignar estructura y cadenas internas |
| `GetCredentialCount`      | ❌                        | Índices / flags                                    | —     |
| `GetCredentialAt`         | ❌                        | `ICredentialProviderCredential*` (puntero COM)     | COM libera con `Release()` |

---

## **ICredentialProviderCredential**

| Método                    | Necesita `CoTaskMemAlloc` | Tipo devuelto          | Notas |
|---------------------------|---------------------------|------------------------|-------|
| `Advise` / `UnAdvise`     | ❌                        | Interfaces COM         | — |
| `SetSelected`             | ❌                        | —                      | — |
| `SetDeselected`           | ❌                        | —                      | — |
| `GetFieldState`           | ❌                        | enums/flags            | — |
| `GetStringValue`          | ✅                        | `PWSTR`                 | Cadena UTF‑16 terminada en `0` |
| `GetBitmapValue`          | 🎨                        | `HBITMAP`               | Usa GDI, handle se libera con `DeleteObject` |
| `GetCheckboxValue`        | ✅                        | `PWSTR` + `BOOL`        | Cadena UTF‑16 y estado |
| `GetSubmitButtonValue`    | ✅                        | `PWSTR` + índice        | Cadena UTF‑16 |
| `GetComboBoxValueCount`   | ✅                        | Array de `PWSTR`        | Cada elemento requiere `CoTaskMemAlloc` |
| `GetComboBoxValueAt`      | ✅                        | `PWSTR`                 | Cadena UTF‑16 |
| `SetStringValue`          | ❌                        | —                      | — |
| `CommandLinkClicked`      | ❌                        | —                      | — |

---

## 🛠 Helper para `PWSTR`

```rust
use windows::Win32::System::Com::CoTaskMemAlloc;
use windows::core::PWSTR;
use std::{ffi::OsStr, os::windows::ffi::OsStrExt, ptr};

pub fn alloc_pwstr(s: &str) -> PWSTR {
    let wide: Vec<u16> = OsStr::new(s)
        .encode_wide()
        .chain(Some(0))
        .collect();
    unsafe {
        let size_bytes = wide.len() * std::mem::size_of::<u16>();
        let mem = CoTaskMemAlloc(size_bytes) as *mut u16;
        if mem.is_null() {
            return PWSTR::null();
        }
        ptr::copy_nonoverlapping(wide.as_ptr(), mem, wide.len());
        PWSTR(mem)
    }
}
