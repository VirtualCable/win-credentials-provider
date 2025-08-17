# Métodos de Credential Provider y uso de CoTaskMemAlloc

## 📌 1. Contexto rápido
En COM/Win32, cada método define **quién es responsable** de liberar la memoria.  
En los interfaces de **ICredentialProvider** y **ICredentialProviderCredential**, muchos de los métodos marcan los parámetros de salida con anotaciones SAL como:

- `_Outptr_result_maybenull_` + `_Ret_writes_` → **llamante libera**  
- `_Outptr_result_z_` → **llamante libera cadena terminada en null**

Cuando la doc dice *"The caller must free the memory by calling CoTaskMemFree"* → ahí es donde en Rust debes usar `CoTaskMemAlloc`.

---

## 📜 2. `ICredentialProvider` (métodos relevantes)

| Método                                           | Devuelve memoria COM | Tipo típico           | Asignar con |
|--------------------------------------------------|----------------------|-----------------------|-------------|
| `GetFieldDescriptorCount`                        | ❌ No                 | `DWORD` (count)       | –           |
| `GetFieldDescriptorAt`                           | ✅ Sí                 | `CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*` | `CoTaskMemAlloc` (estructura y cadenas internas) |
| `GetCredentialCount`                             | ❌ No                 | índices, flags        | –           |
| `GetCredentialAt`                                | ❌ (devuelve interfaz)| `ICredentialProviderCredential*` (COM se encarga) | –           |

---

## 📜 3. `ICredentialProviderCredential`

| Método                                           | Devuelve memoria COM | Tipo típico           | Asignar con |
|--------------------------------------------------|----------------------|-----------------------|-------------|
| `Advise` / `UnAdvise`                            | ❌                   | Solo punteros COM     | –           |
| `SetSelected` / `SetDeselected`                  | ❌                   | –                     | –           |
| `GetFieldState`                                  | ❌                   | enums/flags           | –           |
| `GetStringValue`                                 | ✅ Sí                 | `PWSTR` (caller libera)| `CoTaskMemAlloc` buffer de UTF‑16 con terminador `0` |
| `GetBitmapValue`                                 | ✅ Sí                 | `HBITMAP`             | Depende → normalmente usas GDI y devuelves handle, no CoTaskMem |
| `GetCheckboxValue`                               | ✅ Sí (solo string)   | `PWSTR`               | `CoTaskMemAlloc` buffer UTF‑16 + bool separado |
| `GetSubmitButtonValue`                           | ✅ Sí (solo string)   | `PWSTR`               | `CoTaskMemAlloc` buffer UTF‑16 + índice |
| `GetComboBoxValueCount`                          | ✅ Sí (cada item)     | `PWSTR` por item      | `CoTaskMemAlloc` buffer UTF‑16 por cada string |
| `GetComboBoxValueAt`                             | ✅ Sí                 | `PWSTR`               | `CoTaskMemAlloc` |
| `SetStringValue` / `CommandLinkClicked` etc.     | ❌                   | –                     | –           |

---

## 🛠 4. Helper en Rust para asignar `PWSTR` con `CoTaskMemAlloc`

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
