### Notes

This document has been created using search engines information and AI provided information... 
May be not entirely accurate, but it is a best effort to provide useful information.


# Credential provider call sequence

| Approx. order | Caller | Method `ICredentialProvider` / `ICredentialProviderCredential` | Purpose |
|---:|---|---|---|
| 1 | LogonUI → CP | **SetUsageScenario(cpus, dwFlags)** | Inform the provider of the usage scenario (logon, unlock, credential UI, RDP). Initialize state accordingly. |
| 2 | LogonUI → CP | **Advise(pcpe, upAdviseContext)** | Provide the event interface so the provider can notify dynamic changes. |
| 3 | LogonUI → CP | **GetFieldDescriptorCount()** | Ask how many UI fields will be exposed. |
| 4 | LogonUI → CP | **GetFieldDescriptorAt(index)** | Retrieve each field’s description (type, label, GUID). Repeated per field. |
| 5 | LogonUI → CP | **GetCredentialCount(&count, &default, &autoLogon)** | Ask how many credentials are available and which is default. |
| 6 | LogonUI → CP | **GetCredentialAt(index)** | Retrieve the `ICredentialProviderCredential` object for each tile. |
| 7 | LogonUI → Credential | **Advise(...)** | Provide the event interface so the credential can notify dynamic changes. |
| 8 | LogonUI → Credential | **GetFieldState(...)**, **GetStringValue(...)**, **GetBitmapValue(...)**, etc. | Populate the tile UI by querying the credential object. |
| 9 | User interaction (Credential) | **SetStringValue(...)**, **CommandLinkClicked(...)** | Notify the credential of edits or actions taken by the user. |
| 10 | User submits (Credential) | **GetSerialization(...)** on selected credential | Package credentials into `CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION` for LSA or Winlogon. |
| 11 | LogonUI → Credential | **UnAdvise()** | Cleanup when LogonUI no longer needs notifications. |
| 12 | Optional LogonUI → CP | **SetSerialization(...)** | Provide pre-serialized credentials to the provider, e.g., RDP reconnect. |
| 13 | LogonUI → CP | **UnAdvise()** | Cleanup when LogonUI no longer needs notifications. |
| 14 | COM | Object release | CP and credential objects are released and the lifecycle ends. |

---

### Notes

- **Early SetSerialization**: May occur before field and credential enumeration if LogonUI already holds credentials, such as autologon or RDP reconnect. Your `GetCredentialCount` often returns 1 with a prefilled credential.
- **Advise and UnAdvise**: While optional, they are typically called so the provider can refresh UI via events.
- **Rebuild cycles**: Steps for field descriptors and credentials can repeat if you raise `ICredentialProviderEvents::CredentialsChanged`.
- **Unlock scenario**: Flow is nearly identical; the usage scenario will be `CPUS_UNLOCK_WORKSTATION`, and `SetSerialization` may not be invoked.


# Probable Call Sequence – RDP with Pre‑Serialized Credentials

When the Remote Desktop client sends valid, pre‑serialized credentials that match your Credential Provider, LogonUI can skip most of the interactive UI steps.

| Approx. order | Caller | Method | Purpose |
|---:|---|---|---|
| 1 | LogonUI → CP | **SetUsageScenario(cpus, dwFlags)** | Inform the provider of the usage scenario (e.g., `CPUS_LOGON` for RDP). |
| 2 | LogonUI → CP | **SetSerialization(pcpcs)** | Pass the pre‑serialized credentials (username, password, domain) received from the RDP client. |
| 3 | LogonUI → CP | **Advise(pcpe, upAdviseContext)** | Provide the event interface (may still be called even if no UI is shown). |
| 4 | LogonUI → CP | **GetFieldDescriptorCount()** | May still query field descriptors for consistency, even if they won’t be displayed. |
| 5 | LogonUI → CP | **GetFieldDescriptorAt(index)** | Retrieve field metadata (optional in this path; sometimes skipped). |
| 6 | LogonUI → CP | **GetCredentialCount(&count, &default, &autoLogon)** | Usually returns `count = 1`, `default = 0`, `autoLogon = TRUE` to trigger immediate logon. |
| 7 | LogonUI → CP | **GetCredentialAt(0)** | Return the credential object pre‑populated from `SetSerialization`. |
| 8 | LogonUI → Credential | **Advise(...)** | Provide the event interface so the credential can notify dynamic changes. |
| 9 | LogonUI → Credential | **GetSerialization(...)** | Package the credential into a `CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION` for LSA/Winlogon (often just re‑emits what was passed in). |
| 10 | LogonUI → Credential | **UnAdvise()** | Cleanup when LogonUI no longer needs notifications. |
| 11 | LogonUI → CP | **UnAdvise()** | Cleanup after logon attempt. |
| 12 | COM | Object release | CP and credential objects are released; lifecycle ends. |

---

## Notes

- **UI Skipping**: If `autoLogonWithDefault` is set to `TRUE` in `GetCredentialCount`, LogonUI will not display the tile and will attempt logon immediately.
- **Minimal Calls**: In some builds, LogonUI may skip `GetFieldDescriptor*` entirely if it knows the credential will be auto‑submitted.
- **Other CPs**: If multiple Credential Providers are installed, only the one matching the serialized package will receive `SetSerialization`.
- **Failure Path**: If the serialized credentials fail (e.g., bad password), LogonUI may fall back to the normal interactive flow and call the remaining UI methods.
