use windows::Win32::Foundation::E_FAIL;
use windows_core::Result;

use crate::{
    globals,
    utils::{
        crypt,
        http_client::HttpRequestClient,
        log::{error, warn},
    },
};

pub const BROKER_CREDENTIAL_PREFIX: &str = "uds-"; // Broker credential prefix
pub const BROKER_CREDENTIAL_SIZE: usize = 4 + 48 + 32; // Broker credential size, "uds-" + ticket(48) + key(32)

/// Returns true if the credential is for the broker
pub fn get_broker_credential(token: &str) -> Option<(String, String)> {
    if token.starts_with(BROKER_CREDENTIAL_PREFIX) && token.len() == BROKER_CREDENTIAL_SIZE {
        let ticket = &token[4..52];
        let key = &token[52..84];
        Some((ticket.to_string(), key.to_string()))
    } else {
        None
    }
}

/// Obtains the Username, password, and domain from broker with provided data
/// Returns (Username, Password, Domain)
pub fn get_credentials_from_broker(token: &str, key: &str) -> Result<(String, String, String)> {
    let broker_info = globals::get_broker_info();

    // Allow us to set an environment var to return fixed creds
    // when debugging. Contains username:password:domain
    #[cfg(debug_assertions)]
    {
        let debug_data = std::env::var("UDSCP_FAKE_CREDENTIALS").unwrap_or_default();
        let parts: Vec<&str> = debug_data.split(':').collect();
        if parts.len() == 3 {
            let (username, password, domain) = (
                parts[0].to_string(),
                parts[1].to_string(),
                parts[2].to_string(),
            );

            let domain = if domain.is_empty() {
                use crate::utils::helpers;

                helpers::get_computer_name()
            } else {
                domain
            };
            return Ok((username, password, domain));
        }
        error!("Invalid UDSCP_FAKE_CREDENTIALS format");
    }

    match broker_info {
        Some(info) => {
            if info.url().is_empty() {
                return Err(E_FAIL.into());
            }

            let client = HttpRequestClient::new().with_verify_ssl(info.verify_ssl());

            let _json_body = serde_json::json!({
                "token": token,
            });
            match client.post_json::<serde_json::Value, serde_json::Value>(info.url(), &_json_body)
            {
                // All data in response is base 64 encoded, because it¡s encrypted
                // Note, in a future, can contain a version field, but currently it does not
                // Because is not needed. No field = v1
                Ok(response) => {
                    let username = response
                        .get("username")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let password = response
                        .get("password")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let domain = response
                        .get("domain")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    // Decript values
                    // Important!!
                    // nonce are 1 for username, 2 for password and 3 for domain.. The key is ephemeral, only used once...
                    // Encryption is AES256GCM
                    let username = crypt::decrypt(username, key, 1).unwrap_or_default();
                    let password = crypt::decrypt(password, key, 2).unwrap_or_default();
                    let domain = crypt::decrypt(domain, key, 3).unwrap_or_default();

                    Ok((
                        username.to_string(),
                        password.to_string(),
                        domain.to_string(),
                    ))
                }
                Err(e) => {
                    warn!("Error obtaining credentials from broker: {}", e);
                    Err(E_FAIL.into())
                }
            }
        }
        None => {
            warn!("Broker information is not set");
            Err(E_FAIL.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_utils as utils, utils::log};

    #[test]
    fn test_is_broker_credential() {
        log::setup_logging("debug");
        assert!(get_broker_credential(utils::VALID_BROKER_CREDENTIAL).is_some());
        assert!(get_broker_credential("uds-short").is_none());
        assert!(get_broker_credential("not_a_broker_credential").is_none());
    }

    #[test]
    #[serial_test::serial(broker_info)]
    fn test_get_credentials_from_broker_valid_info() {
        let (_url, _server, mock) = utils::create_fake_broker();
        let result = get_credentials_from_broker("token", utils::TEST_ENCRYPTION_KEY);
        assert!(result.is_ok());

        // Check the returned values
        let (username, password, domain) = result.unwrap();
        assert_eq!(username, utils::VALID_CREDS.0);
        assert_eq!(password, utils::VALID_CREDS.1);
        assert_eq!(domain, utils::VALID_CREDS.2);

        mock.assert();
    }

    #[test]
    #[serial_test::serial(broker_info)]
    fn test_get_credentials_from_broker_no_info() {
        log::setup_logging("debug");
        globals::set_broker_info("", false);
        let result = get_credentials_from_broker("token", "key");
        assert!(result.is_err());
    }
}
