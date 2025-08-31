use windows::Win32::Foundation::E_FAIL;
use windows_core::Result;

use crate::{
    globals,
    utils::http_client::HttpRequestClient,
    utils::log::{error, warn},
};

pub const BROKER_CREDENTIAL_PREFIX: &str = "uds:"; // Broker credential prefix
pub const BROKER_CREDENTIAL_SIZE: usize = 48; // Broker credential size

/// Returns true if the credential is for the broker
pub fn is_broker_credential(token: &str, scrambler: &str) -> bool {
    token.starts_with(BROKER_CREDENTIAL_PREFIX)
        && token.len() == BROKER_CREDENTIAL_SIZE
        && scrambler.len() == BROKER_CREDENTIAL_SIZE
}

/// Obtains the Username, password, and domain from broker with provided data
pub fn get_credentials_from_broker(
    token: &str,
    _scrambler: &str,
    _not_used: &str,
) -> Result<(String, String, String)> {
    let broker_info = globals::get_broker_info();

    // Allow us to set an environment var to return fixed creds
    // when debugging. Contains username:password:domain
    #[cfg(debug_assertions)]
    {
        let debug_data = std::env::var("UDSCP_FAKE_CREDENTIALS").unwrap_or_default();
        let parts: Vec<&str> = debug_data.split(':').collect();
        if parts.len() == 3 {
            return Ok((
                parts[0].to_string(),
                parts[1].to_string(),
                parts[2].to_string(),
            ));
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
    use crate::{debug_dev, utils::log};

    #[test]
    fn test_is_broker_credential() {
        log::setup_logging("debug");
        assert!(is_broker_credential(
            "uds:12345678901234567890123456789012345678901234",
            "123456789012345678901234567890123456789012345678"
        ));
        assert!(!is_broker_credential("uds:short", "uds:short"));
        assert!(!is_broker_credential(
            "not_a_broker_credential",
            "not_a_broker_credential"
        ));
    }

    #[test]
    #[serial_test::serial(broker_info)]
    fn test_get_credentials_from_broker_valid_info() {
        log::setup_logging("debug");
        let mut server = mockito::Server::new();

        let mock = server
            .mock("POST", "/credential")
            .with_status(200)
            .with_header("Content-Type", "application/json")
            .with_body(r#"{"username":"test_user","password":"test_pass","domain":"test_domain"}"#)
            .match_request(|request| {
                let body = request
                    .body()
                    .unwrap()
                    .to_vec()
                    .iter()
                    .map(|&c| c as char)
                    .collect::<String>();
                debug_dev!("Request body: {}", body);
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                v.get("token") == Some(&serde_json::Value::String("token".into()))
                    && v.get("shared_secret")
                        == Some(&serde_json::Value::String("shared_secret".into()))
                    && v.get("scrambler") == Some(&serde_json::Value::String("scrambler".into()))
            })
            .create();

        let url = server.url() + "/credential";

        globals::set_broker_info(&url, true); // Is http, so ssl does not mind here
        let result = get_credentials_from_broker("token", "shared_secret", "scrambler");
        assert!(result.is_ok());

        // Check the returned values
        let (username, password, domain) = result.unwrap();
        assert_eq!(username, "test_user");
        assert_eq!(password, "test_pass");
        assert_eq!(domain, "test_domain");

        mock.assert();
    }

    #[test]
    #[serial_test::serial(broker_info)]
    fn test_get_credentials_from_broker_no_info() {
        log::setup_logging("debug");
        globals::set_broker_info("", false);
        let result = get_credentials_from_broker("token", "shared_secret", "scrambler");
        assert!(result.is_err());
    }
}
