use log::warn;
use windows::Win32::Foundation::E_FAIL;
use windows_core::Result;

use crate::{globals, util::http_client::HttpRequestClient};

pub const BROKER_CREDENTIAL_PREFIX: &str = "uds:"; // Broker credential prefix
pub const BROKER_CREDENTIAL_SIZE: usize = 48; // Broker credential size

/// Returns true if the credential is for the broker
pub fn is_broker_credential(username: &str) -> bool {
    username.starts_with(BROKER_CREDENTIAL_PREFIX) && username.len() == BROKER_CREDENTIAL_SIZE
}

/// Obtains the Username, password, and domain from broker with provided data
pub fn get_credentials_from_broker(
    token: &str,
    shared_secret: &str,
    scrambler: &str,
) -> Result<(String, String, String)> {
    let broker_info = globals::get_broker_info();

    match broker_info {
        Some(info) => {
            if info.url().is_empty() {
                return Err(E_FAIL.into());
            }

            let client = HttpRequestClient::new().with_verify_ssl(info.verify_ssl());

            let _json_body = serde_json::json!({
                "token": token,
                "shared_secret": shared_secret,
                "scrambler": scrambler,
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
    use crate::{debug_dev, util::logger};

    #[test]
    fn test_is_broker_credential() {
        logger::setup_logging("debug");
        assert!(is_broker_credential(
            "uds:12345678901234567890123456789012345678901234"
        ));
        assert!(!is_broker_credential("uds:short"));
        assert!(!is_broker_credential("not_a_broker_credential"));
    }

    #[test]
    #[serial_test::serial(broker_info)]
    fn test_get_credentials_from_broker_valid_info() {
        logger::setup_logging("debug");
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
        logger::setup_logging("debug");
        globals::set_broker_info("", false);
        let result = get_credentials_from_broker("token", "shared_secret", "scrambler");
        assert!(result.is_err());
    }
}
