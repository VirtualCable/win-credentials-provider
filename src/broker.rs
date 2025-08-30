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
        Some(_info) => {
            #[cfg(test)] // Only for testing will allow this
            if _info.url().is_empty() {
                let username = token;
                let password = shared_secret;
                let domain = scrambler;

                return Ok((
                    username.to_string(),
                    password.to_string(),
                    domain.to_string(),
                ));
            }

            let client = HttpRequestClient::new();

            let _json_body = serde_json::json!({
                "token": token,
                "shared_secret": shared_secret,
                "scrambler": scrambler,
            });
            match client.post_json::<serde_json::Value, serde_json::Value>("", &_json_body) {
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
