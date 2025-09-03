// Copyright (c) 2026 Virtual Cable S.L.U.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
//    * Redistributions of source code must retain the above copyright notice,
//      this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above copyright notice,
//      this list of conditions and the following disclaimer in the documentation
//      and/or other materials provided with the distribution.
//    * Neither the name of Virtual Cable S.L.U. nor the names of its contributors
//      may be used to endorse or promote products derived from this software
//      without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
/*!
Author: Adolfo Gómez, dkmaster at dkmon dot com
*/
use std::sync::{OnceLock, RwLock};

use windows::{
    Win32::{
        Foundation::E_FAIL,
        System::Registry::{
            HKEY, KEY_READ, REG_NONE, RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
        },
    },
    core::*,
};

use base64::{Engine, engine::general_purpose::STANDARD};

use crate::{
    globals,
    utils::{
        crypt,
        http_client::HttpRequestClient,
        log::{error, warn},
    },
};

#[derive(Clone)]
pub struct BrokerInfo {
    url: String,
    actor_token: String,
    verify_ssl: bool,
}

impl BrokerInfo {
    pub fn new(url: String, actor_token: String, verify_ssl: bool) -> Self {
        Self {
            url,
            verify_ssl,
            actor_token,
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn verify_ssl(&self) -> bool {
        self.verify_ssl
    }

    pub fn is_valid(&self) -> bool {
        !self.url.is_empty() && !self.actor_token.is_empty()
    }
}

impl Default for BrokerInfo {
    fn default() -> Self {
        Self {
            url: String::new(),
            actor_token: String::new(),
            verify_ssl: true,
        }
    }
}

// Broker info
static BROKER_INFO: OnceLock<RwLock<BrokerInfo>> = OnceLock::new();

/// Obtains the Username, password, and domain from broker with provided data
/// Returns (Username, Password, Domain)
pub fn get_credentials_from_broker(ticket: &str, key: &str) -> Result<(String, String, String)> {
    let broker_info = get_broker_info();
    if !broker_info.is_valid() {
        warn!("Broker info is not available");
        return Err(E_FAIL.into());
    }

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

    let client = HttpRequestClient::new().with_verify_ssl(broker_info.verify_ssl());

    let _json_body = serde_json::json!({
        "token": broker_info.actor_token,
        "ticket": ticket,
    });

    // Respose is:
    // return {'result': result, 'stamp': sql_stamp_seconds(), 'version': consts.system.VERSION, 'build': consts.system.VERSION_STAMP,**kwargs}
    // If "error" is present, there is an error on the response
    // Inside result is our username, password and domain

    match client.post_json::<serde_json::Value, serde_json::Value>(broker_info.url(), &_json_body) {
        // All data in response is base 64 encoded, because it¡s encrypted
        // Note, in a future, can contain a version field, but currently it does not
        // Because is not needed. No field = v1
        Ok(response) => {
            // Check first if there is an error
            if let Some(err) = response.get("error").and_then(|v| v.as_str()) {
                warn!("Error obtaining credentials from broker: {}", err);
                return Err(E_FAIL.into());
            }

            // No, get the result
            let result = response
                .get("result")
                .and_then(|v| v.as_object())
                .ok_or_else(|| {
                    warn!("Invalid response from broker, no result field");
                    E_FAIL
                })?;
            let username = result
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let password = result
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let domain = result.get("domain").and_then(|v| v.as_str()).unwrap_or("");

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

/// Returns true if the credential is for the broker
pub fn transform_broker_credential(token: &str) -> Option<(String, String)> {
    if token.starts_with(globals::BROKER_CREDENTIAL_PREFIX)
        && token.len() == globals::BROKER_CREDENTIAL_SIZE
    {
        let ticket = &token[4..4 + globals::BROKER_CREDENTIAL_TOKEN_SIZE];
        let key = &token[4 + globals::BROKER_CREDENTIAL_TOKEN_SIZE..];
        Some((ticket.to_string(), key.to_string()))
    } else {
        None
    }
}

// Allow setting of any other method the broker info
pub fn set_broker_info(url: &str, actor_token: &str, verify_ssl: bool) {
    *BROKER_INFO
        .get_or_init(|| RwLock::new(BrokerInfo::default()))
        .write()
        .unwrap() = BrokerInfo::new(url.to_string(), actor_token.to_string(), verify_ssl);
}

// Gets and caches the Broker info
pub fn get_broker_info() -> BrokerInfo {
    BROKER_INFO
        .get_or_init(|| RwLock::new(read_broker_info().unwrap_or_default()))
        .read()
        .unwrap()
        .clone()
}

// Reads the configuration from the registry key, that is a base64 json
// Extracts the json and returns the "own_key" string value
fn read_broker_info() -> Result<BrokerInfo> {
    let buffer = unsafe {
        let mut cfg_key = HKEY::default();
        RegOpenKeyExW(
            globals::UDSACTOR_REG_HKEY,
            globals::UDSACTOR_REG_PATH,
            None,
            KEY_READ,
            &mut cfg_key,
        )
        .ok()?;

        let mut data_type = REG_NONE;
        let mut data_len: u32 = 0;

        // First, query the size of the data
        RegQueryValueExW(
            cfg_key,
            w!(""),
            None,
            Some(&mut data_type),
            None,
            Some(&mut data_len),
        )
        .ok()?;

        // create room for the data
        let mut buffer = vec![0u8; data_len as usize];
        RegQueryValueExW(
            cfg_key,
            PCWSTR::null(),
            None,
            Some(&mut data_type),
            Some(buffer.as_mut_ptr()),
            Some(&mut data_len),
        )
        .ok()?;

        RegCloseKey(cfg_key).ok()?;
        buffer
    };

    let b64_str = String::from_utf8_lossy(&buffer);
    let decoded = STANDARD.decode(b64_str.trim()).expect("Invalid Base64");

    let json = serde_json::from_slice::<serde_json::Value>(&decoded).map_err(|e| {
        error!("Error parsing broker config JSON: {}", e);
        E_FAIL
    })?;

    Ok(BrokerInfo {
        url: format!(
            "https://{}/{}",
            globals::BROKER_URL_PATH,
            json.get("url").and_then(|v| v.as_str()).unwrap_or("")
        ),
        verify_ssl: json
            .get("check_certificate")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        actor_token: json
            .get("own_token")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_utils as utils, utils::log};

    #[test]
    fn test_is_broker_credential() {
        log::setup_logging("debug");
        assert!(transform_broker_credential(utils::TEST_BROKER_CREDENTIAL).is_some());
        assert!(transform_broker_credential("uds-short").is_none());
        assert!(transform_broker_credential("not_a_broker_credential").is_none());
    }

    #[test]
    #[serial_test::serial(broker)]
    fn test_get_credentials_from_broker_valid_info() {
        let (_url, _server, mock) = utils::create_fake_broker();
        let result =
            get_credentials_from_broker(utils::TEST_BROKER_CREDENTIAL, utils::TEST_ENCRYPTION_KEY);
        assert!(result.is_ok());

        // Check the returned values
        let (username, password, domain) = result.unwrap();
        assert_eq!(username, utils::VALID_CREDS.0);
        assert_eq!(password, utils::VALID_CREDS.1);
        assert_eq!(domain, utils::VALID_CREDS.2);

        mock.assert();
    }

    #[test]
    #[serial_test::serial(broker)]
    fn test_get_credentials_from_broker_no_info() {
        log::setup_logging("debug");
        set_broker_info("", "", false);
        let result = get_credentials_from_broker("token", "key");
        assert!(result.is_err());
    }

    // Note: This test is disabled by default, needs the key on registry
    // to work
    #[test]
    #[ignore]
    fn test_get_broker_info() {
        log::setup_logging("debug");
        let result = get_broker_info().actor_token;
        assert_eq!(result, "123456");
    }
}
