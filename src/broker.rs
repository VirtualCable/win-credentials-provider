use log::warn;
use windows::Win32::Foundation::E_FAIL;
use windows_core::Result;

use crate::globals;

const BROKER_CREDENTIAL_PREFIX: &str = "broker:";  // Broker credential prefix
const BROKER_CREDENTIAL_SIZE: usize = 48;          // Broker credential size

/// Returns true if the credential is for the broker
pub fn is_broker_credential(username: &str) -> bool {
    username.starts_with(BROKER_CREDENTIAL_PREFIX)
    && username.len() == BROKER_CREDENTIAL_SIZE
}

/// Obtains the Username, password, and domain from broker with provided data
pub fn get_credentials_from_broker(
    token: &str,
    shared_secret: &str,
    scrambler: &str,
) -> Result<(String, String, String)> {
    let broker_info = globals::get_broker_info();

    // TODO: implement correctly the request
    match broker_info {
        Some(_info) => {
            let username = token;
            let password = shared_secret;
            let domain = scrambler;

            Ok((
                username.to_string(),
                password.to_string(),
                domain.to_string(),
            ))
        }
        None => {
            warn!("Broker information is not set");
            Err(E_FAIL.into())
        }
    }
}
