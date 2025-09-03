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

// Except headers, is a copy of the crate test_utils, as helpers for testing
use win_cred_provider::{broker, utils::{lsa, log::debug}};
use windows::{
    Win32::{
        Security::Authentication::Identity::{
            KERB_INTERACTIVE_LOGON, KERB_INTERACTIVE_UNLOCK_LOGON, KerbInteractiveLogon,
        },
        UI::Shell::CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    },
    core::*,
};

pub const TEST_BROKER_CREDENTIAL: &str =
    "uds-12345678901234567890123456789012345678901234567812345678901234567890123456789012";
//                                                       ^ Here starts the key
pub const VALID_RESPONSE: &str = r#"{"result": {"username":"+KpcZ2rcHgyH8HZ4vFBVkEj9bPQV/oRZ","password":"vZ7eWdcfrbXD4YeIK06q3P3o671Zvkz8","domain":"oRxh6xISQjUhpE8DKwF9Nen28rSdMg=="}}"#;
pub const VALID_CREDS: (&str, &str, &str) = ("username", "password", "domain"); // Credentials encripted with TEST_ENCRYPTION_KEY on VALID_RESPONSE
pub const TEST_BROKER_TICKET: &str = "uds-123456789012345678901234567890123456789012345678";
pub const TEST_ENCRYPTION_KEY: &str = "12345678901234567890123456789012"; // Must match the TEST_BROKER_CREDENTIAL

pub const UDS_ACTOR_CONFIG_B64: &str = concat!(
    "eyJob3N0IjogIjEyNy4wLjAuMSIsICJjaGVja19jZXJ0aWZpY2F0ZSI6IHRydWUsIC",
    "JhY3Rvcl90eXBlIjogbnVsbCwgIm1hc3Rlcl90b2tlbiI6IG51bGwsICJvd25fdG9r",
    "ZW4iOiAib3duX3Rva2VuX3Rlc3RfdmFsdWUiLCAicmVzdHJpY3RfbmV0IjogbnVsbC",
    "wgInByZV9jb21tYW5kIjogbnVsbCwgInJ1bm9uY2VfY29tbWFuZCI6IG51bGwsICJw",
    "b3N0X2NvbW1hbmQiOiBudWxsLCAibG9nX2xldmVsIjogMiwgImNvbmZpZyI6IG51bG",
    "wsICJkYXRhIjogbnVsbH0="
);
pub const UDS_TEST_ACTOR_TOKEN: &str = "own_token_test_value";

/// Creates a Fake broker:
/// Note: Keep at least server alive, as long as you need to use the mock
/// That is, ensure variable is on scope, or server will stop on drop
pub fn create_fake_broker() -> (String, mockito::ServerGuard, mockito::Mock) {
    let mut server = mockito::Server::new();

    let mock = server
        .mock("POST", "/credential")
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_body(VALID_RESPONSE)
        .match_request(|request| {
            let body = request
                .body()
                .unwrap()
                .to_vec()
                .iter()
                .map(|&c| c as char)
                .collect::<String>();
            debug!("Request body: {}", body);
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            // Must have ticket and token
            v.get("ticket").is_some() && v.get("token").is_some()
        })
        .create();

    let url = server.url() + "/credential";

    broker::set_broker_info(&url, UDS_TEST_ACTOR_TOKEN, true); // Is http, so ssl does not mind here

    (url, server, mock)
}

pub fn create_credential_serialization(
    username: &str,
    password: &str,
    domain: &str,
    guid: GUID,
) -> Result<CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION> {
    let _lsa_user = lsa::LsaUnicodeString::new(username);
    let _lsa_pass = lsa::LsaUnicodeString::new(password);
    let _lsa_domain = lsa::LsaUnicodeString::new(domain);

    let logon = KERB_INTERACTIVE_UNLOCK_LOGON {
        Logon: KERB_INTERACTIVE_LOGON {
            MessageType: KerbInteractiveLogon,
            LogonDomainName: *_lsa_domain.as_lsa(),
            UserName: *_lsa_user.as_lsa(),
            Password: *_lsa_pass.as_lsa(),
        },
        LogonId: Default::default(),
    };
    // Pack the logon
    let (packed, size) = unsafe { lsa::kerb_interactive_unlock_logon_pack(&logon)? };

    Ok(CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION {
        ulAuthenticationPackage: 0,
        clsidCredentialProvider: guid,
        cbSerialization: size,
        rgbSerialization: packed,
    })
}
