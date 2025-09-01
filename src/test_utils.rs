use crate::{debug_dev, globals};

pub const VALID_BROKER_CREDENTIAL: &str =
    "uds-12345678901234567890123456789012345678901234567812345678901234567890123456789012";
pub const VALID_RESPONSE: &str = r#"{"username":"+KpcZ2rcHgyH8HZ4vFBVkEj9bPQV/oRZ","password":"vZ7eWdcfrbXD4YeIK06q3P3o671Zvkz8","domain":"oRxh6xISQjUhpE8DKwF9Nen28rSdMg=="}"#;
pub const VALID_CREDS: (&str, &str, &str) = ("username", "password", "domain");
pub const TEST_ENCRYPTION_KEY: &str = "12345678901234567890123456789012";

/// Creates a Fake broker:
/// Note: Keep at least server alive, as long as you need to use the mock
/// (That is, ensure variable is on scope, or server will stop on drop)
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
            debug_dev!("Request body: {}", body);
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            v.get("token") == Some(&serde_json::Value::String("token".into()))
        })
        .create();

    let url = server.url() + "/credential";

    globals::set_broker_info(&url, true); // Is http, so ssl does not mind here

    (url, server, mock)
}
