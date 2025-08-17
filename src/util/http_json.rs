use anyhow::{Context, Result};
use serde::{Serialize, de::DeserializeOwned};
use std::collections::HashMap;

use super::http_client::HttpRequestClient;

impl HttpRequestClient {
    #[allow(dead_code)]
    pub fn post_json<T: Serialize, R: DeserializeOwned>(
        &self,
        url: &str,
        payload: &T,
    ) -> Result<R> {
        // Serialize the struct to JSON
        let body = serde_json::to_vec(payload).context("Error in JSON serialization")?;

        // Default headers for JSON
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        // Make the request
        let response = match self.do_request(
            "POST",
            url.starts_with("https://"),
            &Self::parse_url(url)?.1,
            &Self::parse_url(url)?.2,
            Self::parse_url(url)?.3,
            headers,
            Some(&body),
        ) {
            Ok(resp) => resp,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Error making POST request to {}: {}",
                    url,
                    e
                ));
            }
        };

        // Deserialize response body
        let obj: R = serde_json::from_str(&response.body).context("Error parsing JSON response")?;
        Ok(obj)
    }

    #[allow(dead_code)]
    pub fn get_json<R: DeserializeOwned>(&self, url: &str) -> Result<R> {
        // Make the GET request
        let response = match self.get(url, HashMap::new()) {
            Ok(resp) => resp,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Error making GET request to {}: {}",
                    url,
                    e
                ));
            }
        };

        // Deserialize response body
        let obj: R = serde_json::from_str(&response.body).context("Error parsing JSON response")?;
        Ok(obj)
    }
}

// Tests for json
#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct Post {
        userid: u32,
        // id is optional, only on GET not POST
        id: Option<u32>,
        title: String,
        body: String,
    }

    #[test]
    fn test_post_json() {
        let mut server = Server::new();

        let mock = server
            .mock("POST", "/posts")
            .with_status(201)
            .with_header("Content-Type", "application/json")
            .with_body(r#"{"userid":1,"id":101,"title":"Test Title","body":"Test Body"}"#)
            .create();

        let url = server.url() + "/posts";

        let client = HttpRequestClient::new();
        let payload = Post {
            userid: 1,
            id: None,
            title: "Test Title".into(),
            body: "Test Body".into(),
        };
        let result: Result<Post> = client.post_json(&url, &payload);
        match result {
            Ok(post) => {
                assert_eq!(post.userid, 1);
                assert_eq!(post.title, "Test Title");
                assert_eq!(post.body, "Test Body");
                assert!(post.id.is_some());
            }
            Err(e) => panic!("Failed to post JSON: {}", e),
        }
        mock.assert();
    }

    #[test]
    fn test_get_json() {
        let mut server = Server::new();

        let mock = server
            .mock("GET", "/posts/1")
            .with_status(200)
            .with_header("Content-Type", "application/json")
            .with_body(r#"{"userid":1,"id":1,"title":"Test Title","body":"Test Body"}"#)
            .create();

        let url = server.url() + "/posts/1";

        let client = HttpRequestClient::new();
        let result: Result<Post> = client.get_json(&url);
        match result {
            Ok(post) => {
                assert_eq!(post.userid, 1);
                assert_eq!(post.title, "Test Title");
                assert_eq!(post.body, "Test Body");
                assert!(post.id.is_some());
            }
            Err(e) => panic!("Failed to get JSON: {}", e),
        }
        mock.assert();
    }
}
