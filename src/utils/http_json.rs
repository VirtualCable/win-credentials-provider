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
            Some(headers),
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
        let response = match self.get(url, Some(HashMap::new())) {
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

    #[derive(Serialize, Deserialize, Debug)]
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
