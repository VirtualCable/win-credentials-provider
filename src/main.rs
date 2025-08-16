mod util;

use crate::util::http_client::HttpRequestClient;
use std::collections::HashMap;

fn main() -> anyhow::Result<()> {
    let client = HttpRequestClient::new().with_ignore_ssl();

    let mut headers = HashMap::new();
    headers.insert("User-Agent".into(), "RustWinHttp/1.0".into());

    let resp = client.get("https://www.google.com", headers)?;
    println!("Status: {}", resp.status_code);
    for (key, value) in resp.headers {
        println!("{}: {}", key, value);
    }
    println!("Body:\n{}", resp.body);

    Ok(())
}
