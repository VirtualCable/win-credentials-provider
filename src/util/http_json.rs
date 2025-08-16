use serde::{Serialize, de::DeserializeOwned};
use anyhow::{Result, Context};
use std::collections::HashMap;

use super::http_client::{HttpRequestClient};

impl HttpRequestClient {
    pub fn post_json<T: Serialize, R: DeserializeOwned>(
        &self,
        url: &str,
        payload: &T,
    ) -> Result<R> {
        // Serializar el struct a JSON
        let body = serde_json::to_vec(payload)
            .context("Error serializando payload a JSON")?;

        // Cabeceras por defecto para JSON
        let mut headers = HashMap::new();
        headers.insert(
            "Content-Type".to_string(),
            "application/json".to_string()
        );

        // Hacer la petición
        let response = self.do_request(
            "POST",
            url.starts_with("https://"),
            &Self::parse_url(url)?.1,
            &Self::parse_url(url)?.2,
            Self::parse_url(url)?.3,
            headers,
            Some(&body),
        )?;

        // Deserializar el cuerpo de respuesta
        let obj: R = serde_json::from_str(&response.body)
            .context("Error parseando JSON de respuesta")?;
        Ok(obj)
    }

    pub fn get_json<R: DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<R> {
        // Hacer la petición GET
        let response = self.get(url, HashMap::new())?;

        // Deserializar el cuerpo de respuesta
        let obj: R = serde_json::from_str(&response.body)
            .context("Error parseando JSON de respuesta")?;
        Ok(obj)
    }
}
