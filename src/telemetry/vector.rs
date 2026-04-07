use anyhow::{Context, Result};

use crate::domain::types::TelemetryPayload;

pub struct VectorClient {
    client: reqwest::Client,
    url: String,
}

impl VectorClient {
    pub fn new(url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: url.to_string(),
        }
    }

    pub async fn push(&self, payload: &TelemetryPayload) -> Result<()> {
        self.client
            .post(&self.url)
            .json(payload)
            .send()
            .await
            .context("sending telemetry to Vector")?
            .error_for_status()
            .context("Vector returned error status")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_url() {
        let client = VectorClient::new("http://localhost:8686");
        assert_eq!(client.url, "http://localhost:8686");
    }

    #[test]
    fn new_preserves_url_with_path() {
        let client = VectorClient::new("http://vector.svc:8686/api/v1/events");
        assert_eq!(client.url, "http://vector.svc:8686/api/v1/events");
    }
}
