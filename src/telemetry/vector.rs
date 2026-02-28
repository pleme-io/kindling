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
