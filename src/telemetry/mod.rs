pub mod vector;

use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};

use crate::config::TelemetryConfig;
use crate::domain::nix_service::NixService;
use crate::telemetry::vector::VectorClient;

pub async fn run_push_loop(service: Arc<NixService>, config: &TelemetryConfig) {
    let client = VectorClient::new(&config.vector_url);
    let interval_secs = config.push_interval_secs;

    info!(
        vector_url = %config.vector_url,
        interval_secs = interval_secs,
        "Starting telemetry push loop"
    );

    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

    loop {
        interval.tick().await;
        let payload = service.telemetry_payload().await;
        if let Err(e) = client.push(&payload).await {
            warn!(error = %e, "Failed to push telemetry to Vector");
        }
    }
}
