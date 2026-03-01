//! Typed HTTP client for the kindling daemon REST API.

use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use reqwest::Client;

use crate::config::NodeTarget;
use crate::domain::node_report::StoredReport;
use crate::domain::types::{
    CacheInfo, DaemonHealth, GcResult, GcStatus, NixConfig, NixStatus, OptimiseResult, PlatformInfo,
    StoreInfo,
};
use crate::node_identity::NodeIdentity;

const DEFAULT_BASE_URL: &str = "http://127.0.0.1:9100";

pub struct KindlingClient {
    base_url: String,
    http: Client,
}

impl KindlingClient {
    pub fn new(base_url: &str) -> Result<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("building HTTP client")?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http,
        })
    }

    /// Resolve a client from the nodes map.
    /// `None` name → localhost default. `Some(name)` → look up in nodes map.
    pub fn from_node(
        name: Option<&str>,
        nodes: &HashMap<String, NodeTarget>,
    ) -> Result<Self> {
        match name {
            None => Self::new(DEFAULT_BASE_URL),
            Some(n) => match nodes.get(n) {
                Some(target) => Self::new(&target.url),
                None => bail!(
                    "node '{}' not found in config. Available nodes: {}",
                    n,
                    if nodes.is_empty() {
                        "(none configured)".to_string()
                    } else {
                        nodes.keys().cloned().collect::<Vec<_>>().join(", ")
                    }
                ),
            },
        }
    }

    pub async fn health(&self) -> Result<DaemonHealth> {
        self.get("/health").await
    }

    pub async fn status(&self) -> Result<NixStatus> {
        self.get("/api/v1/status").await
    }

    pub async fn platform(&self) -> Result<PlatformInfo> {
        self.get("/api/v1/platform").await
    }

    pub async fn store(&self) -> Result<StoreInfo> {
        self.get("/api/v1/store").await
    }

    pub async fn nix_config(&self) -> Result<NixConfig> {
        self.get("/api/v1/config").await
    }

    pub async fn gc_status(&self) -> Result<GcStatus> {
        self.get("/api/v1/gc").await
    }

    pub async fn gc_run(&self) -> Result<GcResult> {
        self.post("/api/v1/gc/run").await
    }

    pub async fn optimise(&self) -> Result<OptimiseResult> {
        self.post("/api/v1/store/optimise").await
    }

    pub async fn caches(&self) -> Result<Vec<CacheInfo>> {
        self.get("/api/v1/caches").await
    }

    pub async fn identity(&self) -> Result<Option<NodeIdentity>> {
        self.get("/api/v1/identity").await
    }

    pub async fn report(&self) -> Result<StoredReport> {
        self.get("/api/v1/report").await
    }

    pub async fn refresh_report(&self) -> Result<StoredReport> {
        self.post("/api/v1/report/refresh").await
    }

    // ── Internal helpers ───────────────────────────────────

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {}", url))?;

        if !resp.status().is_success() {
            bail!("{} returned {}", url, resp.status());
        }

        resp.json()
            .await
            .with_context(|| format!("parsing response from {}", url))
    }

    async fn post<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .post(&url)
            .send()
            .await
            .with_context(|| format!("POST {}", url))?;

        if !resp.status().is_success() {
            bail!("{} returned {}", url, resp.status());
        }

        resp.json()
            .await
            .with_context(|| format!("parsing response from {}", url))
    }
}
