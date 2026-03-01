//! Node service — wraps NodeIdentity, ReportStore, and MemoryCache.
//!
//! Implements the one-way pipeline:
//!   Discovery → ReportStore (file) → MemoryCache → API
//!
//! API endpoints read ONLY from the memory cache and never trigger discovery.
//! `refresh()` drives the full pipeline: collect → store → cache.

use std::path::PathBuf;

use anyhow::Result;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::{IdentityConfig, ReportConfig};
use crate::node_identity::NodeIdentity;

use super::node_report::StoredReport;
use super::report_collector::ReportCollector;
use super::report_store::ReportStore;

pub struct NodeService {
    identity: RwLock<Option<NodeIdentity>>,
    cache: RwLock<Option<StoredReport>>,
    store: ReportStore,
    identity_config: IdentityConfig,
    report_config: ReportConfig,
}

impl NodeService {
    /// Create a new NodeService, loading identity (with overlays) and
    /// populating the memory cache from the persisted report file if valid.
    pub fn new(identity_config: IdentityConfig, report_config: ReportConfig) -> Self {
        // Load identity with overlay support
        let base_path = NodeIdentity::default_path();
        let identity = if base_path.exists() {
            match NodeIdentity::load_with_overlays(&base_path, &identity_config.overlay_dirs) {
                Ok(id) => {
                    info!("loaded node identity with overlays");
                    Some(id)
                }
                Err(e) => {
                    warn!(error = %e, "failed to load node identity, falling back to base");
                    NodeIdentity::load(&base_path).ok()
                }
            }
        } else {
            None
        };

        let store = ReportStore::new(PathBuf::from(&report_config.cache_file));

        Self {
            identity: RwLock::new(identity),
            cache: RwLock::new(None),
            store,
            identity_config,
            report_config,
        }
    }

    /// Load the persisted report from disk into the memory cache (startup).
    ///
    /// If the file exists and the checksum verifies, the cache is populated.
    /// If the file is corrupt or missing, the cache stays empty.
    pub async fn load_from_disk(&self) {
        if !self.store.exists() {
            info!("no cached report file found, cache starts empty");
            return;
        }

        match self.store.read().await {
            Ok(stored) => {
                let age = stored.age_secs();
                info!(
                    age_secs = age,
                    checksum = %stored.checksum,
                    "loaded report from disk cache"
                );
                *self.cache.write().await = Some(stored);
            }
            Err(e) => {
                warn!(error = %e, "failed to load report from disk, will re-collect");
            }
        }
    }

    /// Run the full discovery → store → cache pipeline.
    ///
    /// 1. Collect a fresh report via ReportCollector
    /// 2. Write the StoredReport to disk (atomic, hash-verified)
    /// 3. Update the in-memory cache
    pub async fn refresh(&self) -> Result<StoredReport> {
        let report = ReportCollector::collect().await?;
        let stored = StoredReport::new(report);

        // Write to file store
        self.store.write(&stored).await?;
        info!(
            checksum = %stored.checksum,
            "report written to disk"
        );

        // Update memory cache
        *self.cache.write().await = Some(stored.clone());

        Ok(stored)
    }

    /// Get the cached StoredReport from memory. Never triggers discovery.
    pub async fn cached_report(&self) -> Option<StoredReport> {
        self.cache.read().await.clone()
    }

    /// Check whether the cached report is stale (exceeds max_age_secs).
    pub async fn is_stale(&self) -> bool {
        match self.cache.read().await.as_ref() {
            Some(stored) => stored.is_stale(self.report_config.max_age_secs),
            None => true,
        }
    }

    /// Get the current node identity (if loaded).
    pub async fn identity(&self) -> Option<NodeIdentity> {
        self.identity.read().await.clone()
    }

    /// Get a redacted copy of the identity with private fields removed.
    pub async fn redacted_identity(&self) -> Option<NodeIdentity> {
        let identity = self.identity.read().await.clone()?;
        match identity.redact(&self.identity_config.private_fields) {
            Ok(redacted) => Some(redacted),
            Err(e) => {
                warn!(error = %e, "failed to redact identity, returning full");
                Some(identity)
            }
        }
    }

    /// Reload identity from disk, re-applying overlays.
    pub async fn reload_identity(&self) -> Result<()> {
        let base_path = NodeIdentity::default_path();
        let identity =
            NodeIdentity::load_with_overlays(&base_path, &self.identity_config.overlay_dirs)?;
        *self.identity.write().await = Some(identity);
        info!("reloaded node identity with overlays");
        Ok(())
    }

    /// Get the report config (for use by server loop).
    pub fn report_config(&self) -> &ReportConfig {
        &self.report_config
    }
}
