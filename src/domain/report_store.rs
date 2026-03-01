//! ReportStore — atomic file I/O with SHA-256 integrity and write locking.
//!
//! Provides the file persistence layer for the one-way report pipeline:
//! Discovery → ReportStore → MemoryCache → API

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use tokio::sync::Mutex;
use tracing::warn;

use super::node_report::StoredReport;

pub struct ReportStore {
    path: PathBuf,
    write_lock: Mutex<()>,
}

impl ReportStore {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            write_lock: Mutex::new(()),
        }
    }

    /// Atomically write a StoredReport to disk.
    ///
    /// Acquires the write lock, serializes to a `.tmp` file, then atomically
    /// renames to the final path. This ensures the file is always complete.
    pub async fn write(&self, stored: &StoredReport) -> Result<()> {
        let _guard = self.write_lock.lock().await;

        let content = serde_json::to_string_pretty(stored)
            .context("failed to serialize StoredReport")?;

        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("creating directory {}", parent.display()))?;
        }

        // Write to a temporary file first
        let tmp_path = self.path.with_extension("json.tmp");
        tokio::fs::write(&tmp_path, &content)
            .await
            .with_context(|| format!("writing temp file {}", tmp_path.display()))?;

        // Atomic rename
        tokio::fs::rename(&tmp_path, &self.path)
            .await
            .with_context(|| {
                format!(
                    "renaming {} to {}",
                    tmp_path.display(),
                    self.path.display()
                )
            })?;

        Ok(())
    }

    /// Read a StoredReport from disk and verify its checksum.
    ///
    /// Returns `Ok(stored)` if the file exists and the hash is valid.
    /// Returns `Err` if the file is missing, corrupt, or the hash doesn't match.
    pub async fn read(&self) -> Result<StoredReport> {
        let content = tokio::fs::read_to_string(&self.path)
            .await
            .with_context(|| format!("reading {}", self.path.display()))?;

        let stored: StoredReport = serde_json::from_str(&content)
            .with_context(|| format!("parsing {}", self.path.display()))?;

        if !stored.verify() {
            warn!(path = %self.path.display(), "report file checksum mismatch");
            bail!(
                "checksum verification failed for {}",
                self.path.display()
            );
        }

        Ok(stored)
    }

    /// Check whether the cache file exists on disk.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }
}
