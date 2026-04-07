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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::node_report::*;
    use chrono::Utc;

    fn make_test_report() -> NodeReport {
        NodeReport {
            timestamp: Utc::now(),
            daemon_version: "0.3.0".to_string(),
            hostname: "test-node".to_string(),
            hardware: HardwareSnapshot {
                cpu_model: "Test CPU".to_string(),
                cpu_vendor: "Test".to_string(),
                cpu_architecture: "x86_64".to_string(),
                cpu_cores: 4,
                cpu_threads: 8,
                cpu_frequency_mhz: None,
                cpu_cache_bytes: None,
                ram_total_bytes: 16_000_000_000,
                ram_available_bytes: 8_000_000_000,
                swap_total_bytes: 0,
                swap_used_bytes: 0,
                disks: vec![],
                gpus: vec![],
                temperatures: vec![],
                power: None,
            },
            os: OsSnapshot {
                distribution: "NixOS".to_string(),
                version: "25.11".to_string(),
                kernel_version: "6.12.0".to_string(),
                architecture: "x86_64".to_string(),
                platform_triple: "x86_64-linux".to_string(),
                hostname: "test-node".to_string(),
                product_name: None,
                build_id: None,
                systemd_version: None,
                boot_time: None,
                uptime_secs: 3600,
                timezone: None,
                is_wsl: false,
                virtualization: None,
            },
            network: NetworkSnapshot {
                hostname: "test-node".to_string(),
                interfaces: vec![],
                routes: vec![],
                dns_resolvers: vec![],
                default_gateway: None,
                listening_ports: vec![],
            },
            nix: NixSnapshot {
                nix_version: "2.24.12".to_string(),
                store_size_bytes: 10_000_000,
                store_path_count: 500,
                gc_roots_count: 20,
                last_rebuild_timestamp: None,
                current_system_path: None,
                substituters: vec![],
                system_generations: 5,
                channels: vec![],
                trusted_users: vec!["root".to_string()],
                max_jobs: None,
                sandbox_enabled: true,
            },
            kubernetes: None,
            health: HealthMetrics {
                load_average_1m: 0.5,
                load_average_5m: 0.3,
                load_average_15m: 0.2,
                memory_usage_percent: 50.0,
                swap_usage_percent: 0.0,
                cpu_usage_percent: 10.0,
                disk_usage: vec![],
                open_file_descriptors: None,
                max_file_descriptors: None,
            },
            security: SecuritySnapshot {
                ssh_keys_deployed: vec![],
                tls_certificates: vec![],
                firewall_active: true,
                firewall_rules_count: 5,
                firewall_backend: Some("nftables".to_string()),
                sshd_running: true,
                root_login_allowed: false,
                password_auth_enabled: false,
            },
            processes: ProcessSnapshot {
                total_processes: 100,
                running_processes: 5,
                zombie_processes: 0,
                top_cpu: vec![],
                top_memory: vec![],
            },
        }
    }

    #[tokio::test]
    async fn write_and_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        let store = ReportStore::new(path.clone());

        let report = make_test_report();
        let stored = StoredReport::new(report);

        store.write(&stored).await.unwrap();
        assert!(store.exists());

        let loaded = store.read().await.unwrap();
        assert_eq!(loaded.checksum, stored.checksum);
        assert_eq!(loaded.report.hostname, "test-node");
    }

    #[tokio::test]
    async fn read_nonexistent_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        let store = ReportStore::new(path);

        assert!(!store.exists());
        assert!(store.read().await.is_err());
    }

    #[tokio::test]
    async fn read_corrupt_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt.json");
        tokio::fs::write(&path, "not valid json").await.unwrap();

        let store = ReportStore::new(path);
        assert!(store.read().await.is_err());
    }

    #[tokio::test]
    async fn read_tampered_checksum_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tampered.json");
        let store = ReportStore::new(path.clone());

        let report = make_test_report();
        let mut stored = StoredReport::new(report);
        stored.checksum = "sha256:0000000000000000".to_string();

        let content = serde_json::to_string_pretty(&stored).unwrap();
        tokio::fs::write(&path, &content).await.unwrap();

        let err = store.read().await.unwrap_err();
        assert!(err.to_string().contains("checksum"));
    }

    #[tokio::test]
    async fn write_creates_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a").join("b").join("report.json");
        let store = ReportStore::new(path.clone());

        let report = make_test_report();
        let stored = StoredReport::new(report);

        store.write(&stored).await.unwrap();
        assert!(path.exists());
    }

    #[test]
    fn exists_false_for_missing_file() {
        let store = ReportStore::new(PathBuf::from("/nonexistent/path/report.json"));
        assert!(!store.exists());
    }
}
