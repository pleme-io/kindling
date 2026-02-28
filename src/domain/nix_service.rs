use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

use crate::config::DaemonConfig;
use crate::domain::types::*;

pub struct NixService {
    nix_path: RwLock<Option<PathBuf>>,
    platform: PlatformInfo,
    start_time: Instant,
    gc_status: RwLock<GcStatus>,
    config: DaemonConfig,
}

impl NixService {
    pub fn new(config: DaemonConfig) -> Arc<Self> {
        let platform = detect_platform();
        let nix_path = crate::nix::detect().nix_path;

        Arc::new(Self {
            nix_path: RwLock::new(nix_path),
            platform,
            start_time: Instant::now(),
            gc_status: RwLock::new(GcStatus {
                auto_gc_enabled: config.gc.schedule_secs > 0,
                schedule_secs: config.gc.schedule_secs,
                last_gc_at: None,
                last_gc_freed_bytes: None,
            }),
            config,
        })
    }

    pub async fn status(&self) -> NixStatus {
        let nix_path = self.nix_path.read().await;
        match &*nix_path {
            Some(path) => {
                let version = self.query_version(path).await;
                let install_method = self.detect_install_method(path);
                NixStatus {
                    installed: true,
                    version,
                    nix_path: Some(path.to_string_lossy().to_string()),
                    install_method,
                }
            }
            None => NixStatus {
                installed: false,
                version: None,
                nix_path: None,
                install_method: None,
            },
        }
    }

    pub fn platform_info(&self) -> PlatformInfo {
        self.platform.clone()
    }

    pub async fn store_info(&self) -> Result<StoreInfo> {
        let nix_path = self.nix_path.read().await;
        let nix = nix_path
            .as_ref()
            .context("nix not installed")?;

        let store_dir = "/nix/store".to_string();

        // Get store size via du
        let size = tokio::process::Command::new("du")
            .args(["-sb", "/nix/store"])
            .output()
            .await
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    let s = String::from_utf8_lossy(&o.stdout);
                    s.split_whitespace().next()?.parse::<u64>().ok()
                } else {
                    None
                }
            });

        // Count paths
        let path_count = tokio::process::Command::new(nix)
            .args(["path-info", "--all"])
            .output()
            .await
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    let s = String::from_utf8_lossy(&o.stdout);
                    Some(s.lines().count() as u64)
                } else {
                    None
                }
            });

        // Count GC roots
        let roots_count = tokio::process::Command::new(nix)
            .args(["store", "gc", "--print-roots"])
            .output()
            .await
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    let s = String::from_utf8_lossy(&o.stdout);
                    Some(s.lines().count() as u64)
                } else {
                    None
                }
            });

        Ok(StoreInfo {
            store_dir,
            store_size_bytes: size,
            path_count,
            roots_count,
        })
    }

    pub async fn nix_config(&self) -> Result<NixConfig> {
        let nix_path = self.nix_path.read().await;
        let nix = nix_path
            .as_ref()
            .context("nix not installed")?;

        let output = tokio::process::Command::new(nix)
            .args(["show-config", "--json"])
            .output()
            .await
            .context("failed to run nix show-config")?;

        if !output.status.success() {
            anyhow::bail!("nix show-config failed");
        }

        let json: serde_json::Value =
            serde_json::from_slice(&output.stdout).context("parsing nix show-config output")?;

        let get_str = |key: &str| -> Option<String> {
            json.get(key)
                .and_then(|v| v.get("value"))
                .and_then(|v| {
                    if let Some(s) = v.as_str() {
                        Some(s.to_string())
                    } else {
                        Some(v.to_string())
                    }
                })
        };

        let get_str_list = |key: &str| -> Vec<String> {
            json.get(key)
                .and_then(|v| v.get("value"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .or_else(|| {
                    // Some config values are space-separated strings
                    json.get(key)
                        .and_then(|v| v.get("value"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.split_whitespace().map(|s| s.to_string()).collect())
                })
                .unwrap_or_default()
        };

        Ok(NixConfig {
            substituters: get_str_list("substituters"),
            trusted_public_keys: get_str_list("trusted-public-keys"),
            max_jobs: get_str("max-jobs"),
            cores: get_str("cores"),
            experimental_features: get_str_list("experimental-features"),
            sandbox: get_str("sandbox"),
        })
    }

    pub async fn gc_status(&self) -> GcStatus {
        self.gc_status.read().await.clone()
    }

    pub async fn trigger_gc(&self) -> Result<GcResult> {
        let nix_path = self.nix_path.read().await;
        let nix = nix_path
            .as_ref()
            .context("nix not installed")?;

        let start = Instant::now();

        let output = tokio::process::Command::new(nix)
            .args(["store", "gc"])
            .output()
            .await
            .context("failed to run nix store gc")?;

        let duration_secs = start.elapsed().as_secs_f64();

        if !output.status.success() {
            anyhow::bail!("nix store gc failed");
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse output: count deleted paths and freed bytes
        // nix store gc outputs lines like: "deleting '/nix/store/...' (X bytes)"
        // and ends with "Y store paths deleted, Z bytes freed"
        let mut freed_bytes: u64 = 0;
        let mut freed_paths: u64 = 0;

        for line in stdout.lines() {
            if let Some(rest) = line.strip_suffix(" bytes freed") {
                if let Some((paths_str, bytes_str)) = rest.rsplit_once(", ") {
                    freed_bytes = bytes_str.parse().unwrap_or(0);
                    freed_paths = paths_str
                        .split_whitespace()
                        .next()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                }
            }
        }

        // Update GC status
        {
            let mut status = self.gc_status.write().await;
            status.last_gc_at = Some(chrono::Utc::now().to_rfc3339());
            status.last_gc_freed_bytes = Some(freed_bytes);
        }

        Ok(GcResult {
            freed_bytes,
            freed_paths,
            duration_secs,
        })
    }

    pub async fn optimise_store(&self) -> Result<OptimiseResult> {
        let nix_path = self.nix_path.read().await;
        let nix = nix_path
            .as_ref()
            .context("nix not installed")?;

        let start = Instant::now();

        let output = tokio::process::Command::new(nix)
            .args(["store", "optimise"])
            .output()
            .await
            .context("failed to run nix store optimise")?;

        let duration_secs = start.elapsed().as_secs_f64();

        if !output.status.success() {
            anyhow::bail!("nix store optimise failed");
        }

        // Parse output for deduplicated bytes
        let stdout = String::from_utf8_lossy(&output.stdout);
        let deduplicated_bytes = stdout
            .lines()
            .find_map(|line| {
                // Format varies; try to extract byte count
                line.split_whitespace()
                    .find_map(|word| word.parse::<u64>().ok())
            })
            .unwrap_or(0);

        Ok(OptimiseResult {
            deduplicated_bytes,
            duration_secs,
        })
    }

    pub async fn cache_info(&self) -> Result<Vec<CacheInfo>> {
        let config = self.nix_config().await?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .context("building HTTP client")?;

        let mut results = Vec::new();

        for sub in &config.substituters {
            let start = Instant::now();
            let resp = client.head(sub).send().await;
            let latency = start.elapsed().as_millis() as u64;

            let (reachable, latency_ms) = match resp {
                Ok(r) if r.status().is_success() || r.status().is_redirection() => {
                    (true, Some(latency))
                }
                _ => (false, None),
            };

            results.push(CacheInfo {
                substituter: sub.clone(),
                reachable,
                latency_ms,
            });
        }

        Ok(results)
    }

    pub async fn health(&self) -> DaemonHealth {
        let uptime_secs = self.start_time.elapsed().as_secs();
        let nix = self.status().await;

        DaemonHealth {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs,
            platform: self.platform.clone(),
            nix,
        }
    }

    pub async fn telemetry_payload(&self) -> TelemetryPayload {
        let nix = self.status().await;
        let store = self.store_info().await.ok();
        let gc = self.gc_status().await;
        let uptime_secs = self.start_time.elapsed().as_secs();

        let node_id = if self.config.telemetry.node_id.is_empty() {
            hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "unknown".to_string())
        } else {
            self.config.telemetry.node_id.clone()
        };

        TelemetryPayload {
            timestamp: chrono::Utc::now().to_rfc3339(),
            node_id,
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs,
            nix,
            platform: self.platform.clone(),
            store,
            gc,
        }
    }

    async fn query_version(&self, nix_path: &PathBuf) -> Option<String> {
        let output = tokio::process::Command::new(nix_path)
            .arg("--version")
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.trim().rsplit(' ').next().map(|s| s.to_string())
    }

    fn detect_install_method(&self, nix_path: &PathBuf) -> Option<String> {
        let path_str = nix_path.to_string_lossy();
        if path_str.contains("determinate") {
            Some("determinate".to_string())
        } else if std::path::Path::new("/nix/nix-installer").exists() {
            Some("nix-installer".to_string())
        } else {
            Some("upstream".to_string())
        }
    }
}

fn detect_platform() -> PlatformInfo {
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();

    let is_wsl = if cfg!(target_os = "linux") {
        std::fs::read_to_string("/proc/version")
            .map(|v| {
                let lower = v.to_lowercase();
                lower.contains("microsoft") || lower.contains("wsl")
            })
            .unwrap_or(false)
    } else {
        false
    };

    let has_systemd = std::path::Path::new("/run/systemd/system").exists();

    let target_triple = match (os.as_str(), arch.as_str()) {
        ("macos", "x86_64") => "x86_64-darwin",
        ("macos", "aarch64") => "aarch64-darwin",
        ("linux", "x86_64") => "x86_64-linux",
        ("linux", "aarch64") => "aarch64-linux",
        _ => "unknown",
    };

    PlatformInfo {
        os,
        arch,
        target_triple: target_triple.to_string(),
        is_wsl,
        has_systemd,
    }
}
