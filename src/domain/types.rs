use async_graphql::SimpleObject;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct NixStatus {
    pub installed: bool,
    pub version: Option<String>,
    pub nix_path: Option<String>,
    pub install_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct PlatformInfo {
    pub os: String,
    pub arch: String,
    pub target_triple: String,
    pub is_wsl: bool,
    pub has_systemd: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct StoreInfo {
    pub store_dir: String,
    pub store_size_bytes: Option<u64>,
    pub path_count: Option<u64>,
    pub roots_count: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct NixConfig {
    pub substituters: Vec<String>,
    pub trusted_public_keys: Vec<String>,
    pub max_jobs: Option<String>,
    pub cores: Option<String>,
    pub experimental_features: Vec<String>,
    pub sandbox: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct GcStatus {
    pub auto_gc_enabled: bool,
    pub schedule_secs: u64,
    pub last_gc_at: Option<String>,
    pub last_gc_freed_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct GcResult {
    pub freed_bytes: u64,
    pub freed_paths: u64,
    pub duration_secs: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct OptimiseResult {
    pub deduplicated_bytes: u64,
    pub duration_secs: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct CacheInfo {
    pub substituter: String,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct DaemonHealth {
    pub version: String,
    pub uptime_secs: u64,
    pub platform: PlatformInfo,
    pub nix: NixStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryPayload {
    pub timestamp: String,
    pub node_id: String,
    pub daemon_version: String,
    pub uptime_secs: u64,
    pub nix: NixStatus,
    pub platform: PlatformInfo,
    pub store: Option<StoreInfo>,
    pub gc: GcStatus,
}
