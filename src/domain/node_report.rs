//! Node report — runtime state collected from a live node.
//!
//! Unlike NodeIdentity (declared in YAML), a NodeReport is generated at runtime
//! by inspecting the actual hardware, OS, network, and service state of a node.

use async_graphql::SimpleObject;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A report wrapped with integrity metadata for storage and caching.
#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct StoredReport {
    /// SHA-256 checksum of the serialized report: "sha256:<hex>"
    pub checksum: String,
    /// When the report was collected.
    pub collected_at: DateTime<Utc>,
    /// Version of the collector that produced this report.
    pub collector_version: String,
    /// The actual report data.
    pub report: NodeReport,
}

impl StoredReport {
    /// Create a new StoredReport from a NodeReport, computing the SHA-256 checksum.
    pub fn new(report: NodeReport) -> Self {
        let serialized = serde_json::to_string(&report).unwrap_or_default();
        let hash = Sha256::digest(serialized.as_bytes());
        let checksum = format!("sha256:{:x}", hash);

        Self {
            checksum,
            collected_at: Utc::now(),
            collector_version: env!("CARGO_PKG_VERSION").to_string(),
            report,
        }
    }

    /// Seconds since the report was collected.
    pub fn age_secs(&self) -> i64 {
        Utc::now()
            .signed_duration_since(self.collected_at)
            .num_seconds()
    }

    /// Whether the report is older than max_age_secs.
    pub fn is_stale(&self, max_age_secs: u64) -> bool {
        self.age_secs() > max_age_secs as i64
    }

    /// Verify the checksum matches the report data. Returns true if valid.
    pub fn verify(&self) -> bool {
        let serialized = serde_json::to_string(&self.report).unwrap_or_default();
        let hash = Sha256::digest(serialized.as_bytes());
        let expected = format!("sha256:{:x}", hash);
        self.checksum == expected
    }
}

/// Complete runtime report from a node.
#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct NodeReport {
    pub timestamp: DateTime<Utc>,
    pub daemon_version: String,
    pub hostname: String,
    pub hardware: HardwareSnapshot,
    pub os: OsSnapshot,
    pub network: NetworkSnapshot,
    pub nix: NixSnapshot,
    pub kubernetes: Option<K8sSnapshot>,
    pub health: HealthMetrics,
    pub security: SecuritySnapshot,
    pub processes: ProcessSnapshot,
}

// ── Hardware ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct HardwareSnapshot {
    pub cpu_model: String,
    pub cpu_vendor: String,
    pub cpu_architecture: String,
    pub cpu_cores: u32,
    pub cpu_threads: u32,
    pub cpu_frequency_mhz: Option<u64>,
    pub cpu_cache_bytes: Option<u64>,
    pub ram_total_bytes: u64,
    pub ram_available_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub disks: Vec<DiskSnapshot>,
    pub gpus: Vec<GpuSnapshot>,
    pub temperatures: Vec<TemperatureReading>,
    pub power: Option<PowerSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct DiskSnapshot {
    pub device: String,
    pub mount_point: String,
    pub filesystem: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    #[serde(default)]
    pub smart_healthy: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct GpuSnapshot {
    pub name: String,
    pub vendor: String,
    #[serde(default)]
    pub vram_bytes: Option<u64>,
    #[serde(default)]
    pub metal_support: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct TemperatureReading {
    pub label: String,
    pub celsius: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct PowerSnapshot {
    pub on_battery: bool,
    pub charge_percent: Option<f64>,
    pub charging: bool,
    #[serde(default)]
    pub time_remaining_minutes: Option<u64>,
}

// ── OS ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct OsSnapshot {
    pub distribution: String,
    pub version: String,
    pub kernel_version: String,
    pub architecture: String,
    pub platform_triple: String,
    pub hostname: String,
    #[serde(default)]
    pub product_name: Option<String>,
    #[serde(default)]
    pub build_id: Option<String>,
    #[serde(default)]
    pub systemd_version: Option<String>,
    #[serde(default)]
    pub boot_time: Option<DateTime<Utc>>,
    pub uptime_secs: u64,
    #[serde(default)]
    pub timezone: Option<String>,
    pub is_wsl: bool,
    #[serde(default)]
    pub virtualization: Option<String>,
}

// ── Network ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct NetworkSnapshot {
    pub hostname: String,
    pub interfaces: Vec<InterfaceSnapshot>,
    pub routes: Vec<RouteSnapshot>,
    pub dns_resolvers: Vec<String>,
    #[serde(default)]
    pub default_gateway: Option<String>,
    pub listening_ports: Vec<ListeningPort>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct InterfaceSnapshot {
    pub name: String,
    pub state: String,
    pub addresses: Vec<String>,
    #[serde(default)]
    pub mac: Option<String>,
    #[serde(default)]
    pub mtu: Option<u32>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    #[serde(default)]
    pub speed_mbps: Option<u32>,
    #[serde(default)]
    pub interface_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct RouteSnapshot {
    pub destination: String,
    #[serde(default)]
    pub gateway: Option<String>,
    pub interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct ListeningPort {
    pub port: u16,
    pub protocol: String,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub process: Option<String>,
}

// ── Nix ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct NixSnapshot {
    pub nix_version: String,
    pub store_size_bytes: u64,
    pub store_path_count: u64,
    pub gc_roots_count: u64,
    #[serde(default)]
    pub last_rebuild_timestamp: Option<DateTime<Utc>>,
    #[serde(default)]
    pub current_system_path: Option<String>,
    pub substituters: Vec<String>,
    pub system_generations: u64,
    pub channels: Vec<String>,
    pub trusted_users: Vec<String>,
    pub max_jobs: Option<String>,
    pub sandbox_enabled: bool,
}

// ── Kubernetes ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct K8sSnapshot {
    #[serde(default)]
    pub k3s_version: Option<String>,
    pub node_ready: bool,
    pub pod_count: u32,
    pub namespace_count: u32,
    pub conditions: Vec<K8sCondition>,
    pub cpu_requests_millis: u64,
    pub cpu_limits_millis: u64,
    pub memory_requests_bytes: u64,
    pub memory_limits_bytes: u64,
    #[serde(default)]
    pub flux_installed: Option<bool>,
    #[serde(default)]
    pub helm_releases: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct K8sCondition {
    pub condition_type: String,
    pub status: String,
    #[serde(default)]
    pub message: Option<String>,
}

// ── Health ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct HealthMetrics {
    pub load_average_1m: f64,
    pub load_average_5m: f64,
    pub load_average_15m: f64,
    pub memory_usage_percent: f64,
    pub swap_usage_percent: f64,
    pub cpu_usage_percent: f64,
    pub disk_usage: Vec<DiskUsage>,
    pub open_file_descriptors: Option<u64>,
    pub max_file_descriptors: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct DiskUsage {
    pub mount_point: String,
    pub usage_percent: f64,
}

// ── Processes ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct ProcessSnapshot {
    pub total_processes: u32,
    pub running_processes: u32,
    pub zombie_processes: u32,
    pub top_cpu: Vec<ProcessInfo>,
    pub top_memory: Vec<ProcessInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f64,
    pub memory_percent: f64,
}

// ── Security ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct SecuritySnapshot {
    pub ssh_keys_deployed: Vec<String>,
    pub tls_certificates: Vec<CertStatus>,
    pub firewall_active: bool,
    pub firewall_rules_count: u32,
    #[serde(default)]
    pub firewall_backend: Option<String>,
    pub sshd_running: bool,
    pub root_login_allowed: bool,
    pub password_auth_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct CertStatus {
    pub domain: String,
    #[serde(default)]
    pub expiry: Option<DateTime<Utc>>,
    #[serde(default)]
    pub days_until_expiry: Option<i64>,
    #[serde(default)]
    pub issuer: Option<String>,
}
