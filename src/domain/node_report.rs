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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn stored_report_new_computes_checksum() {
        let report = make_test_report();
        let stored = StoredReport::new(report);
        assert!(stored.checksum.starts_with("sha256:"));
        assert!(stored.checksum.len() > 10);
    }

    #[test]
    fn stored_report_verify_passes_on_fresh_report() {
        let report = make_test_report();
        let stored = StoredReport::new(report);
        assert!(stored.verify(), "freshly created report should verify");
    }

    #[test]
    fn stored_report_verify_fails_on_tampered_report() {
        let report = make_test_report();
        let mut stored = StoredReport::new(report);
        stored.report.hostname = "tampered".to_string();
        assert!(!stored.verify(), "tampered report should fail verification");
    }

    #[test]
    fn stored_report_verify_fails_on_wrong_checksum() {
        let report = make_test_report();
        let mut stored = StoredReport::new(report);
        stored.checksum = "sha256:0000000000000000".to_string();
        assert!(!stored.verify(), "wrong checksum should fail verification");
    }

    #[test]
    fn stored_report_age_is_non_negative() {
        let report = make_test_report();
        let stored = StoredReport::new(report);
        assert!(stored.age_secs() >= 0);
    }

    #[test]
    fn stored_report_is_stale_false_when_fresh() {
        let report = make_test_report();
        let stored = StoredReport::new(report);
        assert!(!stored.is_stale(600));
    }

    #[test]
    fn stored_report_is_stale_boundary() {
        let report = make_test_report();
        let mut stored = StoredReport::new(report);
        stored.collected_at = Utc::now() - chrono::Duration::seconds(10);
        assert!(stored.is_stale(5), "10s old report should be stale with max_age=5");
        assert!(!stored.is_stale(3600), "10s old report should not be stale with max_age=3600");
    }

    #[test]
    fn stored_report_serialization_round_trip() {
        let report = make_test_report();
        let stored = StoredReport::new(report);
        let json = serde_json::to_string(&stored).unwrap();
        let deserialized: StoredReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.checksum, stored.checksum);
        assert_eq!(deserialized.report.hostname, stored.report.hostname);
        assert!(deserialized.verify());
    }

    #[test]
    fn stored_report_collector_version() {
        let report = make_test_report();
        let stored = StoredReport::new(report);
        assert_eq!(stored.collector_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn two_different_reports_have_different_checksums() {
        let r1 = make_test_report();
        let mut r2 = make_test_report();
        r2.hostname = "other-node".to_string();
        let s1 = StoredReport::new(r1);
        let s2 = StoredReport::new(r2);
        assert_ne!(s1.checksum, s2.checksum);
    }
}
