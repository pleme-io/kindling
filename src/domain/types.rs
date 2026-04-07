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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nix_status_roundtrip() {
        let status = NixStatus {
            installed: true,
            version: Some("2.24.12".to_string()),
            nix_path: Some("/nix/store/bin/nix".to_string()),
            install_method: Some("determinate".to_string()),
        };
        let json = serde_json::to_string(&status).unwrap();
        let deserialized: NixStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.installed, true);
        assert_eq!(deserialized.version.as_deref(), Some("2.24.12"));
    }

    #[test]
    fn platform_info_roundtrip() {
        let info = PlatformInfo {
            os: "Linux".to_string(),
            arch: "x86_64".to_string(),
            target_triple: "x86_64-linux".to_string(),
            is_wsl: false,
            has_systemd: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: PlatformInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.os, "Linux");
        assert!(deserialized.has_systemd);
        assert!(!deserialized.is_wsl);
    }

    #[test]
    fn store_info_roundtrip() {
        let info = StoreInfo {
            store_dir: "/nix/store".to_string(),
            store_size_bytes: Some(1_000_000_000),
            path_count: Some(500),
            roots_count: Some(20),
        };
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: StoreInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.store_size_bytes, Some(1_000_000_000));
    }

    #[test]
    fn gc_result_roundtrip() {
        let result = GcResult {
            freed_bytes: 500_000,
            freed_paths: 50,
            duration_secs: 1.5,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: GcResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.freed_bytes, 500_000);
        assert_eq!(deserialized.freed_paths, 50);
    }

    #[test]
    fn cache_info_roundtrip() {
        let info = CacheInfo {
            substituter: "https://cache.nixos.org".to_string(),
            reachable: true,
            latency_ms: Some(42),
        };
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: CacheInfo = serde_json::from_str(&json).unwrap();
        assert!(deserialized.reachable);
        assert_eq!(deserialized.latency_ms, Some(42));
    }

    #[test]
    fn optimise_result_roundtrip() {
        let result = OptimiseResult {
            deduplicated_bytes: 250_000,
            duration_secs: 0.75,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: OptimiseResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.deduplicated_bytes, 250_000);
    }

    #[test]
    fn gc_status_roundtrip() {
        let status = GcStatus {
            auto_gc_enabled: true,
            schedule_secs: 3600,
            last_gc_at: Some("2026-01-01T00:00:00Z".to_string()),
            last_gc_freed_bytes: Some(1_000_000),
        };
        let json = serde_json::to_string(&status).unwrap();
        let deserialized: GcStatus = serde_json::from_str(&json).unwrap();
        assert!(deserialized.auto_gc_enabled);
        assert_eq!(deserialized.schedule_secs, 3600);
    }

    #[test]
    fn nix_config_roundtrip() {
        let config = NixConfig {
            substituters: vec!["https://cache.nixos.org".to_string()],
            trusted_public_keys: vec!["cache.nixos.org-1:test".to_string()],
            max_jobs: Some("auto".to_string()),
            cores: Some("0".to_string()),
            experimental_features: vec!["nix-command".to_string(), "flakes".to_string()],
            sandbox: Some("true".to_string()),
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: NixConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.substituters.len(), 1);
        assert_eq!(deserialized.experimental_features.len(), 2);
    }

    #[test]
    fn daemon_health_roundtrip() {
        let health = DaemonHealth {
            version: "0.3.0".to_string(),
            uptime_secs: 3600,
            platform: PlatformInfo {
                os: "Linux".to_string(),
                arch: "x86_64".to_string(),
                target_triple: "x86_64-linux".to_string(),
                is_wsl: false,
                has_systemd: true,
            },
            nix: NixStatus {
                installed: true,
                version: Some("2.24.0".to_string()),
                nix_path: None,
                install_method: None,
            },
        };
        let json = serde_json::to_string(&health).unwrap();
        let deserialized: DaemonHealth = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.version, "0.3.0");
        assert_eq!(deserialized.uptime_secs, 3600);
    }

    #[test]
    fn telemetry_payload_roundtrip() {
        let payload = TelemetryPayload {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            node_id: "test-node".to_string(),
            daemon_version: "0.3.0".to_string(),
            uptime_secs: 1000,
            nix: NixStatus {
                installed: true,
                version: None,
                nix_path: None,
                install_method: None,
            },
            platform: PlatformInfo {
                os: "Linux".to_string(),
                arch: "x86_64".to_string(),
                target_triple: "x86_64-linux".to_string(),
                is_wsl: false,
                has_systemd: true,
            },
            store: None,
            gc: GcStatus {
                auto_gc_enabled: false,
                schedule_secs: 0,
                last_gc_at: None,
                last_gc_freed_bytes: None,
            },
        };
        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: TelemetryPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.node_id, "test-node");
    }
}
