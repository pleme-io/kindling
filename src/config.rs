use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use figment::providers::{Env, Format, Serialized, Yaml};
use figment::Figment;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    pub auto_install: Option<bool>,
    pub backend: Option<String>,
    #[serde(default)]
    pub identity: IdentityConfig,
    pub daemon: Option<DaemonConfig>,
    #[serde(default)]
    pub nodes: BTreeMap<String, NodeTarget>,
}

/// A named remote node target for `kindling query --node <name>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeTarget {
    pub url: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_http_addr")]
    pub http_addr: String,
    #[serde(default = "default_grpc_addr")]
    pub grpc_addr: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub gc: GcConfig,
    #[serde(default)]
    pub report: ReportConfig,
    #[serde(default)]
    pub fleet_controller: FleetControllerConfig,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            http_addr: default_http_addr(),
            grpc_addr: default_grpc_addr(),
            log_level: default_log_level(),
            identity: IdentityConfig::default(),
            telemetry: TelemetryConfig::default(),
            gc: GcConfig::default(),
            report: ReportConfig::default(),
            fleet_controller: FleetControllerConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_vector_url")]
    pub vector_url: String,
    #[serde(default = "default_push_interval")]
    pub push_interval_secs: u64,
    #[serde(default)]
    pub node_id: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            vector_url: default_vector_url(),
            push_interval_secs: default_push_interval(),
            node_id: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct GcConfig {
    #[serde(default)]
    pub schedule_secs: u64,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    /// Interval in seconds between automatic report refreshes.
    #[serde(default = "default_report_interval")]
    pub refresh_interval_secs: u64,
    /// Path to the cached report file.
    #[serde(default = "default_cache_file")]
    pub cache_file: String,
    /// Maximum age in seconds before a cached report is considered stale.
    #[serde(default = "default_max_age_secs")]
    pub max_age_secs: u64,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            refresh_interval_secs: default_report_interval(),
            cache_file: default_cache_file(),
            max_age_secs: default_max_age_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct IdentityConfig {
    /// Extra directories to scan for identity overlay YAML files.
    #[serde(default)]
    pub overlay_dirs: Vec<String>,
    /// Dot-path fields to exclude from fleet transmission (e.g. "secrets.age_keys").
    #[serde(default)]
    pub private_fields: Vec<String>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetControllerConfig {
    /// Enable fleet controller mode (accept reports from remote nodes).
    #[serde(default)]
    pub enabled: bool,
    /// Path to persist fleet state.
    #[serde(default = "default_fleet_state_path")]
    pub state_file: String,
}

impl Default for FleetControllerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            state_file: default_fleet_state_path(),
        }
    }
}

fn default_http_addr() -> String {
    "127.0.0.1:9100".to_string()
}
fn default_grpc_addr() -> String {
    "127.0.0.1:9101".to_string()
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_vector_url() -> String {
    "http://localhost:8686".to_string()
}
fn default_push_interval() -> u64 {
    60
}
fn default_report_interval() -> u64 {
    300 // 5 minutes
}
fn default_cache_file() -> String {
    dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("~/.config"))
        .join("kindling")
        .join("report.json")
        .to_string_lossy()
        .to_string()
}
fn default_max_age_secs() -> u64 {
    600 // 10 minutes
}
fn default_fleet_state_path() -> String {
    dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("~/.config"))
        .join("kindling")
        .join("fleet.json")
        .to_string_lossy()
        .to_string()
}

// ── shikumi::TieredConfig — prime directive ────────────────
//
// Every public kindling Config struct impls TieredConfig so operators
// can request `kindling config-show <tier>` + override via
// `KINDLING_TIER` env var. bare() = zero-opinion floor;
// prescribed_default() = the curated kindling defaults that ship.

impl shikumi::TieredConfig for Config {
    fn bare() -> Self {
        Self {
            auto_install: None,
            backend: None,
            identity: IdentityConfig::default(),
            daemon: None,
            nodes: BTreeMap::new(),
        }
    }
    fn prescribed_default() -> Self {
        Self::default()
    }
}

impl shikumi::TieredConfig for DaemonConfig {
    fn bare() -> Self {
        Self {
            http_addr: String::new(),
            grpc_addr: String::new(),
            log_level: String::new(),
            identity: IdentityConfig::default(),
            telemetry: TelemetryConfig {
                enabled: false,
                vector_url: String::new(),
                push_interval_secs: 0,
                node_id: String::new(),
            },
            gc: GcConfig::default(),
            report: ReportConfig {
                refresh_interval_secs: 0,
                cache_file: String::new(),
                max_age_secs: 0,
            },
            fleet_controller: FleetControllerConfig {
                enabled: false,
                state_file: String::new(),
            },
        }
    }
    fn prescribed_default() -> Self {
        Self::default()
    }
}

impl shikumi::TieredConfig for TelemetryConfig {
    fn bare() -> Self {
        Self {
            enabled: false,
            vector_url: String::new(),
            push_interval_secs: 0,
            node_id: String::new(),
        }
    }
    fn prescribed_default() -> Self {
        Self::default()
    }
}

impl shikumi::TieredConfig for ReportConfig {
    fn bare() -> Self {
        Self {
            refresh_interval_secs: 0,
            cache_file: String::new(),
            max_age_secs: 0,
        }
    }
    fn prescribed_default() -> Self {
        Self::default()
    }
}

impl shikumi::TieredConfig for FleetControllerConfig {
    fn bare() -> Self {
        Self {
            enabled: false,
            state_file: String::new(),
        }
    }
    fn prescribed_default() -> Self {
        Self::default()
    }
}

// ── Config file paths ──────────────────────────────────────

fn system_config_path() -> PathBuf {
    PathBuf::from("/etc/kindling/config.yaml")
}

fn user_config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("kindling")
        .join("config.yaml")
}

fn local_config_path() -> PathBuf {
    PathBuf::from(".kindling.yaml")
}

// ── Figment loading ────────────────────────────────────────

/// Build the figment provider chain:
/// defaults → system YAML → env vars → user YAML → local YAML
fn figment() -> Figment {
    Figment::from(Serialized::defaults(Config::default()))
        .merge(Yaml::file(system_config_path()))
        .merge(Env::prefixed("KINDLING_").split("__"))
        .merge(Yaml::file(user_config_path()))
        .merge(Yaml::file(local_config_path()))
}

/// Load config from the full figment chain.
pub fn load() -> Result<Config> {
    figment()
        .extract()
        .map_err(|e| anyhow::anyhow!("config error: {}", e))
}

/// Load config with an additional YAML file merged on top.
pub fn load_with_path(path: &str) -> Result<Config> {
    figment()
        .merge(Yaml::file(path))
        .extract()
        .map_err(|e| anyhow::anyhow!("config error: {}", e))
}

/// Persist the auto_install flag to the user config file.
pub fn save_auto_install(value: bool) -> Result<()> {
    let path = user_config_path();

    let mut config = if path.exists() {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        serde_yaml::from_str(&content).unwrap_or_default()
    } else {
        Config::default()
    };

    config.auto_install = Some(value);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    let content = serde_yaml::to_string(&config).context("serializing config")?;
    std::fs::write(&path, content).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default_has_no_auto_install() {
        let config = Config::default();
        assert!(config.auto_install.is_none());
    }

    #[test]
    fn config_default_has_no_backend() {
        let config = Config::default();
        assert!(config.backend.is_none());
    }

    #[test]
    fn config_default_has_empty_nodes() {
        let config = Config::default();
        assert!(config.nodes.is_empty());
    }

    #[test]
    fn daemon_config_default_addresses() {
        let dc = DaemonConfig::default();
        assert_eq!(dc.http_addr, "127.0.0.1:9100");
        assert_eq!(dc.grpc_addr, "127.0.0.1:9101");
        assert_eq!(dc.log_level, "info");
    }

    #[test]
    fn telemetry_config_default_disabled() {
        let tc = TelemetryConfig::default();
        assert!(!tc.enabled);
        assert_eq!(tc.push_interval_secs, 60);
    }

    #[test]
    fn gc_config_default_zero() {
        let gc = GcConfig::default();
        assert_eq!(gc.schedule_secs, 0);
    }

    #[test]
    fn report_config_defaults() {
        let rc = ReportConfig::default();
        assert_eq!(rc.refresh_interval_secs, 300);
        assert_eq!(rc.max_age_secs, 600);
    }

    #[test]
    fn fleet_controller_config_default_disabled() {
        let fc = FleetControllerConfig::default();
        assert!(!fc.enabled);
    }

    #[test]
    fn load_with_path_merges_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let yaml_path = dir.path().join("test-config.yaml");
        std::fs::write(&yaml_path, "auto_install: true\nbackend: determinate\n").unwrap();
        let config = load_with_path(yaml_path.to_str().unwrap()).unwrap();
        assert_eq!(config.auto_install, Some(true));
        assert_eq!(config.backend.as_deref(), Some("determinate"));
    }

    #[test]
    fn config_deserializes_from_yaml() {
        let yaml = r#"
auto_install: false
backend: upstream
nodes:
  prod:
    url: https://prod.example.com:9100
    description: Production node
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.auto_install, Some(false));
        assert_eq!(config.backend.as_deref(), Some("upstream"));
        let prod = config.nodes.get("prod").unwrap();
        assert_eq!(prod.url, "https://prod.example.com:9100");
        assert_eq!(prod.description.as_deref(), Some("Production node"));
    }

    #[test]
    fn config_serializes_and_deserializes() {
        let mut config = Config::default();
        config.auto_install = Some(true);
        config.backend = Some("determinate".to_string());

        let yaml = serde_yaml::to_string(&config).unwrap();
        let deserialized: Config = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(deserialized.auto_install, Some(true));
        assert_eq!(deserialized.backend.as_deref(), Some("determinate"));
    }

    #[test]
    fn identity_config_default_empty() {
        let ic = IdentityConfig::default();
        assert!(ic.overlay_dirs.is_empty());
        assert!(ic.private_fields.is_empty());
    }

    #[test]
    fn daemon_config_with_nodes() {
        let yaml = r#"
nodes:
  staging:
    url: http://localhost:9100
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.nodes.contains_key("staging"));
    }
}

#[cfg(test)]
mod tiered_tests {
    use super::*;
    use shikumi::{ConfigTier, TieredConfig};

    #[test]
    fn config_bare_is_zero_opinion() {
        let b = <Config as TieredConfig>::bare();
        assert!(b.auto_install.is_none());
        assert!(b.backend.is_none());
        assert!(b.daemon.is_none());
        assert!(b.nodes.is_empty());
    }

    #[test]
    fn daemon_config_bare_is_zero_opinion() {
        let b = <DaemonConfig as TieredConfig>::bare();
        assert_eq!(b.http_addr, "");
        assert_eq!(b.grpc_addr, "");
        assert_eq!(b.log_level, "");
        assert_eq!(b.telemetry.push_interval_secs, 0);
        assert_eq!(b.report.cache_file, "");
        assert!(!b.fleet_controller.enabled);
    }

    #[test]
    fn daemon_config_prescribed_matches_default() {
        let p = <DaemonConfig as TieredConfig>::prescribed_default();
        let d = DaemonConfig::default();
        assert_eq!(p.http_addr, d.http_addr);
        assert_eq!(p.grpc_addr, d.grpc_addr);
        assert_eq!(p.log_level, d.log_level);
    }

    #[test]
    fn daemon_config_diff_bare_vs_default_is_non_empty() {
        let b = <DaemonConfig as TieredConfig>::bare();
        let d = <DaemonConfig as TieredConfig>::prescribed_default();
        let diff = d.diff_against(&b);
        assert!(
            !diff.is_empty_diff(),
            "bare and prescribed_default must differ"
        );
    }

    #[test]
    fn daemon_config_resolve_tier_dispatches() {
        assert_eq!(
            <DaemonConfig as TieredConfig>::resolve_tier(ConfigTier::Bare).http_addr,
            ""
        );
        assert_eq!(
            <DaemonConfig as TieredConfig>::resolve_tier(ConfigTier::Default).http_addr,
            "127.0.0.1:9100"
        );
    }

    #[test]
    fn telemetry_report_fleet_controller_bare_are_zero_opinion() {
        assert_eq!(
            <TelemetryConfig as TieredConfig>::bare().vector_url,
            ""
        );
        assert_eq!(
            <ReportConfig as TieredConfig>::bare().refresh_interval_secs,
            0
        );
        assert!(!<FleetControllerConfig as TieredConfig>::bare().enabled);
    }
}
