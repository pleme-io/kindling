use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    pub auto_install: Option<bool>,
    pub backend: Option<String>,
    pub daemon: Option<DaemonConfig>,
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
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub gc: GcConfig,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            http_addr: default_http_addr(),
            grpc_addr: default_grpc_addr(),
            log_level: default_log_level(),
            telemetry: TelemetryConfig::default(),
            gc: GcConfig::default(),
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
pub struct GcConfig {
    #[serde(default)]
    pub schedule_secs: u64,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self { schedule_secs: 0 }
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

impl Config {
    pub fn path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir().context("could not determine config directory")?;
        Ok(config_dir.join("kindling").join("config.toml"))
    }
}

pub fn load() -> Result<Config> {
    let path = Config::path()?;
    if !path.exists() {
        return Ok(Config::default());
    }
    let content =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let config: Config =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
    Ok(config)
}

pub fn save_auto_install(value: bool) -> Result<()> {
    let path = Config::path()?;
    let mut config = if path.exists() {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&content).unwrap_or_default()
    } else {
        Config::default()
    };

    config.auto_install = Some(value);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    let content = toml::to_string_pretty(&config).context("serializing config")?;
    std::fs::write(&path, content).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}
