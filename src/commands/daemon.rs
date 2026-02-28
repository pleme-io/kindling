use anyhow::Result;

use crate::config;

pub fn run(
    http_addr: Option<String>,
    grpc_addr: Option<String>,
    log_level: Option<String>,
    config_path: Option<String>,
) -> Result<()> {
    // Load config from file (custom path or default)
    let mut daemon_config = if let Some(path) = config_path {
        let content = std::fs::read_to_string(&path)?;
        let cfg: config::Config = toml::from_str(&content)?;
        cfg.daemon.unwrap_or_default()
    } else {
        let cfg = config::load()?;
        cfg.daemon.unwrap_or_default()
    };

    // CLI flags override config values
    if let Some(addr) = http_addr {
        daemon_config.http_addr = addr;
    }
    if let Some(addr) = grpc_addr {
        daemon_config.grpc_addr = addr;
    }
    if let Some(level) = log_level {
        daemon_config.log_level = level;
    }

    // Build tokio runtime explicitly (no #[tokio::main] on fn main)
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(crate::server::run(daemon_config))
}
