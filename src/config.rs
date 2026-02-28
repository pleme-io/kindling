use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    pub auto_install: Option<bool>,
    pub backend: Option<String>,
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
