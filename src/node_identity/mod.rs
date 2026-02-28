//! Node identity — YAML-based machine configuration for kindling.
//!
//! Defines the `NodeIdentity` struct that maps to `~/.config/kindling/node.yaml`.
//! Profiles in kindling-profiles consume these values via `kindling.nodeIdentity.*`.

pub mod nix_gen;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Top-level node identity configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub version: String,
    pub profile: String,
    pub hostname: String,

    #[serde(default)]
    pub user: UserConfig,

    #[serde(default)]
    pub secrets: SecretsConfig,

    #[serde(default)]
    pub network: NetworkConfig,

    #[serde(default)]
    pub nix: NixConfig,

    #[serde(default)]
    pub kubernetes: KubernetesConfig,

    #[serde(default)]
    pub workspace: WorkspaceConfig,

    #[serde(default)]
    pub git: GitConfig,

    #[serde(default)]
    pub fleet: FleetConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserConfig {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub uid: u32,
    #[serde(default = "default_shell")]
    pub shell: String,
    #[serde(default)]
    pub email: String,
}

fn default_shell() -> String {
    "zsh".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretsConfig {
    #[serde(default = "default_secrets_provider")]
    pub provider: String,
    #[serde(default)]
    pub age_key_file: Option<String>,
}

fn default_secrets_provider() -> String {
    "sops".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkConfig {
    #[serde(default)]
    pub ssh: SshConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SshConfig {
    #[serde(default)]
    pub builder: Option<SshBuilderConfig>,
    #[serde(default)]
    pub cloudflare_tunnel: Option<CloudflareTunnelConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshBuilderConfig {
    pub hostname: String,
    pub fqdn: String,
    #[serde(default)]
    pub identity_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareTunnelConfig {
    pub user: String,
    pub domain_suffix: String,
    #[serde(default)]
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NixConfig {
    #[serde(default = "default_trusted_users")]
    pub trusted_users: Vec<String>,

    #[serde(default)]
    pub attic: AtticConfig,
}

fn default_trusted_users() -> Vec<String> {
    vec!["root".to_string()]
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AtticConfig {
    #[serde(default)]
    pub token_file: Option<String>,
    #[serde(default)]
    pub netrc_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KubernetesConfig {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub cluster_cidr: Option<String>,
    #[serde(default)]
    pub service_cidr: Option<String>,
    #[serde(default)]
    pub clusters: Vec<ClusterConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub name: String,
    pub server: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkspaceConfig {
    #[serde(default)]
    pub orgs: Vec<OrgConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgConfig {
    pub name: String,
    pub base_dir: String,
    #[serde(default)]
    pub github_token_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GitConfig {
    #[serde(default)]
    pub user: GitUserConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GitUserConfig {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FleetConfig {
    #[serde(default)]
    pub peers: Vec<FleetPeer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetPeer {
    pub name: String,
    pub hostname: String,
    #[serde(default = "default_ssh_user")]
    pub ssh_user: String,
}

fn default_ssh_user() -> String {
    "root".to_string()
}

impl NodeIdentity {
    /// Default path for node.yaml
    pub fn default_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("kindling")
            .join("node.yaml")
    }

    /// Load from a YAML file
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read node identity from {}", path.display()))?;
        let identity: NodeIdentity = serde_yaml::from_str(&content)
            .with_context(|| format!("failed to parse node identity from {}", path.display()))?;
        Ok(identity)
    }

    /// Save to a YAML file
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
        let content = serde_yaml::to_string(self)
            .context("failed to serialize node identity to YAML")?;
        std::fs::write(path, content)
            .with_context(|| format!("failed to write node identity to {}", path.display()))?;
        Ok(())
    }

    /// Serialize to JSON (for Nix consumption via builtins.fromJSON)
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("failed to serialize node identity to JSON")
    }

    /// Create a minimal identity from bootstrap flags
    pub fn from_bootstrap(
        profile: &str,
        hostname: &str,
        user: &str,
        age_key_file: Option<&str>,
    ) -> Self {
        NodeIdentity {
            version: "1".to_string(),
            profile: profile.to_string(),
            hostname: hostname.to_string(),
            user: UserConfig {
                name: user.to_string(),
                uid: 1000,
                shell: default_shell(),
                email: String::new(),
            },
            secrets: SecretsConfig {
                provider: default_secrets_provider(),
                age_key_file: age_key_file.map(|s| s.to_string()),
            },
            network: NetworkConfig::default(),
            nix: NixConfig {
                trusted_users: vec!["root".to_string(), user.to_string()],
                attic: AtticConfig::default(),
            },
            kubernetes: KubernetesConfig::default(),
            workspace: WorkspaceConfig::default(),
            git: GitConfig {
                user: GitUserConfig {
                    name: user.to_string(),
                    email: String::new(),
                },
            },
            fleet: FleetConfig::default(),
        }
    }
}
