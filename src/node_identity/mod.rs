//! Node identity — YAML-based machine configuration for kindling.
//!
//! Defines the `NodeIdentity` struct that maps to `~/.config/kindling/node.yaml`.
//! Profiles in kindling-profiles consume these values via `kindling.nodeIdentity.*`.

pub mod nix_gen;

use anyhow::{Context, Result};
use async_graphql::SimpleObject;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Top-level node identity configuration.
#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct NodeIdentity {
    pub version: String,
    pub profile: String,
    pub hostname: String,

    #[serde(default)]
    pub user: UserConfig,

    #[serde(default)]
    pub secrets: SecretsConfig,

    #[serde(default)]
    pub hardware: HardwareConfig,

    #[serde(default)]
    pub network: NetworkConfig,

    #[serde(default)]
    pub nix: NixNodeConfig,

    #[serde(default)]
    pub kubernetes: KubernetesConfig,

    #[serde(default)]
    pub fluxcd: FluxcdConfig,

    #[serde(default)]
    pub services: ServicesConfig,

    #[serde(default)]
    pub workspace: WorkspaceConfig,

    #[serde(default)]
    pub git: GitConfig,

    #[serde(default)]
    pub fleet: FleetConfig,
}

// ── User ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, SimpleObject)]
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
    "blzsh".to_string()
}

// ── Secrets ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, SimpleObject)]
pub struct SecretsConfig {
    #[serde(default = "default_secrets_provider")]
    pub provider: String,
    #[serde(default)]
    pub age_key_file: Option<String>,
    #[serde(default)]
    pub ssh_authorized_keys: Vec<String>,
    #[serde(default)]
    pub tls_certificates: Vec<TlsCertificate>,
    #[serde(default)]
    pub age_keys: Vec<String>,
}

fn default_secrets_provider() -> String {
    "sops".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct TlsCertificate {
    pub domain: String,
    #[serde(default)]
    pub cert_file: Option<String>,
    #[serde(default)]
    pub key_file: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
}

// ── Hardware ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, SimpleObject)]
pub struct HardwareConfig {
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub cpu: CpuConfig,
    #[serde(default)]
    pub memory: Option<MemoryConfig>,
    #[serde(default)]
    pub disks: Vec<DiskConfig>,
    #[serde(default)]
    pub gpus: Vec<GpuConfig>,
    #[serde(default)]
    pub network_interfaces: Vec<NicConfig>,
    #[serde(default)]
    pub kernel: KernelConfig,
    #[graphql(skip)]
    #[serde(default)]
    pub filesystems: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, SimpleObject)]
pub struct CpuConfig {
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub cores: Option<u32>,
    #[serde(default)]
    pub threads: Option<u32>,
    #[serde(default)]
    pub model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct MemoryConfig {
    pub size_gb: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct DiskConfig {
    pub device: String,
    #[serde(default)]
    pub size: Option<String>,
    #[serde(default)]
    pub disk_type: Option<String>,
    #[serde(default)]
    pub mount_point: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct GpuConfig {
    pub vendor: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub vram_mb: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct NicConfig {
    pub name: String,
    #[serde(default)]
    pub mac: Option<String>,
    #[serde(default)]
    pub speed_mbps: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, SimpleObject)]
pub struct KernelConfig {
    #[serde(default)]
    pub modules: Vec<String>,
    #[serde(default)]
    pub params: Vec<String>,
}

// ── Network ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, SimpleObject)]
pub struct NetworkConfig {
    #[serde(default)]
    pub ssh: SshConfig,
    #[serde(default)]
    #[graphql(skip)]
    pub interfaces: HashMap<String, NetworkInterface>,
    #[serde(default)]
    #[graphql(skip)]
    pub hosts: HashMap<String, String>,
    #[serde(default)]
    pub firewall: FirewallConfig,
    #[serde(default)]
    pub dns_servers: Vec<String>,
    #[serde(default)]
    pub ntp_servers: Vec<String>,
    #[serde(default)]
    pub vpn: Vec<VpnPeerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, SimpleObject)]
pub struct SshConfig {
    #[serde(default)]
    pub builder: Option<SshBuilderConfig>,
    #[serde(default)]
    pub cloudflare_tunnel: Option<CloudflareTunnelConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct SshBuilderConfig {
    pub hostname: String,
    pub fqdn: String,
    #[serde(default)]
    pub identity_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct CloudflareTunnelConfig {
    pub user: String,
    pub domain_suffix: String,
    #[serde(default)]
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct NetworkInterface {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub prefix_length: Option<u32>,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default)]
    pub mac: Option<String>,
    #[serde(default)]
    pub mtu: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, SimpleObject)]
pub struct FirewallConfig {
    #[serde(default)]
    pub allowed_tcp_ports: Vec<u32>,
    #[serde(default)]
    pub allowed_udp_ports: Vec<u32>,
    #[serde(default)]
    pub rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct VpnPeerConfig {
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
}

// ── Nix ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, SimpleObject)]
pub struct NixNodeConfig {
    #[serde(default = "default_trusted_users")]
    pub trusted_users: Vec<String>,

    #[serde(default)]
    pub attic: AtticConfig,
}

fn default_trusted_users() -> Vec<String> {
    vec!["root".to_string()]
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, SimpleObject)]
pub struct AtticConfig {
    #[serde(default)]
    pub token_file: Option<String>,
    #[serde(default)]
    pub netrc_file: Option<String>,
}

// ── Kubernetes ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, SimpleObject)]
pub struct KubernetesConfig {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub cluster_cidr: Option<String>,
    #[serde(default)]
    pub service_cidr: Option<String>,
    #[serde(default)]
    pub clusters: Vec<ClusterConfig>,
    #[serde(default)]
    pub server_addr: Option<String>,
    #[serde(default)]
    #[graphql(skip)]
    pub node_labels: HashMap<String, String>,
    #[serde(default)]
    pub node_taints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct ClusterConfig {
    pub name: String,
    pub server: String,
}

// ── FluxCD ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, SimpleObject)]
pub struct FluxcdConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub source: String,
    #[graphql(skip)]
    #[serde(default)]
    pub reconcile: serde_json::Value,
}

// ── Services ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, SimpleObject)]
pub struct ServicesConfig {
    #[serde(default)]
    pub custom: Vec<CustomService>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct CustomService {
    pub name: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub health_endpoint: Option<String>,
    #[serde(default = "default_protocol")]
    pub protocol: String,
}

fn default_protocol() -> String {
    "http".to_string()
}

// ── Workspace ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, SimpleObject)]
pub struct WorkspaceConfig {
    #[serde(default)]
    pub orgs: Vec<OrgConfig>,
    #[serde(default)]
    pub zoekt_repos: Vec<String>,
    #[graphql(skip)]
    #[serde(default)]
    pub codesearch: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct OrgConfig {
    pub name: String,
    pub base_dir: String,
    #[serde(default)]
    pub github_token_file: Option<String>,
}

// ── Git ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, SimpleObject)]
pub struct GitConfig {
    #[serde(default)]
    pub user: GitUserConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, SimpleObject)]
pub struct GitUserConfig {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub email: String,
}

// ── Fleet ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, SimpleObject)]
pub struct FleetConfig {
    #[serde(default)]
    pub controller: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub team: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub maintenance_windows: Vec<MaintenanceWindow>,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub peers: Vec<FleetPeer>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct MaintenanceWindow {
    #[serde(default)]
    pub day: Option<String>,
    #[serde(default)]
    pub start_hour: Option<u8>,
    #[serde(default)]
    pub duration_hours: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct FleetPeer {
    pub name: String,
    pub hostname: String,
    #[serde(default = "default_ssh_user")]
    pub ssh_user: String,
}

fn default_ssh_user() -> String {
    "root".to_string()
}

// ── Impl ───────────────────────────────────────────────────

/// Deep merge two serde_yaml::Value trees.
///
/// - Mappings: recursive merge (overlay keys win)
/// - Sequences: overlay replaces entirely
/// - Scalars: overlay wins
/// - Null overlay: skip (preserves base)
pub fn deep_merge(base: &mut serde_yaml::Value, overlay: serde_yaml::Value) {
    match (base, overlay) {
        (serde_yaml::Value::Mapping(base_map), serde_yaml::Value::Mapping(overlay_map)) => {
            for (key, overlay_val) in overlay_map {
                if let Some(base_val) = base_map.get_mut(&key) {
                    deep_merge(base_val, overlay_val);
                } else {
                    base_map.insert(key, overlay_val);
                }
            }
        }
        (base, serde_yaml::Value::Null) => {
            // Null overlay means "don't change" — keep the base
            let _ = base;
        }
        (base, overlay) => {
            *base = overlay;
        }
    }
}

/// Remove a dot-separated field path from a serde_yaml::Value tree.
///
/// e.g. `remove_field_path(&mut val, "secrets.age_keys")` removes the `age_keys`
/// key from the `secrets` mapping.
pub fn remove_field_path(val: &mut serde_yaml::Value, path: &str) {
    let parts: Vec<&str> = path.split('.').collect();
    if parts.is_empty() {
        return;
    }
    remove_field_recursive(val, &parts);
}

fn remove_field_recursive(val: &mut serde_yaml::Value, parts: &[&str]) {
    if parts.is_empty() {
        return;
    }
    if let serde_yaml::Value::Mapping(map) = val {
        let key = serde_yaml::Value::String(parts[0].to_string());
        if parts.len() == 1 {
            map.remove(&key);
        } else if let Some(child) = map.get_mut(&key) {
            remove_field_recursive(child, &parts[1..]);
        }
    }
}

impl NodeIdentity {
    /// Default path for node.yaml
    pub fn default_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("kindling")
            .join("node.yaml")
    }

    /// Default overlay directory: `~/.config/kindling/identity.d/`
    pub fn default_overlay_dir() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("kindling")
            .join("identity.d")
    }

    /// Load from a YAML file
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read node identity from {}", path.display()))?;
        let identity: NodeIdentity = serde_yaml::from_str(&content)
            .with_context(|| format!("failed to parse node identity from {}", path.display()))?;
        Ok(identity)
    }

    /// Load base identity from a YAML file, then apply overlay files from
    /// the default overlay dir plus any extra dirs, sorted alphabetically.
    ///
    /// Bad overlay files log a warning and are skipped. Bad base file is a hard error.
    pub fn load_with_overlays(base_path: &Path, extra_overlay_dirs: &[String]) -> Result<Self> {
        let content = std::fs::read_to_string(base_path)
            .with_context(|| format!("failed to read base identity from {}", base_path.display()))?;
        let mut base: serde_yaml::Value = serde_yaml::from_str(&content)
            .with_context(|| format!("failed to parse base identity from {}", base_path.display()))?;

        // Collect all overlay dirs: default + extras
        let mut overlay_dirs = vec![Self::default_overlay_dir()];
        for dir in extra_overlay_dirs {
            overlay_dirs.push(PathBuf::from(dir));
        }

        // Collect and sort all overlay files across all dirs
        let mut overlay_files: Vec<PathBuf> = Vec::new();
        for dir in &overlay_dirs {
            if dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                            if ext == "yaml" || ext == "yml" {
                                overlay_files.push(path);
                            }
                        }
                    }
                }
            }
        }
        overlay_files.sort();

        // Apply each overlay in order
        for overlay_path in &overlay_files {
            match std::fs::read_to_string(overlay_path) {
                Ok(overlay_content) => {
                    match serde_yaml::from_str::<serde_yaml::Value>(&overlay_content) {
                        Ok(overlay_val) => {
                            tracing::info!(path = %overlay_path.display(), "applying identity overlay");
                            deep_merge(&mut base, overlay_val);
                        }
                        Err(e) => {
                            tracing::warn!(
                                path = %overlay_path.display(),
                                error = %e,
                                "skipping invalid overlay file"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        path = %overlay_path.display(),
                        error = %e,
                        "skipping unreadable overlay file"
                    );
                }
            }
        }

        let identity: NodeIdentity = serde_yaml::from_value(base)
            .context("failed to deserialize merged identity")?;
        Ok(identity)
    }

    /// Create a redacted copy of this identity with private fields removed.
    ///
    /// `private_fields` is a list of dot-separated paths, e.g. `["secrets.age_keys", "network.vpn"]`.
    pub fn redact(&self, private_fields: &[String]) -> Result<Self> {
        let mut val = serde_yaml::to_value(self)
            .context("failed to serialize identity for redaction")?;
        for field_path in private_fields {
            remove_field_path(&mut val, field_path);
        }
        let redacted: NodeIdentity = serde_yaml::from_value(val)
            .context("failed to deserialize redacted identity")?;
        Ok(redacted)
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
                ..Default::default()
            },
            hardware: HardwareConfig::default(),
            network: NetworkConfig::default(),
            nix: NixNodeConfig {
                trusted_users: vec!["root".to_string(), user.to_string()],
                attic: AtticConfig::default(),
            },
            kubernetes: KubernetesConfig::default(),
            fluxcd: FluxcdConfig::default(),
            services: ServicesConfig::default(),
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
