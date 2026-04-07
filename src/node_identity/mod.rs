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
    #[serde(default)]
    pub vpn_links: Vec<VpnLinkConfig>,
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
    #[serde(default)]
    pub persistent_keepalive: Option<u32>,
    #[serde(default)]
    pub preshared_key_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, SimpleObject)]
pub struct VpnFirewallConfig {
    #[serde(default)]
    pub trust_interface: bool,
    #[serde(default)]
    pub allowed_tcp_ports: Vec<u32>,
    #[serde(default)]
    pub allowed_udp_ports: Vec<u32>,
    #[serde(default)]
    pub incoming_udp_port: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct VpnLinkConfig {
    pub name: String,
    #[serde(default)]
    pub private_key_file: Option<String>,
    #[serde(default)]
    pub listen_port: Option<u32>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub persistent_keepalive: Option<u32>,
    #[serde(default)]
    pub mtu: Option<u32>,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default)]
    pub peers: Vec<VpnPeerConfig>,
    #[serde(default)]
    pub firewall: VpnFirewallConfig,
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
    #[serde(default = "default_fluxcd_auth")]
    pub auth: String,
    #[serde(default)]
    pub token_file: Option<String>,
    #[serde(default)]
    pub ssh_key_file: Option<String>,
    #[graphql(skip)]
    #[serde(default)]
    pub reconcile: serde_json::Value,
}

fn default_fluxcd_auth() -> String {
    "token".to_string()
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
    /// Default path for node.yaml (workstation mode: `~/.config/kindling/node.yaml`)
    pub fn default_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("kindling")
            .join("node.yaml")
    }

    /// Server-mode path for node.yaml (`/etc/kindling/node.yaml`)
    pub fn server_path() -> PathBuf {
        PathBuf::from("/etc/kindling/node.yaml")
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
    pub fn redact(&self, private_fields: &[impl AsRef<str>]) -> Result<Self> {
        let mut val = serde_yaml::to_value(self)
            .context("failed to serialize identity for redaction")?;
        for field_path in private_fields {
            remove_field_path(&mut val, field_path.as_ref());
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // ── deep_merge tests ──────────────────────────────

    #[test]
    fn deep_merge_scalar_overlay_wins() {
        let mut base = serde_yaml::from_str::<serde_yaml::Value>("name: alice").unwrap();
        let overlay = serde_yaml::from_str::<serde_yaml::Value>("name: bob").unwrap();
        deep_merge(&mut base, overlay);
        assert_eq!(base["name"].as_str(), Some("bob"));
    }

    #[test]
    fn deep_merge_null_overlay_preserves_base() {
        let mut base = serde_yaml::from_str::<serde_yaml::Value>("name: alice").unwrap();
        let overlay = serde_yaml::Value::Null;
        deep_merge(&mut base, overlay);
        assert_eq!(base["name"].as_str(), Some("alice"));
    }

    #[test]
    fn deep_merge_nested_mappings() {
        let mut base = serde_yaml::from_str::<serde_yaml::Value>(
            "user:\n  name: alice\n  uid: 1000"
        ).unwrap();
        let overlay = serde_yaml::from_str::<serde_yaml::Value>(
            "user:\n  name: bob"
        ).unwrap();
        deep_merge(&mut base, overlay);
        assert_eq!(base["user"]["name"].as_str(), Some("bob"));
        assert_eq!(base["user"]["uid"].as_u64(), Some(1000));
    }

    #[test]
    fn deep_merge_adds_new_keys() {
        let mut base = serde_yaml::from_str::<serde_yaml::Value>("a: 1").unwrap();
        let overlay = serde_yaml::from_str::<serde_yaml::Value>("b: 2").unwrap();
        deep_merge(&mut base, overlay);
        assert_eq!(base["a"].as_u64(), Some(1));
        assert_eq!(base["b"].as_u64(), Some(2));
    }

    #[test]
    fn deep_merge_sequence_overlay_replaces() {
        let mut base = serde_yaml::from_str::<serde_yaml::Value>(
            "tags:\n  - a\n  - b"
        ).unwrap();
        let overlay = serde_yaml::from_str::<serde_yaml::Value>(
            "tags:\n  - x"
        ).unwrap();
        deep_merge(&mut base, overlay);
        let tags = base["tags"].as_sequence().unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].as_str(), Some("x"));
    }

    // ── remove_field_path tests ──────────────────────────────

    #[test]
    fn remove_field_path_single_level() {
        let mut val = serde_yaml::from_str::<serde_yaml::Value>(
            "name: alice\nage: 30"
        ).unwrap();
        remove_field_path(&mut val, "age");
        assert!(val["age"].is_null());
        assert_eq!(val["name"].as_str(), Some("alice"));
    }

    #[test]
    fn remove_field_path_nested() {
        let mut val = serde_yaml::from_str::<serde_yaml::Value>(
            "secrets:\n  age_keys:\n    - key1\n  provider: sops"
        ).unwrap();
        remove_field_path(&mut val, "secrets.age_keys");
        assert!(val["secrets"]["age_keys"].is_null());
        assert_eq!(val["secrets"]["provider"].as_str(), Some("sops"));
    }

    #[test]
    fn remove_field_path_nonexistent_is_noop() {
        let mut val = serde_yaml::from_str::<serde_yaml::Value>("name: alice").unwrap();
        let original = val.clone();
        remove_field_path(&mut val, "nonexistent.deep.path");
        assert_eq!(val, original);
    }

    #[test]
    fn remove_field_path_empty_path_is_noop() {
        let mut val = serde_yaml::from_str::<serde_yaml::Value>("name: alice").unwrap();
        let original = val.clone();
        remove_field_path(&mut val, "");
        assert_eq!(val, original);
    }

    // ── from_bootstrap tests ──────────────────────────────

    #[test]
    fn from_bootstrap_sets_fields() {
        let id = NodeIdentity::from_bootstrap("cloud-server", "node1", "deploy", None);
        assert_eq!(id.profile, "cloud-server");
        assert_eq!(id.hostname, "node1");
        assert_eq!(id.user.name, "deploy");
        assert_eq!(id.user.uid, 1000);
        assert_eq!(id.version, "1");
        assert!(id.secrets.age_key_file.is_none());
    }

    #[test]
    fn from_bootstrap_with_age_key() {
        let id = NodeIdentity::from_bootstrap("server", "h1", "root", Some("/etc/age.key"));
        assert_eq!(id.secrets.age_key_file.as_deref(), Some("/etc/age.key"));
    }

    #[test]
    fn from_bootstrap_includes_user_in_trusted_users() {
        let id = NodeIdentity::from_bootstrap("server", "h1", "deploy", None);
        assert!(id.nix.trusted_users.contains(&"root".to_string()));
        assert!(id.nix.trusted_users.contains(&"deploy".to_string()));
    }

    // ── save + load round-trip tests ──────────────────────────────

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.yaml");
        let original = NodeIdentity::from_bootstrap("cloud-server", "test-node", "root", None);
        original.save(&path).unwrap();
        let loaded = NodeIdentity::load(&path).unwrap();
        assert_eq!(loaded.hostname, "test-node");
        assert_eq!(loaded.profile, "cloud-server");
        assert_eq!(loaded.user.name, "root");
    }

    #[test]
    fn save_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a").join("b").join("node.yaml");
        let id = NodeIdentity::from_bootstrap("server", "h1", "root", None);
        id.save(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn load_nonexistent_returns_error() {
        let result = NodeIdentity::load(Path::new("/nonexistent/path/node.yaml"));
        assert!(result.is_err());
    }

    #[test]
    fn load_invalid_yaml_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yaml");
        std::fs::write(&path, "not: [valid: yaml: {{{{").unwrap();
        let result = NodeIdentity::load(&path);
        assert!(result.is_err());
    }

    // ── to_json tests ──────────────────────────────

    #[test]
    fn to_json_produces_valid_json() {
        let id = NodeIdentity::from_bootstrap("server", "host1", "root", None);
        let json = id.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["hostname"], "host1");
        assert_eq!(parsed["profile"], "server");
    }

    // ── redact tests ──────────────────────────────

    #[test]
    fn redact_removes_specified_fields() {
        let mut id = NodeIdentity::from_bootstrap("server", "h1", "root", Some("/key"));
        id.secrets.age_keys = vec!["AGE-SECRET-KEY-1FAKE".to_string()];
        let redacted = id.redact(&["secrets.age_keys".to_string(), "secrets.age_key_file".to_string()]).unwrap();
        assert!(redacted.secrets.age_keys.is_empty());
        assert!(redacted.secrets.age_key_file.is_none());
        assert_eq!(redacted.hostname, "h1");
    }

    #[test]
    fn redact_empty_fields_is_identity() {
        let id = NodeIdentity::from_bootstrap("server", "h1", "root", None);
        let empty: &[String] = &[];
        let redacted = id.redact(empty).unwrap();
        assert_eq!(redacted.hostname, id.hostname);
        assert_eq!(redacted.profile, id.profile);
    }

    // ── load_with_overlays tests ──────────────────────────────

    #[test]
    fn load_with_overlays_applies_overlay() {
        let dir = tempfile::tempdir().unwrap();

        let base_path = dir.path().join("node.yaml");
        std::fs::write(&base_path, "version: '1'\nprofile: base\nhostname: original\nuser:\n  name: root\n  uid: 0\n  shell: bash\n  email: ''").unwrap();

        let overlay_dir = dir.path().join("overlays");
        std::fs::create_dir_all(&overlay_dir).unwrap();
        std::fs::write(overlay_dir.join("01-override.yaml"), "hostname: overridden").unwrap();

        let identity = NodeIdentity::load_with_overlays(
            &base_path,
            &[overlay_dir.to_string_lossy().to_string()],
        ).unwrap();

        assert_eq!(identity.hostname, "overridden");
        assert_eq!(identity.profile, "base");
    }

    #[test]
    fn load_with_overlays_sorts_alphabetically() {
        let dir = tempfile::tempdir().unwrap();

        let base_path = dir.path().join("node.yaml");
        std::fs::write(&base_path, "version: '1'\nprofile: base\nhostname: h\nuser:\n  name: root\n  uid: 0\n  shell: bash\n  email: ''").unwrap();

        let overlay_dir = dir.path().join("overlays");
        std::fs::create_dir_all(&overlay_dir).unwrap();
        std::fs::write(overlay_dir.join("02-second.yaml"), "hostname: second").unwrap();
        std::fs::write(overlay_dir.join("01-first.yaml"), "hostname: first").unwrap();

        let identity = NodeIdentity::load_with_overlays(
            &base_path,
            &[overlay_dir.to_string_lossy().to_string()],
        ).unwrap();

        assert_eq!(identity.hostname, "second");
    }

    #[test]
    fn load_with_overlays_skips_bad_files() {
        let dir = tempfile::tempdir().unwrap();

        let base_path = dir.path().join("node.yaml");
        std::fs::write(&base_path, "version: '1'\nprofile: base\nhostname: h\nuser:\n  name: root\n  uid: 0\n  shell: bash\n  email: ''").unwrap();

        let overlay_dir = dir.path().join("overlays");
        std::fs::create_dir_all(&overlay_dir).unwrap();
        std::fs::write(overlay_dir.join("01-bad.yaml"), "{{invalid yaml}}}").unwrap();
        std::fs::write(overlay_dir.join("02-good.yaml"), "hostname: good").unwrap();

        let identity = NodeIdentity::load_with_overlays(
            &base_path,
            &[overlay_dir.to_string_lossy().to_string()],
        ).unwrap();

        assert_eq!(identity.hostname, "good");
    }

    #[test]
    fn load_with_overlays_ignores_non_yaml_files() {
        let dir = tempfile::tempdir().unwrap();

        let base_path = dir.path().join("node.yaml");
        std::fs::write(&base_path, "version: '1'\nprofile: base\nhostname: original\nuser:\n  name: root\n  uid: 0\n  shell: bash\n  email: ''").unwrap();

        let overlay_dir = dir.path().join("overlays");
        std::fs::create_dir_all(&overlay_dir).unwrap();
        std::fs::write(overlay_dir.join("readme.txt"), "hostname: should-be-ignored").unwrap();

        let identity = NodeIdentity::load_with_overlays(
            &base_path,
            &[overlay_dir.to_string_lossy().to_string()],
        ).unwrap();

        assert_eq!(identity.hostname, "original");
    }
}
