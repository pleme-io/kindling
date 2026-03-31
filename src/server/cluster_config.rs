//! Parse cloud-init JSON (`/etc/pangea/cluster-config.json`) into typed config.
//!
//! The JSON is written by cloud-init at boot time and contains everything needed
//! to configure a K3s or vanilla Kubernetes node via blackmatter-kubernetes modules.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::node_identity::{
    FluxcdConfig, KubernetesConfig, NodeIdentity, SecretsConfig, UserConfig,
    VpnFirewallConfig, VpnLinkConfig, VpnPeerConfig,
};

/// Top-level cluster configuration from cloud-init JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub cluster_name: String,

    #[serde(default = "default_distribution")]
    pub distribution: String,

    #[serde(default = "default_profile")]
    pub profile: String,

    #[serde(default = "default_distribution_track")]
    pub distribution_track: String,

    #[serde(default = "default_role")]
    pub role: String,

    #[serde(default)]
    pub node_index: u32,

    #[serde(default)]
    pub cluster_init: bool,

    #[serde(default)]
    pub network_id: Option<String>,

    #[serde(default)]
    pub join_server: Option<String>,

    #[serde(default)]
    pub fluxcd: Option<FluxcdClusterConfig>,

    #[serde(default)]
    pub argocd: Option<serde_json::Value>,

    #[serde(default)]
    pub k3s: Option<K3sClusterConfig>,

    #[serde(default)]
    pub kubernetes: Option<KubernetesClusterConfig>,

    #[serde(default)]
    pub secrets: Option<SecretsClusterConfig>,

    #[serde(default)]
    pub vpn: Option<VpnClusterConfig>,

    /// Bootstrap secrets delivered via cloud-init.
    /// Keys: "sops_age_key", "flux_github_token", etc.
    /// Values: the raw secret content (not paths).
    #[serde(default)]
    pub bootstrap_secrets: Option<HashMap<String, String>>,

    /// Skip nixos-rebuild during bootstrap (for AMI integration testing).
    /// When true, the bootstrap provisions secrets, starts WireGuard, and
    /// starts K3s directly without running nixos-rebuild. The AMI already
    /// has the full NixOS config from the build phase.
    #[serde(default)]
    pub skip_nix_rebuild: Option<bool>,

    /// Force nixos-rebuild during bootstrap (bare-metal or non-AMI nodes).
    /// Default: false (max-baked AMI path — no rebuild needed).
    #[serde(default)]
    pub force_rebuild: Option<bool>,
}

/// FluxCD bootstrap configuration from cloud-init.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FluxcdClusterConfig {
    #[serde(default)]
    pub source_url: Option<String>,
    #[serde(default)]
    pub source_auth: Option<String>,
    #[serde(default)]
    pub source_token_file: Option<String>,
    #[serde(default)]
    pub source_ssh_key_file: Option<String>,
    #[serde(default)]
    pub reconcile_path: Option<String>,
    #[serde(default)]
    pub reconcile_interval: Option<String>,
    #[serde(default)]
    pub reconcile_prune: Option<bool>,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub sops_enabled: Option<bool>,
    #[serde(default)]
    pub sops_age_key_file: Option<String>,
}

/// K3s-specific distribution options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K3sClusterConfig {
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub disable: Vec<String>,
    #[serde(default)]
    pub tls_san: Vec<String>,
    #[serde(default)]
    pub node_ip: Option<String>,
    #[serde(default)]
    pub flannel_backend: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Kubernetes (kubeadm) distribution options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesClusterConfig {
    /// Kubernetes version (e.g., "1.32.0"). Used in ClusterConfiguration.
    #[serde(default)]
    pub version: Option<String>,

    /// Pod network CIDR (default: 10.244.0.0/16 for Flannel/Calico).
    #[serde(default = "default_pod_cidr")]
    pub pod_cidr: String,

    /// Service network CIDR (default: 10.96.0.0/12).
    #[serde(default = "default_service_cidr")]
    pub service_cidr: String,

    /// kubeadm bootstrap token for joining (e.g., "abcdef.0123456789abcdef").
    #[serde(default)]
    pub token: Option<String>,

    /// Certificate key for control plane join (from `kubeadm init --upload-certs`).
    #[serde(default)]
    pub certificate_key: Option<String>,

    /// CA certificate hash for secure join (e.g., "sha256:...").
    #[serde(default)]
    pub ca_cert_hash: Option<String>,

    /// Extra SANs for the API server certificate.
    #[serde(default)]
    pub api_server_cert_sans: Vec<String>,

    /// Container runtime socket (default: containerd).
    #[serde(default = "default_cri_socket")]
    pub cri_socket: String,
}

/// Secrets path references for sops-nix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsClusterConfig {
    #[serde(default, alias = "sops_age_key_path")]
    pub age_key_file: Option<String>,
    #[serde(default)]
    pub sops_file: Option<String>,
}

/// VPN configuration from cloud-init — defines WireGuard links for the node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnClusterConfig {
    #[serde(default)]
    pub require_liveness: bool,
    #[serde(default)]
    pub links: Vec<VpnLinkClusterConfig>,
}

/// A single VPN link from cloud-init.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnLinkClusterConfig {
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
    pub peers: Vec<VpnPeerClusterConfig>,
    #[serde(default)]
    pub firewall: Option<VpnFirewallClusterConfig>,
}

/// VPN peer from cloud-init.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnPeerClusterConfig {
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

/// VPN firewall config from cloud-init.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnFirewallClusterConfig {
    #[serde(default)]
    pub trust_interface: bool,
    #[serde(default)]
    pub allowed_tcp_ports: Vec<u32>,
    #[serde(default)]
    pub allowed_udp_ports: Vec<u32>,
    #[serde(default)]
    pub incoming_udp_port: Option<u32>,
}

fn default_pod_cidr() -> String {
    "10.244.0.0/16".to_string()
}

fn default_service_cidr() -> String {
    "10.96.0.0/12".to_string()
}

fn default_cri_socket() -> String {
    "unix:///run/containerd/containerd.sock".to_string()
}

fn default_distribution() -> String {
    "k3s".to_string()
}

fn default_profile() -> String {
    "cloud-server".to_string()
}

fn default_distribution_track() -> String {
    "1.34".to_string()
}

fn default_role() -> String {
    "server".to_string()
}

use crate::vpn::validate as vpn_validate;

impl ClusterConfig {
    /// Whether nixos-rebuild should run during bootstrap.
    /// Returns true only if force_rebuild is explicitly true, or if
    /// skip_nix_rebuild is explicitly false (backward compat).
    /// Default (both None) = no rebuild (max-baked AMI path).
    pub fn should_rebuild(&self) -> bool {
        if self.force_rebuild == Some(true) {
            return true;
        }
        if self.skip_nix_rebuild == Some(false) {
            return true;
        }
        false
    }

    /// Load from a JSON file on disk.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read cluster config from {}", path.display()))?;
        Self::from_json(&content)
    }

    /// Parse from a JSON string.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).context("failed to parse cluster config JSON")
    }

    /// Whether this config targets K3s distribution.
    pub fn is_k3s(&self) -> bool {
        self.distribution == "k3s"
    }

    /// Whether this config targets upstream Kubernetes (kubeadm) distribution.
    pub fn is_kubernetes(&self) -> bool {
        self.distribution == "kubernetes"
    }

    /// Derive a hostname from cluster name + role + index.
    pub fn derive_hostname(&self) -> String {
        format!("{}-{}-{}", self.cluster_name, self.role, self.node_index)
    }

    /// Validate VPN security invariants (structural checks only).
    /// Delegates to shared `vpn::validate` module.
    pub fn validate_vpn_security(&self) -> Result<()> {
        self.validate_vpn_security_inner(false)
    }

    /// Full security validation including filesystem checks.
    /// Only call this during bootstrap when key files should exist on disk.
    pub fn validate_vpn_security_full(&self) -> Result<()> {
        self.validate_vpn_security_inner(true)
    }

    fn validate_vpn_security_inner(&self, check_files: bool) -> Result<()> {
        let vpn = match &self.vpn {
            Some(v) => v,
            None => return Ok(()),
        };

        let links: Vec<vpn_validate::VpnLink<'_>> = vpn
            .links
            .iter()
            .map(|l| vpn_validate::VpnLink {
                name: &l.name,
                private_key_file: l.private_key_file.as_deref(),
                listen_port: l.listen_port,
                address: l.address.as_deref(),
                profile: l.profile.as_deref(),
                persistent_keepalive: l.persistent_keepalive,
                peers: l
                    .peers
                    .iter()
                    .map(|p| vpn_validate::VpnPeer {
                        public_key: p.public_key.as_deref(),
                        endpoint: p.endpoint.as_deref(),
                        allowed_ips: &p.allowed_ips,
                        persistent_keepalive: p.persistent_keepalive,
                        preshared_key_file: p.preshared_key_file.as_deref(),
                    })
                    .collect(),
                firewall: l.firewall.as_ref().map(|fw| vpn_validate::VpnFirewall {
                    trust_interface: fw.trust_interface,
                    allowed_tcp_ports: &fw.allowed_tcp_ports,
                    allowed_udp_ports: &fw.allowed_udp_ports,
                    incoming_udp_port: fw.incoming_udp_port,
                }),
            })
            .collect();

        vpn_validate::validate_vpn_links(&links, check_files)
    }

    /// Convert to a NodeIdentity suitable for kindling's NixOS rebuild.
    pub fn to_node_identity(&self) -> NodeIdentity {
        let hostname = self.derive_hostname();

        // Map distribution to a kindling profile name
        let profile = format!("{}-{}", self.distribution, self.profile);

        // Build kubernetes config
        let kubernetes = KubernetesConfig {
            role: Some(self.role.clone()),
            server_addr: self.join_server.clone(),
            ..Default::default()
        };

        // Build fluxcd config
        let fluxcd = match &self.fluxcd {
            Some(fc) => FluxcdConfig {
                enable: true,
                source: fc.source_url.clone().unwrap_or_default(),
                auth: fc.source_auth.clone().unwrap_or_else(|| "token".to_string()),
                token_file: fc.source_token_file.clone(),
                ssh_key_file: fc.source_ssh_key_file.clone(),
                reconcile: serde_json::json!({
                    "path": fc.reconcile_path.as_deref().unwrap_or(""),
                    "branch": fc.branch.as_deref().unwrap_or("main"),
                    "interval": fc.reconcile_interval.as_deref().unwrap_or("2m0s"),
                    "prune": fc.reconcile_prune.unwrap_or(true),
                }),
            },
            None => FluxcdConfig::default(),
        };

        // Build secrets config
        let secrets = match &self.secrets {
            Some(sc) => crate::node_identity::SecretsConfig {
                provider: "sops".to_string(),
                age_key_file: sc.age_key_file.clone(),
                ..Default::default()
            },
            None => SecretsConfig::default(),
        };

        // Build VPN links
        let vpn_links = match &self.vpn {
            Some(vpn) => vpn.links.iter().map(|link| {
                VpnLinkConfig {
                    name: link.name.clone(),
                    private_key_file: link.private_key_file.clone(),
                    listen_port: link.listen_port,
                    address: link.address.clone(),
                    profile: link.profile.clone(),
                    persistent_keepalive: link.persistent_keepalive,
                    mtu: link.mtu,
                    dns: vec![],
                    peers: link.peers.iter().map(|p| VpnPeerConfig {
                        public_key: p.public_key.clone(),
                        endpoint: p.endpoint.clone(),
                        allowed_ips: p.allowed_ips.clone(),
                        persistent_keepalive: p.persistent_keepalive,
                        preshared_key_file: p.preshared_key_file.clone(),
                    }).collect(),
                    firewall: link.firewall.as_ref().map(|fw| VpnFirewallConfig {
                        trust_interface: fw.trust_interface,
                        allowed_tcp_ports: fw.allowed_tcp_ports.clone(),
                        allowed_udp_ports: fw.allowed_udp_ports.clone(),
                        incoming_udp_port: fw.incoming_udp_port,
                    }).unwrap_or_default(),
                }
            }).collect(),
            None => vec![],
        };

        let mut identity = NodeIdentity::from_bootstrap("server", "placeholder", "root", None);
        identity.version = "1".to_string();
        identity.profile = profile;
        identity.hostname = hostname;
        identity.user = UserConfig {
            name: "root".to_string(),
            uid: 0,
            shell: "bash".to_string(),
            ..Default::default()
        };
        identity.secrets = secrets;
        identity.kubernetes = kubernetes;
        identity.fluxcd = fluxcd;
        identity.network.vpn_links = vpn_links;
        identity
    }
}


#[cfg(test)]
#[path = "cluster_config_tests.rs"]
mod tests;
