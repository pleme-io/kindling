//! Parse cloud-init JSON (`/etc/pangea/cluster-config.json`) into typed config.
//!
//! The JSON is written by cloud-init at boot time and contains everything needed
//! to configure a K3s or vanilla Kubernetes node via blackmatter-kubernetes modules.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
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
    pub kubernetes: Option<serde_json::Value>,

    #[serde(default)]
    pub secrets: Option<SecretsClusterConfig>,

    #[serde(default)]
    pub vpn: Option<VpnClusterConfig>,
}

/// FluxCD bootstrap configuration from cloud-init.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FluxcdClusterConfig {
    #[serde(default)]
    pub source_url: Option<String>,
    #[serde(default)]
    pub reconcile_path: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
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

/// Secrets path references for sops-nix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsClusterConfig {
    #[serde(default)]
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

fn default_distribution() -> String {
    "k3s".to_string()
}

fn default_profile() -> String {
    "cilium-standard".to_string()
}

fn default_distribution_track() -> String {
    "1.34".to_string()
}

fn default_role() -> String {
    "server".to_string()
}

use crate::vpn::validate as vpn_validate;

impl ClusterConfig {
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
                reconcile: serde_json::json!({
                    "path": fc.reconcile_path.as_deref().unwrap_or(""),
                    "branch": fc.branch.as_deref().unwrap_or("main"),
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
mod tests {
    use super::*;
    use crate::vpn::validate::{validate_cidr, validate_endpoint};

    const MINIMAL_JSON: &str = r#"{
        "cluster_name": "prod-us-east",
        "distribution": "k3s",
        "profile": "cilium-standard",
        "role": "server",
        "cluster_init": true
    }"#;

    const FULL_JSON: &str = r#"{
        "cluster_name": "staging-eu",
        "distribution": "k3s",
        "profile": "cilium-standard",
        "distribution_track": "1.34",
        "role": "agent",
        "node_index": 2,
        "cluster_init": false,
        "join_server": "10.0.0.1",
        "fluxcd": {
            "source_url": "ssh://git@github.com/pleme-io/k8s.git",
            "reconcile_path": "clusters/staging",
            "branch": "main"
        },
        "k3s": {
            "token": "secret-token",
            "disable": ["traefik", "servicelb"],
            "tls_san": ["10.0.0.1"]
        },
        "secrets": {
            "age_key_file": "/etc/sops/age/keys.txt"
        }
    }"#;

    #[test]
    fn parse_minimal_config() {
        let config = ClusterConfig::from_json(MINIMAL_JSON).unwrap();
        assert_eq!(config.cluster_name, "prod-us-east");
        assert_eq!(config.distribution, "k3s");
        assert_eq!(config.profile, "cilium-standard");
        assert_eq!(config.role, "server");
        assert!(config.cluster_init);
        assert!(config.join_server.is_none());
        assert!(config.fluxcd.is_none());
    }

    #[test]
    fn parse_full_config() {
        let config = ClusterConfig::from_json(FULL_JSON).unwrap();
        assert_eq!(config.cluster_name, "staging-eu");
        assert_eq!(config.role, "agent");
        assert_eq!(config.node_index, 2);
        assert!(!config.cluster_init);
        assert_eq!(config.join_server.as_deref(), Some("10.0.0.1"));

        let fluxcd = config.fluxcd.as_ref().unwrap();
        assert_eq!(
            fluxcd.source_url.as_deref(),
            Some("ssh://git@github.com/pleme-io/k8s.git")
        );
        assert_eq!(fluxcd.reconcile_path.as_deref(), Some("clusters/staging"));

        let k3s = config.k3s.as_ref().unwrap();
        assert_eq!(k3s.disable, vec!["traefik", "servicelb"]);
    }

    #[test]
    fn derive_hostname() {
        let config = ClusterConfig::from_json(MINIMAL_JSON).unwrap();
        assert_eq!(config.derive_hostname(), "prod-us-east-server-0");
    }

    #[test]
    fn to_node_identity_minimal() {
        let config = ClusterConfig::from_json(MINIMAL_JSON).unwrap();
        let identity = config.to_node_identity();

        assert_eq!(identity.hostname, "prod-us-east-server-0");
        assert_eq!(identity.profile, "k3s-cilium-standard");
        assert_eq!(identity.kubernetes.role.as_deref(), Some("server"));
        assert!(!identity.fluxcd.enable);
    }

    #[test]
    fn to_node_identity_with_fluxcd() {
        let config = ClusterConfig::from_json(FULL_JSON).unwrap();
        let identity = config.to_node_identity();

        assert_eq!(identity.hostname, "staging-eu-agent-2");
        assert!(identity.fluxcd.enable);
        assert_eq!(
            identity.fluxcd.source,
            "ssh://git@github.com/pleme-io/k8s.git"
        );
        assert_eq!(
            identity.kubernetes.server_addr.as_deref(),
            Some("10.0.0.1")
        );
    }

    #[test]
    fn to_node_identity_with_secrets() {
        let config = ClusterConfig::from_json(FULL_JSON).unwrap();
        let identity = config.to_node_identity();

        assert_eq!(
            identity.secrets.age_key_file.as_deref(),
            Some("/etc/sops/age/keys.txt")
        );
    }

    #[test]
    fn load_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cluster-config.json");
        std::fs::write(&path, MINIMAL_JSON).unwrap();

        let config = ClusterConfig::load(&path).unwrap();
        assert_eq!(config.cluster_name, "prod-us-east");
    }

    #[test]
    fn invalid_json_returns_error() {
        let result = ClusterConfig::from_json("not json");
        assert!(result.is_err());
    }

    const VPN_JSON: &str = r#"{
        "cluster_name": "prod-vpn",
        "distribution": "k3s",
        "profile": "cilium-standard",
        "role": "server",
        "cluster_init": true,
        "vpn": {
            "links": [{
                "name": "wg-k8s",
                "private_key_file": "/run/secrets/wg-private-key",
                "listen_port": 51820,
                "address": "10.100.0.1/24",
                "profile": "k8s-control-plane",
                "persistent_keepalive": 25,
                "mtu": 1420,
                "peers": [{
                    "public_key": "abc123...",
                    "endpoint": "vpn.example.com:51820",
                    "allowed_ips": ["10.0.0.0/16"],
                    "persistent_keepalive": 25,
                    "preshared_key_file": "/run/secrets/wg-psk"
                }],
                "firewall": {
                    "trust_interface": false,
                    "allowed_tcp_ports": [6443],
                    "allowed_udp_ports": [],
                    "incoming_udp_port": 51820
                }
            }]
        }
    }"#;

    #[test]
    fn parse_vpn_config() {
        let config = ClusterConfig::from_json(VPN_JSON).unwrap();
        let vpn = config.vpn.as_ref().unwrap();
        assert_eq!(vpn.links.len(), 1);
        assert_eq!(vpn.links[0].name, "wg-k8s");
        assert_eq!(vpn.links[0].listen_port, Some(51820));
        assert_eq!(vpn.links[0].peers.len(), 1);
        assert_eq!(vpn.links[0].peers[0].public_key.as_deref(), Some("abc123..."));
        assert_eq!(vpn.links[0].peers[0].preshared_key_file.as_deref(), Some("/run/secrets/wg-psk"));

        let fw = vpn.links[0].firewall.as_ref().unwrap();
        assert!(!fw.trust_interface);
        assert_eq!(fw.allowed_tcp_ports, vec![6443]);
    }

    #[test]
    fn to_node_identity_with_vpn() {
        let config = ClusterConfig::from_json(VPN_JSON).unwrap();
        let identity = config.to_node_identity();

        assert_eq!(identity.network.vpn_links.len(), 1);
        let link = &identity.network.vpn_links[0];
        assert_eq!(link.name, "wg-k8s");
        assert_eq!(link.private_key_file.as_deref(), Some("/run/secrets/wg-private-key"));
        assert_eq!(link.address.as_deref(), Some("10.100.0.1/24"));
        assert_eq!(link.profile.as_deref(), Some("k8s-control-plane"));
        assert_eq!(link.peers.len(), 1);
        assert_eq!(link.peers[0].allowed_ips, vec!["10.0.0.0/16"]);
        assert!(!link.firewall.trust_interface);
        assert_eq!(link.firewall.allowed_tcp_ports, vec![6443]);
    }

    #[test]
    fn to_node_identity_without_vpn() {
        let config = ClusterConfig::from_json(MINIMAL_JSON).unwrap();
        let identity = config.to_node_identity();
        assert!(identity.network.vpn_links.is_empty());
    }

    // ── require_liveness tests ──────────────────────────────

    #[test]
    fn vpn_require_liveness_defaults_false() {
        let config = ClusterConfig::from_json(VPN_JSON).unwrap();
        let vpn = config.vpn.as_ref().unwrap();
        assert!(!vpn.require_liveness);
    }

    #[test]
    fn vpn_require_liveness_parsed_when_true() {
        let json = r#"{
            "cluster_name": "prod-vpn",
            "distribution": "k3s",
            "profile": "cilium-standard",
            "role": "server",
            "cluster_init": true,
            "vpn": {
                "require_liveness": true,
                "links": [{
                    "name": "wg-k8s",
                    "private_key_file": "/run/secrets/wg-private-key",
                    "listen_port": 51820,
                    "address": "10.100.0.1/24",
                    "profile": "k8s-control-plane",
                    "peers": [{
                        "public_key": "abc123...",
                        "endpoint": "vpn.example.com:51820",
                        "allowed_ips": ["10.0.0.0/16"],
                        "preshared_key_file": "/run/secrets/wg-psk"
                    }],
                    "firewall": {
                        "trust_interface": false,
                        "allowed_tcp_ports": [6443],
                        "incoming_udp_port": 51820
                    }
                }]
            }
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        let vpn = config.vpn.as_ref().unwrap();
        assert!(vpn.require_liveness);
    }

    // ── Security validation tests ──────────────────────────────

    #[test]
    fn validate_vpn_security_passes_for_valid_config() {
        let config = ClusterConfig::from_json(VPN_JSON).unwrap();
        assert!(config.validate_vpn_security().is_ok());
    }

    #[test]
    fn validate_vpn_security_passes_without_vpn() {
        let config = ClusterConfig::from_json(MINIMAL_JSON).unwrap();
        assert!(config.validate_vpn_security().is_ok());
    }

    #[test]
    fn validate_vpn_rejects_missing_private_key() {
        let json = r#"{
            "cluster_name": "test",
            "vpn": { "links": [{
                "name": "wg0",
                "address": "10.0.0.1/24",
                "peers": [{"public_key": "key", "allowed_ips": ["10.0.0.0/24"],
                           "preshared_key_file": "/psk"}],
                "firewall": {"allowed_tcp_ports": [6443]}
            }]}
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        let err = config.validate_vpn_security().unwrap_err();
        assert!(err.to_string().contains("private_key_file is required"));
    }

    #[test]
    fn validate_vpn_rejects_missing_address() {
        let json = r#"{
            "cluster_name": "test",
            "vpn": { "links": [{
                "name": "wg0",
                "private_key_file": "/key",
                "peers": [{"public_key": "key", "allowed_ips": ["10.0.0.0/24"],
                           "preshared_key_file": "/psk"}],
                "firewall": {"allowed_tcp_ports": [6443]}
            }]}
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        let err = config.validate_vpn_security().unwrap_err();
        assert!(err.to_string().contains("address is required"));
    }

    #[test]
    fn validate_vpn_rejects_no_peers() {
        let json = r#"{
            "cluster_name": "test",
            "vpn": { "links": [{
                "name": "wg0",
                "private_key_file": "/key",
                "address": "10.0.0.1/24",
                "peers": [],
                "firewall": {"allowed_tcp_ports": [6443]}
            }]}
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        let err = config.validate_vpn_security().unwrap_err();
        assert!(err.to_string().contains("at least one peer is required"));
    }

    #[test]
    fn validate_vpn_rejects_full_tunnel() {
        let json = r#"{
            "cluster_name": "test",
            "vpn": { "links": [{
                "name": "wg0",
                "private_key_file": "/key",
                "address": "10.0.0.1/24",
                "peers": [{"public_key": "key", "allowed_ips": ["0.0.0.0/0"],
                           "preshared_key_file": "/psk"}],
                "firewall": {"allowed_tcp_ports": [6443]}
            }]}
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        let err = config.validate_vpn_security().unwrap_err();
        assert!(err.to_string().contains("full tunnel forbidden"));
    }

    #[test]
    fn validate_vpn_rejects_ipv6_full_tunnel() {
        let json = r#"{
            "cluster_name": "test",
            "vpn": { "links": [{
                "name": "wg0",
                "private_key_file": "/key",
                "address": "10.0.0.1/24",
                "peers": [{"public_key": "key", "allowed_ips": ["::/0"],
                           "preshared_key_file": "/psk"}],
                "firewall": {"allowed_tcp_ports": [6443]}
            }]}
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        let err = config.validate_vpn_security().unwrap_err();
        assert!(err.to_string().contains("full tunnel forbidden"));
    }

    #[test]
    fn validate_vpn_rejects_missing_preshared_key() {
        let json = r#"{
            "cluster_name": "test",
            "vpn": { "links": [{
                "name": "wg0",
                "private_key_file": "/key",
                "address": "10.0.0.1/24",
                "peers": [{"public_key": "key", "allowed_ips": ["10.0.0.0/24"]}],
                "firewall": {"allowed_tcp_ports": [6443]}
            }]}
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        let err = config.validate_vpn_security().unwrap_err();
        assert!(err.to_string().contains("preshared_key_file is required"));
    }

    #[test]
    fn validate_vpn_rejects_missing_firewall() {
        let json = r#"{
            "cluster_name": "test",
            "vpn": { "links": [{
                "name": "wg0",
                "private_key_file": "/key",
                "address": "10.0.0.1/24",
                "peers": [{"public_key": "key", "allowed_ips": ["10.0.0.0/24"],
                           "preshared_key_file": "/psk"}]
            }]}
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        let err = config.validate_vpn_security().unwrap_err();
        assert!(err.to_string().contains("firewall config is required"));
    }

    #[test]
    fn validate_vpn_rejects_k8s_trust_interface() {
        let json = r#"{
            "cluster_name": "test",
            "vpn": { "links": [{
                "name": "wg0",
                "private_key_file": "/key",
                "address": "10.0.0.1/24",
                "profile": "k8s-control-plane",
                "peers": [{"public_key": "key", "allowed_ips": ["10.0.0.0/24"],
                           "preshared_key_file": "/psk"}],
                "firewall": {"trust_interface": true, "allowed_tcp_ports": [6443]}
            }]}
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        let err = config.validate_vpn_security().unwrap_err();
        assert!(err.to_string().contains("trust_interface must be false for k8s profiles"));
    }

    #[test]
    fn validate_vpn_rejects_k8s_empty_ports() {
        let json = r#"{
            "cluster_name": "test",
            "vpn": { "links": [{
                "name": "wg0",
                "private_key_file": "/key",
                "address": "10.0.0.1/24",
                "profile": "k8s-full",
                "peers": [{"public_key": "key", "allowed_ips": ["10.0.0.0/24"],
                           "preshared_key_file": "/psk"}],
                "firewall": {"trust_interface": false}
            }]}
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        let err = config.validate_vpn_security().unwrap_err();
        assert!(err.to_string().contains("k8s profile requires explicit port allowlist"));
    }

    #[test]
    fn validate_vpn_rejects_invalid_interface_name() {
        let json = r#"{
            "cluster_name": "test",
            "vpn": { "links": [{
                "name": "this-name-is-way-too-long-for-linux",
                "private_key_file": "/key",
                "address": "10.0.0.1/24",
                "peers": [{"public_key": "key", "allowed_ips": ["10.0.0.0/24"],
                           "preshared_key_file": "/psk"}],
                "firewall": {"allowed_tcp_ports": [6443]}
            }]}
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        let err = config.validate_vpn_security().unwrap_err();
        assert!(err.to_string().contains("exceeds 15 chars"));
    }

    #[test]
    fn validate_vpn_rejects_unknown_profile() {
        let json = r#"{
            "cluster_name": "test",
            "vpn": { "links": [{
                "name": "wg0",
                "private_key_file": "/key",
                "address": "10.0.0.1/24",
                "profile": "invalid-profile",
                "peers": [{"public_key": "key", "allowed_ips": ["10.0.0.0/24"],
                           "preshared_key_file": "/psk"}],
                "firewall": {"allowed_tcp_ports": [6443]}
            }]}
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        let err = config.validate_vpn_security().unwrap_err();
        assert!(err.to_string().contains("unknown profile"));
    }

    #[test]
    fn validate_vpn_rejects_listen_port_without_firewall_port() {
        let json = r#"{
            "cluster_name": "test",
            "vpn": { "links": [{
                "name": "wg0",
                "private_key_file": "/key",
                "address": "10.0.0.1/24",
                "listen_port": 51820,
                "peers": [{"public_key": "key", "allowed_ips": ["10.0.0.0/24"],
                           "preshared_key_file": "/psk"}],
                "firewall": {"allowed_tcp_ports": [6443]}
            }]}
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        let err = config.validate_vpn_security().unwrap_err();
        assert!(err.to_string().contains("incoming_udp_port not set"));
    }

    #[test]
    fn validate_vpn_full_rejects_missing_key_files() {
        let json = r#"{
            "cluster_name": "test",
            "vpn": { "links": [{
                "name": "wg0",
                "private_key_file": "/nonexistent/wg-private-key",
                "address": "10.0.0.1/24",
                "peers": [{"public_key": "key", "allowed_ips": ["10.0.0.0/24"],
                           "preshared_key_file": "/nonexistent/wg-psk"}],
                "firewall": {"allowed_tcp_ports": [6443]}
            }]}
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        // Structural validation passes (files are specified)
        assert!(config.validate_vpn_security().is_ok());
        // Full validation fails (files don't exist)
        let err = config.validate_vpn_security_full().unwrap_err();
        assert!(err.to_string().contains("does not exist on disk"));
    }

    #[cfg(unix)]
    #[test]
    fn validate_vpn_full_rejects_insecure_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("wg-key");
        let psk_path = dir.path().join("wg-psk");
        std::fs::write(&key_path, "fake-key").unwrap();
        std::fs::write(&psk_path, "fake-psk").unwrap();
        // Set world-readable permissions (insecure)
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&psk_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let json = format!(r#"{{
            "cluster_name": "test",
            "vpn": {{ "links": [{{
                "name": "wg0",
                "private_key_file": "{}",
                "address": "10.0.0.1/24",
                "peers": [{{"public_key": "key", "allowed_ips": ["10.0.0.0/24"],
                           "preshared_key_file": "{}"}}],
                "firewall": {{"allowed_tcp_ports": [6443]}}
            }}]}}
        }}"#, key_path.display(), psk_path.display());

        let config = ClusterConfig::from_json(&json).unwrap();
        let err = config.validate_vpn_security_full().unwrap_err();
        assert!(err.to_string().contains("insecure permissions"));
    }

    #[cfg(unix)]
    #[test]
    fn validate_vpn_full_passes_with_secure_key_files() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("wg-key");
        let psk_path = dir.path().join("wg-psk");
        std::fs::write(&key_path, "fake-key").unwrap();
        std::fs::write(&psk_path, "fake-psk").unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&psk_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let json = format!(r#"{{
            "cluster_name": "test",
            "vpn": {{ "links": [{{
                "name": "wg0",
                "private_key_file": "{}",
                "address": "10.0.0.1/24",
                "peers": [{{"public_key": "key", "allowed_ips": ["10.0.0.0/24"],
                           "preshared_key_file": "{}"}}],
                "firewall": {{"allowed_tcp_ports": [6443], "incoming_udp_port": 51820}},
                "listen_port": 51820
            }}]}}
        }}"#, key_path.display(), psk_path.display());

        let config = ClusterConfig::from_json(&json).unwrap();
        assert!(config.validate_vpn_security_full().is_ok());
    }

    #[test]
    fn validate_vpn_reports_all_violations() {
        // Multiple violations should all be reported in one pass
        let json = r#"{
            "cluster_name": "test",
            "vpn": { "links": [{
                "name": "",
                "profile": "k8s-control-plane",
                "peers": [{"allowed_ips": ["0.0.0.0/0"]}]
            }]}
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        let err = config.validate_vpn_security().unwrap_err();
        let msg = err.to_string();
        // Should contain multiple violations
        assert!(msg.contains("name must not be empty"));
        assert!(msg.contains("private_key_file is required"));
        assert!(msg.contains("address is required"));
        assert!(msg.contains("full tunnel forbidden"));
        assert!(msg.contains("public_key is required"));
        assert!(msg.contains("preshared_key_file is required"));
        assert!(msg.contains("firewall config is required"));
    }

    // ── CIDR validation tests ──────────────────────────────

    #[test]
    fn validate_cidr_valid_ipv4() {
        assert!(validate_cidr("10.0.0.0/24"));
        assert!(validate_cidr("192.168.1.1/32"));
        assert!(validate_cidr("0.0.0.0/0"));
        assert!(validate_cidr("10.100.0.1/24"));
    }

    #[test]
    fn validate_cidr_valid_ipv6() {
        assert!(validate_cidr("::1/128"));
        assert!(validate_cidr("fe80::/10"));
        assert!(validate_cidr("::/0"));
        assert!(validate_cidr("fd00::1/64"));
    }

    #[test]
    fn validate_cidr_rejects_invalid() {
        assert!(!validate_cidr("999.999.999.999/32"));
        assert!(!validate_cidr("10.0.0.0"));
        assert!(!validate_cidr("10.0.0.0/33"));
        assert!(!validate_cidr("not-a-cidr"));
        assert!(!validate_cidr("10.0.0.0/-1"));
        assert!(!validate_cidr("/24"));
        assert!(!validate_cidr(""));
    }

    #[test]
    fn validate_endpoint_valid() {
        assert!(validate_endpoint("vpn.example.com:51820"));
        assert!(validate_endpoint("10.0.0.1:51820"));
        assert!(validate_endpoint("[::1]:51820"));
        assert!(validate_endpoint("host:1"));
        assert!(validate_endpoint("host:65535"));
    }

    #[test]
    fn validate_endpoint_rejects_invalid() {
        assert!(!validate_endpoint("no-port"));
        assert!(!validate_endpoint(":51820"));
        assert!(!validate_endpoint("host:0"));
        assert!(!validate_endpoint("host:99999"));
        assert!(!validate_endpoint("host:"));
        assert!(!validate_endpoint(""));
    }

    #[test]
    fn validate_vpn_rejects_invalid_cidr_in_allowed_ips() {
        let json = r#"{
            "cluster_name": "test",
            "vpn": { "links": [{
                "name": "wg0",
                "private_key_file": "/key",
                "address": "10.0.0.1/24",
                "peers": [{"public_key": "key", "allowed_ips": ["999.999.999.999/32"],
                           "preshared_key_file": "/psk"}],
                "firewall": {"allowed_tcp_ports": [6443]}
            }]}
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        let err = config.validate_vpn_security().unwrap_err();
        assert!(err.to_string().contains("not a valid CIDR"));
    }

    #[test]
    fn validate_vpn_rejects_invalid_address_cidr() {
        let json = r#"{
            "cluster_name": "test",
            "vpn": { "links": [{
                "name": "wg0",
                "private_key_file": "/key",
                "address": "not-valid",
                "peers": [{"public_key": "key", "allowed_ips": ["10.0.0.0/24"],
                           "preshared_key_file": "/psk"}],
                "firewall": {"allowed_tcp_ports": [6443]}
            }]}
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        let err = config.validate_vpn_security().unwrap_err();
        assert!(err.to_string().contains("not a valid CIDR"));
    }

    #[test]
    fn validate_vpn_rejects_invalid_endpoint() {
        let json = r#"{
            "cluster_name": "test",
            "vpn": { "links": [{
                "name": "wg0",
                "private_key_file": "/key",
                "address": "10.0.0.1/24",
                "peers": [{"public_key": "key", "allowed_ips": ["10.0.0.0/24"],
                           "endpoint": "no-port",
                           "preshared_key_file": "/psk"}],
                "firewall": {"allowed_tcp_ports": [6443]}
            }]}
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        let err = config.validate_vpn_security().unwrap_err();
        assert!(err.to_string().contains("endpoint"));
    }

    #[test]
    fn validate_vpn_rejects_privileged_listen_port() {
        let json = r#"{
            "cluster_name": "test",
            "vpn": { "links": [{
                "name": "wg0",
                "private_key_file": "/key",
                "address": "10.0.0.1/24",
                "listen_port": 80,
                "peers": [{"public_key": "key", "allowed_ips": ["10.0.0.0/24"],
                           "preshared_key_file": "/psk"}],
                "firewall": {"allowed_tcp_ports": [6443], "incoming_udp_port": 80}
            }]}
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        let err = config.validate_vpn_security().unwrap_err();
        assert!(err.to_string().contains("outside valid range"));
    }

    // ── Collision detection tests ──────────────────────────

    #[test]
    fn validate_vpn_rejects_duplicate_listen_ports() {
        let json = r#"{
            "cluster_name": "test",
            "vpn": { "links": [
                {
                    "name": "wg0",
                    "private_key_file": "/key",
                    "address": "10.0.0.1/24",
                    "listen_port": 51820,
                    "peers": [{"public_key": "key1", "allowed_ips": ["10.0.0.0/24"],
                               "preshared_key_file": "/psk"}],
                    "firewall": {"allowed_tcp_ports": [6443], "incoming_udp_port": 51820}
                },
                {
                    "name": "wg1",
                    "private_key_file": "/key2",
                    "address": "10.0.1.1/24",
                    "listen_port": 51820,
                    "peers": [{"public_key": "key2", "allowed_ips": ["10.0.1.0/24"],
                               "preshared_key_file": "/psk2"}],
                    "firewall": {"allowed_tcp_ports": [6443], "incoming_udp_port": 51820}
                }
            ]}
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        let err = config.validate_vpn_security().unwrap_err();
        assert!(err.to_string().contains("duplicate listen_port"));
    }

    #[test]
    fn validate_vpn_rejects_duplicate_addresses() {
        let json = r#"{
            "cluster_name": "test",
            "vpn": { "links": [
                {
                    "name": "wg0",
                    "private_key_file": "/key",
                    "address": "10.0.0.1/24",
                    "peers": [{"public_key": "key1", "allowed_ips": ["10.0.0.0/24"],
                               "preshared_key_file": "/psk"}],
                    "firewall": {"allowed_tcp_ports": [6443]}
                },
                {
                    "name": "wg1",
                    "private_key_file": "/key2",
                    "address": "10.0.0.1/24",
                    "peers": [{"public_key": "key2", "allowed_ips": ["10.0.1.0/24"],
                               "preshared_key_file": "/psk2"}],
                    "firewall": {"allowed_tcp_ports": [6443]}
                }
            ]}
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        let err = config.validate_vpn_security().unwrap_err();
        assert!(err.to_string().contains("duplicate address"));
    }

    #[test]
    fn validate_vpn_rejects_duplicate_peer_keys() {
        let json = r#"{
            "cluster_name": "test",
            "vpn": { "links": [{
                "name": "wg0",
                "private_key_file": "/key",
                "address": "10.0.0.1/24",
                "peers": [
                    {"public_key": "same-key", "allowed_ips": ["10.0.0.0/24"],
                     "preshared_key_file": "/psk"},
                    {"public_key": "same-key", "allowed_ips": ["10.0.1.0/24"],
                     "preshared_key_file": "/psk2"}
                ],
                "firewall": {"allowed_tcp_ports": [6443]}
            }]}
        }"#;
        let config = ClusterConfig::from_json(json).unwrap();
        let err = config.validate_vpn_security().unwrap_err();
        assert!(err.to_string().contains("duplicate public_key"));
    }
}
