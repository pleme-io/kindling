//! Kubeadm config generation for upstream Kubernetes (kubeadm) distribution.
//!
//! Generates `kubeadm init` config (ClusterConfiguration + InitConfiguration) for
//! control plane nodes, and `kubeadm join` config (JoinConfiguration) for workers.
//! Mirrors the K3s config generation pattern in `bootstrap.rs`.

use anyhow::{Context, Result};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use super::cluster_config::ClusterConfig;

/// Generate kubeadm config YAML from a ClusterConfig (pure function, no IO).
///
/// For control plane init (`cluster_init == true`): generates ClusterConfiguration
/// + InitConfiguration YAML suitable for `kubeadm init --config`.
///
/// For join (workers or secondary CP): generates JoinConfiguration YAML suitable
/// for `kubeadm join --config`.
pub fn generate_kubeadm_config(config: &ClusterConfig) -> Result<String> {
    if config.cluster_init && config.role == "server" {
        generate_init_config(config)
    } else {
        generate_join_config(config)
    }
}

/// Generate ClusterConfiguration + InitConfiguration for `kubeadm init`.
fn generate_init_config(config: &ClusterConfig) -> Result<String> {
    let node_name = config.derive_hostname();
    let k8s = config.kubernetes.as_ref();

    let k8s_version = k8s
        .and_then(|k| k.version.as_deref())
        .unwrap_or("1.32.0");
    let pod_cidr = k8s
        .map(|k| k.pod_cidr.as_str())
        .unwrap_or("10.244.0.0/16");
    let service_cidr = k8s
        .map(|k| k.service_cidr.as_str())
        .unwrap_or("10.96.0.0/12");
    let cri_socket = k8s
        .map(|k| k.cri_socket.as_str())
        .unwrap_or("unix:///run/containerd/containerd.sock");

    // Collect API server cert SANs: explicit + VPN addresses
    let mut cert_sans: Vec<String> = Vec::new();
    if let Some(k8s_config) = k8s {
        cert_sans.extend(k8s_config.api_server_cert_sans.iter().cloned());
    }
    // Add VPN addresses as SANs (strip /24 mask)
    if let Some(ref vpn) = config.vpn {
        for link in &vpn.links {
            if let Some(ref addr) = link.address {
                if let Some(ip) = addr.split('/').next() {
                    cert_sans.push(ip.to_string());
                }
            }
        }
    }

    // Determine advertise address: prefer first VPN IP, fall back to empty (kubeadm auto-detect)
    let advertise_address = config
        .vpn
        .as_ref()
        .and_then(|vpn| vpn.links.first())
        .and_then(|link| link.address.as_ref())
        .and_then(|addr| addr.split('/').next().map(String::from))
        .unwrap_or_default();

    let mut yaml = String::new();

    // --- ClusterConfiguration ---
    yaml.push_str("apiVersion: kubeadm.k8s.io/v1beta4\n");
    yaml.push_str("kind: ClusterConfiguration\n");
    yaml.push_str(&format!("kubernetesVersion: \"{}\"\n", k8s_version));
    yaml.push_str(&format!("clusterName: \"{}\"\n", config.cluster_name));

    yaml.push_str("networking:\n");
    yaml.push_str(&format!("  podSubnet: \"{}\"\n", pod_cidr));
    yaml.push_str(&format!("  serviceSubnet: \"{}\"\n", service_cidr));

    if !cert_sans.is_empty() || !advertise_address.is_empty() {
        yaml.push_str("apiServer:\n");
        if !cert_sans.is_empty() {
            yaml.push_str("  certSANs:\n");
            for san in &cert_sans {
                yaml.push_str(&format!("    - \"{}\"\n", san));
            }
        }
    }

    if !advertise_address.is_empty() {
        yaml.push_str("controlPlaneEndpoint: \"");
        yaml.push_str(&advertise_address);
        yaml.push_str(":6443\"\n");
    }

    // Etcd local config
    yaml.push_str("etcd:\n");
    yaml.push_str("  local:\n");
    yaml.push_str("    dataDir: /var/lib/etcd\n");

    // --- InitConfiguration ---
    yaml.push_str("---\n");
    yaml.push_str("apiVersion: kubeadm.k8s.io/v1beta4\n");
    yaml.push_str("kind: InitConfiguration\n");

    yaml.push_str("nodeRegistration:\n");
    yaml.push_str(&format!("  name: \"{}\"\n", node_name));
    yaml.push_str(&format!("  criSocket: \"{}\"\n", cri_socket));

    // Bootstrap token
    if let Some(token) = get_kubeadm_token(config) {
        yaml.push_str("bootstrapTokens:\n");
        yaml.push_str("  - token: \"");
        yaml.push_str(&token);
        yaml.push_str("\"\n");
        yaml.push_str("    ttl: \"0\"\n"); // Never expire for cluster bootstrap
    }

    if !advertise_address.is_empty() {
        yaml.push_str("localAPIEndpoint:\n");
        yaml.push_str(&format!("  advertiseAddress: \"{}\"\n", advertise_address));
        yaml.push_str("  bindPort: 6443\n");
    }

    // Certificate key for --upload-certs
    if let Some(ref cert_key) = k8s.and_then(|k| k.certificate_key.as_ref()) {
        yaml.push_str(&format!("certificateKey: \"{}\"\n", cert_key));
    }

    Ok(yaml)
}

/// Generate JoinConfiguration for `kubeadm join`.
fn generate_join_config(config: &ClusterConfig) -> Result<String> {
    let node_name = config.derive_hostname();
    let k8s = config.kubernetes.as_ref();
    let cri_socket = k8s
        .map(|k| k.cri_socket.as_str())
        .unwrap_or("unix:///run/containerd/containerd.sock");

    let token = get_kubeadm_token(config).unwrap_or_default();
    let ca_cert_hash = k8s
        .and_then(|k| k.ca_cert_hash.as_deref())
        .unwrap_or("");

    // Join server address
    let api_server_endpoint = config
        .join_server
        .as_deref()
        .unwrap_or("127.0.0.1:6443");

    let mut yaml = String::new();

    yaml.push_str("apiVersion: kubeadm.k8s.io/v1beta4\n");
    yaml.push_str("kind: JoinConfiguration\n");

    yaml.push_str("nodeRegistration:\n");
    yaml.push_str(&format!("  name: \"{}\"\n", node_name));
    yaml.push_str(&format!("  criSocket: \"{}\"\n", cri_socket));

    yaml.push_str("discovery:\n");
    yaml.push_str("  bootstrapToken:\n");
    yaml.push_str(&format!("    apiServerEndpoint: \"{}\"\n", api_server_endpoint));
    yaml.push_str(&format!("    token: \"{}\"\n", token));
    if !ca_cert_hash.is_empty() {
        yaml.push_str("    caCertHashes:\n");
        yaml.push_str(&format!("      - \"{}\"\n", ca_cert_hash));
    } else {
        yaml.push_str("    unsafeSkipCAVerification: true\n");
    }

    // Control plane join: secondary CP nodes join as control-plane
    if config.role == "server" {
        yaml.push_str("controlPlane:\n");
        // Advertise address from VPN IP
        let advertise_address = config
            .vpn
            .as_ref()
            .and_then(|vpn| vpn.links.first())
            .and_then(|link| link.address.as_ref())
            .and_then(|addr| addr.split('/').next().map(String::from))
            .unwrap_or_default();
        if !advertise_address.is_empty() {
            yaml.push_str("  localAPIEndpoint:\n");
            yaml.push_str(&format!("    advertiseAddress: \"{}\"\n", advertise_address));
            yaml.push_str("    bindPort: 6443\n");
        }
        if let Some(ref cert_key) = k8s.and_then(|k| k.certificate_key.as_ref()) {
            yaml.push_str(&format!("  certificateKey: \"{}\"\n", cert_key));
        }
    }

    Ok(yaml)
}

/// Extract the kubeadm bootstrap token from config sources.
///
/// Checks: kubernetes.token, then bootstrap_secrets["kubeadm_token"].
fn get_kubeadm_token(config: &ClusterConfig) -> Option<String> {
    // First: typed kubernetes config
    if let Some(ref k8s) = config.kubernetes {
        if let Some(ref token) = k8s.token {
            if !token.is_empty() {
                return Some(token.clone());
            }
        }
    }
    // Fallback: bootstrap_secrets
    config
        .bootstrap_secrets
        .as_ref()
        .and_then(|s| s.get("kubeadm_token"))
        .filter(|t| !t.is_empty())
        .cloned()
}

/// Write kubeadm config to `/etc/kubernetes/kubeadm-config.yaml`.
///
/// Also writes the role sentinel files for systemd ConditionPathExists-based
/// role selection, mirroring the K3s pattern.
pub fn write_kubeadm_config(config: &ClusterConfig) -> Result<()> {
    let config_dir = Path::new("/etc/kubernetes");
    let config_path = config_dir.join("kubeadm-config.yaml");

    std::fs::create_dir_all(config_dir)
        .with_context(|| format!("failed to create {}", config_dir.display()))?;

    let content = generate_kubeadm_config(config)?;

    std::fs::write(&config_path, &content)
        .with_context(|| format!("failed to write {}", config_path.display()))?;

    // Restrict permissions — config may contain bootstrap tokens
    #[cfg(unix)]
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o640))
        .with_context(|| format!("failed to set permissions on {}", config_path.display()))?;

    println!(
        "{} Wrote {} ({} bytes)",
        colored::Colorize::bold(colored::Colorize::green("ok")),
        config_path.display(),
        content.len()
    );

    // Write role sentinel file for systemd ConditionPathExists-based role selection.
    // kubelet.service has ConditionPathExists=/var/lib/kindling/server-mode.
    // kubelet-agent.service (or just kubelet) has ConditionPathExists=/var/lib/kindling/agent-mode.
    // Same dual-sentinel pattern as K3s.
    let sentinel_dir = std::path::Path::new("/var/lib/kindling");
    let server_sentinel = sentinel_dir.join("server-mode");
    let agent_sentinel = sentinel_dir.join("agent-mode");
    let _ = std::fs::create_dir_all(sentinel_dir);

    let service_name = if config.role == "server" {
        let _ = std::fs::remove_file(&agent_sentinel);
        std::fs::write(&server_sentinel, "server")
            .with_context(|| format!("failed to write sentinel {}", server_sentinel.display()))?;
        println!(
            "{} Server mode: wrote {}",
            colored::Colorize::bold(colored::Colorize::green("ok")),
            server_sentinel.display()
        );
        "kubelet.service"
    } else {
        let _ = std::fs::remove_file(&server_sentinel);
        std::fs::write(&agent_sentinel, "agent")
            .with_context(|| format!("failed to write sentinel {}", agent_sentinel.display()))?;
        println!(
            "{} Agent mode: wrote {} (kubelet will join as worker)",
            colored::Colorize::bold(colored::Colorize::green("ok")),
            agent_sentinel.display()
        );
        "kubelet.service"
    };

    // Explicitly start kubelet. ConditionPathExists is a safety net
    // but systemd may have already evaluated (and failed) the condition before
    // the sentinel was written.
    let _ = std::process::Command::new("systemctl")
        .args(["start", "--no-block", service_name])
        .status();
    println!(
        "{} Queued {} for start",
        colored::Colorize::bold(colored::Colorize::green("ok")),
        service_name
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kubeadm_init_config_basic() {
        let config = ClusterConfig::from_json(
            r#"{"cluster_name":"test-k8s","distribution":"kubernetes","cluster_init":true,"role":"server","kubernetes":{"version":"1.32.0"}}"#,
        )
        .unwrap();
        let yaml = generate_kubeadm_config(&config).unwrap();
        assert!(yaml.contains("kind: ClusterConfiguration"));
        assert!(yaml.contains("kind: InitConfiguration"));
        assert!(yaml.contains("kubernetesVersion: \"1.32.0\""));
        assert!(yaml.contains("clusterName: \"test-k8s\""));
        assert!(yaml.contains("name: \"test-k8s-server-0\""));
        assert!(yaml.contains("podSubnet: \"10.244.0.0/16\""));
        assert!(yaml.contains("serviceSubnet: \"10.96.0.0/12\""));
        assert!(yaml.contains("criSocket: \"unix:///run/containerd/containerd.sock\""));
    }

    #[test]
    fn kubeadm_init_config_with_token() {
        let config = ClusterConfig::from_json(
            r#"{"cluster_name":"test","distribution":"kubernetes","cluster_init":true,"role":"server","kubernetes":{"token":"abcdef.0123456789abcdef"}}"#,
        )
        .unwrap();
        let yaml = generate_kubeadm_config(&config).unwrap();
        assert!(yaml.contains("token: \"abcdef.0123456789abcdef\""));
        assert!(yaml.contains("ttl: \"0\""));
    }

    #[test]
    fn kubeadm_init_config_with_vpn_san() {
        let config = ClusterConfig::from_json(
            r#"{"cluster_name":"test","distribution":"kubernetes","cluster_init":true,"role":"server","kubernetes":{"version":"1.32.0"},"vpn":{"require_liveness":false,"links":[{"name":"wg-test","address":"10.99.0.1/24","private_key_file":"/tmp/key","peers":[],"firewall":{"trust_interface":false,"allowed_tcp_ports":[],"allowed_udp_ports":[]}}]}}"#,
        )
        .unwrap();
        let yaml = generate_kubeadm_config(&config).unwrap();
        assert!(yaml.contains("certSANs:"));
        assert!(yaml.contains("10.99.0.1"));
        assert!(yaml.contains("advertiseAddress: \"10.99.0.1\""));
        assert!(yaml.contains("controlPlaneEndpoint: \"10.99.0.1:6443\""));
    }

    #[test]
    fn kubeadm_join_config_worker() {
        let config = ClusterConfig::from_json(
            r#"{"cluster_name":"test","distribution":"kubernetes","role":"agent","node_index":1,"join_server":"10.0.0.1:6443","kubernetes":{"token":"abcdef.0123456789abcdef","ca_cert_hash":"sha256:abc123"}}"#,
        )
        .unwrap();
        let yaml = generate_kubeadm_config(&config).unwrap();
        assert!(yaml.contains("kind: JoinConfiguration"));
        assert!(yaml.contains("name: \"test-agent-1\""));
        assert!(yaml.contains("apiServerEndpoint: \"10.0.0.1:6443\""));
        assert!(yaml.contains("token: \"abcdef.0123456789abcdef\""));
        assert!(yaml.contains("caCertHashes:"));
        assert!(yaml.contains("sha256:abc123"));
        assert!(!yaml.contains("controlPlane:"));
    }

    #[test]
    fn kubeadm_join_config_secondary_cp() {
        let config = ClusterConfig::from_json(
            r#"{"cluster_name":"test","distribution":"kubernetes","role":"server","node_index":1,"join_server":"10.0.0.1:6443","kubernetes":{"token":"abcdef.0123456789abcdef","certificate_key":"certkey123"},"vpn":{"require_liveness":false,"links":[{"name":"wg-test","address":"10.99.0.2/24","private_key_file":"/tmp/key","peers":[],"firewall":{"trust_interface":false,"allowed_tcp_ports":[],"allowed_udp_ports":[]}}]}}"#,
        )
        .unwrap();
        let yaml = generate_kubeadm_config(&config).unwrap();
        assert!(yaml.contains("kind: JoinConfiguration"));
        assert!(yaml.contains("controlPlane:"));
        assert!(yaml.contains("advertiseAddress: \"10.99.0.2\""));
        assert!(yaml.contains("certificateKey: \"certkey123\""));
    }

    #[test]
    fn kubeadm_join_config_no_ca_hash_uses_unsafe_skip() {
        let config = ClusterConfig::from_json(
            r#"{"cluster_name":"test","distribution":"kubernetes","role":"agent","join_server":"10.0.0.1:6443","kubernetes":{"token":"tok"}}"#,
        )
        .unwrap();
        let yaml = generate_kubeadm_config(&config).unwrap();
        assert!(yaml.contains("unsafeSkipCAVerification: true"));
        assert!(!yaml.contains("caCertHashes"));
    }

    #[test]
    fn kubeadm_token_from_bootstrap_secrets() {
        let config = ClusterConfig::from_json(
            r#"{"cluster_name":"test","distribution":"kubernetes","role":"agent","join_server":"10.0.0.1:6443","bootstrap_secrets":{"kubeadm_token":"from-secrets.token12345"}}"#,
        )
        .unwrap();
        let yaml = generate_kubeadm_config(&config).unwrap();
        assert!(yaml.contains("token: \"from-secrets.token12345\""));
    }

    #[test]
    fn kubeadm_node_name_uses_derive_hostname() {
        let config = ClusterConfig::from_json(
            r#"{"cluster_name":"prod-us","distribution":"kubernetes","role":"server","node_index":3,"cluster_init":true}"#,
        )
        .unwrap();
        let yaml = generate_kubeadm_config(&config).unwrap();
        assert!(yaml.contains("name: \"prod-us-server-3\""));
    }

    #[test]
    fn kubeadm_custom_cidrs() {
        let config = ClusterConfig::from_json(
            r#"{"cluster_name":"test","distribution":"kubernetes","cluster_init":true,"role":"server","kubernetes":{"pod_cidr":"10.200.0.0/16","service_cidr":"10.201.0.0/16"}}"#,
        )
        .unwrap();
        let yaml = generate_kubeadm_config(&config).unwrap();
        assert!(yaml.contains("podSubnet: \"10.200.0.0/16\""));
        assert!(yaml.contains("serviceSubnet: \"10.201.0.0/16\""));
    }

    #[test]
    fn distribution_helpers() {
        let k3s = ClusterConfig::from_json(r#"{"cluster_name":"test"}"#).unwrap();
        assert!(k3s.is_k3s());
        assert!(!k3s.is_kubernetes());

        let k8s = ClusterConfig::from_json(
            r#"{"cluster_name":"test","distribution":"kubernetes"}"#,
        )
        .unwrap();
        assert!(!k8s.is_k3s());
        assert!(k8s.is_kubernetes());
    }
}
