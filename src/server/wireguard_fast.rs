//! WireGuard fast-start: bring up VPN interfaces before nixos-rebuild.
//!
//! Generates wg-quick config files from the cluster config and runs `wg-quick up`
//! for each VPN link. This provides VPN connectivity in <12s rather than waiting
//! for the full nixos-rebuild cycle.
//!
//! All operations are non-fatal: failures are logged as warnings and bootstrap
//! continues. WireGuard will come up after nixos-rebuild regardless.

use anyhow::{Context, Result};
use std::path::Path;
use tracing::{info, warn};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use super::cluster_config::{ClusterConfig, VpnLinkClusterConfig};

/// Directory for generated wg-quick config files.
const WG_RUN_DIR: &str = "/run/wireguard";

/// Attempt to fast-start all WireGuard interfaces from the cluster config.
///
/// Non-fatal: if any step fails, log a warning and continue (nixos-rebuild will
/// handle it). Returns `Ok(())` even if individual links fail.
pub fn fast_start(config: &ClusterConfig) -> Result<()> {
    let vpn = match &config.vpn {
        Some(v) if !v.links.is_empty() => v,
        Some(_) => {
            info!("VPN configured but no links defined, skipping fast-start");
            return Ok(());
        }
        None => {
            info!("No VPN configuration, skipping WireGuard fast-start");
            return Ok(());
        }
    };

    // Create the run directory for config files
    let run_dir = Path::new(WG_RUN_DIR);
    std::fs::create_dir_all(run_dir)
        .with_context(|| format!("failed to create {}", run_dir.display()))?;
    #[cfg(unix)]
    std::fs::set_permissions(run_dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to set permissions on {}", run_dir.display()))?;

    let mut successes = 0;
    let mut failures = 0;

    for link in &vpn.links {
        match bring_up_link(link, run_dir) {
            Ok(()) => {
                info!(link = %link.name, "WireGuard fast-start: link up");
                successes += 1;
            }
            Err(e) => {
                warn!(
                    link = %link.name,
                    error = %e,
                    "WireGuard fast-start: failed to bring up link (will retry after rebuild)"
                );
                failures += 1;
            }
        }
    }

    info!(
        successes = successes,
        failures = failures,
        "WireGuard fast-start complete"
    );

    if failures > 0 && successes == 0 {
        anyhow::bail!(
            "all {} WireGuard link(s) failed to fast-start",
            failures
        );
    }

    Ok(())
}

/// Bring up a single WireGuard link via wg-quick.
fn bring_up_link(link: &VpnLinkClusterConfig, run_dir: &Path) -> Result<()> {
    let config_content = generate_wg_quick_config(link)?;

    let conf_path = run_dir.join(format!("{}.conf", link.name));

    // Write config with restrictive permissions
    std::fs::write(&conf_path, &config_content)
        .with_context(|| format!("failed to write {}", conf_path.display()))?;
    #[cfg(unix)]
    std::fs::set_permissions(&conf_path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set permissions on {}", conf_path.display()))?;

    info!(
        link = %link.name,
        path = %conf_path.display(),
        "wrote wg-quick config"
    );

    // Run wg-quick up
    let output = std::process::Command::new("wg-quick")
        .args(["up", &conf_path.to_string_lossy()])
        .output()
        .with_context(|| format!("failed to execute wg-quick up for {}", link.name))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "wg-quick up {} failed (exit {}): {}",
            link.name,
            output.status.code().unwrap_or(-1),
            stderr.trim()
        );
    }

    Ok(())
}

/// Generate a wg-quick compatible config string.
///
/// wg-quick expects key VALUES inline (not file paths), so we read the key
/// files and embed their contents directly.
fn generate_wg_quick_config(link: &VpnLinkClusterConfig) -> Result<String> {
    let mut config = String::new();

    // [Interface] section
    config.push_str("[Interface]\n");

    // Private key — required
    let private_key_path = link
        .private_key_file
        .as_deref()
        .context("VPN link missing private_key_file")?;
    let private_key = read_key_file(Path::new(private_key_path))
        .with_context(|| format!("failed to read private key from {}", private_key_path))?;
    config.push_str(&format!("PrivateKey = {}\n", private_key));

    // Address — required for wg-quick
    if let Some(ref address) = link.address {
        config.push_str(&format!("Address = {}\n", address));
    }

    // Optional: ListenPort
    if let Some(port) = link.listen_port {
        config.push_str(&format!("ListenPort = {}\n", port));
    }

    // Optional: MTU
    if let Some(mtu) = link.mtu {
        config.push_str(&format!("MTU = {}\n", mtu));
    }

    // [Peer] sections
    for peer in &link.peers {
        config.push('\n');
        config.push_str("[Peer]\n");

        // Public key — required for a peer
        let public_key = peer
            .public_key
            .as_deref()
            .context("VPN peer missing public_key")?;
        config.push_str(&format!("PublicKey = {}\n", public_key));

        // Optional: PresharedKey (read from file)
        if let Some(ref psk_path) = peer.preshared_key_file {
            match read_key_file(Path::new(psk_path)) {
                Ok(psk) => config.push_str(&format!("PresharedKey = {}\n", psk)),
                Err(e) => {
                    warn!(
                        path = %psk_path,
                        error = %e,
                        "failed to read preshared key file, omitting"
                    );
                }
            }
        }

        // AllowedIPs
        if !peer.allowed_ips.is_empty() {
            config.push_str(&format!("AllowedIPs = {}\n", peer.allowed_ips.join(", ")));
        }

        // Optional: Endpoint
        if let Some(ref endpoint) = peer.endpoint {
            config.push_str(&format!("Endpoint = {}\n", endpoint));
        }

        // Optional: PersistentKeepalive (peer-level overrides link-level)
        let keepalive = peer.persistent_keepalive.or(link.persistent_keepalive);
        if let Some(ka) = keepalive {
            config.push_str(&format!("PersistentKeepalive = {}\n", ka));
        }
    }

    Ok(config)
}

/// Read a key file, trim whitespace and newlines.
fn read_key_file(path: &Path) -> Result<String> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read key file {}", path.display()))?;
    Ok(content.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::cluster_config::{VpnLinkClusterConfig, VpnPeerClusterConfig};

    #[test]
    fn generate_config_full() {
        let dir = tempfile::tempdir().unwrap();

        // Write mock key files
        let priv_key_path = dir.path().join("private.key");
        std::fs::write(&priv_key_path, "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/=\n").unwrap();

        let psk_path = dir.path().join("psk.key");
        std::fs::write(&psk_path, "PsKaBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789=\n").unwrap();

        let link = VpnLinkClusterConfig {
            name: "wg0".to_string(),
            private_key_file: Some(priv_key_path.to_string_lossy().to_string()),
            listen_port: Some(51820),
            address: Some("10.100.0.1/24".to_string()),
            profile: None,
            persistent_keepalive: Some(25),
            mtu: Some(1420),
            peers: vec![VpnPeerClusterConfig {
                public_key: Some("PeerPublicKeyBase64==".to_string()),
                endpoint: Some("203.0.113.1:51820".to_string()),
                allowed_ips: vec!["10.100.0.0/24".to_string(), "10.200.0.0/16".to_string()],
                persistent_keepalive: Some(30),
                preshared_key_file: Some(psk_path.to_string_lossy().to_string()),
            }],
            firewall: None,
        };

        let config = generate_wg_quick_config(&link).unwrap();

        // Verify [Interface] section
        assert!(config.contains("[Interface]"));
        assert!(config.contains("PrivateKey = aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/="));
        assert!(config.contains("Address = 10.100.0.1/24"));
        assert!(config.contains("ListenPort = 51820"));
        assert!(config.contains("MTU = 1420"));

        // Verify [Peer] section
        assert!(config.contains("[Peer]"));
        assert!(config.contains("PublicKey = PeerPublicKeyBase64=="));
        assert!(config.contains("PresharedKey = PsKaBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789="));
        assert!(config.contains("AllowedIPs = 10.100.0.0/24, 10.200.0.0/16"));
        assert!(config.contains("Endpoint = 203.0.113.1:51820"));
        // Peer-level keepalive (30) overrides link-level (25)
        assert!(config.contains("PersistentKeepalive = 30"));
    }

    #[test]
    fn generate_config_minimal() {
        let dir = tempfile::tempdir().unwrap();

        let priv_key_path = dir.path().join("private.key");
        std::fs::write(&priv_key_path, "MinimalPrivateKey==\n").unwrap();

        let link = VpnLinkClusterConfig {
            name: "wg0".to_string(),
            private_key_file: Some(priv_key_path.to_string_lossy().to_string()),
            listen_port: None,
            address: Some("10.100.0.1/24".to_string()),
            profile: None,
            persistent_keepalive: None,
            mtu: None,
            peers: vec![VpnPeerClusterConfig {
                public_key: Some("PeerKey==".to_string()),
                endpoint: None,
                allowed_ips: vec!["0.0.0.0/0".to_string()],
                persistent_keepalive: None,
                preshared_key_file: None,
            }],
            firewall: None,
        };

        let config = generate_wg_quick_config(&link).unwrap();

        // Required fields present
        assert!(config.contains("[Interface]"));
        assert!(config.contains("PrivateKey = MinimalPrivateKey=="));
        assert!(config.contains("Address = 10.100.0.1/24"));
        assert!(config.contains("[Peer]"));
        assert!(config.contains("PublicKey = PeerKey=="));
        assert!(config.contains("AllowedIPs = 0.0.0.0/0"));

        // Optional fields absent
        assert!(!config.contains("ListenPort"));
        assert!(!config.contains("MTU"));
        assert!(!config.contains("Endpoint"));
        assert!(!config.contains("PresharedKey"));
        assert!(!config.contains("PersistentKeepalive"));
    }

    #[test]
    fn generate_config_no_address() {
        let dir = tempfile::tempdir().unwrap();

        let priv_key_path = dir.path().join("private.key");
        std::fs::write(&priv_key_path, "SomeKey==\n").unwrap();

        let link = VpnLinkClusterConfig {
            name: "wg0".to_string(),
            private_key_file: Some(priv_key_path.to_string_lossy().to_string()),
            listen_port: None,
            address: None,
            profile: None,
            persistent_keepalive: None,
            mtu: None,
            peers: vec![],
            firewall: None,
        };

        let config = generate_wg_quick_config(&link).unwrap();
        assert!(config.contains("PrivateKey = SomeKey=="));
        assert!(!config.contains("Address"));
    }

    #[test]
    fn generate_config_missing_private_key_file() {
        let link = VpnLinkClusterConfig {
            name: "wg0".to_string(),
            private_key_file: None,
            listen_port: None,
            address: None,
            profile: None,
            persistent_keepalive: None,
            mtu: None,
            peers: vec![],
            firewall: None,
        };

        let result = generate_wg_quick_config(&link);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("private_key_file"),
            "expected error about private_key_file, got: {}",
            err
        );
    }

    #[test]
    fn generate_config_missing_peer_public_key() {
        let dir = tempfile::tempdir().unwrap();

        let priv_key_path = dir.path().join("private.key");
        std::fs::write(&priv_key_path, "SomeKey==\n").unwrap();

        let link = VpnLinkClusterConfig {
            name: "wg0".to_string(),
            private_key_file: Some(priv_key_path.to_string_lossy().to_string()),
            listen_port: None,
            address: Some("10.0.0.1/24".to_string()),
            profile: None,
            persistent_keepalive: None,
            mtu: None,
            peers: vec![VpnPeerClusterConfig {
                public_key: None,
                endpoint: None,
                allowed_ips: vec![],
                persistent_keepalive: None,
                preshared_key_file: None,
            }],
            firewall: None,
        };

        let result = generate_wg_quick_config(&link);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("public_key"),
            "expected error about public_key, got: {}",
            err
        );
    }

    #[test]
    fn generate_config_multiple_peers() {
        let dir = tempfile::tempdir().unwrap();

        let priv_key_path = dir.path().join("private.key");
        std::fs::write(&priv_key_path, "PrivKey==").unwrap();

        let link = VpnLinkClusterConfig {
            name: "wg0".to_string(),
            private_key_file: Some(priv_key_path.to_string_lossy().to_string()),
            listen_port: Some(51820),
            address: Some("10.100.0.1/24".to_string()),
            profile: None,
            persistent_keepalive: Some(25),
            mtu: None,
            peers: vec![
                VpnPeerClusterConfig {
                    public_key: Some("PeerA==".to_string()),
                    endpoint: Some("1.2.3.4:51820".to_string()),
                    allowed_ips: vec!["10.100.0.2/32".to_string()],
                    persistent_keepalive: None, // Falls back to link-level 25
                    preshared_key_file: None,
                },
                VpnPeerClusterConfig {
                    public_key: Some("PeerB==".to_string()),
                    endpoint: Some("5.6.7.8:51820".to_string()),
                    allowed_ips: vec!["10.100.0.3/32".to_string()],
                    persistent_keepalive: Some(15), // Overrides link-level 25
                    preshared_key_file: None,
                },
            ],
            firewall: None,
        };

        let config = generate_wg_quick_config(&link).unwrap();

        // Count [Peer] sections
        let peer_count = config.matches("[Peer]").count();
        assert_eq!(peer_count, 2, "expected 2 [Peer] sections");

        // First peer uses link-level keepalive
        assert!(config.contains("PersistentKeepalive = 25"));
        // Second peer overrides with 15
        assert!(config.contains("PersistentKeepalive = 15"));
    }

    #[test]
    fn generate_config_link_level_keepalive_fallback() {
        let dir = tempfile::tempdir().unwrap();

        let priv_key_path = dir.path().join("private.key");
        std::fs::write(&priv_key_path, "PrivKey==").unwrap();

        let link = VpnLinkClusterConfig {
            name: "wg0".to_string(),
            private_key_file: Some(priv_key_path.to_string_lossy().to_string()),
            listen_port: None,
            address: Some("10.0.0.1/24".to_string()),
            profile: None,
            persistent_keepalive: Some(25),
            mtu: None,
            peers: vec![VpnPeerClusterConfig {
                public_key: Some("PeerKey==".to_string()),
                endpoint: None,
                allowed_ips: vec!["10.0.0.0/24".to_string()],
                persistent_keepalive: None, // Should fall back to link-level 25
                preshared_key_file: None,
            }],
            firewall: None,
        };

        let config = generate_wg_quick_config(&link).unwrap();
        assert!(
            config.contains("PersistentKeepalive = 25"),
            "expected link-level keepalive fallback, config:\n{}",
            config
        );
    }

    #[test]
    fn read_key_file_trims_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key.txt");

        // Write key with trailing newline and spaces
        std::fs::write(&key_path, "  MySecretKey123==  \n\n").unwrap();

        let key = read_key_file(&key_path).unwrap();
        assert_eq!(key, "MySecretKey123==");
    }

    #[test]
    fn read_key_file_clean_value() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key.txt");

        std::fs::write(&key_path, "CleanKey==").unwrap();

        let key = read_key_file(&key_path).unwrap();
        assert_eq!(key, "CleanKey==");
    }

    #[test]
    fn read_key_file_missing() {
        let result = read_key_file(Path::new("/nonexistent/path/key.txt"));
        assert!(result.is_err());
    }
}
