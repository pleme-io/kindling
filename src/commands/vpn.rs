//! CLI subcommands for VPN key management and validation.

use anyhow::{Context, Result};
use std::path::Path;

use crate::server::cluster_config::ClusterConfig;
use crate::vpn::{keygen, validate};

/// List available VPN profiles and their configurations.
pub fn run_profiles() -> Result<()> {
    println!("Available VPN profiles:");
    println!();
    println!("  k8s-control-plane  K8s API access only (TCP 6443)");
    println!("                     trustInterface=false, persistentKeepalive=25");
    println!("                     Use for: kubectl access to K3s/K8s servers");
    println!();
    println!("  k8s-full           Full K8s cluster access (TCP 6443, 10250, 10257, 10259)");
    println!("                     trustInterface=false, persistentKeepalive=25");
    println!("                     Use for: multi-node clusters, kubelet/controller access");
    println!();
    println!("  site-to-site       LAN extension between sites");
    println!("                     trustInterface=true, persistentKeepalive=25");
    println!("                     Use for: subnet routing between data centers");
    println!();
    println!("  mesh               All-to-all peer connectivity");
    println!("                     trustInterface=true, persistentKeepalive=25");
    println!("                     Use for: distributed clusters without central server");
    Ok(())
}

/// Generate WireGuard keys for a new VPN link.
pub fn run_keygen(link: &str, side_a: &str, side_b: &str, profile: &str) -> Result<()> {
    keygen::run(link, side_a, side_b, profile)
}

/// Validate VPN configuration from a cluster-config.json file.
pub fn run_validate(config_path: &str, check_files: bool) -> Result<()> {
    let path = Path::new(config_path);
    let config = ClusterConfig::load(path)
        .with_context(|| format!("failed to load config from {}", config_path))?;

    let vpn = match &config.vpn {
        Some(v) => v,
        None => {
            println!("No VPN configuration found in {}", config_path);
            return Ok(());
        }
    };

    if vpn.links.is_empty() {
        println!("VPN section present but no links configured.");
        return Ok(());
    }

    let links: Vec<validate::VpnLink<'_>> = vpn
        .links
        .iter()
        .map(|l| validate::VpnLink {
            name: &l.name,
            private_key_file: l.private_key_file.as_deref(),
            listen_port: l.listen_port,
            address: l.address.as_deref(),
            profile: l.profile.as_deref(),
            persistent_keepalive: l.persistent_keepalive,
            peers: l
                .peers
                .iter()
                .map(|p| validate::VpnPeer {
                    public_key: p.public_key.as_deref(),
                    endpoint: p.endpoint.as_deref(),
                    allowed_ips: &p.allowed_ips,
                    persistent_keepalive: p.persistent_keepalive,
                    preshared_key_file: p.preshared_key_file.as_deref(),
                })
                .collect(),
            firewall: l.firewall.as_ref().map(|fw| validate::VpnFirewall {
                trust_interface: fw.trust_interface,
                allowed_tcp_ports: &fw.allowed_tcp_ports,
                allowed_udp_ports: &fw.allowed_udp_ports,
                incoming_udp_port: fw.incoming_udp_port,
            }),
        })
        .collect();

    match validate::validate_vpn_links(&links, check_files) {
        Ok(()) => {
            println!(
                "VPN validation passed: {} link(s) OK",
                links.len()
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}
