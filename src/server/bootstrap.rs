//! Bootstrap state machine for server mode.
//!
//! Orchestrates the full sequence: parse config → write identity → nixos-rebuild
//! → wait for K3s → wait for FluxCD → report readiness.
//!
//! State is persisted to `/var/lib/kindling/server-state.json` after each phase
//! transition, so re-running `kindling server bootstrap` resumes from the last
//! good phase.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use super::cluster_config::ClusterConfig;
use super::health;
use super::wireguard_fast;
use crate::commands::apply;
use crate::node_identity::NodeIdentity;

/// Phases of the server bootstrap process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapPhase {
    Pending,
    ConfigLoaded,
    SecretsProvisioned,
    WireguardFastStart,
    IdentityWritten,
    NixRebuildRunning,
    NixRebuildComplete,
    WireguardWaiting,
    WireguardReady,
    K3sWaiting,
    K3sReady,
    FluxcdBootstrapping,
    FluxcdReady,
    Complete,
    Failed,
}

impl std::fmt::Display for BootstrapPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{:?}", self));
        write!(f, "{}", s)
    }
}

/// Persisted bootstrap state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapState {
    pub phase: BootstrapPhase,
    pub config_path: String,
    pub cluster_name: String,
    pub error: Option<String>,
    pub updated_at: String,
}

impl BootstrapState {
    fn state_path() -> PathBuf {
        PathBuf::from("/var/lib/kindling/server-state.json")
    }

    /// Load from disk, or return a fresh Pending state.
    pub fn load_or_default(config_path: &str) -> Self {
        let path = Self::state_path();
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(state) = serde_json::from_str::<BootstrapState>(&content) {
                    return state;
                }
            }
        }
        BootstrapState {
            phase: BootstrapPhase::Pending,
            config_path: config_path.to_string(),
            cluster_name: String::new(),
            error: None,
            updated_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Persist current state to disk.
    pub fn save(&self) -> Result<()> {
        let path = Self::state_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let content =
            serde_json::to_string_pretty(self).context("failed to serialize bootstrap state")?;
        std::fs::write(&path, content)
            .with_context(|| format!("failed to write state to {}", path.display()))?;
        Ok(())
    }

    fn transition(&mut self, phase: BootstrapPhase) -> Result<()> {
        self.phase = phase;
        self.error = None;
        self.updated_at = chrono::Utc::now().to_rfc3339();
        self.save()
    }

    fn fail(&mut self, error: &str) -> Result<()> {
        self.phase = BootstrapPhase::Failed;
        self.error = Some(error.to_string());
        self.updated_at = chrono::Utc::now().to_rfc3339();
        self.save()
    }
}

/// Run the full server bootstrap sequence.
///
/// Resumes from the last persisted phase on re-invocation.
pub fn run(config_path: &Path) -> Result<()> {
    let config_str = config_path.to_string_lossy().to_string();
    let mut state = BootstrapState::load_or_default(&config_str);

    // Peek at config to determine test mode (for EC2 tag reporting).
    // In test mode (skip_nix_rebuild=true), tag the instance after each phase
    // so the cluster test orchestrator can watch tags instead of SSH polling.
    let test_mode = ClusterConfig::load(config_path)
        .map(|c| c.skip_nix_rebuild == Some(true))
        .unwrap_or(false);

    // If previously failed, reset to re-attempt from the failed phase's predecessor
    if state.phase == BootstrapPhase::Failed {
        println!(
            "{} Previous run failed: {}",
            "!!".yellow().bold(),
            state.error.as_deref().unwrap_or("unknown")
        );
        println!("{} Resetting to retry", ">>".blue().bold());
        state.phase = BootstrapPhase::Pending;
    }

    // Phase: Load config + security validation
    // SECURITY: VPN validation runs BEFORE any config details are logged or identity is written.
    // This ensures no information leaks from invalid/malicious configs.
    if state.phase == BootstrapPhase::Pending {
        println!(
            "{} Loading cluster config from {}",
            ">>".blue().bold(),
            config_path.display()
        );
        let config = match ClusterConfig::load(config_path) {
            Ok(c) => c,
            Err(e) => {
                state.fail(&e.to_string())?;
                bail!("failed to load cluster config: {}", e);
            }
        };

        // Security gate: validate VPN config BEFORE logging any config details.
        // If this fails, the node does NOT come up. No config details are leaked.
        println!(
            "{} Validating security invariants",
            ">>".blue().bold()
        );
        // Structural only — key files don't exist yet (written in SecretsProvisioned phase)
        match config.validate_vpn_security() {
            Ok(()) => {
                if config.vpn.is_some() {
                    println!(
                        "{} VPN security validation passed",
                        "ok".green().bold()
                    );
                }
            }
            Err(e) => {
                state.fail(&e.to_string())?;
                bail!(
                    "SECURITY: VPN validation failed — refusing to bootstrap.\n\
                     The node will NOT come up until all security invariants are satisfied.\n\
                     {}",
                    e
                );
            }
        }

        // Only log config details AFTER security validation passes
        state.cluster_name = config.cluster_name.clone();
        println!(
            "{} Cluster: {}, Role: {}, Distribution: {}",
            "ok".green().bold(),
            config.cluster_name,
            config.role,
            config.distribution
        );
        state.transition(BootstrapPhase::ConfigLoaded)?;
        if test_mode {
            tag_instance_phase("config_loaded");
            tag_instance("NodeRole", &config.role);
            tag_instance("NodeIndex", &config.node_index.to_string());
            tag_instance("ClusterName", &config.cluster_name);
        }
    }

    // Phase: Stop K3s before writing PKI secrets
    // K3s auto-starts from the AMI config and generates its own CA.
    // We must stop it, clear stale TLS state, then let nixos-rebuild
    // start it fresh with our seeded PKI.
    if state.phase == BootstrapPhase::ConfigLoaded {
        // K3s may have auto-started from the AMI config and generated its own
        // CA certs + datastore. We must halt it and clear ALL state so it starts
        // fresh with our seeded PKI. K3s reads CA from its datastore on restart —
        // if the datastore has a different CA, it ignores files on disk.
        println!("{} Preparing K3s for deterministic PKI seeding", ">>".blue().bold());
        let k3s_active = std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", "k3s.service"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if k3s_active {
            println!("{} Halting K3s before PKI seeding", "::".blue().bold());
            match std::process::Command::new("systemctl")
                .args(["stop", "k3s.service"])
                .output()
            {
                Ok(output) if !output.status.success() => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    println!(
                        "{} systemctl stop k3s failed (non-fatal): {}",
                        "!!".yellow().bold(),
                        stderr.trim()
                    );
                }
                Err(e) => {
                    println!(
                        "{} systemctl not found (non-fatal): {}",
                        "!!".yellow().bold(),
                        e
                    );
                }
                _ => {}
            }
        }

        // Clear K3s server state (TLS + datastore) for clean PKI seeding.
        // K3s stores its CA in an embedded SQLite datastore — if that exists
        // from a prior boot, K3s ignores CA files on disk. Clear everything
        // so K3s initializes fresh from our seeded PKI files.
        // provision_bootstrap_secrets (next phase) re-writes all needed files.
        let server_dir = std::path::Path::new("/var/lib/rancher/k3s/server");
        if server_dir.exists() {
            if let Err(e) = std::fs::remove_dir_all(server_dir) {
                println!("{} Failed to clear K3s server dir: {e}", "!!".yellow().bold());
            } else {
                println!("{} Cleared K3s server state for deterministic PKI", "ok".green().bold());
            }
        }
    }

    // Phase: Provision bootstrap secrets (age key, GitHub token, PKI, etc.)
    // MUST run before NixOS rebuild so sops-nix can find the age key.
    if state.phase == BootstrapPhase::ConfigLoaded {
        let config = ClusterConfig::load(config_path)?;
        match provision_bootstrap_secrets(&config) {
            Ok(provisioned) => {
                if provisioned > 0 {
                    println!(
                        "{} Provisioned {} bootstrap secret(s)",
                        "ok".green().bold(),
                        provisioned
                    );
                } else {
                    println!(
                        "{} No bootstrap secrets to provision",
                        "::".blue().bold()
                    );
                }
                state.transition(BootstrapPhase::SecretsProvisioned)?;
                if test_mode {
                    tag_instance_phase("secrets_provisioned");
                }
            }
            Err(e) => {
                state.fail(&e.to_string())?;
                bail!("bootstrap secrets provisioning failed: {}", e);
            }
        }
    }

    // Phase: WireGuard fast-start (before nixos-rebuild for <12s VPN connectivity)
    if state.phase == BootstrapPhase::SecretsProvisioned {
        let config = ClusterConfig::load(config_path)?;
        println!(
            "{} Fast-starting WireGuard (before nixos-rebuild)",
            ">>".blue().bold()
        );

        // Open firewall for WireGuard listen ports BEFORE bringing up interfaces.
        // NixOS firewall blocks incoming UDP by default. Without nixos-rebuild,
        // the only way to open ports is via iptables directly.
        if let Some(ref vpn) = config.vpn {
            for link in &vpn.links {
                if let Some(port) = link.listen_port {
                    match std::process::Command::new("iptables")
                        .args(["-I", "INPUT", "-p", "udp", "--dport", &port.to_string(), "-j", "ACCEPT"])
                        .output()
                    {
                        Ok(output) if !output.status.success() => {
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            println!(
                                "{} iptables failed (non-fatal): {}",
                                "!!".yellow().bold(),
                                stderr.trim()
                            );
                        }
                        Err(e) => {
                            println!(
                                "{} iptables not found (non-fatal): {}",
                                "!!".yellow().bold(),
                                e
                            );
                        }
                        _ => {}
                    }
                    println!(
                        "{} Opened UDP port {} in firewall for WireGuard",
                        "ok".green().bold(),
                        port
                    );
                }
            }
        }

        match wireguard_fast::fast_start(&config) {
            Ok(()) => {
                println!(
                    "{} WireGuard fast-start successful",
                    "ok".green().bold()
                );
            }
            Err(e) => {
                println!(
                    "{} WireGuard fast-start failed (will retry after rebuild): {}",
                    "!!".yellow().bold(),
                    e
                );
            }
        }
        state.transition(BootstrapPhase::WireguardFastStart)?;
        if test_mode {
            tag_instance_phase("wireguard_fast_start");
        }
    }

    // Phase: Write node identity
    if state.phase == BootstrapPhase::WireguardFastStart {
        println!("{} Generating node identity", ">>".blue().bold());
        let config = ClusterConfig::load(config_path)?;
        let identity = config.to_node_identity();
        let identity_path = NodeIdentity::server_path();

        identity.save(&identity_path)?;
        println!(
            "{} Identity written to {}",
            "ok".green().bold(),
            identity_path.display()
        );
        state.transition(BootstrapPhase::IdentityWritten)?;
        if test_mode {
            tag_instance_phase("identity_written");
        }
    }

    // Phase: NixOS rebuild (or skip + manual K3s start for AMI integration tests)
    if state.phase == BootstrapPhase::IdentityWritten {
        let config = ClusterConfig::load(config_path)?;
        if config.skip_nix_rebuild == Some(true) {
            println!(
                "{} Skipping nixos-rebuild (skip_nix_rebuild=true)",
                "::".blue().bold()
            );
            state.transition(BootstrapPhase::NixRebuildRunning)?;

            // Write K3s runtime config so K3s starts with the right flags.
            // Without nixos-rebuild, the NixOS systemd unit has the AMI's
            // default flags. This config.yaml overrides them at runtime.
            println!(
                "{} Writing K3s runtime config",
                ">>".blue().bold()
            );
            write_k3s_runtime_config(&config)?;

            // K3s will auto-start after kindling-init completes because the
            // NixOS module sets Before=k3s.service on kindling-init.service.
            println!(
                "{} K3s will auto-start after init completes (Before=k3s.service)",
                "::".blue().bold()
            );
            state.transition(BootstrapPhase::NixRebuildComplete)?;
            if test_mode {
                tag_instance_phase("nix_rebuild_skipped");
            }
        } else {
            println!("{} Running nixos-rebuild switch", ">>".blue().bold());
            state.transition(BootstrapPhase::NixRebuildRunning)?;

            let identity_path = NodeIdentity::server_path();
            match apply::run_rebuild_from_path(&identity_path) {
                Ok(()) => {
                    println!(
                        "{} NixOS rebuild completed successfully",
                        "ok".green().bold()
                    );
                    state.transition(BootstrapPhase::NixRebuildComplete)?;
                    if test_mode {
                        tag_instance_phase("nix_rebuild_complete");
                    }
                }
                Err(e) => {
                    state.fail(&e.to_string())?;
                    bail!("nixos-rebuild failed: {}", e);
                }
            }
        }
    }

    // Phase: Wait for WireGuard (only if VPN configured)
    if state.phase == BootstrapPhase::NixRebuildComplete {
        let config = ClusterConfig::load(config_path)?;
        if let Some(ref vpn_config) = config.vpn {
            println!(
                "{} Waiting for WireGuard tunnels to establish",
                ">>".blue().bold()
            );
            state.transition(BootstrapPhase::WireguardWaiting)?;

            match health::wait_for_wireguard(Duration::from_secs(60), Duration::from_secs(5)) {
                Ok(status) => {
                    println!("{} WireGuard ready: {}", "ok".green().bold(), status.message);
                    state.transition(BootstrapPhase::WireguardReady)?;
                    if test_mode {
                        tag_instance_phase("wireguard_ready");
                    }
                }
                Err(e) => {
                    if vpn_config.require_liveness {
                        state.fail(&e.to_string())?;
                        bail!("WireGuard health check failed: {}", e);
                    } else {
                        println!(
                            "{} WireGuard liveness check timed out (non-fatal, require_liveness=false): {}",
                            "!!".yellow().bold(),
                            e
                        );
                        state.transition(BootstrapPhase::WireguardReady)?;
                        if test_mode {
                            tag_instance_phase("wireguard_ready");
                        }
                    }
                }
            }
        } else {
            println!(
                "{} No VPN configured, skipping WireGuard check",
                "::".blue().bold()
            );
            state.transition(BootstrapPhase::WireguardReady)?;
            if test_mode {
                tag_instance_phase("wireguard_ready");
            }
        }
    }

    // Phase: Wait for K3s (skip when skip_nix_rebuild — K3s starts AFTER init exits)
    if state.phase == BootstrapPhase::WireguardReady {
        let config = ClusterConfig::load(config_path)?;
        if config.skip_nix_rebuild == Some(true) {
            println!(
                "{} Skipping K3s health check (K3s starts after init exits via Before=k3s.service)",
                "::".blue().bold()
            );
            state.transition(BootstrapPhase::K3sReady)?;
            if test_mode {
                tag_instance_phase("k3s_ready");
            }
        } else {
            println!("{} Waiting for K3s to become ready", ">>".blue().bold());
            state.transition(BootstrapPhase::K3sWaiting)?;

            match health::wait_for_k3s(Duration::from_secs(300), Duration::from_secs(10)) {
                Ok(status) => {
                    println!("{} K3s ready: {}", "ok".green().bold(), status.message);
                    state.transition(BootstrapPhase::K3sReady)?;
                    if test_mode {
                        tag_instance_phase("k3s_ready");
                    }
                }
                Err(e) => {
                    state.fail(&e.to_string())?;
                    bail!("K3s health check failed: {}", e);
                }
            }
        }
    }

    // Phase: Wait for FluxCD (only if enabled; skip when skip_nix_rebuild)
    if state.phase == BootstrapPhase::K3sReady {
        let config = ClusterConfig::load(config_path)?;
        if config.skip_nix_rebuild == Some(true) {
            println!(
                "{} Skipping FluxCD check (skip_nix_rebuild mode)",
                "::".blue().bold()
            );
            state.transition(BootstrapPhase::FluxcdReady)?;
        } else if config.fluxcd.is_some() {
            println!(
                "{} Waiting for FluxCD reconciliation",
                ">>".blue().bold()
            );
            state.transition(BootstrapPhase::FluxcdBootstrapping)?;

            match health::wait_for_fluxcd(Duration::from_secs(600), Duration::from_secs(15)) {
                Ok(status) => {
                    println!("{} FluxCD ready: {}", "ok".green().bold(), status.message);
                    state.transition(BootstrapPhase::FluxcdReady)?;
                }
                Err(e) => {
                    state.fail(&e.to_string())?;
                    bail!("FluxCD health check failed: {}", e);
                }
            }
        } else {
            println!(
                "{} FluxCD not configured, skipping",
                "::".blue().bold()
            );
            state.transition(BootstrapPhase::FluxcdReady)?;
        }
    }

    // Phase: Complete
    if state.phase == BootstrapPhase::FluxcdReady {
        state.transition(BootstrapPhase::Complete)?;
        if test_mode {
            tag_instance_phase("complete");
        }
        println!();
        println!(
            "{} Server bootstrap complete for cluster '{}'",
            "ok".green().bold(),
            state.cluster_name
        );
    }

    if state.phase == BootstrapPhase::Complete {
        println!(
            "{} Current phase: {}",
            "ok".green().bold(),
            state.phase
        );
    }

    Ok(())
}

/// Generate K3s config YAML from a ClusterConfig (pure function, no IO).
///
/// Produces the YAML content for `/etc/rancher/k3s/config.yaml` covering:
/// - `cluster-init: true` for the first server
/// - `server: https://...` for joining an existing cluster
/// - `token` for cluster authentication
/// - `disable-network-policy: true` to avoid WireGuard/Flannel conflicts
/// - `tls-san` for certificate SANs (explicit + VPN addresses)
///
/// Does NOT include `node-ip` or `flannel-iface` — those require IMDS/network
/// discovery and are appended by the caller (`write_k3s_runtime_config`).
fn generate_k3s_config_yaml(config: &ClusterConfig) -> Result<String> {
    let mut lines: Vec<String> = Vec::new();

    // Cluster init vs join
    if let Some(ref join) = config.join_server {
        lines.push(format!("server: \"{}\"", join));
    } else if config.cluster_init {
        lines.push("cluster-init: true".to_string());
    }

    // Token from bootstrap_secrets
    if let Some(ref secrets) = config.bootstrap_secrets {
        if let Some(token) = secrets.get("k3s_server_token") {
            if !token.is_empty() {
                lines.push(format!("token: \"{}\"", token));
            }
        }
    }

    // Disable network policy controller — it crashes intermittently when
    // WireGuard interfaces are present alongside Flannel. The controller
    // re-evaluates interfaces on restart and fails to find the node IP.
    // Network policies can be provided by Cilium/Calico if needed.
    lines.push("disable-network-policy: true".to_string());

    // TLS SANs — include VPN addresses so K3s cert is valid for VPN connections
    let mut sans: Vec<String> = Vec::new();
    if let Some(ref k3s) = config.k3s {
        for san in &k3s.tls_san {
            sans.push(san.clone());
        }
    }
    // Add VPN addresses as SANs (strip /24 mask)
    if let Some(ref vpn) = config.vpn {
        for link in &vpn.links {
            if let Some(ref addr) = link.address {
                if let Some(ip) = addr.split('/').next() {
                    sans.push(ip.to_string());
                }
            }
        }
    }
    if !sans.is_empty() {
        lines.push("tls-san:".to_string());
        for san in &sans {
            lines.push(format!("  - \"{}\"", san));
        }
    }

    Ok(lines.join("\n") + "\n")
}

/// Write `/etc/rancher/k3s/config.yaml` for K3s runtime configuration.
///
/// When `skip_nix_rebuild` is true, the NixOS K3s systemd unit has the AMI's
/// default flags. This config file overrides K3s behavior at startup.
///
/// Calls `generate_k3s_config_yaml` for the pure config generation, then
/// appends IMDS-dependent fields (node-ip, flannel-iface) and writes to disk.
fn write_k3s_runtime_config(config: &ClusterConfig) -> Result<()> {
    let config_dir = Path::new("/etc/rancher/k3s");
    let config_path = config_dir.join("config.yaml");

    std::fs::create_dir_all(config_dir)
        .with_context(|| format!("failed to create {}", config_dir.display()))?;

    let mut content = generate_k3s_config_yaml(config)?;

    // Node IP from IMDS — ensures K3s binds to the correct VPC interface.
    // These require network/IMDS access so they live outside the pure function.
    if let Ok(node_ip) = get_vpc_private_ip() {
        content.push_str(&format!("node-ip: \"{}\"\n", node_ip));
        // Discover which interface has this IP — Flannel needs explicit iface
        // when multiple interfaces exist (e.g., ens5 + wg-test VPN).
        if let Ok(iface) = get_interface_for_ip(&node_ip) {
            content.push_str(&format!("flannel-iface: \"{}\"\n", iface));
        }
    }

    std::fs::write(&config_path, &content)
        .with_context(|| format!("failed to write {}", config_path.display()))?;

    println!(
        "{} Wrote {} ({} bytes)",
        "ok".green().bold(),
        config_path.display(),
        content.len()
    );

    // If role is "agent", mask k3s.service (server) and enable k3s-agent.service.
    // The AMI includes both services via the NixOS module; only one should run.
    // Previous approach used a systemd drop-in in /run/systemd/system, but NixOS's
    // read-only /etc/systemd/system takes priority. Using mask+enable is reliable.
    if config.role == "agent" {
        let _ = std::process::Command::new("systemctl")
            .args(["mask", "k3s.service"])
            .status();
        let _ = std::process::Command::new("systemctl")
            .args(["enable", "k3s-agent.service"])
            .status();
        println!(
            "{} K3s agent mode: masked k3s.service, enabled k3s-agent.service",
            "ok".green().bold()
        );
    }

    Ok(())
}

/// Find the network interface that has the given IP assigned.
///
/// First attempts a pure-Rust approach by reading `/proc/net/fib_trie` (Linux only,
/// no external dependencies). Falls back to parsing `ip -o addr show` output if
/// `/proc/net/fib_trie` is unavailable or unparseable.
fn get_interface_for_ip(ip: &str) -> Result<String> {
    // Attempt 1: Pure Rust — scan /sys/class/net/*/operstate + /proc/net/fib_trie
    if let Ok(iface) = get_interface_for_ip_proc(ip) {
        return Ok(iface);
    }

    // Attempt 2: Fall back to `ip -o addr show` with full error context
    let output = std::process::Command::new("ip")
        .args(["-o", "addr", "show"])
        .output()
        .context("failed to run `ip -o addr show`")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "`ip -o addr show` exited with {}: {}",
            output.status,
            stderr.trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        // Format: "2: ens5    inet 172.31.23.43/20 brd ..."
        if line.contains(&format!("inet {ip}/")) || line.contains(&format!("inet {ip} ")) {
            // Interface name is the second field
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return Ok(parts[1].trim_end_matches(':').to_string());
            }
        }
    }
    bail!("no interface found with IP {ip}")
}

/// Pure-Rust interface lookup by scanning `/sys/class/net/` and reading each
/// interface's addresses from `/proc/net/if_net6` or by matching against the
/// kernel's FIB trie.
///
/// Reads `/sys/class/net/<iface>/` to enumerate interfaces, then checks
/// `/proc/net/fib_trie` entries to match the target IPv4 address to its device.
fn get_interface_for_ip_proc(target_ip: &str) -> Result<String> {
    let target: std::net::Ipv4Addr = target_ip
        .parse()
        .context("target IP is not a valid IPv4 address")?;

    // Enumerate interfaces from /sys/class/net
    let net_dir = std::path::Path::new("/sys/class/net");
    let entries = std::fs::read_dir(net_dir).context("failed to read /sys/class/net")?;

    let mut ifaces: Vec<String> = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "lo" {
            continue;
        }
        ifaces.push(name);
    }

    // Parse /proc/net/fib_trie to find which interface owns the target IP.
    //
    // The format has sections like:
    //   Local:
    //     /0 ...
    //       +-- 172.31.16.0/20 ...
    //         /32 host LOCAL
    //           |-- 172.31.23.43
    //              ...
    // We track the current "device" context by looking for lines like:
    //   |-- <ip>
    // after a `/32 host LOCAL` line. But actually a simpler approach:
    // scan for lines matching our target IP under a device section.
    //
    // Alternative simpler approach: for each interface, read
    // /proc/net/if_inet6 or try /sys/class/net/<iface>/..., but IPv4
    // addresses aren't directly exposed via sysfs.
    //
    // Simplest reliable approach: read /proc/net/fib_trie, look for our IP
    // in a LOCAL section, and correlate with the interface.
    //
    // Actually the most robust pure-Rust zero-dep approach: for each interface,
    // try to bind a UDP socket to target_ip on that interface.
    // But that doesn't directly tell us the interface name.
    //
    // Parse approach: read all of /proc/net/fib_trie. The structure is:
    //   Main:              <- routing table
    //     +-- 0.0.0.0/0    <- prefix
    //        ...
    //   Local:             <- local addresses table
    //     +-- 172.31.16.0/20
    //        /32 host LOCAL
    //           |-- 172.31.23.43
    //
    // But we need the interface. /proc/net/fib_trie doesn't directly show device names.
    // The file /proc/net/route has device names with hex-encoded IPs.
    let route_content =
        std::fs::read_to_string("/proc/net/route").context("failed to read /proc/net/route")?;

    // /proc/net/route format (tab-separated):
    //   Iface  Destination  Gateway  Flags  RefCnt  Use  Metric  Mask  MTU  Window  IRTT
    //   ens5   0000A8AC     ...
    // Destination and Gateway are hex-encoded in network byte order (little-endian on x86,
    // but /proc/net/route uses host byte order which is little-endian).

    // Strategy: find the interface whose route subnet contains our target IP.
    // For a directly-connected interface, there will be a route with Gateway=00000000
    // and the Destination+Mask covering our IP.
    let target_u32 = u32::from(target);

    for line in route_content.lines().skip(1) {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 8 {
            continue;
        }
        let iface_name = fields[0].trim();
        let dest = u32::from_str_radix(fields[1].trim(), 16).unwrap_or(0);
        let mask = u32::from_str_radix(fields[7].trim(), 16).unwrap_or(0);

        // /proc/net/route stores values in host byte order (little-endian on x86).
        // Convert target IP to the same format.
        let target_le = target_u32.swap_bytes();

        if (target_le & mask) == dest && ifaces.contains(&iface_name.to_string()) {
            return Ok(iface_name.to_string());
        }
    }

    bail!("no interface found for {target_ip} via /proc/net/route")
}

/// Read the VPC private IP from EC2 instance metadata (IMDSv2).
fn get_vpc_private_ip() -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("failed to build HTTP client for IMDS")?;

    // Get IMDSv2 token
    let token = client
        .put("http://169.254.169.254/latest/api/token")
        .header("X-aws-ec2-metadata-token-ttl-seconds", "60")
        .send()
        .context("IMDS token request failed")?
        .error_for_status()
        .context("IMDS token request returned error status")?
        .text()
        .context("failed to read IMDS token body")?;

    let token = token.trim().to_string();
    if token.is_empty() {
        bail!("IMDS token is empty — not running on EC2?");
    }

    // Get private IP
    let ip = client
        .get("http://169.254.169.254/latest/meta-data/local-ipv4")
        .header("X-aws-ec2-metadata-token", &token)
        .send()
        .context("IMDS private IP request failed")?
        .error_for_status()
        .context("IMDS private IP request returned error status")?
        .text()
        .context("failed to read IMDS private IP body")?;

    let ip = ip.trim().to_string();
    if ip.is_empty() {
        bail!("IMDS private IP is empty");
    }

    Ok(ip)
}

/// Known bootstrap secret keys and their target paths + permissions.
struct SecretTarget {
    key: &'static str,
    dir: &'static str,
    path: &'static str,
    dir_mode: u32,
    file_mode: u32,
    /// If true, base64-decode the value before writing (for PEM certs stored as base64 in JSON).
    base64_decode: bool,
}

const BOOTSTRAP_SECRET_TARGETS: &[SecretTarget] = &[
    SecretTarget {
        key: "sops_age_key",
        dir: "/var/lib/sops-nix",
        path: "/var/lib/sops-nix/key.txt",
        dir_mode: 0o700,
        file_mode: 0o600,
        base64_decode: false,
    },
    SecretTarget {
        key: "flux_github_token",
        dir: "/run/secrets.d",
        path: "/run/secrets.d/flux-github-token",
        dir_mode: 0o700,
        file_mode: 0o400,
        base64_decode: false,
    },
    SecretTarget {
        key: "nix_github_token",
        dir: "/etc/nix",
        path: "/etc/nix/github-access-token",
        dir_mode: 0o755,
        file_mode: 0o600,
        base64_decode: false,
    },
    SecretTarget {
        key: "vpn_private_key",
        dir: "/run/secrets.d",
        path: "/run/secrets.d/vpn-private-key",
        dir_mode: 0o700,
        file_mode: 0o400,
        base64_decode: false,
    },
    SecretTarget {
        key: "vpn_psk",
        dir: "/run/secrets.d",
        path: "/run/secrets.d/vpn-psk",
        dir_mode: 0o700,
        file_mode: 0o400,
        base64_decode: false,
    },
    SecretTarget {
        key: "k3s_server_token",
        dir: "/var/lib/rancher/k3s/server",
        path: "/var/lib/rancher/k3s/server/token",
        dir_mode: 0o700,
        file_mode: 0o600,
        base64_decode: false,
    },
    SecretTarget {
        key: "k3s_admin_password",
        dir: "/var/lib/rancher/k3s/server/cred",
        path: "/var/lib/rancher/k3s/server/cred/passwd",
        dir_mode: 0o700,
        file_mode: 0o600,
        base64_decode: false,
    },
    // ── K3s PKI (deterministic kubeconfig) ────────────────────────
    // Pre-seeding the CA certs + keys ensures k3s reuses them instead
    // of generating new ones. Values are base64-encoded PEM.
    SecretTarget {
        key: "k3s_tls_server_ca_crt",
        dir: "/var/lib/rancher/k3s/server/tls",
        path: "/var/lib/rancher/k3s/server/tls/server-ca.crt",
        dir_mode: 0o700,
        file_mode: 0o600,
        base64_decode: true,
    },
    SecretTarget {
        key: "k3s_tls_server_ca_key",
        dir: "/var/lib/rancher/k3s/server/tls",
        path: "/var/lib/rancher/k3s/server/tls/server-ca.key",
        dir_mode: 0o700,
        file_mode: 0o600,
        base64_decode: true,
    },
    SecretTarget {
        key: "k3s_tls_client_ca_crt",
        dir: "/var/lib/rancher/k3s/server/tls",
        path: "/var/lib/rancher/k3s/server/tls/client-ca.crt",
        dir_mode: 0o700,
        file_mode: 0o600,
        base64_decode: true,
    },
    SecretTarget {
        key: "k3s_tls_client_ca_key",
        dir: "/var/lib/rancher/k3s/server/tls",
        path: "/var/lib/rancher/k3s/server/tls/client-ca.key",
        dir_mode: 0o700,
        file_mode: 0o600,
        base64_decode: true,
    },
    SecretTarget {
        key: "k3s_tls_request_header_ca_crt",
        dir: "/var/lib/rancher/k3s/server/tls",
        path: "/var/lib/rancher/k3s/server/tls/request-header-ca.crt",
        dir_mode: 0o700,
        file_mode: 0o600,
        base64_decode: true,
    },
    SecretTarget {
        key: "k3s_tls_request_header_ca_key",
        dir: "/var/lib/rancher/k3s/server/tls",
        path: "/var/lib/rancher/k3s/server/tls/request-header-ca.key",
        dir_mode: 0o700,
        file_mode: 0o600,
        base64_decode: true,
    },
    SecretTarget {
        key: "k3s_tls_service_key",
        dir: "/var/lib/rancher/k3s/server/tls",
        path: "/var/lib/rancher/k3s/server/tls/service.key",
        dir_mode: 0o700,
        file_mode: 0o600,
        base64_decode: true,
    },
];

/// Write a secret value to a file with restrictive permissions.
/// Creates the parent directory if needed. Idempotent: skips if file already
/// exists with non-zero size.
///
/// Returns `true` if the file was written, `false` if skipped.
fn write_secret_file(
    dir_path: &Path,
    file_path: &Path,
    value: &str,
    dir_mode: u32,
    file_mode: u32,
) -> Result<bool> {
    // Idempotent: skip if file exists with content
    if file_path.exists() {
        let meta = std::fs::metadata(file_path)
            .with_context(|| format!("failed to stat {}", file_path.display()))?;
        if meta.len() > 0 {
            println!(
                "{} {} already exists, skipping",
                "::".blue().bold(),
                file_path.display()
            );
            return Ok(false);
        }
    }

    // Create parent directory with restrictive permissions
    if !dir_path.exists() {
        std::fs::create_dir_all(dir_path)
            .with_context(|| format!("failed to create {}", dir_path.display()))?;
        #[cfg(unix)]
        std::fs::set_permissions(dir_path, std::fs::Permissions::from_mode(dir_mode))
            .with_context(|| format!("failed to set permissions on {}", dir_path.display()))?;
    }

    // Write secret with restrictive permissions
    std::fs::write(file_path, value)
        .with_context(|| format!("failed to write {}", file_path.display()))?;
    #[cfg(unix)]
    std::fs::set_permissions(file_path, std::fs::Permissions::from_mode(file_mode))
        .with_context(|| format!("failed to set permissions on {}", file_path.display()))?;

    println!(
        "{} Wrote {} ({:04o})",
        "ok".green().bold(),
        file_path.display(),
        file_mode
    );
    Ok(true)
}

/// Provision bootstrap secrets from cloud-init to filesystem paths.
///
/// Returns the number of secrets provisioned. Idempotent: skips secrets
/// whose target paths already exist with non-zero size.
fn provision_bootstrap_secrets(config: &ClusterConfig) -> Result<usize> {
    let secrets = match &config.bootstrap_secrets {
        Some(s) if !s.is_empty() => s,
        _ => return Ok(0),
    };

    let mut provisioned = 0;

    for target in BOOTSTRAP_SECRET_TARGETS {
        let raw_value = match secrets.get(target.key) {
            Some(v) if !v.is_empty() => v,
            _ => continue,
        };

        // Base64 decode if needed (TLS certs are stored as base64 in JSON)
        let value = if target.base64_decode {
            use base64::Engine;
            match base64::engine::general_purpose::STANDARD.decode(raw_value.trim()) {
                Ok(decoded) => String::from_utf8(decoded)
                    .unwrap_or_else(|_| raw_value.clone()),
                Err(_) => raw_value.clone(), // fallback: write as-is
            }
        } else {
            raw_value.clone()
        };

        if write_secret_file(
            Path::new(target.dir),
            Path::new(target.path),
            &value,
            target.dir_mode,
            target.file_mode,
        )? {
            provisioned += 1;
        }
    }

    Ok(provisioned)
}

// ── EC2 tag-based state reporting (test mode only) ─────────────────────

/// Fetch the EC2 instance ID from IMDS (IMDSv2).
///
/// Returns `Err` when not running on EC2 or IMDS is unavailable.
fn get_instance_id() -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("failed to build HTTP client for IMDS")?;

    // IMDSv2 token
    let token = client
        .put("http://169.254.169.254/latest/api/token")
        .header("X-aws-ec2-metadata-token-ttl-seconds", "60")
        .send()
        .context("IMDS token request failed")?
        .error_for_status()
        .context("IMDS token request returned error status")?
        .text()
        .context("failed to read IMDS token body")?;

    let token = token.trim().to_string();
    if token.is_empty() {
        bail!("IMDS token is empty — not running on EC2?");
    }

    let id = client
        .get("http://169.254.169.254/latest/meta-data/instance-id")
        .header("X-aws-ec2-metadata-token", &token)
        .send()
        .context("IMDS instance-id request failed")?
        .error_for_status()
        .context("IMDS instance-id request returned error status")?
        .text()
        .context("failed to read IMDS instance-id body")?;

    let id = id.trim().to_string();
    if id.is_empty() {
        bail!("IMDS instance-id is empty");
    }
    Ok(id)
}

/// Fetch the EC2 instance region from IMDS (IMDSv2).
///
/// Returns `Err` when not running on EC2 or IMDS is unavailable.
fn get_instance_region() -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("failed to build HTTP client for IMDS")?;

    let token = client
        .put("http://169.254.169.254/latest/api/token")
        .header("X-aws-ec2-metadata-token-ttl-seconds", "60")
        .send()
        .context("IMDS token request failed")?
        .error_for_status()
        .context("IMDS token request returned error status")?
        .text()
        .context("failed to read IMDS token body")?;

    let token = token.trim().to_string();
    if token.is_empty() {
        bail!("IMDS token is empty — not running on EC2?");
    }

    let region = client
        .get("http://169.254.169.254/latest/meta-data/placement/region")
        .header("X-aws-ec2-metadata-token", &token)
        .send()
        .context("IMDS region request failed")?
        .error_for_status()
        .context("IMDS region request returned error status")?
        .text()
        .context("failed to read IMDS region body")?;

    let region = region.trim().to_string();
    if region.is_empty() {
        bail!("IMDS region is empty");
    }
    Ok(region)
}

/// Tag the current EC2 instance with a key-value pair (non-fatal).
///
/// Requires the `aws` CLI in PATH and an IAM instance profile with
/// `ec2:CreateTags` permission. If either is missing, the call fails
/// silently — this is by design for production instances that may not
/// have the tag permission.
fn tag_instance(key: &str, value: &str) {
    let instance_id = match get_instance_id() {
        Ok(id) => id,
        Err(_) => return, // Not on EC2 or IMDS unavailable
    };

    let region = get_instance_region().unwrap_or_else(|_| "us-east-1".to_string());

    let _ = std::process::Command::new("aws")
        .args([
            "ec2",
            "create-tags",
            "--region",
            &region,
            "--resources",
            &instance_id,
            "--tags",
            &format!("Key={key},Value={value}"),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Tag the current EC2 instance with the bootstrap phase (non-fatal).
///
/// Only called when `skip_nix_rebuild=true` (test mode). Allows the cluster
/// test orchestrator to watch EC2 tags instead of SSH polling.
fn tag_instance_phase(phase: &str) {
    tag_instance("BootstrapPhase", phase);
}

/// Print the current bootstrap status.
pub fn status() -> Result<()> {
    let state = BootstrapState::load_or_default("");

    println!("{} Server Bootstrap Status", ">>".blue().bold());
    println!("  Phase:   {}", state.phase);
    println!("  Cluster: {}", state.cluster_name);
    println!("  Config:  {}", state.config_path);
    println!("  Updated: {}", state.updated_at);

    if let Some(ref err) = state.error {
        println!("  Error:   {}", err.red());
    }

    // If bootstrap is complete, also show live health
    if state.phase == BootstrapPhase::Complete {
        println!();
        println!("{} Live Health", ">>".blue().bold());

        match health::check_k3s_health() {
            Ok(s) => println!("  K3s:    {}", s.message),
            Err(e) => println!("  K3s:    error: {}", e),
        }

        match health::check_fluxcd_health() {
            Ok(s) => println!("  FluxCD: {}", s.message),
            Err(e) => println!("  FluxCD: error: {}", e),
        }

        match health::check_wireguard_health() {
            Ok(s) => println!("  WireGuard: {}", s.message),
            Err(e) => println!("  WireGuard: error: {}", e),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_phase_display() {
        assert_eq!(BootstrapPhase::Pending.to_string(), "pending");
        assert_eq!(BootstrapPhase::ConfigLoaded.to_string(), "config_loaded");
        assert_eq!(
            BootstrapPhase::SecretsProvisioned.to_string(),
            "secrets_provisioned"
        );
        assert_eq!(
            BootstrapPhase::WireguardFastStart.to_string(),
            "wireguard_fast_start"
        );
        assert_eq!(BootstrapPhase::WireguardWaiting.to_string(), "wireguard_waiting");
        assert_eq!(BootstrapPhase::WireguardReady.to_string(), "wireguard_ready");
        assert_eq!(BootstrapPhase::Complete.to_string(), "complete");
        assert_eq!(BootstrapPhase::Failed.to_string(), "failed");
    }

    #[test]
    fn bootstrap_state_serialization() {
        let state = BootstrapState {
            phase: BootstrapPhase::K3sReady,
            config_path: "/etc/pangea/cluster-config.json".to_string(),
            cluster_name: "test-cluster".to_string(),
            error: None,
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&state).unwrap();
        let deserialized: BootstrapState = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.phase, BootstrapPhase::K3sReady);
        assert_eq!(deserialized.cluster_name, "test-cluster");
    }

    #[test]
    fn provision_writes_secrets_with_correct_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let secret_dir = dir.path().join("sops-nix");
        let secret_path = secret_dir.join("key.txt");

        let wrote = write_secret_file(
            &secret_dir,
            &secret_path,
            "AGE-SECRET-KEY-TEST",
            0o700,
            0o600,
        )
        .unwrap();

        assert!(wrote);
        assert_eq!(
            std::fs::read_to_string(&secret_path).unwrap(),
            "AGE-SECRET-KEY-TEST"
        );

        #[cfg(unix)]
        {
            let file_mode = std::fs::metadata(&secret_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(file_mode, 0o600);
            let dir_mode = std::fs::metadata(&secret_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
        }
    }

    #[test]
    fn provision_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let secret_dir = dir.path().join("secrets");
        let secret_path = secret_dir.join("token");

        // First write
        let wrote = write_secret_file(&secret_dir, &secret_path, "value1", 0o700, 0o400).unwrap();
        assert!(wrote);

        // Second write should skip (file exists with content)
        let wrote = write_secret_file(&secret_dir, &secret_path, "value2", 0o700, 0o400).unwrap();
        assert!(!wrote);

        // Content should be the original value
        assert_eq!(std::fs::read_to_string(&secret_path).unwrap(), "value1");
    }

    #[test]
    fn provision_skips_when_no_secrets() {
        let config = ClusterConfig::from_json(r#"{"cluster_name":"test"}"#).unwrap();
        let result = provision_bootstrap_secrets(&config).unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn provision_skips_empty_values() {
        let config = ClusterConfig::from_json(
            r#"{"cluster_name":"test","bootstrap_secrets":{"sops_age_key":"","flux_github_token":""}}"#,
        )
        .unwrap();
        let result = provision_bootstrap_secrets(&config).unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn k3s_config_cluster_init() {
        let config = ClusterConfig::from_json(
            r#"{"cluster_name":"test","cluster_init":true,"skip_nix_rebuild":true,"bootstrap_secrets":{"k3s_server_token":"test-token"}}"#,
        )
        .unwrap();
        let yaml = generate_k3s_config_yaml(&config).unwrap();
        assert!(yaml.contains("cluster-init: true"));
        assert!(yaml.contains("token: \"test-token\""));
        assert!(yaml.contains("disable-network-policy: true"));
        assert!(!yaml.contains("server:"));
    }

    #[test]
    fn k3s_config_join_server() {
        let config = ClusterConfig::from_json(
            r#"{"cluster_name":"test","join_server":"https://1.2.3.4:6443","skip_nix_rebuild":true,"bootstrap_secrets":{"k3s_server_token":"join-token"}}"#,
        )
        .unwrap();
        let yaml = generate_k3s_config_yaml(&config).unwrap();
        assert!(yaml.contains("server: \"https://1.2.3.4:6443\""));
        assert!(!yaml.contains("cluster-init"));
        assert!(yaml.contains("token: \"join-token\""));
    }

    #[test]
    fn k3s_config_vpn_tls_san() {
        let config = ClusterConfig::from_json(
            r#"{"cluster_name":"test","cluster_init":true,"skip_nix_rebuild":true,"vpn":{"require_liveness":false,"links":[{"name":"wg-test","address":"10.99.0.1/24","private_key_file":"/tmp/key","peers":[],"firewall":{"trust_interface":false,"allowed_tcp_ports":[],"allowed_udp_ports":[]}}]}}"#,
        )
        .unwrap();
        let yaml = generate_k3s_config_yaml(&config).unwrap();
        assert!(yaml.contains("tls-san:"));
        assert!(yaml.contains("10.99.0.1"));
    }

    #[test]
    fn k3s_config_no_token_when_empty() {
        let config =
            ClusterConfig::from_json(r#"{"cluster_name":"test","cluster_init":true,"skip_nix_rebuild":true}"#)
                .unwrap();
        let yaml = generate_k3s_config_yaml(&config).unwrap();
        assert!(!yaml.contains("token:"));
    }

    // ── EC2 tag reporting tests ────────────────────────────────────

    #[test]
    fn get_instance_id_fails_gracefully_off_ec2() {
        // Not on EC2 — IMDS is unreachable, should return Err (not panic)
        let result = get_instance_id();
        assert!(result.is_err());
    }

    #[test]
    fn get_instance_region_fails_gracefully_off_ec2() {
        let result = get_instance_region();
        assert!(result.is_err());
    }

    #[test]
    fn tag_instance_phase_is_nonfatal_off_ec2() {
        // Should not panic when IMDS is unavailable
        tag_instance_phase("test_phase");
    }

    #[test]
    fn tag_instance_is_nonfatal_off_ec2() {
        // Should not panic when IMDS is unavailable
        tag_instance("TestKey", "test_value");
    }
}
