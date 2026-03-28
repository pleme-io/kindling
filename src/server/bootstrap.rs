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
            let _ = std::process::Command::new("systemctl")
                .args(["stop", "k3s.service"])
                .status();
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
    }

    // Phase: NixOS rebuild
    if state.phase == BootstrapPhase::IdentityWritten {
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
            }
            Err(e) => {
                state.fail(&e.to_string())?;
                bail!("nixos-rebuild failed: {}", e);
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
                    }
                }
            }
        } else {
            println!(
                "{} No VPN configured, skipping WireGuard check",
                "::".blue().bold()
            );
            state.transition(BootstrapPhase::WireguardReady)?;
        }
    }

    // Phase: Wait for K3s
    if state.phase == BootstrapPhase::WireguardReady {
        println!("{} Waiting for K3s to become ready", ">>".blue().bold());
        state.transition(BootstrapPhase::K3sWaiting)?;

        match health::wait_for_k3s(Duration::from_secs(300), Duration::from_secs(10)) {
            Ok(status) => {
                println!("{} K3s ready: {}", "ok".green().bold(), status.message);
                state.transition(BootstrapPhase::K3sReady)?;
            }
            Err(e) => {
                state.fail(&e.to_string())?;
                bail!("K3s health check failed: {}", e);
            }
        }
    }

    // Phase: Wait for FluxCD (only if enabled)
    if state.phase == BootstrapPhase::K3sReady {
        let config = ClusterConfig::load(config_path)?;
        if config.fluxcd.is_some() {
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
}
