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

use super::cluster_config::ClusterConfig;
use super::health;
use crate::commands::apply;
use crate::node_identity::NodeIdentity;

/// Phases of the server bootstrap process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapPhase {
    Pending,
    ConfigLoaded,
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
        match config.validate_vpn_security_full() {
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

    // Phase: Write node identity
    if state.phase == BootstrapPhase::ConfigLoaded {
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
}
