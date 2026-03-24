//! K3s API + FluxCD health polling.
//!
//! Provides async functions that shell out to `kubectl` to check node readiness
//! and FluxCD reconciliation status. Used by the bootstrap orchestrator to
//! determine when the cluster is ready.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::time::Duration;

/// Result of a K3s health check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K3sHealthStatus {
    pub ready: bool,
    pub node_count: u32,
    pub ready_nodes: u32,
    pub message: String,
}

/// Result of a FluxCD health check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FluxcdHealthStatus {
    pub ready: bool,
    pub kustomizations_ready: u32,
    pub kustomizations_total: u32,
    pub message: String,
}

/// Check if K3s API server is reachable and nodes are ready.
pub fn check_k3s_health() -> Result<K3sHealthStatus> {
    let output = Command::new("kubectl")
        .args(["get", "nodes", "-o", "json"])
        .output()
        .context("failed to run kubectl get nodes")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Ok(K3sHealthStatus {
            ready: false,
            node_count: 0,
            ready_nodes: 0,
            message: format!("kubectl failed: {}", stderr.trim()),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let nodes: serde_json::Value =
        serde_json::from_str(&stdout).context("failed to parse kubectl output")?;

    let items = nodes["items"].as_array().map(|a| a.len()).unwrap_or(0) as u32;

    let ready_count = nodes["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|node| {
                    node["status"]["conditions"]
                        .as_array()
                        .map(|conds| {
                            conds.iter().any(|c| {
                                c["type"].as_str() == Some("Ready")
                                    && c["status"].as_str() == Some("True")
                            })
                        })
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0) as u32;

    let ready = items > 0 && ready_count == items;
    let message = if ready {
        format!("{}/{} nodes ready", ready_count, items)
    } else {
        format!("{}/{} nodes ready (waiting)", ready_count, items)
    };

    Ok(K3sHealthStatus {
        ready,
        node_count: items,
        ready_nodes: ready_count,
        message,
    })
}

/// Check if FluxCD kustomizations have reconciled successfully.
pub fn check_fluxcd_health() -> Result<FluxcdHealthStatus> {
    let output = Command::new("kubectl")
        .args([
            "get",
            "kustomizations.kustomize.toolkit.fluxcd.io",
            "-A",
            "-o",
            "json",
        ])
        .output()
        .context("failed to run kubectl get kustomizations")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Ok(FluxcdHealthStatus {
            ready: false,
            kustomizations_ready: 0,
            kustomizations_total: 0,
            message: format!("kubectl failed: {}", stderr.trim()),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let ks: serde_json::Value =
        serde_json::from_str(&stdout).context("failed to parse kubectl output")?;

    let items = ks["items"].as_array().map(|a| a.len()).unwrap_or(0) as u32;

    let ready_count = ks["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|ks_item| {
                    ks_item["status"]["conditions"]
                        .as_array()
                        .map(|conds| {
                            conds.iter().any(|c| {
                                c["type"].as_str() == Some("Ready")
                                    && c["status"].as_str() == Some("True")
                            })
                        })
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0) as u32;

    let ready = items > 0 && ready_count == items;
    let message = if ready {
        format!("{}/{} kustomizations ready", ready_count, items)
    } else if items == 0 {
        "no kustomizations found (FluxCD may not be installed)".to_string()
    } else {
        format!(
            "{}/{} kustomizations ready (waiting)",
            ready_count, items
        )
    };

    Ok(FluxcdHealthStatus {
        ready,
        kustomizations_ready: ready_count,
        kustomizations_total: items,
        message,
    })
}

/// Poll K3s health until all nodes are ready or timeout expires.
pub fn wait_for_k3s(timeout: Duration, poll_interval: Duration) -> Result<K3sHealthStatus> {
    let start = std::time::Instant::now();

    loop {
        let status = check_k3s_health()?;
        if status.ready {
            return Ok(status);
        }

        if start.elapsed() >= timeout {
            bail!(
                "timed out waiting for K3s after {:?}: {}",
                timeout,
                status.message
            );
        }

        std::thread::sleep(poll_interval);
    }
}

/// Poll FluxCD health until all kustomizations reconcile or timeout expires.
pub fn wait_for_fluxcd(timeout: Duration, poll_interval: Duration) -> Result<FluxcdHealthStatus> {
    let start = std::time::Instant::now();

    loop {
        let status = check_fluxcd_health()?;
        if status.ready {
            return Ok(status);
        }

        if start.elapsed() >= timeout {
            bail!(
                "timed out waiting for FluxCD after {:?}: {}",
                timeout,
                status.message
            );
        }

        std::thread::sleep(poll_interval);
    }
}

/// Result of a WireGuard health check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireguardHealthStatus {
    pub ready: bool,
    pub interface_count: u32,
    pub peers_with_handshake: u32,
    pub message: String,
}

/// Check if WireGuard interfaces are up and peers have completed handshakes.
pub fn check_wireguard_health() -> Result<WireguardHealthStatus> {
    let output = Command::new("wg")
        .args(["show", "all", "latest-handshakes"])
        .output()
        .context("failed to run wg show")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Ok(WireguardHealthStatus {
            ready: false,
            interface_count: 0,
            peers_with_handshake: 0,
            message: format!("wg show failed: {}", stderr.trim()),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let (interfaces, peers_with_handshake) = parse_wg_handshakes(&stdout);

    let ready = !interfaces.is_empty() && peers_with_handshake > 0;
    let message = if ready {
        format!(
            "{} interface(s), {} peer(s) with recent handshake",
            interfaces.len(),
            peers_with_handshake
        )
    } else if interfaces.is_empty() {
        "no WireGuard interfaces found".to_string()
    } else {
        format!(
            "{} interface(s) up but no peers have completed handshake",
            interfaces.len()
        )
    };

    Ok(WireguardHealthStatus {
        ready,
        interface_count: interfaces.len() as u32,
        peers_with_handshake,
        message,
    })
}

/// Parse `wg show all latest-handshakes` output.
/// Format: `<interface>\t<peer-public-key>\t<unix-timestamp>`
/// Timestamp of 0 means no handshake has occurred.
fn parse_wg_handshakes(output: &str) -> (std::collections::HashSet<String>, u32) {
    let mut interfaces = std::collections::HashSet::new();
    let mut peers_with_handshake: u32 = 0;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for line in output.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 3 {
            interfaces.insert(parts[0].to_string());
            if let Ok(timestamp) = parts[2].trim().parse::<u64>() {
                // Handshake within last 2 minutes is considered recent
                if timestamp > 0 && (now - timestamp) < 120 {
                    peers_with_handshake += 1;
                }
            }
        }
    }

    (interfaces, peers_with_handshake)
}

/// Poll WireGuard health until interfaces are up and peers have handshakes.
pub fn wait_for_wireguard(timeout: Duration, poll_interval: Duration) -> Result<WireguardHealthStatus> {
    let start = std::time::Instant::now();

    loop {
        let status = check_wireguard_health()?;
        if status.ready {
            return Ok(status);
        }

        if start.elapsed() >= timeout {
            bail!(
                "timed out waiting for WireGuard after {:?}: {}",
                timeout,
                status.message
            );
        }

        std::thread::sleep(poll_interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn k3s_health_status_serializes() {
        let status = K3sHealthStatus {
            ready: true,
            node_count: 3,
            ready_nodes: 3,
            message: "3/3 nodes ready".to_string(),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"ready\":true"));
    }

    #[test]
    fn fluxcd_health_status_serializes() {
        let status = FluxcdHealthStatus {
            ready: false,
            kustomizations_ready: 1,
            kustomizations_total: 3,
            message: "1/3 kustomizations ready (waiting)".to_string(),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"ready\":false"));
    }

    #[test]
    fn wireguard_health_status_serializes() {
        let status = WireguardHealthStatus {
            ready: true,
            interface_count: 1,
            peers_with_handshake: 2,
            message: "1 interface(s), 2 peer(s) with recent handshake".to_string(),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"ready\":true"));
    }

    #[test]
    fn parse_wg_handshakes_valid_output() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let output = format!(
            "wg0\tpeerkey1\t{}\nwg0\tpeerkey2\t{}\nwg1\tpeerkey3\t0\n",
            now - 30,  // 30 seconds ago
            now - 60,  // 60 seconds ago
        );
        let (interfaces, peers) = parse_wg_handshakes(&output);
        assert_eq!(interfaces.len(), 2);
        assert_eq!(peers, 2);
    }

    #[test]
    fn parse_wg_handshakes_no_handshake() {
        let output = "wg0\tpeerkey1\t0\n";
        let (interfaces, peers) = parse_wg_handshakes(output);
        assert_eq!(interfaces.len(), 1);
        assert_eq!(peers, 0);
    }
}
