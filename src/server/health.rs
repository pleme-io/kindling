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

/// Count items in a Kubernetes resource list that have a `Ready=True` condition.
fn count_ready_items(resource_list: &serde_json::Value) -> (u32, u32) {
    let items = resource_list["items"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0) as u32;

    let ready = resource_list["items"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter(|item| {
                    item["status"]["conditions"]
                        .as_array()
                        .is_some_and(|conds| {
                            conds.iter().any(|c| {
                                c["type"].as_str() == Some("Ready")
                                    && c["status"].as_str() == Some("True")
                            })
                        })
                })
                .count()
        })
        .unwrap_or(0) as u32;

    (items, ready)
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

    let (total, ready_count) = count_ready_items(&nodes);
    let ready = total > 0 && ready_count == total;
    let message = if ready {
        format!("{}/{} nodes ready", ready_count, total)
    } else {
        format!("{}/{} nodes ready (waiting)", ready_count, total)
    };

    Ok(K3sHealthStatus {
        ready,
        node_count: total,
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

    let (total, ready_count) = count_ready_items(&ks);
    let ready = total > 0 && ready_count == total;
    let message = if ready {
        format!("{}/{} kustomizations ready", ready_count, total)
    } else if total == 0 {
        "no kustomizations found (FluxCD may not be installed)".to_string()
    } else {
        format!(
            "{}/{} kustomizations ready (waiting)",
            ready_count, total
        )
    };

    Ok(FluxcdHealthStatus {
        ready,
        kustomizations_ready: ready_count,
        kustomizations_total: total,
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
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Parse lines into (interface, optional timestamp) tuples.
    // Lines with unparseable timestamps still contribute to the interface set.
    let parsed_lines: Vec<(&str, Option<u64>)> = output
        .lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            let iface = parts.next()?;
            let _peer = parts.next()?;
            let ts_str = parts.next()?;
            Some((iface, ts_str.trim().parse::<u64>().ok()))
        })
        .collect();

    let interfaces = parsed_lines
        .iter()
        .map(|(iface, _)| (*iface).to_string())
        .collect();

    let peers_with_handshake = parsed_lines
        .iter()
        .filter(|(_, ts)| ts.is_some_and(|t| t > 0 && (now - t) < 120))
        .count() as u32;

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

    #[test]
    fn parse_wg_handshakes_empty_output() {
        let (interfaces, peers) = parse_wg_handshakes("");
        assert!(interfaces.is_empty());
        assert_eq!(peers, 0);
    }

    #[test]
    fn parse_wg_handshakes_stale_handshake() {
        let old = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - 300; // 5 minutes ago — beyond 2-minute window
        let output = format!("wg0\tpeerkey1\t{}\n", old);
        let (interfaces, peers) = parse_wg_handshakes(&output);
        assert_eq!(interfaces.len(), 1);
        assert_eq!(peers, 0, "handshake older than 120s should not count");
    }

    #[test]
    fn parse_wg_handshakes_malformed_lines_ignored() {
        let output = "wg0\tpeerkey1\n\nshort\n";
        let (interfaces, peers) = parse_wg_handshakes(output);
        assert!(interfaces.is_empty());
        assert_eq!(peers, 0);
    }

    #[test]
    fn parse_wg_handshakes_invalid_timestamp_ignored() {
        let output = "wg0\tpeerkey1\tnot-a-number\n";
        let (interfaces, peers) = parse_wg_handshakes(output);
        assert_eq!(interfaces.len(), 1);
        assert_eq!(peers, 0);
    }

    #[test]
    fn parse_wg_handshakes_multiple_interfaces() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let output = format!(
            "wg0\tpeerA\t{}\nwg1\tpeerB\t{}\nwg2\tpeerC\t0\n",
            now - 10,
            now - 50,
        );
        let (interfaces, peers) = parse_wg_handshakes(&output);
        assert_eq!(interfaces.len(), 3);
        assert_eq!(peers, 2);
    }

    #[test]
    fn wireguard_health_status_roundtrip() {
        let status = WireguardHealthStatus {
            ready: false,
            interface_count: 0,
            peers_with_handshake: 0,
            message: "no WireGuard interfaces found".to_string(),
        };
        let json = serde_json::to_string(&status).unwrap();
        let deserialized: WireguardHealthStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.ready, false);
        assert_eq!(deserialized.interface_count, 0);
        assert_eq!(deserialized.message, "no WireGuard interfaces found");
    }

    #[test]
    fn k3s_health_status_roundtrip() {
        let status = K3sHealthStatus {
            ready: false,
            node_count: 3,
            ready_nodes: 1,
            message: "1/3 nodes ready (waiting)".to_string(),
        };
        let json = serde_json::to_string(&status).unwrap();
        let deserialized: K3sHealthStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.node_count, 3);
        assert_eq!(deserialized.ready_nodes, 1);
    }
}
