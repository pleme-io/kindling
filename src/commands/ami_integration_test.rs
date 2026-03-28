//! CLI handler for `kindling ami-integration-test` — validates full boot orchestration.
//!
//! Called by Packer on a test instance that booted from a freshly built AMI with
//! test userdata. Waits for kindling-init to complete, then validates that VPN,
//! K3s, and kubectl all work. Exit 1 fails the Packer test → AMI is deregistered.

use anyhow::{bail, Context, Result};
use clap::Args;
use serde::Serialize;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Args)]
pub struct AmiIntegrationTestArgs {
    /// Total timeout in seconds for the entire integration test
    #[arg(long, default_value_t = 600)]
    pub timeout: u64,
}

#[derive(Serialize)]
struct CheckResult {
    name: String,
    passed: bool,
    message: String,
    duration_ms: u64,
}

pub fn run(args: AmiIntegrationTestArgs) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(args.timeout);

    println!("=== AMI Integration Test ===");
    println!("Timeout: {}s", args.timeout);

    // Pre-check: show userdata status for debugging
    let ud_path = std::path::Path::new("/etc/ec2-metadata/user-data");
    if ud_path.exists() {
        let ud_size = std::fs::metadata(ud_path).map(|m| m.len()).unwrap_or(0);
        println!("Userdata: {} ({} bytes)", ud_path.display(), ud_size);
        if ud_size < 2048 {
            if let Ok(content) = std::fs::read_to_string(ud_path) {
                println!("Userdata content (first 500 chars): {}", &content[..content.len().min(500)]);
            }
        }
    } else {
        println!("WARNING: {} does not exist — kindling-init will skip", ud_path.display());
    }

    // Phase 1: Wait for kindling-init.service to complete
    println!();
    println!("[phase:1/3] Waiting for kindling-init.service to complete...");
    wait_for_kindling_init(deadline)?;

    // Phase 2: Validate bootstrap state
    println!();
    println!("[phase:2/3] Validating bootstrap state...");
    let state_result = check_bootstrap_state();
    print_check(&state_result);
    if !state_result.passed {
        // Dump journal for debugging before failing
        dump_kindling_journal();
        bail!("Bootstrap state check failed: {}", state_result.message);
    }

    // Phase 3: Validate orchestration results
    println!();
    println!("[phase:3/3] Validating orchestration...");
    let mut results = vec![
        state_result,
        check_wireguard_interface(),
        check_wireguard_address(),
    ];

    // Wait for K3s with remaining time
    let k3s_timeout = remaining_secs(deadline, 30);
    results.push(wait_and_check_k3s(k3s_timeout));
    results.push(check_kubectl_namespaces());

    // Print results
    println!();
    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();

    for r in &results {
        print_check(r);
    }

    println!();
    if passed == total {
        println!("{}/{} integration checks passed — AMI orchestration verified", passed, total);
        Ok(())
    } else {
        dump_kindling_journal();
        bail!("{}/{} integration checks failed", total - passed, total);
    }
}

fn print_check(r: &CheckResult) {
    let tag = if r.passed { "[PASS]" } else { "[FAIL]" };
    println!("{} {} ({}ms): {}", tag, r.name, r.duration_ms, r.message);
}

fn remaining_secs(deadline: Instant, min: u64) -> u64 {
    let remaining = deadline.saturating_duration_since(Instant::now());
    remaining.as_secs().max(min)
}

/// Wait for kindling-init.service to finish (oneshot, RemainAfterExit=true).
/// The service is "active" while running (oneshot), then stays "active" after exit.
/// We check for the service being active (completed) or failed.
fn wait_for_kindling_init(deadline: Instant) -> Result<()> {
    let poll_interval = Duration::from_secs(5);

    loop {
        if Instant::now() >= deadline {
            bail!("Timed out waiting for kindling-init.service");
        }

        let output = Command::new("systemctl")
            .args(["show", "kindling-init.service", "--property=ActiveState,SubState"])
            .output()
            .context("failed to query kindling-init.service")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let active_state = extract_property(&stdout, "ActiveState");
        let sub_state = extract_property(&stdout, "SubState");

        match (active_state.as_str(), sub_state.as_str()) {
            // oneshot + RemainAfterExit: "active" + "exited" means completed successfully
            ("active", "exited") => {
                println!("  kindling-init.service completed successfully");
                return Ok(());
            }
            // Failed
            ("failed", _) | ("inactive", "failed") => {
                dump_kindling_journal();
                bail!("kindling-init.service failed (SubState={})", sub_state);
            }
            // Still starting or not yet started
            ("activating", _) | ("inactive", "dead") | ("active", "running") => {
                println!(
                    "  Waiting... (ActiveState={}, SubState={}, remaining={}s)",
                    active_state,
                    sub_state,
                    deadline.saturating_duration_since(Instant::now()).as_secs()
                );
                std::thread::sleep(poll_interval);
            }
            _ => {
                println!(
                    "  Unknown state: ActiveState={}, SubState={} — continuing to wait",
                    active_state, sub_state
                );
                std::thread::sleep(poll_interval);
            }
        }
    }
}

fn extract_property(output: &str, key: &str) -> String {
    for line in output.lines() {
        if let Some(value) = line.strip_prefix(&format!("{key}=")) {
            return value.trim().to_string();
        }
    }
    String::new()
}

fn check_bootstrap_state() -> CheckResult {
    let start = Instant::now();
    let state_path = Path::new("/var/lib/kindling/server-state.json");

    let (passed, message) = if !state_path.exists() {
        (false, "server-state.json not found".into())
    } else {
        match std::fs::read_to_string(state_path) {
            Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(state) => {
                    let phase = state["phase"].as_str().unwrap_or("unknown");
                    if phase == "complete" {
                        (true, format!("bootstrap phase: {phase}"))
                    } else {
                        let error = state["error"]
                            .as_str()
                            .unwrap_or("none");
                        (false, format!("bootstrap phase: {phase}, error: {error}"))
                    }
                }
                Err(e) => (false, format!("failed to parse state: {e}")),
            },
            Err(e) => (false, format!("failed to read state: {e}")),
        }
    };

    CheckResult {
        name: "bootstrap-state".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn check_wireguard_interface() -> CheckResult {
    let start = Instant::now();
    let (passed, message) = match Command::new("ip")
        .args(["link", "show", "type", "wireguard"])
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("wg-") || stdout.contains("wg0") {
                (true, "WireGuard interface found".into())
            } else if stdout.trim().is_empty() {
                (false, "no WireGuard interfaces".into())
            } else {
                (true, format!("WireGuard: {}", stdout.lines().next().unwrap_or("")))
            }
        }
        Err(e) => (false, format!("ip link failed: {e}")),
    };

    CheckResult {
        name: "wireguard-interface".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn check_wireguard_address() -> CheckResult {
    let start = Instant::now();
    let (passed, message) = match Command::new("wg").args(["show", "all", "dump"]).output() {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let interfaces: Vec<&str> = stdout
                .lines()
                .filter_map(|l| l.split('\t').next())
                .collect();
            let unique: std::collections::HashSet<&str> = interfaces.into_iter().collect();
            if unique.is_empty() {
                (false, "no WireGuard tunnels configured".into())
            } else {
                (true, format!("{} tunnel(s) configured", unique.len()))
            }
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            (false, format!("wg show failed: {}", stderr.trim()))
        }
        Err(e) => (false, format!("wg command failed: {e}")),
    };

    CheckResult {
        name: "wireguard-config".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn wait_and_check_k3s(timeout_secs: u64) -> CheckResult {
    let start = Instant::now();
    let deadline = start + Duration::from_secs(timeout_secs);
    let poll_interval = Duration::from_secs(10);

    loop {
        match Command::new("kubectl")
            .args(["get", "nodes", "--no-headers"])
            .output()
        {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
                let ready = lines.iter().filter(|l| l.contains("Ready")).count();
                if ready > 0 {
                    return CheckResult {
                        name: "k3s-api".into(),
                        passed: true,
                        message: format!("{} node(s) Ready", ready),
                        duration_ms: start.elapsed().as_millis() as u64,
                    };
                }
            }
            _ => {}
        }

        if Instant::now() >= deadline {
            return CheckResult {
                name: "k3s-api".into(),
                passed: false,
                message: format!("K3s API not ready after {}s", timeout_secs),
                duration_ms: start.elapsed().as_millis() as u64,
            };
        }

        std::thread::sleep(poll_interval);
    }
}

fn check_kubectl_namespaces() -> CheckResult {
    let start = Instant::now();
    let (passed, message) = match Command::new("kubectl")
        .args(["get", "namespaces", "--no-headers"])
        .output()
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let count = stdout.lines().filter(|l| !l.is_empty()).count();
            (true, format!("{count} namespace(s)"))
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            (false, format!("kubectl failed: {}", stderr.trim()))
        }
        Err(e) => (false, format!("kubectl not found: {e}")),
    };

    CheckResult {
        name: "kubectl-namespaces".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn dump_kindling_journal() {
    println!();
    println!("=== kindling-init journal (last 50 lines) ===");
    let _ = Command::new("journalctl")
        .args(["-u", "kindling-init.service", "-n", "50", "--no-pager"])
        .status();
    println!();
    println!("=== k3s journal (last 30 lines) ===");
    let _ = Command::new("journalctl")
        .args(["-u", "k3s.service", "-n", "30", "--no-pager"])
        .status();
    println!("=== end journal ===");
}
