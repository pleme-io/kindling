//! CLI handler for `kindling ami-test` — validates a NixOS AMI before Packer snapshots it.
//!
//! Runs 9 checks and exits non-zero if any fail. Packer calls this after
//! nixos-rebuild but before cleanup — if it fails, no AMI is created.

use anyhow::Result;
use clap::Args;
use serde::Serialize;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

#[derive(Clone, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Args)]
pub struct AmiTestArgs {
    /// Output format (text or json)
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
}

#[derive(Serialize)]
struct TestResult {
    name: String,
    passed: bool,
    message: String,
    duration_ms: u64,
}

pub fn run(args: AmiTestArgs) -> Result<()> {
    tracing::info!("starting AMI validation checks");

    let results = vec![
        // Binary presence
        check_kindling_binary(),
        check_k3s_binary(),
        check_wireguard_tools(),
        check_nixos_rebuild(),
        // Service configuration
        check_kindling_init_service(),
        check_nix_daemon(),
        check_amazon_init_disabled(),
        // Orchestration invariants (catch boot ordering issues at AMI build time)
        check_k3s_no_stale_state(),
        check_no_stale_tls(),
        check_no_leaked_secrets(),
        // Network
        check_network_connectivity(),
    ];

    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();

    match args.format {
        OutputFormat::Json => {
            let output = serde_json::json!({
                "results": results,
                "total": total,
                "passed": passed,
                "valid": passed == total,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        OutputFormat::Text => {
            for r in &results {
                let tag = if r.passed { "[PASS]" } else { "[FAIL]" };
                println!("{} {}: {}", tag, r.name, r.message);
            }
            println!();
            if passed == total {
                println!("{}/{} checks passed — AMI is valid", passed, total);
            } else {
                println!(
                    "{}/{} checks passed — AMI is NOT valid",
                    passed, total
                );
            }
        }
    }

    if passed < total {
        anyhow::bail!("{}/{} checks failed", total - passed, total);
    }

    Ok(())
}

/// Run a command and capture its stdout (trimmed).
fn run_cmd(program: &str, args: &[&str]) -> std::result::Result<String, String> {
    match Command::new(program).args(args).output() {
        Ok(output) => {
            if output.status.success() {
                Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                Err(format!(
                    "exit code {}: {}",
                    output.status.code().unwrap_or(-1),
                    stderr
                ))
            }
        }
        Err(e) => Err(format!("failed to execute: {}", e)),
    }
}

fn check_kindling_binary() -> TestResult {
    let start = Instant::now();
    let (passed, message) = match run_cmd("kindling", &["--version"]) {
        Ok(out) => (true, out),
        Err(e) => (false, e),
    };
    TestResult {
        name: "kindling-binary".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn check_kindling_init_service() -> TestResult {
    let start = Instant::now();
    let (passed, message) = match run_cmd("systemctl", &["is-enabled", "kindling-init.service"]) {
        Ok(out) => {
            let trimmed = out.trim().to_string();
            if trimmed == "enabled" {
                (true, "enabled".into())
            } else {
                (false, format!("expected 'enabled', got '{}'", trimmed))
            }
        }
        Err(e) => (false, e),
    };
    TestResult {
        name: "kindling-init-service".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn check_k3s_binary() -> TestResult {
    let start = Instant::now();
    let (passed, message) = match run_cmd("k3s", &["--version"]) {
        Ok(out) => {
            // k3s --version outputs something like "k3s version v1.34.5+k3s1 (...)"
            // Take just the first line
            let first_line = out.lines().next().unwrap_or(&out).to_string();
            (true, first_line)
        }
        Err(e) => (false, e),
    };
    TestResult {
        name: "k3s-binary".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn check_wireguard_tools() -> TestResult {
    let start = Instant::now();
    let (passed, message) = match run_cmd("wg", &["--version"]) {
        Ok(out) => (true, out),
        Err(e) => (false, e),
    };
    TestResult {
        name: "wireguard-tools".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn check_nix_daemon() -> TestResult {
    let start = Instant::now();
    // Check is-enabled (will start on boot) rather than is-active
    // (may be stopped after ami-build cleanup)
    let (passed, message) = match run_cmd("systemctl", &["is-enabled", "nix-daemon.service"]) {
        Ok(out) => {
            let trimmed = out.trim().to_string();
            if trimmed == "enabled" {
                (true, "enabled".into())
            } else {
                (false, format!("expected 'enabled', got '{trimmed}'"))
            }
        }
        Err(e) => (false, e),
    };
    TestResult {
        name: "nix-daemon".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn check_nixos_rebuild() -> TestResult {
    let start = Instant::now();
    let (passed, message) = match run_cmd("nixos-rebuild", &["--help"]) {
        Ok(out) => (true, out),
        Err(e) => (false, e),
    };
    TestResult {
        name: "nixos-rebuild".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn check_network_connectivity() -> TestResult {
    let start = Instant::now();
    let (passed, message) = match run_cmd(
        "curl",
        &[
            "-sf",
            "--connect-timeout",
            "5",
            "https://cache.nixos.org/nix-cache-info",
        ],
    ) {
        Ok(_) => (true, "cache.nixos.org reachable".into()),
        Err(e) => (false, format!("cache.nixos.org unreachable: {}", e)),
    };
    TestResult {
        name: "network-connectivity".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn check_no_leaked_secrets() -> TestResult {
    let start = Instant::now();

    let forbidden_files = [
        "/etc/pangea/cluster-config.json",
        "/var/lib/kindling/server-state.json",
    ];

    let mut leaked: Vec<String> = Vec::new();

    for path in &forbidden_files {
        if Path::new(path).exists() {
            leaked.push((*path).to_string());
        }
    }

    // /run/secrets.d/ — if it exists, it must be empty
    let secrets_dir = Path::new("/run/secrets.d");
    if secrets_dir.is_dir() {
        match std::fs::read_dir(secrets_dir) {
            Ok(entries) => {
                let count = entries.count();
                if count > 0 {
                    leaked.push(format!("/run/secrets.d/ ({} entries)", count));
                }
            }
            Err(e) => {
                leaked.push(format!("/run/secrets.d/ (unreadable: {})", e));
            }
        }
    }

    let (passed, message) = if leaked.is_empty() {
        (true, "clean AMI".into())
    } else {
        (false, format!("leaked: {}", leaked.join(", ")))
    };

    TestResult {
        name: "no-leaked-secrets".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

/// Verify no stale K3s server state exists in the AMI.
/// If K3s state exists in the AMI, kindling can't seed deterministic PKI.
fn check_k3s_no_stale_state() -> TestResult {
    let start = Instant::now();
    let server_dir = Path::new("/var/lib/rancher/k3s/server");

    let (passed, message) = if !server_dir.exists() {
        (true, "no stale K3s server state".into())
    } else {
        // Check for datastore (kine.db or other state)
        let has_db = server_dir.join("db").exists()
            || server_dir.join("kine.db").exists()
            || server_dir.join("kine.sock").exists();
        if has_db {
            (false, "K3s datastore exists — AMI has stale cluster state".into())
        } else {
            (true, "K3s server dir exists but no datastore (clean)".into())
        }
    };
    TestResult {
        name: "k3s-no-stale-state".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

/// Verify no stale TLS certificates exist in the AMI.
/// Stale certs would cause K3s to use the wrong CA.
fn check_no_stale_tls() -> TestResult {
    let start = Instant::now();
    let tls_dir = Path::new("/var/lib/rancher/k3s/server/tls");

    let (passed, message) = if !tls_dir.exists() {
        (true, "no stale TLS certs".into())
    } else {
        match std::fs::read_dir(tls_dir) {
            Ok(entries) => {
                let count = entries.count();
                if count > 0 {
                    (false, format!("stale TLS dir has {count} files — K3s will ignore seeded PKI"))
                } else {
                    (true, "TLS dir exists but empty".into())
                }
            }
            Err(e) => (false, format!("can't read TLS dir: {e}")),
        }
    };
    TestResult {
        name: "no-stale-tls".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn check_amazon_init_disabled() -> TestResult {
    let start = Instant::now();
    let (passed, message) = match run_cmd("systemctl", &["is-enabled", "amazon-init.service"]) {
        Ok(out) => {
            let trimmed = out.trim().to_string();
            if trimmed == "enabled" {
                (false, "amazon-init.service is enabled — kindling-init should replace it".into())
            } else {
                // "disabled", "masked", "not-found", etc. are all acceptable
                (true, format!("not enabled ({})", trimmed))
            }
        }
        // is-enabled exits non-zero for disabled/not-found services — that is the expected state
        Err(_) => (true, "not enabled".into()),
    };
    TestResult {
        name: "amazon-init-disabled".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}
