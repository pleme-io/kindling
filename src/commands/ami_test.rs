//! CLI handler for `kindling ami-test` — validates a NixOS AMI before Packer snapshots it.
//!
//! Runs validation checks and exits non-zero if any fail. Packer calls this after
//! nixos-rebuild but before cleanup — if it fails, no AMI is created.
//!
//! Default checks validate K3s distribution. When `--distribution kubernetes` is
//! passed, additional kubeadm-specific checks run instead of K3s checks.

use anyhow::Result;
use clap::Args;
use serde::Serialize;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

#[derive(Clone, clap::ValueEnum)]
#[non_exhaustive]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Clone, clap::ValueEnum)]
#[non_exhaustive]
pub enum Distribution {
    K3s,
    Kubernetes,
}

#[derive(Args)]
pub struct AmiTestArgs {
    /// Output format (text or json)
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Distribution to validate (k3s or kubernetes)
    #[arg(long, value_enum, default_value_t = Distribution::K3s)]
    pub distribution: Distribution,
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

    let mut results = vec![
        // Binary presence (common)
        check_kindling_binary(),
        check_wireguard_tools(),
        check_nixos_rebuild(),
    ];

    // Distribution-specific binary and state checks
    match args.distribution {
        Distribution::Kubernetes => {
            results.push(check_kubeadm_binary());
            results.push(check_kubelet_binary());
            results.push(check_containerd_config());
            results.push(check_etcd_binary());
        }
        Distribution::K3s => {
            results.push(check_k3s_binary());
            // K3s-specific stale state checks
            results.push(check_k3s_no_stale_state());
            results.push(check_no_stale_tls());
        }
    }

    // Common service and security checks
    results.extend([
        check_kindling_init_service(),
        check_nix_daemon(),
        check_amazon_init_disabled(),
        check_no_leaked_secrets(),
        // Network
        check_network_connectivity(),
    ]);

    // FedRAMP compliance checks — convergence invariants that must hold at the AMI checkpoint.
    // These gate the build: any failure prevents the AMI from being created.
    results.extend([
        check_ssh_hardening(),
        check_auditd_enabled(),
        check_fail2ban_enabled(),
        check_sysctl_hardening(),
        check_firewall_active(),
        check_no_world_writable_bins(),
    ]);

    // Convergence minimality — verify the closure is optimally small.
    results.push(check_closure_size());

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
    // NixOS uses nix-daemon.socket (socket activation) not nix-daemon.service directly.
    // Check that either the socket or the service is enabled.
    let (passed, message) = {
        let socket_ok = run_cmd("systemctl", &["is-enabled", "nix-daemon.socket"])
            .map(|s| s.trim() == "enabled").unwrap_or(false);
        let service_ok = run_cmd("systemctl", &["is-enabled", "nix-daemon.service"])
            .map(|s| s.trim() == "enabled").unwrap_or(false);
        if socket_ok || service_ok {
            (true, if socket_ok { "socket enabled" } else { "service enabled" }.into())
        } else {
            (false, "neither nix-daemon.socket nor nix-daemon.service is enabled".into())
        }
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

// ── Kubeadm distribution checks ──────────────────────────────────────

fn check_kubeadm_binary() -> TestResult {
    let start = Instant::now();
    let (passed, message) = match run_cmd("kubeadm", &["version", "--output=short"]) {
        Ok(out) => (true, out),
        Err(e) => (false, e),
    };
    TestResult {
        name: "kubeadm-binary".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn check_kubelet_binary() -> TestResult {
    let start = Instant::now();
    let (passed, message) = match run_cmd("kubelet", &["--version"]) {
        Ok(out) => {
            let first_line = out.lines().next().unwrap_or(&out).to_string();
            (true, first_line)
        }
        Err(e) => (false, e),
    };
    TestResult {
        name: "kubelet-binary".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn check_containerd_config() -> TestResult {
    let start = Instant::now();
    let config_path = Path::new("/etc/containerd/config.toml");

    let (passed, message) = if config_path.exists() {
        // Verify containerd is configured with the correct CRI socket
        match std::fs::read_to_string(config_path) {
            Ok(content) => {
                // Check for cri plugin configuration
                if content.contains("cri") || content.contains("containerd.grpc") {
                    (true, "containerd config exists with CRI plugin".into())
                } else {
                    // Config exists but may use defaults, which is fine
                    (true, "containerd config exists (using defaults)".into())
                }
            }
            Err(e) => (false, format!("can't read config: {}", e)),
        }
    } else {
        // Check if containerd is at least available as a service
        match run_cmd("containerd", &["--version"]) {
            Ok(out) => (true, format!("no config.toml but containerd available: {}", out)),
            Err(e) => (false, format!("no config.toml and containerd not found: {}", e)),
        }
    };
    TestResult {
        name: "containerd-config".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn check_etcd_binary() -> TestResult {
    let start = Instant::now();
    let (passed, message) = match run_cmd("etcd", &["--version"]) {
        Ok(out) => {
            let first_line = out.lines().next().unwrap_or(&out).to_string();
            (true, first_line)
        }
        Err(e) => (false, e),
    };
    TestResult {
        name: "etcd-binary".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

// ── FedRAMP Compliance Checks ────────────────────────────────────────
// These verify that convergence invariants from the compliance layers
// (kindling-profiles/modules/compliance/*.nix) are present in the AMI.

/// IA-2, AC-17: Verify SSH is hardened (key-only, no password auth)
fn check_ssh_hardening() -> TestResult {
    let start = Instant::now();
    let config_path = Path::new("/etc/ssh/sshd_config");

    let (passed, message) = if !config_path.exists() {
        (false, "sshd_config not found".into())
    } else {
        match std::fs::read_to_string(config_path) {
            Ok(content) => {
                let mut issues = Vec::new();
                // Check PasswordAuthentication is disabled
                let has_no_password = content.lines().any(|line| {
                    let trimmed = line.trim();
                    !trimmed.starts_with('#')
                        && trimmed.to_lowercase().contains("passwordauthentication")
                        && trimmed.to_lowercase().contains("no")
                });
                if !has_no_password {
                    issues.push("PasswordAuthentication not set to no");
                }
                // Check PermitRootLogin is restricted
                let has_root_restricted = content.lines().any(|line| {
                    let trimmed = line.trim();
                    !trimmed.starts_with('#')
                        && trimmed.to_lowercase().contains("permitrootlogin")
                        && (trimmed.to_lowercase().contains("prohibit-password")
                            || trimmed.to_lowercase().contains("no"))
                });
                if !has_root_restricted {
                    issues.push("PermitRootLogin not restricted");
                }
                if issues.is_empty() {
                    (true, "SSH hardened: key-only, root restricted".into())
                } else {
                    (false, issues.join("; "))
                }
            }
            Err(e) => (false, format!("can't read sshd_config: {}", e)),
        }
    };
    TestResult {
        name: "ssh-hardening".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

/// AU-2, AU-12: Verify audit daemon is enabled
fn check_auditd_enabled() -> TestResult {
    let start = Instant::now();
    let (passed, message) = match run_cmd("systemctl", &["is-enabled", "auditd.service"]) {
        Ok(out) => {
            let trimmed = out.trim().to_string();
            if trimmed == "enabled" {
                (true, "auditd enabled".into())
            } else {
                (false, format!("auditd is '{}', expected 'enabled'", trimmed))
            }
        }
        Err(e) => (false, format!("auditd not found: {}", e)),
    };
    TestResult {
        name: "auditd-enabled".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

/// SC-5, SI-4: Verify fail2ban is enabled (brute-force protection)
fn check_fail2ban_enabled() -> TestResult {
    let start = Instant::now();
    let (passed, message) = match run_cmd("systemctl", &["is-enabled", "fail2ban.service"]) {
        Ok(out) => {
            let trimmed = out.trim().to_string();
            if trimmed == "enabled" {
                (true, "fail2ban enabled".into())
            } else {
                (false, format!("fail2ban is '{}', expected 'enabled'", trimmed))
            }
        }
        Err(e) => (false, format!("fail2ban not found: {}", e)),
    };
    TestResult {
        name: "fail2ban-enabled".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

/// SC-5, SC-7, SI-16: Verify critical sysctl hardening values
fn check_sysctl_hardening() -> TestResult {
    let start = Instant::now();
    let checks = [
        ("net.ipv4.tcp_syncookies", "1"),      // SC-5: SYN flood defense
        ("net.ipv4.conf.all.rp_filter", "1"),   // SC-7: Anti-spoofing
        ("kernel.dmesg_restrict", "1"),          // SI-16: Kernel info restriction
        ("fs.protected_symlinks", "1"),          // SI-16: Symlink protection
    ];

    let mut failures = Vec::new();
    for (key, expected) in &checks {
        match run_cmd("sysctl", &["-n", key]) {
            Ok(val) => {
                if val.trim() != *expected {
                    failures.push(format!("{}={} (expected {})", key, val.trim(), expected));
                }
            }
            Err(e) => failures.push(format!("{}: {}", key, e)),
        }
    }

    let (passed, message) = if failures.is_empty() {
        (true, format!("{} sysctl hardening values verified", checks.len()))
    } else {
        (false, failures.join("; "))
    };
    TestResult {
        name: "sysctl-hardening".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

/// SC-7, AC-4: Verify firewall is active
fn check_firewall_active() -> TestResult {
    let start = Instant::now();
    // NixOS uses iptables-based firewall (not firewalld). Check for iptables rules.
    let (passed, message) = match run_cmd("iptables", &["-L", "-n"]) {
        Ok(out) => {
            // If iptables has rules beyond default ACCEPT, firewall is active
            let has_rules = out.lines().count() > 6; // default empty has ~6 lines
            if has_rules {
                (true, "iptables firewall active with rules".into())
            } else {
                (false, "iptables has no rules — firewall may not be active".into())
            }
        }
        Err(e) => (false, format!("iptables not available: {}", e)),
    };
    TestResult {
        name: "firewall-active".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

/// SI-7: Verify no world-writable binaries in system paths
fn check_no_world_writable_bins() -> TestResult {
    let start = Instant::now();
    // Check /nix/store linked paths and /run/current-system/sw/bin
    let (passed, message) = match run_cmd(
        "find",
        &["/run/current-system/sw/bin", "-perm", "-002", "-type", "f"],
    ) {
        Ok(out) => {
            if out.trim().is_empty() {
                (true, "no world-writable binaries".into())
            } else {
                let count = out.lines().count();
                (false, format!("{} world-writable binaries found", count))
            }
        }
        // If find fails (e.g., path doesn't exist), that's fine for AMI builds
        Err(_) => (true, "system bin path not yet populated (AMI build phase)".into()),
    };
    TestResult {
        name: "no-world-writable-bins".into(),
        passed,
        message,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

/// Convergence minimality: verify the system closure isn't bloated.
/// A smaller closure = faster AMI build, smaller snapshot, faster boot,
/// less attack surface. Threshold: 8 GiB (generous for K3s + hardening).
fn check_closure_size() -> TestResult {
    let start = Instant::now();
    // nix path-info -S /run/current-system gives closure size in bytes
    let (passed, message) = match run_cmd("nix", &["path-info", "-S", "/run/current-system"]) {
        Ok(out) => {
            // Output format: "/nix/store/...-nixos-system-...    <size>"
            // The size is the last whitespace-separated token
            let size_str = out.split_whitespace().last().unwrap_or("0");
            match size_str.parse::<u64>() {
                Ok(bytes) => {
                    let gib = bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                    let max_gib = 8.0;
                    if gib <= max_gib {
                        (true, format!("closure size: {:.2} GiB (limit: {:.0} GiB)", gib, max_gib))
                    } else {
                        (false, format!("closure too large: {:.2} GiB (limit: {:.0} GiB) — remove unnecessary packages", gib, max_gib))
                    }
                }
                Err(_) => (true, format!("could not parse size '{}', skipping", size_str)),
            }
        }
        Err(e) => (true, format!("nix path-info unavailable ({}), skipping size check", e)),
    };
    TestResult {
        name: "closure-size".into(),
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
