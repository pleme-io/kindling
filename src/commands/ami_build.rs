//! CLI handler for `kindling ami-build` — complete AMI build orchestration in Rust.
//!
//! Replaces the Packer shell provisioner with a single Rust command that handles:
//! 1. Nix access-tokens configuration
//! 2. nixos-rebuild switch
//! 3. K3s state cleanup (deterministic PKI seeding)
//! 4. AMI validation (11 checks)
//! 5. Post-build cleanup (garbage collection, secrets, temp files)
//!
//! Usage: kindling ami-build --flake-ref github:org/repo#config

use anyhow::{Context, Result, bail};
use clap::Args;
use std::path::Path;
use std::process::Command;

use crate::commands::ami_test;

#[derive(Args)]
pub struct AmiBuildArgs {
    /// Flake reference for nixos-rebuild (e.g. github:pleme-io/kindling-profiles#ami-builder)
    #[arg(long)]
    pub flake_ref: String,

    /// Skip nixos-rebuild (for testing ami-test changes)
    #[arg(long)]
    pub skip_rebuild: bool,

    /// Skip AMI validation checks
    #[arg(long)]
    pub skip_validation: bool,
}

pub fn run(args: AmiBuildArgs) -> Result<()> {
    let total_phases = if args.skip_rebuild { 3 } else { 5 };
    let mut phase = 0;

    // ── Phase 1: Configure nix access-tokens ──────────────────────
    phase += 1;
    println!("[phase:{phase}/{total_phases}] Configuring nix access-tokens");

    let github_token = std::env::var("GITHUB_TOKEN").unwrap_or_default();
    if !github_token.is_empty() {
        let token_path = Path::new("/etc/nix/github-access-token");
        let token_dir = token_path.parent().unwrap();
        std::fs::create_dir_all(token_dir)
            .with_context(|| format!("failed to create {}", token_dir.display()))?;
        std::fs::write(token_path, &github_token)
            .with_context(|| format!("failed to write {}", token_path.display()))?;
        println!("[phase:{phase}/{total_phases}] OK — access-token written ({} chars)", github_token.len());
    } else {
        println!("[phase:{phase}/{total_phases}] WARN — no GITHUB_TOKEN set, private repos may fail");
    }

    // ── Phase 2: nixos-rebuild switch ─────────────────────────────
    if !args.skip_rebuild {
        phase += 1;
        println!("[phase:{phase}/{total_phases}] Running nixos-rebuild switch --flake {}", args.flake_ref);

        let mut rebuild_args = vec![
            "switch".to_string(),
            "--flake".to_string(),
            args.flake_ref.clone(),
        ];

        // Inject access-tokens via --option (daemon doesn't read user config)
        if !github_token.is_empty() {
            rebuild_args.extend([
                "--option".to_string(),
                "access-tokens".to_string(),
                format!("github.com={github_token}"),
            ]);
        }

        let status = Command::new("nixos-rebuild")
            .args(&rebuild_args)
            .status()
            .context("failed to run nixos-rebuild")?;

        if !status.success() {
            bail!("[phase:{phase}/{total_phases}] FAILED — nixos-rebuild exited {}", status);
        }
        println!("[phase:{phase}/{total_phases}] OK — nixos-rebuild completed");
    }

    // ── Phase 3: Clean K3s state (deterministic PKI on boot) ──────
    phase += 1;
    println!("[phase:{phase}/{total_phases}] Cleaning K3s state for deterministic PKI seeding");

    // Stop K3s if it was started by nixos-rebuild
    let _ = Command::new("systemctl").args(["stop", "k3s.service"]).status();

    // Remove entire server dir (datastore + TLS + creds)
    // kindling-init will re-seed these from bootstrap_secrets on cluster boot
    let server_dir = Path::new("/var/lib/rancher/k3s/server");
    if server_dir.exists() {
        std::fs::remove_dir_all(server_dir)
            .with_context(|| format!("failed to remove {}", server_dir.display()))?;
        println!("[phase:{phase}/{total_phases}] OK — K3s server state cleared");
    } else {
        println!("[phase:{phase}/{total_phases}] OK — no K3s state to clear");
    }

    // ── Phase 4: AMI validation (11 checks) ───────────────────────
    if !args.skip_validation {
        phase += 1;
        println!("[phase:{phase}/{total_phases}] Running AMI validation (11 checks)");

        ami_test::run(ami_test::AmiTestArgs {
            format: ami_test::OutputFormat::Text,
        })
        .context("AMI validation failed — AMI will NOT be created")?;

        println!("[phase:{phase}/{total_phases}] OK — all checks passed");
    }

    // ── Phase 5: Post-build cleanup ───────────────────────────────
    phase += 1;
    println!("[phase:{phase}/{total_phases}] Post-build cleanup");

    // Nix garbage collection
    let _ = Command::new("nix-collect-garbage").arg("-d").status();

    // Remove build-time secrets
    let files_to_remove = [
        "/root/.config/nix/nix.conf",
        "/etc/nix/github-access-token",
        "/root/.ssh/authorized_keys",
    ];
    for path in &files_to_remove {
        if Path::new(path).exists() {
            std::fs::remove_file(path).ok();
        }
    }

    // Clean journals
    let _ = Command::new("journalctl")
        .args(["--rotate", "--vacuum-time=1s"])
        .status();

    // Clean temp files
    for dir in ["/tmp", "/var/tmp", "/var/log/journal"] {
        if Path::new(dir).exists() {
            let _ = std::fs::remove_dir_all(dir);
            let _ = std::fs::create_dir_all(dir);
        }
    }

    // Trim filesystem
    let _ = Command::new("fstrim").arg("/").status();

    println!("[phase:{phase}/{total_phases}] OK — cleanup complete");
    println!("AMI build successful — ready for Packer snapshot");

    Ok(())
}
