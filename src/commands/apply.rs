//! `kindling apply` — read node.yaml, regenerate Nix, run rebuild.
//!
//! Reads the node identity from ~/.config/kindling/node.yaml, generates
//! node.json + flake.nix, and runs the appropriate system rebuild command.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::process::Command;

use crate::node_identity::{self, nix_gen};

pub fn run(diff_only: bool) -> Result<()> {
    let node_path = node_identity::NodeIdentity::default_path();

    if !node_path.exists() {
        bail!(
            "No node.yaml found at {}\n   \
             Create one with `kindling bootstrap --profile <name> --hostname <host> --user <user>`\n   \
             or write it manually.",
            node_path.display()
        );
    }

    println!("{} Reading {}", ">>".blue().bold(), node_path.display());
    let identity = node_identity::NodeIdentity::load(&node_path)?;

    println!(
        "{} Profile: {}, Hostname: {}, User: {}",
        "ok".green().bold(),
        identity.profile,
        identity.hostname,
        identity.user.name
    );
    println!();

    // Generate Nix files
    println!("{} Generating Nix configuration", ">>".blue().bold());
    let gen_dir = nix_gen::generate(&identity)?;
    println!(
        "{} Generated files in {}",
        "ok".green().bold(),
        gen_dir.display()
    );
    println!();

    if diff_only {
        println!("{} Diff mode — showing what would change", ">>".blue().bold());
        run_rebuild_diff(&identity, &gen_dir)?;
    } else {
        println!("{} Applying system configuration", ">>".blue().bold());
        run_rebuild(&identity, &gen_dir)?;
    }

    Ok(())
}

fn run_rebuild(identity: &node_identity::NodeIdentity, gen_dir: &std::path::Path) -> Result<()> {
    let is_darwin = matches!(identity.profile.as_str(), "macos-developer");
    let flake_ref = format!("{}#{}", gen_dir.display(), identity.hostname);

    let cmd = if is_darwin { "darwin-rebuild" } else { "nixos-rebuild" };
    let args = vec!["switch", "--flake", &flake_ref];

    println!(
        "{} Running: {} {}",
        ">>".blue().bold(),
        cmd,
        args.join(" ")
    );

    let status = Command::new(cmd)
        .args(&args)
        .status()
        .with_context(|| format!("failed to run {cmd}"))?;

    if status.success() {
        println!();
        println!(
            "{} System configuration applied successfully",
            "ok".green().bold()
        );
    } else {
        bail!("{} exited with status {}", cmd, status);
    }

    Ok(())
}

fn run_rebuild_diff(
    identity: &node_identity::NodeIdentity,
    gen_dir: &std::path::Path,
) -> Result<()> {
    let is_darwin = matches!(identity.profile.as_str(), "macos-developer");
    let flake_ref = format!("{}#{}", gen_dir.display(), identity.hostname);

    let cmd = if is_darwin { "darwin-rebuild" } else { "nixos-rebuild" };
    let args = vec!["build", "--flake", &flake_ref];

    println!(
        "{} Running: {} {}",
        ">>".blue().bold(),
        cmd,
        args.join(" ")
    );
    println!(
        "{} (build only — will not activate)",
        "::".blue().bold()
    );

    let status = Command::new(cmd)
        .args(&args)
        .status()
        .with_context(|| format!("failed to run {cmd}"))?;

    if status.success() {
        // Show diff between current system and built result
        let result_path = gen_dir.join("result");
        if result_path.exists() {
            println!();
            println!("{} Diff against current system:", ">>".blue().bold());
            let result_str = result_path.display().to_string();
            let _ = Command::new("nix")
                .args(["store", "diff-closures", "/run/current-system", &result_str])
                .status();
        }

        println!();
        println!(
            "{} Build succeeded. Run `kindling apply` to activate.",
            "ok".green().bold()
        );
    } else {
        bail!("{} exited with status {}", cmd, status);
    }

    Ok(())
}
