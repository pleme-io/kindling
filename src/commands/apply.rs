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

/// Run a full rebuild from a node.yaml path.
///
/// Shared entry point used by both `kindling apply` and `kindling server bootstrap`.
/// The optional `context` label is printed before the rebuild command for traceability
/// (e.g. the bootstrap phase name).
pub fn run_rebuild_from_path(node_path: &std::path::Path) -> Result<()> {
    run_rebuild_from_path_with_context(node_path, None)
}

/// Like [`run_rebuild_from_path`] but with an optional context label printed
/// before the rebuild command (e.g. `"[bootstrap: nix_rebuild_running]"`).
pub fn run_rebuild_from_path_with_context(
    node_path: &std::path::Path,
    context: Option<&str>,
) -> Result<()> {
    if let Some(ctx) = context {
        println!(
            "{} Bootstrap phase: {}",
            "::".blue().bold(),
            ctx,
        );
    }
    let identity = node_identity::NodeIdentity::load(node_path)?;
    let gen_dir = nix_gen::generate(&identity)?;
    run_rebuild(&identity, &gen_dir)
}

fn run_rebuild(identity: &node_identity::NodeIdentity, gen_dir: &std::path::Path) -> Result<()> {
    let is_darwin = matches!(identity.profile.as_str(), "macos-developer");
    let flake_ref = format!("{}#{}", gen_dir.display(), identity.hostname);

    let cmd = if is_darwin { "darwin-rebuild" } else { "nixos-rebuild" };
    let mut args = vec!["switch".to_string(), "--flake".to_string(), flake_ref.clone()];

    // Inject GitHub access token for private flake inputs if available.
    // Uses --option to pass directly to nix — NIX_CONFIG env var is NOT
    // inherited by the nix daemon, so env-based injection doesn't work.
    let token_path = std::path::Path::new("/etc/nix/github-access-token");
    if token_path.exists() {
        if let Ok(token) = std::fs::read_to_string(token_path) {
            let token = token.trim();
            if !token.is_empty() {
                args.push("--option".to_string());
                args.push("access-tokens".to_string());
                args.push(format!("github.com={token}"));
                println!(
                    "{} Injecting GitHub access-tokens via --option for private flake inputs",
                    "::".blue().bold()
                );
            }
        }
    }

    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    // On NixOS, wrap in systemd-run --scope so switch-to-configuration doesn't
    // SIGTERM the calling service (kindling-init) when activating the new config.
    let status = if !is_darwin {
        let mut scope_args = vec!["--scope", "--", cmd];
        scope_args.extend(arg_refs.iter());
        println!(
            "{} Running: systemd-run {}",
            ">>".blue().bold(),
            scope_args.join(" ")
        );
        Command::new("systemd-run")
            .args(&scope_args)
            .status()
            .with_context(|| format!("failed to run systemd-run --scope -- {cmd}"))?
    } else {
        println!(
            "{} Running: {} {}",
            ">>".blue().bold(),
            cmd,
            args.join(" ")
        );
        Command::new(cmd)
            .args(&arg_refs)
            .status()
            .with_context(|| format!("failed to run {cmd}"))?
    };

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
