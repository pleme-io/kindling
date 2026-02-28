use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::path::PathBuf;
use std::process::Command;

/// Search PATH and nix profile bin dirs for a tool.
pub fn find(name: &str) -> Option<PathBuf> {
    // Check PATH first
    if let Some(p) = find_in_path(name) {
        return Some(p);
    }

    // Check nix profile locations
    let nix_dirs = [
        "/nix/var/nix/profiles/default/bin",
        "/run/current-system/sw/bin",
    ];
    for dir in &nix_dirs {
        let p = PathBuf::from(dir).join(name);
        if p.is_file() {
            return Some(p);
        }
    }

    // Check user nix profile
    if let Some(home) = dirs::home_dir() {
        let p = home.join(".nix-profile/bin").join(name);
        if p.is_file() {
            return Some(p);
        }
    }

    None
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|path| path.is_file())
    })
}

/// Install a package via `nix profile install`.
pub fn nix_profile_install(installable: &str) -> Result<()> {
    println!(
        "{} Installing {} via nix profile...",
        "::".blue().bold(),
        installable
    );

    let nix = find("nix").context("nix not found on PATH")?;

    let status = Command::new(&nix)
        .args([
            "profile",
            "install",
            "--extra-experimental-features",
            "nix-command flakes",
            installable,
        ])
        .status()
        .with_context(|| format!("failed to run nix profile install {}", installable))?;

    if !status.success() {
        bail!("nix profile install {} failed with status {}", installable, status);
    }

    // Refresh PATH with nix profile bin dir
    prepend_nix_profile_to_path();

    println!("{} {} installed", "ok".green().bold(), installable);
    Ok(())
}

/// Prepend nix profile bin dirs to the current process PATH so newly installed
/// tools are immediately visible.
pub fn prepend_nix_profile_to_path() {
    let mut dirs_to_add: Vec<PathBuf> = Vec::new();

    dirs_to_add.push(PathBuf::from("/nix/var/nix/profiles/default/bin"));

    if let Some(home) = dirs::home_dir() {
        dirs_to_add.push(home.join(".nix-profile/bin"));
    }

    if let Ok(current) = std::env::var("PATH") {
        let current_paths: Vec<PathBuf> = std::env::split_paths(&current).collect();
        // Only add dirs not already in PATH
        dirs_to_add.retain(|d| !current_paths.contains(d));
        if !dirs_to_add.is_empty() {
            dirs_to_add.extend(current_paths);
            let new_path = std::env::join_paths(&dirs_to_add).unwrap_or_default();
            std::env::set_var("PATH", &new_path);
        }
    }
}
