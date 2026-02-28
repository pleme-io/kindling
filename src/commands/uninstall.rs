use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::path::Path;
use std::process::Command;

pub fn run() -> Result<()> {
    // The nix-installer binary is left behind in /nix after install
    let installer_paths = [
        "/nix/nix-installer",
        "/nix/var/nix/profiles/default/bin/nix-installer",
    ];

    let installer = installer_paths
        .iter()
        .map(Path::new)
        .find(|p| p.exists());

    let installer = match installer {
        Some(p) => p,
        None => {
            bail!(
                "nix-installer not found at {}. Was Nix installed with kindling/nix-installer?",
                installer_paths.join(" or ")
            );
        }
    };

    println!(
        "{} Running nix-installer uninstall...",
        "::".blue().bold()
    );

    let status = Command::new(installer)
        .args(["uninstall", "--no-confirm"])
        .status()
        .context("failed to run nix-installer uninstall")?;

    if !status.success() {
        bail!("nix-installer uninstall exited with status {}", status);
    }

    println!("{} Nix uninstalled successfully", "ok".green().bold());
    Ok(())
}
