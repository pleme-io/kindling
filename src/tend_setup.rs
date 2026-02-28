use anyhow::{Context, Result};
use colored::Colorize;
use std::path::PathBuf;
use std::process::Command;

use crate::tools;

/// Ensure tend is installed (via nix profile if missing).
pub fn ensure_installed() -> Result<()> {
    if tools::find("tend").is_some() {
        println!("{} tend already installed", "ok".green().bold());
        return Ok(());
    }

    tools::nix_profile_install("github:pleme-io/tend")
}

/// Generate a starter tend config if none exists and --org was provided.
pub fn ensure_config(org: &str) -> Result<()> {
    let config_path = tend_config_path()?;

    if config_path.exists() {
        println!(
            "{} tend config already exists at {}",
            "ok".green().bold(),
            config_path.display()
        );
        return Ok(());
    }

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    let home = dirs::home_dir().context("could not determine home directory")?;
    let base_dir = home.join("code/github").join(org);

    let config = format!(
        r#"workspaces:
  - name: {org}
    provider: github
    base_dir: {base_dir}
    clone_method: ssh
    discover: true
    org: {org}
"#,
        org = org,
        base_dir = base_dir.display(),
    );

    std::fs::write(&config_path, &config)
        .with_context(|| format!("writing {}", config_path.display()))?;

    println!(
        "{} Created starter tend config at {}",
        "ok".green().bold(),
        config_path.display()
    );
    Ok(())
}

/// Run `tend sync --quiet` to clone workspace repos.
pub fn sync() -> Result<()> {
    let config_path = tend_config_path()?;
    if !config_path.exists() {
        println!(
            "{} No tend config found, skipping sync",
            "::".blue().bold()
        );
        return Ok(());
    }

    let tend = match tools::find("tend") {
        Some(p) => p,
        None => {
            println!(
                "{} tend not found on PATH, skipping sync",
                "!!".yellow().bold()
            );
            return Ok(());
        }
    };

    println!("{} Running tend sync...", "::".blue().bold());

    let status = Command::new(&tend)
        .args(["sync"])
        .status()
        .context("failed to run tend sync")?;

    if !status.success() {
        println!(
            "{} tend sync exited with status {} (non-fatal)",
            "!!".yellow().bold(),
            status
        );
    } else {
        println!("{} tend sync complete", "ok".green().bold());
    }

    Ok(())
}

fn tend_config_path() -> Result<PathBuf> {
    let config_dir = dirs::config_dir().context("could not determine config directory")?;
    Ok(config_dir.join("tend").join("config.yaml"))
}
