use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::process::Command;

use crate::nix;
use crate::platform::{self, Backend};

pub fn run(backend: Backend, no_confirm: bool) -> Result<()> {
    let platform = platform::detect()?;
    let url = platform::installer_url(&platform, &backend);
    let tmp = std::env::temp_dir().join("nix-installer");
    let tmp_str = tmp.to_string_lossy().to_string();

    println!(
        "{} Downloading nix-installer ({} backend)...",
        "::".blue().bold(),
        backend
    );

    let status = Command::new("curl")
        .args(["-sSfL", "-o", &tmp_str, &url])
        .status()
        .context("failed to run curl")?;
    if !status.success() {
        bail!("failed to download installer from {}", url);
    }

    Command::new("chmod")
        .args(["+x", &tmp_str])
        .status()
        .context("failed to chmod installer")?;

    println!("{} Running nix-installer...", "::".blue().bold());

    let mut cmd = Command::new(&tmp);
    cmd.arg("install");
    if no_confirm {
        cmd.arg("--no-confirm");
    }
    if platform.is_wsl && !platform::has_systemd() {
        cmd.args(["--init", "none"]);
    }

    let status = cmd.status().context("failed to run nix-installer")?;
    if !status.success() {
        bail!("nix-installer exited with status {}", status);
    }

    // Verify installation
    let nix_status = nix::detect();
    if nix_status.installed {
        if let Some(ver) = nix_status.version {
            println!(
                "{} Nix {} installed successfully",
                "ok".green().bold(),
                ver
            );
        } else {
            println!("{} Nix installed successfully", "ok".green().bold());
        }
    } else {
        println!(
            "{} Installation completed but nix not found on PATH.",
            "!!".yellow().bold()
        );
        println!("   You may need to restart your shell or source the nix profile.");
    }

    Ok(())
}

pub fn install_now() -> Result<()> {
    let config = crate::config::load()?;
    let backend_str = config.backend.as_deref().unwrap_or("upstream");
    let backend: Backend = backend_str.parse()?;
    run(backend, true)
}
