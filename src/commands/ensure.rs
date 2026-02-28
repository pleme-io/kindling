use anyhow::Result;
use colored::Colorize;

use crate::commands::install;
use crate::config;
use crate::nix;

pub fn run(required_version: Option<semver::VersionReq>) -> Result<()> {
    let status = nix::detect();

    if status.installed {
        if let Some(req) = &required_version {
            if let Some(ver) = &status.version {
                if req.matches(ver) {
                    return Ok(());
                }
                println!(
                    "{} Nix {} installed but {} required",
                    "!!".yellow().bold(),
                    ver,
                    req
                );
            }
        } else {
            return Ok(());
        }
    }

    // Check env var override
    if std::env::var("KINDLING_AUTO_INSTALL").as_deref() == Ok("1") {
        return install::install_now();
    }

    // Check config
    let cfg = config::load()?;
    match cfg.auto_install {
        Some(true) => install::install_now(),
        Some(false) => {
            println!(
                "{} Nix is not installed. Auto-install is disabled.",
                "::".blue().bold()
            );
            println!("   Run `kindling install` to install manually.");
            std::process::exit(1);
        }
        None => {
            // First run — prompt user
            if confirm("Nix is not installed. Install it now?")? {
                config::save_auto_install(true)?;
                install::install_now()
            } else {
                config::save_auto_install(false)?;
                println!(
                    "{} Run `kindling install` when you're ready.",
                    "::".blue().bold()
                );
                std::process::exit(1);
            }
        }
    }
}

fn confirm(prompt: &str) -> Result<bool> {
    eprint!("{} {} [y/N] ", "??".blue().bold(), prompt);
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(matches!(input.trim().to_lowercase().as_str(), "y" | "yes"))
}
