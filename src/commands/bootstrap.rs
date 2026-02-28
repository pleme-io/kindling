use anyhow::Result;
use colored::Colorize;

use crate::commands::install;
use crate::nix;
use crate::tools;
use crate::{direnv_setup, tend_setup};

pub fn run(skip_direnv: bool, skip_tend: bool, org: Option<String>, no_confirm: bool) -> Result<()> {
    println!("{}", "kindling bootstrap".bold());
    println!();

    let mut actions: Vec<&str> = Vec::new();

    // ── Step 1: Nix ──────────────────────────────────────────────
    println!("{} Step 1: Nix", ">>".blue().bold());

    let nix_status = nix::detect();
    if nix_status.installed {
        if let Some(ver) = &nix_status.version {
            println!("{} Nix {} already installed", "ok".green().bold(), ver);
        } else {
            println!("{} Nix already installed", "ok".green().bold());
        }
    } else {
        if !no_confirm {
            if !confirm("Nix is not installed. Install it now?")? {
                println!("{} Skipping nix install", "::".blue().bold());
                println!("   Run `kindling install` when you're ready.");
                return Ok(());
            }
        }
        install::install_now()?;
        // Fix PATH so subsequent steps can find nix
        tools::prepend_nix_profile_to_path();
        actions.push("Installed Nix");
    }
    println!();

    // ── Step 2: direnv ───────────────────────────────────────────
    if !skip_direnv {
        println!("{} Step 2: direnv", ">>".blue().bold());

        if direnv_setup::ensure_installed().is_ok() {
            if let Err(e) = direnv_setup::ensure_shell_hook() {
                println!(
                    "{} Could not inject direnv hook: {}",
                    "!!".yellow().bold(),
                    e
                );
            } else {
                actions.push("Configured direnv shell hook");
            }

            if let Err(e) = direnv_setup::install_direnv_lib() {
                println!(
                    "{} Could not install direnv lib: {}",
                    "!!".yellow().bold(),
                    e
                );
            } else {
                actions.push("Installed use_kindling direnv lib");
            }
        }
        println!();
    }

    // ── Step 3: tend ─────────────────────────────────────────────
    if !skip_tend {
        println!("{} Step 3: tend", ">>".blue().bold());

        if tend_setup::ensure_installed().is_ok() {
            if let Some(ref org_name) = org {
                if let Err(e) = tend_setup::ensure_config(org_name) {
                    println!(
                        "{} Could not create tend config: {}",
                        "!!".yellow().bold(),
                        e
                    );
                } else {
                    actions.push("Created tend config");
                }
            }

            if let Err(e) = tend_setup::sync() {
                println!(
                    "{} tend sync failed: {}",
                    "!!".yellow().bold(),
                    e
                );
            } else {
                actions.push("Synced workspace repos");
            }
        }
        println!();
    }

    // ── Summary ──────────────────────────────────────────────────
    println!("{}", "── Summary ──".bold());
    if actions.is_empty() {
        println!("  Everything was already set up.");
    } else {
        for action in &actions {
            println!("  {} {}", "+".green().bold(), action);
        }
    }
    println!();
    println!(
        "{} Restart your shell to pick up any PATH changes.",
        "::".blue().bold()
    );
    println!(
        "{} In project directories, run `direnv allow` to activate.",
        "::".blue().bold()
    );

    Ok(())
}

fn confirm(prompt: &str) -> Result<bool> {
    eprint!("{} {} [y/N] ", "??".blue().bold(), prompt);
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(matches!(input.trim().to_lowercase().as_str(), "y" | "yes"))
}
