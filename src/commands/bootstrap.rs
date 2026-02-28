use anyhow::Result;
use colored::Colorize;

use crate::commands::install;
use crate::nix;
use crate::node_identity::{nix_gen, NodeIdentity};
use crate::tools;
use crate::{direnv_setup, tend_setup};

#[allow(clippy::too_many_arguments)]
pub fn run(
    skip_direnv: bool,
    skip_tend: bool,
    org: Option<String>,
    no_confirm: bool,
    profile: Option<String>,
    hostname: Option<String>,
    user: Option<String>,
    age_key_file: Option<String>,
    node_config: Option<String>,
) -> Result<()> {
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

    // ── Step 4: Node Identity ────────────────────────────────────
    let has_profile_args = profile.is_some() || node_config.is_some();

    if has_profile_args {
        println!("{} Step 4: Node Identity", ">>".blue().bold());

        let identity = if let Some(config_path) = node_config {
            // Load from existing node.yaml
            let path = std::path::PathBuf::from(&config_path);
            println!("  Loading node config from {}", config_path);
            NodeIdentity::load(&path)?
        } else {
            // Build from CLI flags
            let profile_name = profile.as_deref().unwrap_or("macos-developer");
            let host = hostname
                .as_deref()
                .or_else(|| {
                    ::hostname::get()
                        .ok()
                        .and_then(|h| h.into_string().ok())
                        .as_deref()
                        .map(|_| "")
                })
                .unwrap_or("localhost");

            // Try to get the actual hostname if not provided
            let host = if host.is_empty() {
                hostname::get()
                    .map(|h| h.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "localhost".to_string())
            } else {
                host.to_string()
            };

            let username = user
                .as_deref()
                .unwrap_or_else(|| {
                    // Would use std::env::var but need static lifetime
                    "user"
                });

            NodeIdentity::from_bootstrap(
                profile_name,
                &host,
                username,
                age_key_file.as_deref(),
            )
        };

        // Save node.yaml
        let node_path = NodeIdentity::default_path();
        identity.save(&node_path)?;
        println!(
            "{} Node identity saved to {}",
            "ok".green().bold(),
            node_path.display()
        );
        actions.push("Created node identity");
        println!();

        // ── Step 5: Nix Generation ───────────────────────────────
        println!("{} Step 5: Nix Generation", ">>".blue().bold());

        let gen_dir = nix_gen::generate(&identity)?;
        println!(
            "{} Generated Nix config in {}",
            "ok".green().bold(),
            gen_dir.display()
        );
        actions.push("Generated Nix configuration");
        println!();

        // ── Step 6: System Activate ──────────────────────────────
        if !no_confirm {
            println!(
                "{} Generated config is ready at {}",
                "::".blue().bold(),
                gen_dir.display()
            );
            println!(
                "{} Run `kindling apply` to activate the system configuration.",
                "::".blue().bold()
            );
            println!(
                "{} Or run `kindling apply --diff` to preview changes first.",
                "::".blue().bold()
            );
        }
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
    if !has_profile_args {
        println!(
            "{} In project directories, run `direnv allow` to activate.",
            "::".blue().bold()
        );
    }

    Ok(())
}

fn confirm(prompt: &str) -> Result<bool> {
    eprint!("{} {} [y/N] ", "??".blue().bold(), prompt);
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(matches!(input.trim().to_lowercase().as_str(), "y" | "yes"))
}
