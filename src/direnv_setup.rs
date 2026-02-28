use anyhow::{Context, Result};
use colored::Colorize;
use std::path::PathBuf;

use crate::tools;

const USE_KINDLING_SH: &str = include_str!("../direnv/use_kindling.sh");

/// Ensure direnv is installed (via nix profile if missing).
pub fn ensure_installed() -> Result<()> {
    if tools::find("direnv").is_some() {
        println!("{} direnv already installed", "ok".green().bold());
        return Ok(());
    }

    tools::nix_profile_install("nixpkgs#direnv")
}

/// Inject the direnv shell hook into the user's RC file.
/// Skips if the RC file is a symlink (home-manager managed) or already has the hook.
pub fn ensure_shell_hook() -> Result<()> {
    let (rc_path, hook_line) = shell_rc_and_hook()?;

    if rc_path.is_symlink() {
        println!(
            "{} {} is a symlink (likely home-manager managed), skipping hook injection",
            "::".blue().bold(),
            rc_path.display()
        );
        return Ok(());
    }

    if !rc_path.exists() {
        // Create the file with the hook
        std::fs::write(&rc_path, format!("{}\n", hook_line))
            .with_context(|| format!("writing {}", rc_path.display()))?;
        println!(
            "{} Created {} with direnv hook",
            "ok".green().bold(),
            rc_path.display()
        );
        return Ok(());
    }

    let content = std::fs::read_to_string(&rc_path)
        .with_context(|| format!("reading {}", rc_path.display()))?;

    if content.contains("direnv hook") {
        println!(
            "{} direnv hook already in {}",
            "ok".green().bold(),
            rc_path.display()
        );
        return Ok(());
    }

    // Append the hook
    let mut new_content = content;
    if !new_content.ends_with('\n') {
        new_content.push('\n');
    }
    new_content.push_str(&format!("\n# Added by kindling\n{}\n", hook_line));
    std::fs::write(&rc_path, new_content)
        .with_context(|| format!("writing {}", rc_path.display()))?;

    println!(
        "{} Added direnv hook to {}",
        "ok".green().bold(),
        rc_path.display()
    );
    Ok(())
}

/// Install use_kindling.sh into the direnv lib directory.
pub fn install_direnv_lib() -> Result<()> {
    let target = direnv_lib_dir()?.join("kindling.sh");

    if target.exists() {
        let existing = std::fs::read_to_string(&target)
            .with_context(|| format!("reading {}", target.display()))?;
        if existing == USE_KINDLING_SH {
            println!(
                "{} direnv lib kindling.sh already up to date",
                "ok".green().bold()
            );
            return Ok(());
        }
    }

    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    std::fs::write(&target, USE_KINDLING_SH)
        .with_context(|| format!("writing {}", target.display()))?;

    println!(
        "{} Installed direnv lib to {}",
        "ok".green().bold(),
        target.display()
    );
    Ok(())
}

fn shell_rc_and_hook() -> Result<(PathBuf, String)> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    let shell = std::env::var("SHELL").unwrap_or_default();

    if shell.ends_with("fish") {
        Ok((
            home.join(".config/fish/config.fish"),
            "direnv hook fish | source".to_string(),
        ))
    } else if shell.ends_with("zsh") {
        Ok((home.join(".zshrc"), "eval \"$(direnv hook zsh)\"".to_string()))
    } else {
        // Default to bash
        Ok((
            home.join(".bashrc"),
            "eval \"$(direnv hook bash)\"".to_string(),
        ))
    }
}

fn direnv_lib_dir() -> Result<PathBuf> {
    let config_dir = dirs::config_dir().context("could not determine config directory")?;
    Ok(config_dir.join("direnv").join("lib"))
}
