//! `kindling profile list` / `kindling profile show <name>`
//!
//! Lists available profiles from kindling-profiles and shows details.

use anyhow::Result;
use colored::Colorize;

/// Known profiles — mirrors kindling-profiles/lib.profileMeta.
/// In the future this can be fetched from the flake at runtime.
struct ProfileInfo {
    name: &'static str,
    platform: &'static str,
    description: &'static str,
    components: &'static [&'static str],
}

const PROFILES: &[ProfileInfo] = &[
    ProfileInfo {
        name: "macos-developer",
        platform: "darwin",
        description: "macOS developer workstation with blackmatter shell, neovim, code search, and workspace tooling",
        components: &["blackmatter-shell", "blackmatter-nvim", "zoekt", "codesearch", "tend", "ghostty", "claude-code"],
    },
    ProfileInfo {
        name: "k3s-server",
        platform: "linux",
        description: "NixOS K3s control plane server with FluxCD, IPVS, and production tuning",
        components: &["k3s", "fluxcd", "wireguard", "dnsmasq"],
    },
    ProfileInfo {
        name: "k3s-agent",
        platform: "linux",
        description: "NixOS K3s worker node with staging taints and node labels",
        components: &["k3s", "docker", "github-actions-runner"],
    },
    ProfileInfo {
        name: "k3s-cloud-server",
        platform: "linux",
        description: "NixOS K3s server for cloud hosts (Hetzner/AWS) with WireGuard mesh",
        components: &["k3s", "wireguard", "firewall"],
    },
];

pub fn list() -> Result<()> {
    println!("{}", "Available profiles:".bold());
    println!();

    for p in PROFILES {
        println!(
            "  {} {} {}",
            p.name.green().bold(),
            format!("({})", p.platform).dimmed(),
            ""
        );
        println!("    {}", p.description);
    }

    println!();
    println!(
        "{} Use `kindling profile show <name>` for details.",
        "::".blue().bold()
    );
    Ok(())
}

pub fn show(name: &str) -> Result<()> {
    let profile = PROFILES
        .iter()
        .find(|p| p.name == name);

    match profile {
        Some(p) => {
            println!("{} {}", "Profile:".bold(), p.name.green().bold());
            println!("{} {}", "Platform:".bold(), p.platform);
            println!("{} {}", "Description:".bold(), p.description);
            println!();
            println!("{}", "Components:".bold());
            for component in p.components {
                println!("  {} {}", "+".green().bold(), component);
            }
            println!();
            println!(
                "{} Bootstrap with: kindling bootstrap --profile {}",
                "::".blue().bold(),
                p.name
            );
        }
        None => {
            eprintln!(
                "{} Unknown profile: {}",
                "!!".red().bold(),
                name
            );
            eprintln!("   Run `kindling profile list` to see available profiles.");
            std::process::exit(1);
        }
    }

    Ok(())
}
