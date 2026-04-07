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
            "  {} {} ",
            p.name.green().bold(),
            format!("({})", p.platform).dimmed()
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

/// Look up a profile by name from the built-in registry.
fn find_profile(name: &str) -> Option<&'static ProfileInfo> {
    PROFILES.iter().find(|p| p.name == name)
}

pub fn show(name: &str) -> Result<()> {
    match find_profile(name) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_list_is_not_empty() {
        assert!(!PROFILES.is_empty());
    }

    #[test]
    fn all_profiles_have_components() {
        for p in PROFILES {
            assert!(
                !p.components.is_empty(),
                "profile '{}' should have at least one component",
                p.name
            );
        }
    }

    #[test]
    fn all_profiles_have_valid_platform() {
        for p in PROFILES {
            assert!(
                p.platform == "darwin" || p.platform == "linux",
                "profile '{}' has unexpected platform '{}'",
                p.name,
                p.platform
            );
        }
    }

    #[test]
    fn find_profile_known() {
        let p = find_profile("macos-developer");
        assert!(p.is_some());
        let p = p.unwrap();
        assert_eq!(p.platform, "darwin");
        assert!(p.components.contains(&"blackmatter-shell"));
    }

    #[test]
    fn find_profile_k3s_server() {
        let p = find_profile("k3s-server").unwrap();
        assert_eq!(p.platform, "linux");
        assert!(p.components.contains(&"k3s"));
        assert!(p.components.contains(&"fluxcd"));
    }

    #[test]
    fn find_profile_unknown() {
        assert!(find_profile("nonexistent-profile").is_none());
    }

    #[test]
    fn profile_names_are_unique() {
        let mut names: Vec<&str> = PROFILES.iter().map(|p| p.name).collect();
        names.sort();
        names.dedup();
        assert_eq!(
            names.len(),
            PROFILES.len(),
            "profile names should be unique"
        );
    }
}
