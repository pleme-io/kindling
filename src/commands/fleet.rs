//! `kindling fleet status` / `kindling fleet apply <node>`
//!
//! Fleet management commands for multi-node deployments.

use anyhow::{bail, Result};
use colored::Colorize;
use std::process::Command;

use crate::node_identity;

pub fn status() -> Result<()> {
    let node_path = node_identity::NodeIdentity::default_path();

    if !node_path.exists() {
        bail!(
            "No node.yaml found at {}\n   \
             Fleet management requires a node identity.",
            node_path.display()
        );
    }

    let identity = node_identity::NodeIdentity::load(&node_path)?;

    if identity.fleet.peers.is_empty() {
        println!("{} No fleet peers configured in node.yaml", "::".blue().bold());
        println!("   Add peers under the `fleet.peers` section.");
        return Ok(());
    }

    println!("{}", "Fleet Status".bold());
    println!();

    for peer in &identity.fleet.peers {
        let reachable = check_ssh_connectivity(&peer.hostname, &peer.ssh_user);
        let status_icon = if reachable {
            "ok".green().bold()
        } else {
            "!!".red().bold()
        };
        let status_text = if reachable { "reachable" } else { "unreachable" };

        println!(
            "  {} {} ({}) — {}",
            status_icon,
            peer.name.bold(),
            peer.hostname.dimmed(),
            status_text
        );
    }

    println!();
    Ok(())
}

pub fn apply(node: &str) -> Result<()> {
    let node_path = node_identity::NodeIdentity::default_path();

    if !node_path.exists() {
        bail!(
            "No node.yaml found at {}\n   \
             Fleet management requires a node identity.",
            node_path.display()
        );
    }

    let identity = node_identity::NodeIdentity::load(&node_path)?;

    let peer = identity
        .fleet
        .peers
        .iter()
        .find(|p| p.name == node);

    match peer {
        Some(peer) => {
            println!(
                "{} Deploying to {} ({}@{})",
                ">>".blue().bold(),
                peer.name.bold(),
                peer.ssh_user,
                peer.hostname
            );

            // Check connectivity first
            if !check_ssh_connectivity(&peer.hostname, &peer.ssh_user) {
                bail!("Cannot reach {} — check SSH connectivity", peer.hostname);
            }

            println!(
                "{} SSH connectivity confirmed",
                "ok".green().bold()
            );

            // Run remote nixos-rebuild
            let remote_cmd = format!(
                "nixos-rebuild switch --flake /etc/nixos#{}",
                peer.name
            );

            println!(
                "{} Running: ssh {}@{} {}",
                ">>".blue().bold(),
                peer.ssh_user,
                peer.hostname,
                remote_cmd
            );

            let status = Command::new("ssh")
                .args([
                    &format!("{}@{}", peer.ssh_user, peer.hostname),
                    &remote_cmd,
                ])
                .status();

            match status {
                Ok(s) if s.success() => {
                    println!();
                    println!(
                        "{} Successfully deployed to {}",
                        "ok".green().bold(),
                        peer.name
                    );
                }
                Ok(s) => {
                    bail!("Remote rebuild failed with status {}", s);
                }
                Err(e) => {
                    bail!("Failed to SSH to {}: {}", peer.hostname, e);
                }
            }
        }
        None => {
            eprintln!(
                "{} Unknown fleet node: {}",
                "!!".red().bold(),
                node
            );
            eprintln!("   Known peers:");
            for p in &identity.fleet.peers {
                eprintln!("     - {}", p.name);
            }
            std::process::exit(1);
        }
    }

    Ok(())
}

fn check_ssh_connectivity(hostname: &str, user: &str) -> bool {
    Command::new("ssh")
        .args([
            "-o", "ConnectTimeout=5",
            "-o", "BatchMode=yes",
            &format!("{user}@{hostname}"),
            "true",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
