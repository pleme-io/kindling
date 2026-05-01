//! Pure-Rust portao **fleet** bootstrap — generates key material for every
//! portao listed in a YAML config in one pass.
//!
//! The single-portao [`super::portao_bootstrap`] command is the right tool when
//! you onboard one new account. The fleet command is the right tool when you
//! stand up the multi-account portao matrix (akeyless saas/staging/prod/cicd
//! across multiple regions) that replaces a corporate VPN like FortiGate. One
//! YAML file, one invocation, one consolidated output the operator can paste
//! into `sops secrets.yaml` once and into per-account SSM independently.
//!
//! ## Why fleet-level
//!
//! Hand-rolling the single-portao command 8 times (one per account/region)
//! produces 8 independent terminal sessions, 8 ad-hoc SOPS edits, and an
//! easy chance to mix up subnet bases or skip a spoke node. The fleet
//! command takes a typed manifest and emits:
//!
//! * one merged YAML block to paste into `secrets.yaml`
//! * one `vpn-links.nix` snippet covering every portao
//! * per-portao `aws ssm put-parameter` commands grouped by AWS profile
//!
//! It does *not* shell out to AWS or write files — the operator stays in
//! the loop on every credential boundary.
//!
//! ## Config format
//!
//! ```yaml
//! default_spokes: [ryn, cid, rio]
//!
//! portaos:
//!   - env_name: akeyless-cicd
//!     subnet_base: "10.100.31"
//!     region: us-east-1
//!     aws_profile: akeyless-cicd
//!     advertise_cidrs: ["10.0.0.0/16"]
//!     interface_suffix: cic
//!
//!   - env_name: akeyless-staging-use2
//!     subnet_base: "10.100.32"
//!     region: us-east-2
//!     aws_profile: akeyless-staging
//!     advertise_cidrs: ["10.0.0.0/16"]
//!     interface_suffix: stu
//! ```
//!
//! `default_spokes` applies to every entry that doesn't set its own `spokes:`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

use super::portao_bootstrap::{bootstrap, BootstrapInput, PortaoBootstrap};

/// Top-level fleet config (parsed from YAML on disk).
#[derive(Debug, Deserialize, Serialize)]
pub struct FleetConfig {
    /// Spoke node aliases that get keys for every portao unless overridden
    /// per-entry. Typical: `[ryn, cid, rio]`.
    #[serde(default = "default_spokes_default")]
    pub default_spokes: Vec<String>,

    /// Per-portao entries.
    pub portaos: Vec<PortaoEntry>,
}

fn default_spokes_default() -> Vec<String> {
    vec!["ryn".to_string()]
}

/// One entry in the fleet manifest.
#[derive(Debug, Deserialize, Serialize)]
pub struct PortaoEntry {
    /// Logical environment name (used as the `vpn-links.nix` link name and
    /// as the `/portao/<env>/...` SSM scope).
    pub env_name: String,

    /// First three octets of the WG /24 (e.g. `10.100.31`).
    pub subnet_base: String,

    /// AWS region this portao runs in.
    pub region: String,

    /// AWS profile name to use for the SSM put-parameter commands.
    pub aws_profile: String,

    /// VPC/extra CIDRs the hub will advertise via masquerade. Informational
    /// in the bootstrap output; consumed downstream by `pangea-architectures`.
    #[serde(default)]
    pub advertise_cidrs: Vec<String>,

    /// Spoke-side WG interface suffix (kept short — Linux limits interface
    /// names to 15 chars including `wg-<spoke>-`). Optional: the underlying
    /// portao bootstrap derives a 3-char suffix from `env_name`'s last
    /// hyphen segment when this is omitted.
    #[serde(default)]
    pub interface_suffix: Option<String>,

    /// Override the fleet `default_spokes` for this entry. Useful when one
    /// account should reach a strict subset of nodes.
    #[serde(default)]
    pub spokes: Option<Vec<String>>,
}

/// Output of one fleet bootstrap invocation — every per-portao bootstrap
/// in declaration order plus the per-portao advertise CIDRs (which the
/// underlying [`PortaoBootstrap`] does not carry).
#[derive(Debug, Serialize)]
pub struct FleetOutput {
    pub portaos: Vec<FleetPortaoOutput>,
}

#[derive(Debug, Serialize)]
pub struct FleetPortaoOutput {
    /// Verbatim from the input — propagated so the consumer can tie this
    /// portao to a downstream `vpn-links.nix` `hub.advertiseCidrs` entry.
    pub advertise_cidrs: Vec<String>,
    #[serde(flatten)]
    pub bootstrap: PortaoBootstrap,
}

/// Generate every portao's key material in one shot.
///
/// Pure (other than RNG). Errors propagate from the per-portao bootstrap
/// (e.g. zero spokes, > 253 spokes).
pub fn bootstrap_fleet(config: &FleetConfig) -> Result<FleetOutput> {
    if config.portaos.is_empty() {
        anyhow::bail!("fleet config has zero portaos");
    }

    // Reject duplicate env_name / subnet_base before generating any keys —
    // a fleet with collisions would silently overwrite SOPS paths.
    let mut seen_env = std::collections::BTreeSet::new();
    let mut seen_subnet = std::collections::BTreeSet::new();
    for p in &config.portaos {
        if !seen_env.insert(&p.env_name) {
            anyhow::bail!("duplicate env_name in fleet: {}", p.env_name);
        }
        if !seen_subnet.insert(&p.subnet_base) {
            anyhow::bail!("duplicate subnet_base in fleet: {}", p.subnet_base);
        }
    }

    let mut out = Vec::with_capacity(config.portaos.len());
    for entry in &config.portaos {
        let spokes_owned: Vec<String> = entry
            .spokes
            .clone()
            .unwrap_or_else(|| config.default_spokes.clone());
        if spokes_owned.is_empty() {
            anyhow::bail!(
                "portao '{}' has no spokes (default_spokes is also empty)",
                entry.env_name
            );
        }
        let spoke_refs: Vec<&str> = spokes_owned.iter().map(String::as_str).collect();
        let input = BootstrapInput {
            env_name: &entry.env_name,
            subnet_base: &entry.subnet_base,
            spokes: &spoke_refs,
            interface_suffix: entry.interface_suffix.as_deref(),
            region: &entry.region,
            aws_profile: &entry.aws_profile,
        };
        let bs = bootstrap(&input)
            .with_context(|| format!("bootstrapping portao '{}'", entry.env_name))?;
        out.push(FleetPortaoOutput {
            advertise_cidrs: entry.advertise_cidrs.clone(),
            bootstrap: bs,
        });
    }

    Ok(FleetOutput { portaos: out })
}

/// Load a fleet config from a YAML file on disk.
pub fn load_config(path: &Path) -> Result<FleetConfig> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading fleet config {}", path.display()))?;
    let config: FleetConfig = serde_yaml::from_str(&raw)
        .with_context(|| format!("parsing fleet config {}", path.display()))?;
    Ok(config)
}

/// CLI entry point: load YAML, bootstrap, print.
pub fn run(config_path: &Path, output_format: &str) -> Result<()> {
    let config = load_config(config_path)?;
    let out = bootstrap_fleet(&config)?;

    match output_format {
        "json" => println!("{}", serde_json::to_string_pretty(&out)?),
        "yaml" => println!("{}", serde_yaml::to_string(&out)?),
        _ => print_text(&out),
    }
    Ok(())
}

fn print_text(out: &FleetOutput) {
    println!("# Portao fleet bootstrap — {} portao(s)", out.portaos.len());
    for p in &out.portaos {
        println!(
            "#   - {:30}  subnet={}  region={}  profile={}",
            p.bootstrap.env_name,
            p.bootstrap.subnet_cidr,
            p.bootstrap.ssm_commands.region,
            p.bootstrap.ssm_commands.aws_profile,
        );
    }
    println!();
    println!("# ── Step 1: merge into pleme-io/nix/secrets.yaml under sops ──");
    println!("# (run `sops secrets.yaml` and merge into existing keys)");
    println!();
    println!("clusters:");
    for p in &out.portaos {
        println!("    {}:", p.bootstrap.env_name);
        println!("        wireguard:");
        println!("            private-key: {}", p.bootstrap.hub.private_key);
    }

    // Group spoke material by node so the operator can paste one block per
    // node (matches existing `secrets.yaml` shape: `<node>: { wireguard:
    // { <env>: { private-key, psk } } }`).
    let mut by_node: BTreeMap<&str, Vec<(&str, &str, &str)>> = BTreeMap::new();
    for p in &out.portaos {
        for s in &p.bootstrap.spokes {
            by_node
                .entry(s.node.as_str())
                .or_default()
                .push((p.bootstrap.env_name.as_str(), &s.private_key, &s.psk));
        }
    }
    for (node, entries) in &by_node {
        println!("{}:", node);
        println!("    wireguard:");
        for (env, priv_key, psk) in entries {
            println!("        {}:", env);
            println!("            private-key: {priv_key}");
            println!("            psk: {psk}");
        }
    }

    println!();
    println!("# ── Step 2: vpn-links.nix snippet (paste into nix/lib/vpn-links.nix) ──");
    println!();
    for p in &out.portaos {
        let bs = &p.bootstrap;
        println!("  {} = {{", bs.env_name);
        println!("    interface = \"portao0\";");
        println!("    subnet = \"{}\";", bs.subnet_cidr);
        println!("    profile = \"portao\";");
        println!("    hub = {{");
        println!("      node = \"portao-{}\";", bs.env_name);
        println!("      address = \"{}\";", bs.hub_address);
        println!("      publicKey = \"{}\";", bs.hub.public_key);
        println!("      listenPort = 51820;");
        println!(
            "      endpoint = \"vpn.{}.quero.lol:51820\";",
            bs.env_name
        );
        if !p.advertise_cidrs.is_empty() {
            print!("      advertiseCidrs = [ ");
            for c in &p.advertise_cidrs {
                print!("\"{c}\" ");
            }
            println!("];");
        }
        println!("      ssmPrivateKeyParam = \"{}\";", bs.hub.ssm_private_key_param);
        println!("    }};");
        println!("    spokes = {{");
        for s in &bs.spokes {
            println!("      {} = {{", s.node);
            println!("        address = \"{}\";", s.address);
            println!("        publicKey = \"{}\";", s.public_key);
            println!("        interface = \"{}\";", s.interface);
            println!(
                "        secrets.privateKey = \"{}\";",
                s.sops_paths.private_key
            );
            println!("        secrets.psk = \"{}\";", s.sops_paths.psk);
            println!("      }};");
        }
        println!("    }};");
        println!("  }};");
        println!();
    }

    println!("# ── Step 3: seed SSM (one block per AWS profile — sso login each) ──");
    let mut by_profile: BTreeMap<&str, Vec<&FleetPortaoOutput>> = BTreeMap::new();
    for p in &out.portaos {
        by_profile
            .entry(p.bootstrap.ssm_commands.aws_profile.as_str())
            .or_default()
            .push(p);
    }
    for (profile, group) in &by_profile {
        println!();
        println!("# AWS profile: {profile}");
        println!("aws sso login --profile {profile}");
        for p in group {
            println!("# {}", p.bootstrap.env_name);
            println!("{}", p.bootstrap.ssm_commands.put_hub_private_key);
            println!("{}", p.bootstrap.ssm_commands.put_peers_json);
        }
    }

    println!();
    println!("# ── Step 4: rebuild every spoke node so the (still-inert) entries land ──");
    let mut nodes: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for p in &out.portaos {
        for s in &p.bootstrap.spokes {
            nodes.insert(s.node.as_str());
        }
    }
    for n in &nodes {
        println!("#   {n}: nix run .#rebuild   (from pleme-io/nix on that node)");
    }
    println!();
    println!("# ── Step 5: flip a portao live ──");
    println!("# For each env, edit vpn-links.nix and replace `hub.publicKey = null;` with");
    println!("# the public key from Step 2's snippet, then run pangea apply for that env.");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn three_portao_yaml() -> &'static str {
        r#"
default_spokes: [ryn, cid, rio]

portaos:
  - env_name: akeyless-cicd
    subnet_base: "10.100.31"
    region: us-east-1
    aws_profile: akeyless-cicd
    advertise_cidrs: ["10.0.0.0/16"]
    interface_suffix: cic

  - env_name: akeyless-staging-use2
    subnet_base: "10.100.32"
    region: us-east-2
    aws_profile: akeyless-staging
    advertise_cidrs: ["10.0.0.0/16"]
    interface_suffix: stu

  - env_name: akeyless-prod-euw3
    subnet_base: "10.100.37"
    region: eu-west-3
    aws_profile: akeyless-production
    advertise_cidrs: ["10.2.0.0/16"]
    interface_suffix: pe3
"#
    }

    #[test]
    fn parses_yaml_config() {
        let cfg: FleetConfig = serde_yaml::from_str(three_portao_yaml()).unwrap();
        assert_eq!(cfg.default_spokes, vec!["ryn", "cid", "rio"]);
        assert_eq!(cfg.portaos.len(), 3);
        assert_eq!(cfg.portaos[0].env_name, "akeyless-cicd");
        assert_eq!(cfg.portaos[2].advertise_cidrs, vec!["10.2.0.0/16"]);
    }

    #[test]
    fn bootstrap_yields_one_portao_per_entry() {
        let cfg: FleetConfig = serde_yaml::from_str(three_portao_yaml()).unwrap();
        let out = bootstrap_fleet(&cfg).unwrap();
        assert_eq!(out.portaos.len(), 3);
        assert_eq!(out.portaos[0].bootstrap.env_name, "akeyless-cicd");
        assert_eq!(out.portaos[1].bootstrap.env_name, "akeyless-staging-use2");
        assert_eq!(out.portaos[2].bootstrap.env_name, "akeyless-prod-euw3");
    }

    #[test]
    fn bootstrap_default_spokes_apply_when_per_entry_omitted() {
        let cfg: FleetConfig = serde_yaml::from_str(three_portao_yaml()).unwrap();
        let out = bootstrap_fleet(&cfg).unwrap();
        for p in &out.portaos {
            let nodes: Vec<&str> = p.bootstrap.spokes.iter().map(|s| s.node.as_str()).collect();
            assert_eq!(nodes, vec!["ryn", "cid", "rio"]);
        }
    }

    #[test]
    fn bootstrap_per_entry_spokes_override_defaults() {
        let yaml = r#"
default_spokes: [ryn, cid, rio]
portaos:
  - env_name: prod-only
    subnet_base: "10.100.40"
    region: us-east-1
    aws_profile: akeyless-production
    spokes: [ryn]
"#;
        let cfg: FleetConfig = serde_yaml::from_str(yaml).unwrap();
        let out = bootstrap_fleet(&cfg).unwrap();
        let nodes: Vec<&str> = out.portaos[0]
            .bootstrap
            .spokes
            .iter()
            .map(|s| s.node.as_str())
            .collect();
        assert_eq!(nodes, vec!["ryn"]);
    }

    #[test]
    fn bootstrap_keys_unique_across_portaos() {
        let cfg: FleetConfig = serde_yaml::from_str(three_portao_yaml()).unwrap();
        let out = bootstrap_fleet(&cfg).unwrap();
        // Hub keys distinct
        let hubs: Vec<&str> = out
            .portaos
            .iter()
            .map(|p| p.bootstrap.hub.public_key.as_str())
            .collect();
        assert_ne!(hubs[0], hubs[1]);
        assert_ne!(hubs[1], hubs[2]);
        // ryn's spoke keys distinct across portaos
        let ryn_keys: Vec<&str> = out
            .portaos
            .iter()
            .map(|p| {
                p.bootstrap
                    .spokes
                    .iter()
                    .find(|s| s.node == "ryn")
                    .unwrap()
                    .public_key
                    .as_str()
            })
            .collect();
        assert_ne!(ryn_keys[0], ryn_keys[1]);
        assert_ne!(ryn_keys[1], ryn_keys[2]);
    }

    #[test]
    fn rejects_empty_fleet() {
        let yaml = r#"
default_spokes: [ryn]
portaos: []
"#;
        let cfg: FleetConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(bootstrap_fleet(&cfg).is_err());
    }

    #[test]
    fn rejects_duplicate_env_name() {
        let yaml = r#"
default_spokes: [ryn]
portaos:
  - env_name: dupe
    subnet_base: "10.100.31"
    region: us-east-1
    aws_profile: a
  - env_name: dupe
    subnet_base: "10.100.32"
    region: us-east-2
    aws_profile: b
"#;
        let cfg: FleetConfig = serde_yaml::from_str(yaml).unwrap();
        let err = bootstrap_fleet(&cfg).unwrap_err().to_string();
        assert!(err.contains("duplicate env_name"));
    }

    #[test]
    fn rejects_duplicate_subnet_base() {
        let yaml = r#"
default_spokes: [ryn]
portaos:
  - env_name: a
    subnet_base: "10.100.31"
    region: us-east-1
    aws_profile: a
  - env_name: b
    subnet_base: "10.100.31"
    region: us-east-2
    aws_profile: b
"#;
        let cfg: FleetConfig = serde_yaml::from_str(yaml).unwrap();
        let err = bootstrap_fleet(&cfg).unwrap_err().to_string();
        assert!(err.contains("duplicate subnet_base"));
    }

    #[test]
    fn rejects_zero_spokes_with_empty_default() {
        let yaml = r#"
default_spokes: []
portaos:
  - env_name: a
    subnet_base: "10.100.31"
    region: us-east-1
    aws_profile: a
"#;
        let cfg: FleetConfig = serde_yaml::from_str(yaml).unwrap();
        let err = bootstrap_fleet(&cfg).unwrap_err().to_string();
        assert!(err.contains("no spokes"));
    }

    #[test]
    fn ssm_param_paths_match_pangea_convention_per_env() {
        let cfg: FleetConfig = serde_yaml::from_str(three_portao_yaml()).unwrap();
        let out = bootstrap_fleet(&cfg).unwrap();
        assert_eq!(
            out.portaos[0].bootstrap.hub.ssm_private_key_param,
            "/portao/akeyless-cicd/hub-private-key"
        );
        assert_eq!(
            out.portaos[1].bootstrap.hub.ssm_private_key_param,
            "/portao/akeyless-staging-use2/hub-private-key"
        );
    }

    #[test]
    fn json_output_round_trips() {
        let cfg: FleetConfig = serde_yaml::from_str(three_portao_yaml()).unwrap();
        let out = bootstrap_fleet(&cfg).unwrap();
        let json = serde_json::to_string(&out).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["portaos"].as_array().unwrap().len(), 3);
        assert_eq!(parsed["portaos"][0]["env_name"], "akeyless-cicd");
        // Flattened bootstrap fields are present.
        assert!(parsed["portaos"][0]["hub"]["private_key"].as_str().is_some());
        // Custom fleet fields are present.
        assert_eq!(
            parsed["portaos"][0]["advertise_cidrs"][0],
            "10.0.0.0/16"
        );
    }

    #[test]
    fn load_config_reads_yaml_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("fleet.yaml");
        std::fs::write(&p, three_portao_yaml()).unwrap();
        let cfg = load_config(&p).unwrap();
        assert_eq!(cfg.portaos.len(), 3);
    }
}
