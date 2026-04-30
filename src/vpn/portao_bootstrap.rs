//! Pure-Rust portao secret material bootstrap.
//!
//! Generates the WireGuard key material for a JIT WireGuard concentrator
//! deployment (`Pangea::Architectures::Portao` + `kindling-profiles/portao`):
//!
//!   - hub keypair                   → SSM SecureString
//!     `/portao/<env>/hub-private-key` (AMI's portao-init reads this)
//!   - per-spoke keypair + PSK       → SOPS at conventional paths
//!     - `<spoke>/wireguard/<env>/private-key`
//!     - `<spoke>/wireguard/<env>/psk`
//!   - hub address (highest /24 IP, by convention)
//!   - per-spoke /32 addresses (.1, .2, .3, … in the link's subnet)
//!   - peers.json content → SSM SecureString
//!     `/portao/<env>/peers.json` (AMI's portao-peer-refresh reads this)
//!
//! Output is structured (YAML or JSON) — no shell, no string-templated
//! Nix snippets. Callers (operator scripts, tatara-lisp orchestration,
//! future GitOps controllers) consume `PortaoBootstrap` directly.

use anyhow::Result;
use serde::Serialize;

use super::keygen::{generate_keypair, generate_psk};

/// Output of one portao bootstrap invocation.
#[derive(Debug, Serialize)]
pub struct PortaoBootstrap {
    /// Logical environment alias (akeyless-dev, akeyless-saas, …).
    pub env_name: String,
    /// CIDR of the WG /24 inside which spokes live (e.g. `10.100.30.0/24`).
    pub subnet_cidr: String,
    /// Hub WG-side address (interface address with prefix).
    pub hub_address: String,
    /// Hub keypair. Public key goes into `vpn-links.nix` `hub.publicKey`;
    /// private key goes into SSM SecureString.
    pub hub: HubKeys,
    /// Spoke entries, one per workstation that should reach the env.
    pub spokes: Vec<SpokeEntry>,
    /// SSM SecureString content for `/portao/<env>/peers.json` —
    /// consumed by the AMI's `portao-init` and `portao-peer-refresh`.
    pub peers_json: PeersJson,
    /// Pre-formatted SSM `put-parameter` commands. Operators run these
    /// after sopsing the hub private key.
    pub ssm_commands: SsmCommands,
}

#[derive(Debug, Serialize)]
pub struct HubKeys {
    pub private_key: String,
    pub public_key: String,
    /// SSM parameter path for the private key (SecureString).
    pub ssm_private_key_param: String,
    /// SSM parameter path for the public key (String — drift detection).
    pub ssm_public_key_param: String,
}

#[derive(Debug, Serialize)]
pub struct SpokeEntry {
    pub node: String,
    /// Spoke's WG-side interface address with /24 prefix.
    pub address: String,
    /// Spoke's address as the hub sees it: /32 single-IP for AllowedIPs.
    pub hub_view_address: String,
    pub private_key: String,
    pub public_key: String,
    pub psk: String,
    /// Conventional WG interface name on the spoke (e.g. `wg-ryn-ak`).
    pub interface: String,
    pub sops_paths: SpokeSopsPaths,
}

#[derive(Debug, Serialize)]
pub struct SpokeSopsPaths {
    pub private_key: String,
    pub psk: String,
}

#[derive(Debug, Serialize)]
pub struct PeersJson {
    pub hub_address: String,
    pub peers: Vec<PeersJsonEntry>,
}

#[derive(Debug, Serialize)]
pub struct PeersJsonEntry {
    pub name: String,
    pub public_key: String,
    pub psk: String,
    /// `/32` single-IP CIDR, suitable for the hub's per-peer
    /// `AllowedIPs` line.
    pub address: String,
}

#[derive(Debug, Serialize)]
pub struct SsmCommands {
    pub aws_profile: String,
    pub region: String,
    /// `aws ssm put-parameter` for the hub private key (SecureString).
    pub put_hub_private_key: String,
    /// `aws ssm put-parameter` for the peers.json (SecureString).
    pub put_peers_json: String,
}

/// Inputs to the bootstrap: env name + spoke alias list + subnet base.
#[derive(Debug)]
pub struct BootstrapInput<'a> {
    pub env_name: &'a str,
    /// e.g. `"10.100.30"` — the first three octets. Hub goes at .254,
    /// spokes at .1, .2, .3, …
    pub subnet_base: &'a str,
    pub spokes: &'a [&'a str],
    /// Conventional `wg-<spoke>-<env-shorthand>` interface naming.
    /// When `None`, derives from spoke + env (truncated to 15 chars).
    pub interface_suffix: Option<&'a str>,
    /// AWS region for the SSM put-parameter commands. Default `us-east-1`.
    pub region: &'a str,
    /// AWS profile for the SSM put-parameter commands.
    /// Default `akeyless-development`.
    pub aws_profile: &'a str,
}

impl<'a> BootstrapInput<'a> {
    /// Default interface naming: `wg-<spoke>-<short>` where `short` is
    /// the first three letters of the env's last hyphenated segment
    /// (akeyless-dev → "dev" → "wg-ryn-dev"; akeyless-saas → "saas" →
    /// "wg-ryn-saas"). Linux limits interface names to 15 chars; we
    /// don't enforce that here, the caller's `validate_vpn_links` does.
    fn interface_for(&self, spoke: &str) -> String {
        if let Some(suffix) = self.interface_suffix {
            return format!("wg-{spoke}-{suffix}");
        }
        let short = self
            .env_name
            .rsplit('-')
            .next()
            .unwrap_or(self.env_name)
            .chars()
            .take(3)
            .collect::<String>();
        format!("wg-{spoke}-{short}")
    }
}

/// Derive the conventional SOPS paths for a spoke under a hub-and-spoke
/// link. Mirrors the legacy 2-sided convention but with the env_name
/// (the hub-and-spoke link name) as the link slot.
pub fn spoke_sops_paths(spoke: &str, env_name: &str) -> SpokeSopsPaths {
    SpokeSopsPaths {
        private_key: format!("{spoke}/wireguard/{env_name}/private-key"),
        psk: format!("{spoke}/wireguard/{env_name}/psk"),
    }
}

/// Generate everything in one shot. Pure (other than RNG) — output is
/// fully determined by the input.
pub fn bootstrap(input: &BootstrapInput<'_>) -> Result<PortaoBootstrap> {
    if input.spokes.is_empty() {
        anyhow::bail!("portao-bootstrap requires at least one spoke");
    }
    if input.spokes.len() > 253 {
        anyhow::bail!(
            "portao subnet /24 has 253 usable host addresses; got {} spokes",
            input.spokes.len()
        );
    }

    let subnet_cidr = format!("{}.0/24", input.subnet_base);
    let hub_address = format!("{}.254/24", input.subnet_base);

    let hub_kp = generate_keypair();
    let hub = HubKeys {
        private_key: hub_kp.private_key.clone(),
        public_key: hub_kp.public_key.clone(),
        ssm_private_key_param: format!("/portao/{}/hub-private-key", input.env_name),
        ssm_public_key_param: format!("/portao/{}/hub-public-key", input.env_name),
    };

    let mut spokes = Vec::with_capacity(input.spokes.len());
    let mut peer_entries = Vec::with_capacity(input.spokes.len());

    for (i, spoke) in input.spokes.iter().enumerate() {
        let octet = i + 1;
        let address = format!("{}.{octet}/24", input.subnet_base);
        let hub_view_address = format!("{}.{octet}/32", input.subnet_base);

        let kp = generate_keypair();
        let psk = generate_psk();
        let sops = spoke_sops_paths(spoke, input.env_name);

        peer_entries.push(PeersJsonEntry {
            name: (*spoke).to_string(),
            public_key: kp.public_key.clone(),
            psk: psk.clone(),
            address: hub_view_address.clone(),
        });

        spokes.push(SpokeEntry {
            node: (*spoke).to_string(),
            address,
            hub_view_address,
            private_key: kp.private_key,
            public_key: kp.public_key,
            psk,
            interface: input.interface_for(spoke),
            sops_paths: sops,
        });
    }

    let peers_json = PeersJson {
        hub_address: hub_address.clone(),
        peers: peer_entries,
    };
    let peers_json_inline = serde_json::to_string(&peers_json)?;

    let ssm_commands = SsmCommands {
        aws_profile: input.aws_profile.to_owned(),
        region: input.region.to_owned(),
        put_hub_private_key: format!(
            "aws ssm put-parameter --profile {profile} --region {region} \
             --name {param} --type SecureString --overwrite --value '{value}'",
            profile = input.aws_profile,
            region = input.region,
            param = hub.ssm_private_key_param,
            value = hub.private_key,
        ),
        put_peers_json: format!(
            "aws ssm put-parameter --profile {profile} --region {region} \
             --name /portao/{env}/peers.json --type SecureString --overwrite --value '{value}'",
            profile = input.aws_profile,
            region = input.region,
            env = input.env_name,
            value = peers_json_inline,
        ),
    };

    Ok(PortaoBootstrap {
        env_name: input.env_name.to_owned(),
        subnet_cidr,
        hub_address,
        hub,
        spokes,
        peers_json,
        ssm_commands,
    })
}

/// Operator-facing report: print a structured YAML manifest of the
/// generated material plus actionable next-steps.
pub fn run(input: &BootstrapInput<'_>, output_format: &str) -> Result<()> {
    let out = bootstrap(input)?;

    match output_format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        "yaml" => {
            println!("{}", serde_yaml::to_string(&out)?);
        }
        _ => print_text(&out),
    }
    Ok(())
}

fn print_text(out: &PortaoBootstrap) {
    println!("# Portao bootstrap — env: {}", out.env_name);
    println!("# Subnet: {}", out.subnet_cidr);
    println!("# Hub address: {}", out.hub_address);
    println!();
    println!("# ── Step 1: paste into pleme-io/nix/secrets.yaml under sops ──");
    println!("# (run `sops secrets.yaml` and merge into existing keys)");
    println!();
    println!("clusters:");
    println!("    {}:", out.env_name);
    println!("        wireguard:");
    println!("            private-key: {}", out.hub.private_key);
    for s in &out.spokes {
        println!("{}:", s.node);
        println!("    wireguard:");
        println!("        {}:", out.env_name);
        println!("            private-key: {}", s.private_key);
        println!("            psk: {}", s.psk);
    }
    println!();
    println!("# ── Step 2: patch pleme-io/nix/lib/vpn-links.nix ──");
    println!("# Under `{} = {{ ... }}` block, set:", out.env_name);
    println!("    hub.publicKey = \"{}\";", out.hub.public_key);
    for s in &out.spokes {
        println!(
            "    spokes.{}.publicKey = \"{}\";",
            s.node, s.public_key
        );
    }
    println!();
    println!("# ── Step 3: seed SSM (after pangea apply on the workspace) ──");
    println!();
    println!("# Hub private key (SecureString):");
    println!("{}", out.ssm_commands.put_hub_private_key);
    println!();
    println!("# Peers registry (SecureString):");
    println!("{}", out.ssm_commands.put_peers_json);
    println!();
    println!("# ── Step 4: rebuild each spoke node ──");
    for s in &out.spokes {
        println!("#   {}: nix run .#rebuild  (from pleme-io/nix on that node)", s.node);
    }
    println!();
    println!("# Spoke interface naming (informational):");
    for s in &out.spokes {
        println!(
            "#   {} → interface={} address={} hub-view={}",
            s.node, s.interface, s.address, s.hub_view_address
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(env: &'a str, spokes: &'a [&'a str]) -> BootstrapInput<'a> {
        BootstrapInput {
            env_name: env,
            subnet_base: "10.100.30",
            spokes,
            interface_suffix: None,
            region: "us-east-1",
            aws_profile: "akeyless-development",
        }
    }

    #[test]
    fn rejects_empty_spokes() {
        let i = input("akeyless-dev", &[]);
        assert!(bootstrap(&i).is_err());
    }

    #[test]
    fn rejects_too_many_spokes() {
        let many = vec!["x"; 254];
        let many_refs: Vec<&str> = many.iter().copied().collect();
        let i = input("akeyless-dev", &many_refs);
        assert!(bootstrap(&i).is_err());
    }

    #[test]
    fn assigns_distinct_addresses() {
        let i = input("akeyless-dev", &["ryn", "cid", "rio"]);
        let out = bootstrap(&i).unwrap();
        assert_eq!(out.hub_address, "10.100.30.254/24");
        assert_eq!(out.spokes[0].address, "10.100.30.1/24");
        assert_eq!(out.spokes[0].hub_view_address, "10.100.30.1/32");
        assert_eq!(out.spokes[1].address, "10.100.30.2/24");
        assert_eq!(out.spokes[2].address, "10.100.30.3/24");
    }

    #[test]
    fn ssm_paths_match_pangea_architecture_convention() {
        let i = input("akeyless-dev", &["ryn"]);
        let out = bootstrap(&i).unwrap();
        assert_eq!(
            out.hub.ssm_private_key_param,
            "/portao/akeyless-dev/hub-private-key"
        );
        assert_eq!(
            out.hub.ssm_public_key_param,
            "/portao/akeyless-dev/hub-public-key"
        );
    }

    #[test]
    fn sops_paths_match_vpn_links_convention() {
        let i = input("akeyless-dev", &["ryn", "cid"]);
        let out = bootstrap(&i).unwrap();
        assert_eq!(
            out.spokes[0].sops_paths.private_key,
            "ryn/wireguard/akeyless-dev/private-key"
        );
        assert_eq!(
            out.spokes[0].sops_paths.psk,
            "ryn/wireguard/akeyless-dev/psk"
        );
        assert_eq!(
            out.spokes[1].sops_paths.private_key,
            "cid/wireguard/akeyless-dev/private-key"
        );
    }

    #[test]
    fn peers_json_uses_hub_view_addresses() {
        let i = input("akeyless-dev", &["ryn", "cid", "rio"]);
        let out = bootstrap(&i).unwrap();
        assert_eq!(out.peers_json.hub_address, "10.100.30.254/24");
        assert_eq!(out.peers_json.peers.len(), 3);
        assert_eq!(out.peers_json.peers[0].address, "10.100.30.1/32");
        assert_eq!(out.peers_json.peers[2].name, "rio");
    }

    #[test]
    fn each_spoke_has_unique_keypair() {
        let i = input("akeyless-dev", &["ryn", "cid", "rio"]);
        let out = bootstrap(&i).unwrap();
        let pubs: Vec<_> = out.spokes.iter().map(|s| &s.public_key).collect();
        assert_ne!(pubs[0], pubs[1]);
        assert_ne!(pubs[1], pubs[2]);
        assert_ne!(out.hub.public_key, *pubs[0]);
    }

    #[test]
    fn each_spoke_has_unique_psk() {
        let i = input("akeyless-dev", &["ryn", "cid", "rio"]);
        let out = bootstrap(&i).unwrap();
        assert_ne!(out.spokes[0].psk, out.spokes[1].psk);
    }

    #[test]
    fn interface_naming_default_truncates_env_to_3_chars() {
        let i = input("akeyless-dev", &["ryn"]);
        let out = bootstrap(&i).unwrap();
        assert_eq!(out.spokes[0].interface, "wg-ryn-dev");
    }

    #[test]
    fn interface_naming_explicit_suffix_wins() {
        let mut i = input("akeyless-dev", &["ryn"]);
        i.interface_suffix = Some("ak");
        let out = bootstrap(&i).unwrap();
        assert_eq!(out.spokes[0].interface, "wg-ryn-ak");
    }

    #[test]
    fn ssm_commands_inline_the_credentials() {
        let i = input("akeyless-dev", &["ryn"]);
        let out = bootstrap(&i).unwrap();
        assert!(out
            .ssm_commands
            .put_hub_private_key
            .contains(&out.hub.private_key));
        assert!(out
            .ssm_commands
            .put_peers_json
            .contains("/portao/akeyless-dev/peers.json"));
    }

    #[test]
    fn json_output_is_round_trippable() {
        let i = input("akeyless-dev", &["ryn", "cid"]);
        let out = bootstrap(&i).unwrap();
        let json = serde_json::to_string(&out).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["env_name"], "akeyless-dev");
        assert_eq!(parsed["spokes"].as_array().unwrap().len(), 2);
    }
}
