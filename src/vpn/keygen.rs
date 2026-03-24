//! Pure-Rust WireGuard key generation using x25519-dalek.
//!
//! Generates private keys, public keys, and pre-shared keys without shelling
//! out to `wg genkey`. Output is structured YAML with SOPS paths, or
//! machine-readable JSON when `--output json` is used.

use anyhow::Result;
use base64::Engine;
use x25519_dalek::{PublicKey, StaticSecret};

use super::validate::VALID_VPN_PROFILES;

/// A complete WireGuard key pair (private + public).
pub struct KeyPair {
    pub private_key: String,
    pub public_key: String,
}

/// Machine-readable keygen output (top-level).
#[derive(serde::Serialize)]
pub struct KeygenOutput {
    pub link: String,
    pub side_a: SideOutput,
    pub side_b: SideOutput,
    pub psk: String,
    pub sops_paths: SopsPathsOutput,
}

/// One side of a VPN link (node name + key pair).
#[derive(serde::Serialize)]
pub struct SideOutput {
    pub node: String,
    pub private_key: String,
    pub public_key: String,
}

/// SOPS secret paths for the generated keys.
#[derive(serde::Serialize)]
pub struct SopsPathsOutput {
    pub side_a_private_key: String,
    pub side_a_psk: String,
    pub side_b_private_key: String,
}

/// Generate a WireGuard key pair (Curve25519).
pub fn generate_keypair() -> KeyPair {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);

    let engine = base64::engine::general_purpose::STANDARD;
    KeyPair {
        private_key: engine.encode(secret.to_bytes()),
        public_key: engine.encode(public.to_bytes()),
    }
}

/// Generate a 256-bit pre-shared key.
pub fn generate_psk() -> String {
    let mut psk = [0u8; 32];
    rand::fill(&mut psk);
    base64::engine::general_purpose::STANDARD.encode(psk)
}

/// SOPS path conventions for VPN keys.
pub struct SopsPaths {
    pub side_a_private_key: String,
    pub side_a_psk: String,
    pub side_b_private_key: String,
}

/// Derive SOPS paths from link and node names following conventions:
/// - side a: `<node>/wireguard/<link>/private-key` and `<node>/wireguard/<link>/psk`
/// - side b: `clusters/<link>/wireguard/private-key`
pub fn sops_paths(link: &str, side_a: &str) -> SopsPaths {
    SopsPaths {
        side_a_private_key: format!("{}/wireguard/{}/private-key", side_a, link),
        side_a_psk: format!("{}/wireguard/{}/psk", side_a, link),
        side_b_private_key: format!("clusters/{}/wireguard/private-key", link),
    }
}

/// Profile-specific template hints.
struct ProfileHints {
    mtu: u16,
    keepalive: &'static str,
    comment: &'static str,
}

fn hints_for_profile(profile: &str) -> ProfileHints {
    match profile {
        "k8s-control-plane" => ProfileHints {
            mtu: 1420,
            keepalive: "# No persistentKeepalive for local links; add 25 for internet links",
            comment: "# Profile: k8s-control-plane — TCP 6443 only (kubectl API access)",
        },
        "k8s-full" => ProfileHints {
            mtu: 1420,
            keepalive: "    persistentKeepalive = 25;  # NAT traversal (multi-node cluster)",
            comment: "# Profile: k8s-full — TCP 6443, 10250, 10257, 10259 (full cluster access)",
        },
        "site-to-site" => ProfileHints {
            mtu: 1420,
            keepalive: "    persistentKeepalive = 25;  # LAN extension requires keepalive",
            comment: "# Profile: site-to-site — trustInterface=true (full LAN extension)",
        },
        "mesh" => ProfileHints {
            mtu: 1380,
            keepalive: "    persistentKeepalive = 25;  # Mesh requires keepalive",
            comment: "# Profile: mesh — trustInterface=true (all-to-all connectivity)",
        },
        _ => ProfileHints {
            mtu: 1420,
            keepalive: "# persistentKeepalive = 25;  # Uncomment for internet links",
            comment: "# Profile: custom",
        },
    }
}

/// Generate all keys for a VPN link and return a structured [`KeygenOutput`].
///
/// Validates the profile, generates two key pairs and a PSK, then assembles
/// the output struct. Does **not** print anything — the caller decides the
/// output format.
pub fn generate(link: &str, side_a: &str, side_b: &str, profile: &str) -> Result<KeygenOutput> {
    if !VALID_VPN_PROFILES.contains(&profile) {
        anyhow::bail!(
            "Unknown profile '{}'. Valid profiles: {:?}",
            profile,
            VALID_VPN_PROFILES
        );
    }

    let kp_a = generate_keypair();
    let kp_b = generate_keypair();
    let psk = generate_psk();
    let paths = sops_paths(link, side_a);

    Ok(KeygenOutput {
        link: link.to_owned(),
        side_a: SideOutput {
            node: side_a.to_owned(),
            private_key: kp_a.private_key,
            public_key: kp_a.public_key,
        },
        side_b: SideOutput {
            node: side_b.to_owned(),
            private_key: kp_b.private_key,
            public_key: kp_b.public_key,
        },
        psk,
        sops_paths: SopsPathsOutput {
            side_a_private_key: paths.side_a_private_key,
            side_a_psk: paths.side_a_psk,
            side_b_private_key: paths.side_b_private_key,
        },
    })
}

/// Generate all keys for a VPN link and print output.
///
/// When `output_format` is `"json"` the output is machine-readable JSON.
/// Any other value (including the default `"text"`) produces the original
/// human-readable YAML-ish output with inline Nix template hints.
pub fn run(link: &str, side_a: &str, side_b: &str, profile: &str, output_format: &str) -> Result<()> {
    let output = generate(link, side_a, side_b, profile)?;

    if output_format == "json" {
        let json = serde_json::to_string_pretty(&output)?;
        println!("{}", json);
        return Ok(());
    }

    // Human-readable text output (original format).
    let hints = hints_for_profile(profile);

    println!("# VPN keygen for link: {}", output.link);
    println!("# Side A: {} | Side B: {}", output.side_a.node, output.side_b.node);
    println!("{}", hints.comment);
    println!("#");
    println!("# Insert these values into SOPS secrets.yaml:");
    println!("#   cd ~/code/github/pleme-io/nix && sops secrets.yaml");
    println!();
    println!("side_a:");
    println!("  node: {}", output.side_a.node);
    println!("  private_key: {}", output.side_a.private_key);
    println!("  public_key: {}", output.side_a.public_key);
    println!("  sops_paths:");
    println!("    private_key: \"{}\"", output.sops_paths.side_a_private_key);
    println!("    psk: \"{}\"", output.sops_paths.side_a_psk);
    println!();
    println!("side_b:");
    println!("  node: {}", output.side_b.node);
    println!("  private_key: {}", output.side_b.private_key);
    println!("  public_key: {}", output.side_b.public_key);
    println!("  sops_paths:");
    println!("    private_key: \"{}\"", output.sops_paths.side_b_private_key);
    println!();
    println!("psk: {}", output.psk);
    println!();
    println!("# vpn-links.nix entry:");
    println!("  {} = {{", output.link);
    println!("    interface = \"wg-{}\";", output.link);
    println!("    subnet = \"10.100.X.0/24\";  # pick next available");
    println!("    profile = \"{}\";", profile);
    println!("    mtu = {};", hints.mtu);
    println!("{}", hints.keepalive);
    println!("    a = {{");
    println!("      node = \"{}\";", output.side_a.node);
    println!("      address = \"10.100.X.1/24\";");
    println!("      publicKey = \"{}\";", output.side_a.public_key);
    println!(
        "      secrets.privateKey = \"{}\";",
        output.sops_paths.side_a_private_key
    );
    println!("      secrets.psk = \"{}\";", output.sops_paths.side_a_psk);
    println!("    }};");
    println!("    b = {{");
    println!("      node = \"{}\";", output.side_b.node);
    println!("      address = \"10.100.X.2/24\";");
    println!("      listenPort = 518XX;");
    println!("      endpoint = \"<IP>:518XX\";");
    println!("      publicKey = \"{}\";", output.side_b.public_key);
    println!(
        "      secrets.privateKey = \"{}\";",
        output.sops_paths.side_b_private_key
    );
    println!("    }};");
    println!("  }};");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keypair_produces_valid_base64() {
        let kp = generate_keypair();
        let engine = base64::engine::general_purpose::STANDARD;
        let priv_bytes = engine.decode(&kp.private_key).unwrap();
        let pub_bytes = engine.decode(&kp.public_key).unwrap();
        assert_eq!(priv_bytes.len(), 32);
        assert_eq!(pub_bytes.len(), 32);
    }

    #[test]
    fn generate_keypair_derives_correct_public_key() {
        let kp = generate_keypair();
        let engine = base64::engine::general_purpose::STANDARD;
        let priv_bytes: [u8; 32] = engine
            .decode(&kp.private_key)
            .unwrap()
            .try_into()
            .unwrap();
        let secret = StaticSecret::from(priv_bytes);
        let expected_pub = PublicKey::from(&secret);
        let actual_pub_bytes = engine.decode(&kp.public_key).unwrap();
        assert_eq!(actual_pub_bytes.as_slice(), expected_pub.as_bytes());
    }

    #[test]
    fn generate_psk_is_32_bytes() {
        let psk = generate_psk();
        let engine = base64::engine::general_purpose::STANDARD;
        let bytes = engine.decode(&psk).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn keypairs_are_unique() {
        let kp1 = generate_keypair();
        let kp2 = generate_keypair();
        assert_ne!(kp1.private_key, kp2.private_key);
        assert_ne!(kp1.public_key, kp2.public_key);
    }

    #[test]
    fn sops_paths_follow_convention() {
        let paths = sops_paths("ryn-k3s", "ryn");
        assert_eq!(
            paths.side_a_private_key,
            "ryn/wireguard/ryn-k3s/private-key"
        );
        assert_eq!(paths.side_a_psk, "ryn/wireguard/ryn-k3s/psk");
        assert_eq!(
            paths.side_b_private_key,
            "clusters/ryn-k3s/wireguard/private-key"
        );
    }

    #[test]
    fn run_rejects_invalid_profile() {
        let err = run("test", "a", "b", "invalid-profile", "text").unwrap_err();
        assert!(err.to_string().contains("Unknown profile"));
    }

    #[test]
    fn run_succeeds_with_valid_profiles() {
        for profile in VALID_VPN_PROFILES {
            assert!(run("test", "nodeA", "nodeB", profile, "text").is_ok());
        }
    }

    #[test]
    fn generate_returns_structured_output() {
        let out = generate("ryn-k3s", "ryn", "k3s-vm", "k8s-control-plane").unwrap();
        assert_eq!(out.link, "ryn-k3s");
        assert_eq!(out.side_a.node, "ryn");
        assert_eq!(out.side_b.node, "k3s-vm");
        assert!(!out.psk.is_empty());
        assert_eq!(
            out.sops_paths.side_a_private_key,
            "ryn/wireguard/ryn-k3s/private-key"
        );
    }

    #[test]
    fn json_output_is_valid() {
        let out = generate("test-link", "nodeA", "nodeB", "k8s-control-plane").unwrap();
        let json = serde_json::to_string_pretty(&out).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["link"], "test-link");
        assert_eq!(parsed["side_a"]["node"], "nodeA");
        assert_eq!(parsed["side_b"]["node"], "nodeB");
        assert!(parsed["psk"].as_str().is_some());
        assert!(parsed["sops_paths"]["side_a_private_key"].as_str().is_some());
        assert!(parsed["sops_paths"]["side_a_psk"].as_str().is_some());
        assert!(parsed["sops_paths"]["side_b_private_key"].as_str().is_some());
    }
}
