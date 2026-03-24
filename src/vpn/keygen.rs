//! Pure-Rust WireGuard key generation using x25519-dalek.
//!
//! Generates private keys, public keys, and pre-shared keys without shelling
//! out to `wg genkey`. Output is structured YAML with SOPS paths.

use anyhow::Result;
use base64::Engine;
use x25519_dalek::{PublicKey, StaticSecret};

use super::validate::VALID_VPN_PROFILES;

/// A complete WireGuard key pair (private + public).
pub struct KeyPair {
    pub private_key: String,
    pub public_key: String,
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

/// Generate all keys for a VPN link and print structured YAML output.
pub fn run(link: &str, side_a: &str, side_b: &str, profile: &str) -> Result<()> {
    // Validate profile
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
    let hints = hints_for_profile(profile);

    println!("# VPN keygen for link: {}", link);
    println!("# Side A: {} | Side B: {}", side_a, side_b);
    println!("{}", hints.comment);
    println!("#");
    println!("# Insert these values into SOPS secrets.yaml:");
    println!("#   cd ~/code/github/pleme-io/nix && sops secrets.yaml");
    println!();
    println!("side_a:");
    println!("  node: {}", side_a);
    println!("  private_key: {}", kp_a.private_key);
    println!("  public_key: {}", kp_a.public_key);
    println!("  sops_paths:");
    println!("    private_key: \"{}\"", paths.side_a_private_key);
    println!("    psk: \"{}\"", paths.side_a_psk);
    println!();
    println!("side_b:");
    println!("  node: {}", side_b);
    println!("  private_key: {}", kp_b.private_key);
    println!("  public_key: {}", kp_b.public_key);
    println!("  sops_paths:");
    println!("    private_key: \"{}\"", paths.side_b_private_key);
    println!();
    println!("psk: {}", psk);
    println!();
    println!("# vpn-links.nix entry:");
    println!("  {} = {{", link);
    println!("    interface = \"wg-{}\";", link);
    println!("    subnet = \"10.100.X.0/24\";  # pick next available");
    println!("    profile = \"{}\";", profile);
    println!("    mtu = {};", hints.mtu);
    println!("{}", hints.keepalive);
    println!("    a = {{");
    println!("      node = \"{}\";", side_a);
    println!("      address = \"10.100.X.1/24\";");
    println!("      publicKey = \"{}\";", kp_a.public_key);
    println!(
        "      secrets.privateKey = \"{}\";",
        paths.side_a_private_key
    );
    println!("      secrets.psk = \"{}\";", paths.side_a_psk);
    println!("    }};");
    println!("    b = {{");
    println!("      node = \"{}\";", side_b);
    println!("      address = \"10.100.X.2/24\";");
    println!("      listenPort = 518XX;");
    println!("      endpoint = \"<IP>:518XX\";");
    println!("      publicKey = \"{}\";", kp_b.public_key);
    println!(
        "      secrets.privateKey = \"{}\";",
        paths.side_b_private_key
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
        let err = run("test", "a", "b", "invalid-profile").unwrap_err();
        assert!(err.to_string().contains("Unknown profile"));
    }

    #[test]
    fn run_succeeds_with_valid_profiles() {
        for profile in VALID_VPN_PROFILES {
            assert!(run("test", "nodeA", "nodeB", profile).is_ok());
        }
    }
}
