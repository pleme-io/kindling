//! Shared VPN security validation logic.
//!
//! Extracted from `server::cluster_config` so both the bootstrap path and the
//! `kindling vpn validate` CLI command can share the same validation.
//!
//! Security invariants enforced (least privilege, defense in depth):
//!
//!  1. Every link MUST have a private_key_file (no cleartext keys)
//!  2. Every link MUST have an address (interface must be bound)
//!  3. Every link MUST have at least one peer
//!  4. Every peer MUST have a public_key
//!  5. Every peer MUST have at least one allowed_ips entry
//!  6. No peer may have 0.0.0.0/0 in allowed_ips (no full tunnel)
//!  7. No peer may have ::/0 in allowed_ips (same for IPv6)
//!  8. Every peer MUST have a preshared_key_file (post-quantum resistance)
//!  9. Firewall MUST be present on every link
//! 10. trust_interface MUST be false for k8s profiles
//! 11. k8s profiles MUST have explicit port allowlists
//! 12. Link names must be valid interface names (max 15 chars)
//! 13. Profiles must be from the known set
//! 14. listen_port requires incoming_udp_port in firewall
//! 15. Key files must exist on disk (with --check-files)
//! 16. Key files must have restrictive permissions (with --check-files)

use anyhow::{bail, Result};
use std::path::Path;

/// Known VPN profiles and their allowed firewall configurations.
///
/// CANONICAL SOURCE: blackmatter-vpn lib/profiles.nix
/// Also validated in pangea-kubernetes types/vpn_config.rb (VALID_VPN_PROFILES).
/// Keep all three in sync.
pub const VALID_VPN_PROFILES: &[&str] = &[
    "k8s-control-plane",
    "k8s-full",
    "site-to-site",
    "mesh",
];

/// A VPN link to validate. This trait-free struct mirrors the fields needed
/// for validation without coupling to cluster_config or node_identity types.
pub struct VpnLink<'a> {
    pub name: &'a str,
    pub private_key_file: Option<&'a str>,
    pub listen_port: Option<u32>,
    pub address: Option<&'a str>,
    pub profile: Option<&'a str>,
    pub persistent_keepalive: Option<u32>,
    pub peers: Vec<VpnPeer<'a>>,
    pub firewall: Option<VpnFirewall<'a>>,
}

pub struct VpnPeer<'a> {
    pub public_key: Option<&'a str>,
    pub endpoint: Option<&'a str>,
    pub allowed_ips: &'a [String],
    pub persistent_keepalive: Option<u32>,
    pub preshared_key_file: Option<&'a str>,
}

pub struct VpnFirewall<'a> {
    pub trust_interface: bool,
    pub allowed_tcp_ports: &'a [u32],
    pub allowed_udp_ports: &'a [u32],
    pub incoming_udp_port: Option<u32>,
}

/// Validate a string is valid CIDR notation (IPv4 or IPv6).
pub fn validate_cidr(cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.splitn(2, '/').collect();
    if parts.len() != 2 {
        return false;
    }
    let ip_str = parts[0];
    let prefix_str = parts[1];

    let ip: std::net::IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    let prefix: u8 = match prefix_str.parse() {
        Ok(p) => p,
        Err(_) => return false,
    };

    match ip {
        std::net::IpAddr::V4(_) => prefix <= 32,
        std::net::IpAddr::V6(_) => prefix <= 128,
    }
}

/// Validate a string is a valid endpoint (host:port).
pub fn validate_endpoint(endpoint: &str) -> bool {
    // Handle IPv6 endpoints like [::1]:51820
    if let Some(bracket_end) = endpoint.find("]:") {
        let port_str = &endpoint[bracket_end + 2..];
        let host = &endpoint[..bracket_end + 1];
        if host.len() < 3 {
            return false;
        }
        match port_str.parse::<u16>() {
            Ok(p) => p >= 1,
            Err(_) => false,
        }
    } else {
        match endpoint.rfind(':') {
            Some(pos) => {
                let host = &endpoint[..pos];
                let port_str = &endpoint[pos + 1..];
                if host.is_empty() {
                    return false;
                }
                match port_str.parse::<u16>() {
                    Ok(p) => p >= 1,
                    Err(_) => false,
                }
            }
            None => false,
        }
    }
}

/// Validate a key file exists and has secure permissions.
pub fn validate_key_file(errors: &mut Vec<String>, ctx: &str, field: &str, path: &str) {
    let p = Path::new(path);
    if !p.exists() {
        errors.push(format!("{}: {} '{}' does not exist on disk", ctx, field, path));
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(p) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                errors.push(format!(
                    "{}: {} '{}' has insecure permissions {:o} \
                     (must not be group/world-readable, expected 0400 or 0600)",
                    ctx, field, path, mode
                ));
            }
        }
    }
}

/// Core VPN validation logic shared between bootstrap and CLI.
///
/// `check_files`: when true, also verify key files exist on disk with correct permissions.
pub fn validate_vpn_links(links: &[VpnLink<'_>], check_files: bool) -> Result<()> {
    if links.is_empty() {
        return Ok(());
    }

    let mut errors: Vec<String> = Vec::new();

    for (i, link) in links.iter().enumerate() {
        let ctx = format!("vpn.links[{}] ({})", i, link.name);

        // 12. Interface name validation
        if link.name.is_empty() {
            errors.push(format!("{}: name must not be empty", ctx));
        } else if link.name.len() > 15 {
            errors.push(format!(
                "{}: name exceeds 15 chars (Linux interface name limit)",
                ctx
            ));
        } else if !link.name.chars().all(|c| c.is_alphanumeric() || c == '-') {
            errors.push(format!(
                "{}: name contains invalid characters (only alphanumeric and dash allowed)",
                ctx
            ));
        }

        // 1. Private key file mandatory
        if link.private_key_file.is_none() {
            errors.push(format!(
                "{}: private_key_file is required (no cleartext keys)",
                ctx
            ));
        }

        // 2. Address mandatory
        if link.address.is_none() {
            errors.push(format!(
                "{}: address is required (interface must be bound)",
                ctx
            ));
        }

        // Address CIDR syntax validation
        if let Some(addr) = link.address {
            if !validate_cidr(addr) {
                errors.push(format!(
                    "{}: address '{}' is not a valid CIDR (expected format: IP/prefix)",
                    ctx, addr
                ));
            }
        }

        // 3. At least one peer
        if link.peers.is_empty() {
            errors.push(format!("{}: at least one peer is required", ctx));
        }

        // 13. Profile validation
        if let Some(profile) = link.profile {
            if !VALID_VPN_PROFILES.contains(&profile) {
                errors.push(format!(
                    "{}: unknown profile '{}' (valid: {:?})",
                    ctx, profile, VALID_VPN_PROFILES
                ));
            }
        }

        // 9. Firewall mandatory
        let firewall = match &link.firewall {
            Some(fw) => Some(fw),
            None => {
                errors.push(format!(
                    "{}: firewall config is required (explicit firewall rules mandatory)",
                    ctx
                ));
                None
            }
        };

        // 10 + 11. Profile-specific firewall enforcement
        let is_k8s_profile = link
            .profile
            .map_or(false, |p| p.starts_with("k8s-"));
        if is_k8s_profile {
            if let Some(fw) = firewall {
                if fw.trust_interface {
                    errors.push(format!(
                        "{}: trust_interface must be false for k8s profiles (defense in depth)",
                        ctx
                    ));
                }
                if fw.allowed_tcp_ports.is_empty() && fw.allowed_udp_ports.is_empty() {
                    errors.push(format!(
                        "{}: k8s profile requires explicit port allowlist in firewall",
                        ctx
                    ));
                }
            }
        }

        // 14. Server listen port firewall consistency
        if let Some(port) = link.listen_port {
            if port > 0 {
                if let Some(fw) = firewall {
                    if fw.incoming_udp_port.is_none() {
                        errors.push(format!(
                            "{}: listen_port {} set but firewall.incoming_udp_port not set \
                             (firewall must explicitly allow the listen port)",
                            ctx, port
                        ));
                    }
                }
            }
        }

        // Listen port range validation
        if let Some(port) = link.listen_port {
            if port != 0 && (port < 1024 || port > 65535) {
                errors.push(format!(
                    "{}: listen_port {} is outside valid range (must be 0 for random, or 1024-65535)",
                    ctx, port
                ));
            }
        }

        // Persistent keepalive range (link-level)
        if let Some(ka) = link.persistent_keepalive {
            if ka > 65535 {
                errors.push(format!(
                    "{}: persistent_keepalive {} exceeds maximum (0-65535)",
                    ctx, ka
                ));
            }
        }

        // Per-peer validation
        for (j, peer) in link.peers.iter().enumerate() {
            let pctx = format!("{}.peers[{}]", ctx, j);

            // 4. Public key mandatory
            if peer.public_key.is_none() {
                errors.push(format!("{}: public_key is required", pctx));
            }

            // 5. Allowed IPs mandatory
            if peer.allowed_ips.is_empty() {
                errors.push(format!(
                    "{}: allowed_ips must not be empty (routes must be explicit)",
                    pctx
                ));
            }

            // 6 + 7. No full tunnel
            for ip in peer.allowed_ips {
                let normalized = ip.trim();
                if normalized == "0.0.0.0/0" || normalized == "::/0" {
                    errors.push(format!(
                        "{}: allowed_ips contains '{}' (full tunnel forbidden — use split tunnel with scoped CIDRs)",
                        pctx, normalized
                    ));
                }
            }

            // Validate CIDR syntax in allowed_ips
            for ip in peer.allowed_ips {
                let trimmed = ip.trim();
                if trimmed != "0.0.0.0/0" && trimmed != "::/0" && !validate_cidr(trimmed) {
                    errors.push(format!(
                        "{}: allowed_ips entry '{}' is not a valid CIDR",
                        pctx, trimmed
                    ));
                }
            }

            // Validate endpoint format
            if let Some(ep) = peer.endpoint {
                if !validate_endpoint(ep) {
                    errors.push(format!(
                        "{}: endpoint '{}' is not valid (expected host:port with port 1-65535)",
                        pctx, ep
                    ));
                }
            }

            // Per-peer keepalive range
            if let Some(ka) = peer.persistent_keepalive {
                if ka > 65535 {
                    errors.push(format!(
                        "{}: persistent_keepalive {} exceeds maximum (0-65535)",
                        pctx, ka
                    ));
                }
            }

            // 8. Pre-shared key mandatory
            if peer.preshared_key_file.is_none() {
                errors.push(format!(
                    "{}: preshared_key_file is required (post-quantum resistance mandatory)",
                    pctx
                ));
            }

            // 15+16. PSK file checks
            if check_files {
                if let Some(psk_path) = peer.preshared_key_file {
                    validate_key_file(&mut errors, &pctx, "preshared_key_file", psk_path);
                }
            }
        }

        // 15+16. Private key file checks
        if check_files {
            if let Some(key_path) = link.private_key_file {
                validate_key_file(&mut errors, &ctx, "private_key_file", key_path);
            }
        }
    }

    // Cross-link collision detection
    {
        use std::collections::HashSet;

        let mut seen_names: HashSet<&str> = HashSet::new();
        for link in links {
            if !seen_names.insert(link.name) {
                errors.push(format!("vpn: duplicate link name '{}'", link.name));
            }
        }

        let mut seen_ports: HashSet<u32> = HashSet::new();
        for link in links {
            if let Some(port) = link.listen_port {
                if port > 0 && !seen_ports.insert(port) {
                    errors.push(format!(
                        "vpn: duplicate listen_port {} (link '{}')",
                        port, link.name
                    ));
                }
            }
        }

        let mut seen_addrs: HashSet<&str> = HashSet::new();
        for link in links {
            if let Some(addr) = link.address {
                if !seen_addrs.insert(addr) {
                    errors.push(format!(
                        "vpn: duplicate address '{}' (link '{}')",
                        addr, link.name
                    ));
                }
            }
        }

        for link in links {
            let mut seen_keys: HashSet<&str> = HashSet::new();
            for peer in &link.peers {
                if let Some(key) = peer.public_key {
                    if !seen_keys.insert(key) {
                        errors.push(format!(
                            "vpn.links ({}).peers: duplicate public_key '{}'",
                            link.name, key
                        ));
                    }
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        let msg = format!(
            "VPN security validation failed — node will NOT bootstrap.\n\
             {} violation(s) detected:\n  - {}",
            errors.len(),
            errors.join("\n  - ")
        );
        bail!(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_cidr_ipv4() {
        assert!(validate_cidr("10.100.1.1/24"));
        assert!(validate_cidr("192.168.1.0/32"));
        assert!(validate_cidr("0.0.0.0/0"));
    }

    #[test]
    fn valid_cidr_ipv6() {
        assert!(validate_cidr("::1/128"));
        assert!(validate_cidr("::/0"));
    }

    #[test]
    fn invalid_cidr() {
        assert!(!validate_cidr("10.100.1.1"));
        assert!(!validate_cidr("not-an-ip/24"));
        assert!(!validate_cidr("10.0.0.1/33"));
    }

    #[test]
    fn valid_endpoint() {
        assert!(validate_endpoint("192.168.64.3:51821"));
        assert!(validate_endpoint("example.com:51820"));
        assert!(validate_endpoint("[::1]:51820"));
    }

    #[test]
    fn invalid_endpoint() {
        assert!(!validate_endpoint("192.168.64.3"));
        assert!(!validate_endpoint(":51820"));
        assert!(!validate_endpoint("host:0"));
    }

    fn valid_allowed_ips() -> Vec<String> {
        vec!["10.100.1.2/32".to_string()]
    }

    fn make_valid_link(allowed_ips: &[String]) -> VpnLink<'_> {
        static TCP_PORTS: [u32; 1] = [6443];
        static UDP_PORTS: [u32; 0] = [];
        VpnLink {
            name: "wg-test",
            private_key_file: Some("/tmp/key"),
            listen_port: Some(51821),
            address: Some("10.100.1.1/24"),
            profile: Some("k8s-control-plane"),
            persistent_keepalive: None,
            peers: vec![VpnPeer {
                public_key: Some("AAAA"),
                endpoint: Some("192.168.1.1:51821"),
                allowed_ips,
                persistent_keepalive: None,
                preshared_key_file: Some("/tmp/psk"),
            }],
            firewall: Some(VpnFirewall {
                trust_interface: false,
                allowed_tcp_ports: &TCP_PORTS,
                allowed_udp_ports: &UDP_PORTS,
                incoming_udp_port: Some(51821),
            }),
        }
    }

    #[test]
    fn valid_config_passes() {
        let ips = valid_allowed_ips();
        let link = make_valid_link(&ips);
        assert!(validate_vpn_links(&[link], false).is_ok());
    }

    #[test]
    fn empty_links_passes() {
        assert!(validate_vpn_links(&[], false).is_ok());
    }

    #[test]
    fn rejects_missing_private_key() {
        let ips = valid_allowed_ips();
        let mut link = make_valid_link(&ips);
        link.private_key_file = None;
        let err = validate_vpn_links(&[link], false).unwrap_err();
        assert!(err.to_string().contains("private_key_file is required"));
    }

    #[test]
    fn rejects_full_tunnel() {
        let full_tunnel = vec!["0.0.0.0/0".to_string()];
        static EMPTY_TCP: [u32; 0] = [];
        static EMPTY_UDP: [u32; 0] = [];
        let link = VpnLink {
            name: "wg-test",
            private_key_file: Some("/tmp/key"),
            listen_port: None,
            address: Some("10.100.1.1/24"),
            profile: Some("site-to-site"),
            persistent_keepalive: None,
            peers: vec![VpnPeer {
                public_key: Some("AAAA"),
                endpoint: Some("1.2.3.4:51820"),
                allowed_ips: &full_tunnel,
                persistent_keepalive: None,
                preshared_key_file: Some("/tmp/psk"),
            }],
            firewall: Some(VpnFirewall {
                trust_interface: false,
                allowed_tcp_ports: &EMPTY_TCP,
                allowed_udp_ports: &EMPTY_UDP,
                incoming_udp_port: None,
            }),
        };
        let err = validate_vpn_links(&[link], false).unwrap_err();
        assert!(err.to_string().contains("full tunnel forbidden"));
    }

    #[test]
    fn rejects_long_interface_name() {
        let ips = valid_allowed_ips();
        let mut link = make_valid_link(&ips);
        link.name = "this-name-is-way-too-long";
        let err = validate_vpn_links(&[link], false).unwrap_err();
        assert!(err.to_string().contains("exceeds 15 chars"));
    }

    #[test]
    fn rejects_unknown_profile() {
        let ips = valid_allowed_ips();
        let mut link = make_valid_link(&ips);
        link.profile = Some("unknown-profile");
        let err = validate_vpn_links(&[link], false).unwrap_err();
        assert!(err.to_string().contains("unknown profile"));
    }

    // ── validate_key_file tests ──────────────────────────────

    #[test]
    fn validate_key_file_nonexistent() {
        let mut errors = Vec::new();
        validate_key_file(&mut errors, "test-ctx", "private_key_file", "/nonexistent/key");
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("does not exist on disk"));
    }

    #[cfg(unix)]
    #[test]
    fn validate_key_file_insecure_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key");
        std::fs::write(&key_path, "secret").unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let mut errors = Vec::new();
        validate_key_file(&mut errors, "ctx", "field", key_path.to_str().unwrap());
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("insecure permissions"));
    }

    #[cfg(unix)]
    #[test]
    fn validate_key_file_secure_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key");
        std::fs::write(&key_path, "secret").unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let mut errors = Vec::new();
        validate_key_file(&mut errors, "ctx", "field", key_path.to_str().unwrap());
        assert!(errors.is_empty());
    }

    // ── Interface name character validation ──────────────────────────────

    #[test]
    fn rejects_interface_with_special_chars() {
        let ips = valid_allowed_ips();
        let mut link = make_valid_link(&ips);
        link.name = "wg_0";
        let err = validate_vpn_links(&[link], false).unwrap_err();
        assert!(err.to_string().contains("invalid characters"));
    }

    #[test]
    fn rejects_empty_interface_name() {
        let ips = valid_allowed_ips();
        let mut link = make_valid_link(&ips);
        link.name = "";
        let err = validate_vpn_links(&[link], false).unwrap_err();
        assert!(err.to_string().contains("name must not be empty"));
    }

    #[test]
    fn accepts_15_char_interface_name() {
        let ips = valid_allowed_ips();
        let mut link = make_valid_link(&ips);
        link.name = "wg-exactly15chr";
        assert_eq!(link.name.len(), 15);
        assert!(validate_vpn_links(&[link], false).is_ok());
    }

    // ── Missing address ──────────────────────────────

    #[test]
    fn rejects_missing_address() {
        let ips = valid_allowed_ips();
        let mut link = make_valid_link(&ips);
        link.address = None;
        let err = validate_vpn_links(&[link], false).unwrap_err();
        assert!(err.to_string().contains("address is required"));
    }

    // ── Missing firewall ──────────────────────────────

    #[test]
    fn rejects_missing_firewall() {
        let ips = valid_allowed_ips();
        let mut link = make_valid_link(&ips);
        link.firewall = None;
        let err = validate_vpn_links(&[link], false).unwrap_err();
        assert!(err.to_string().contains("firewall config is required"));
    }

    // ── Duplicate link names ──────────────────────────────

    #[test]
    fn rejects_duplicate_link_names() {
        let ips = valid_allowed_ips();
        let link1 = make_valid_link(&ips);
        let ips2 = valid_allowed_ips();
        let mut link2 = make_valid_link(&ips2);
        link2.listen_port = Some(51822);
        link2.address = Some("10.100.2.1/24");
        let err = validate_vpn_links(&[link1, link2], false).unwrap_err();
        assert!(err.to_string().contains("duplicate link name"));
    }

    // ── Privileged port ──────────────────────────────

    #[test]
    fn rejects_privileged_listen_port() {
        let ips = valid_allowed_ips();
        let mut link = make_valid_link(&ips);
        link.listen_port = Some(80);
        let err = validate_vpn_links(&[link], false).unwrap_err();
        assert!(err.to_string().contains("outside valid range"));
    }

    // ── No peers ──────────────────────────────

    #[test]
    fn rejects_no_peers() {
        let ips = valid_allowed_ips();
        let mut link = make_valid_link(&ips);
        link.peers = vec![];
        let err = validate_vpn_links(&[link], false).unwrap_err();
        assert!(err.to_string().contains("at least one peer is required"));
    }

    // ── Peer missing public key ──────────────────────────────

    #[test]
    fn rejects_peer_missing_public_key() {
        let ips = valid_allowed_ips();
        let mut link = make_valid_link(&ips);
        link.peers[0].public_key = None;
        let err = validate_vpn_links(&[link], false).unwrap_err();
        assert!(err.to_string().contains("public_key is required"));
    }

    // ── IPv6 full tunnel ──────────────────────────────

    #[test]
    fn rejects_ipv6_full_tunnel() {
        let full_tunnel = vec!["::/0".to_string()];
        static EMPTY_TCP: [u32; 0] = [];
        static EMPTY_UDP: [u32; 0] = [];
        let link = VpnLink {
            name: "wg-test",
            private_key_file: Some("/tmp/key"),
            listen_port: None,
            address: Some("10.100.1.1/24"),
            profile: Some("site-to-site"),
            persistent_keepalive: None,
            peers: vec![VpnPeer {
                public_key: Some("AAAA"),
                endpoint: Some("1.2.3.4:51820"),
                allowed_ips: &full_tunnel,
                persistent_keepalive: None,
                preshared_key_file: Some("/tmp/psk"),
            }],
            firewall: Some(VpnFirewall {
                trust_interface: false,
                allowed_tcp_ports: &EMPTY_TCP,
                allowed_udp_ports: &EMPTY_UDP,
                incoming_udp_port: None,
            }),
        };
        let err = validate_vpn_links(&[link], false).unwrap_err();
        assert!(err.to_string().contains("full tunnel forbidden"));
    }

    // ── check_files validates key files on disk ──────────────────────────────

    #[test]
    fn check_files_reports_missing_private_key() {
        let ips = valid_allowed_ips();
        let mut link = make_valid_link(&ips);
        link.private_key_file = Some("/nonexistent/private.key");
        let err = validate_vpn_links(&[link], true).unwrap_err();
        assert!(err.to_string().contains("does not exist on disk"));
    }

    // ── Profile-specific enforcement ──────────────────────────────

    #[test]
    fn k8s_profile_rejects_trust_interface() {
        let ips = valid_allowed_ips();
        static TCP_PORTS: [u32; 1] = [6443];
        static EMPTY_UDP: [u32; 0] = [];
        let link = VpnLink {
            name: "wg-test",
            private_key_file: Some("/tmp/key"),
            listen_port: Some(51821),
            address: Some("10.100.1.1/24"),
            profile: Some("k8s-control-plane"),
            persistent_keepalive: None,
            peers: vec![VpnPeer {
                public_key: Some("AAAA"),
                endpoint: Some("1.2.3.4:51820"),
                allowed_ips: &ips,
                persistent_keepalive: None,
                preshared_key_file: Some("/tmp/psk"),
            }],
            firewall: Some(VpnFirewall {
                trust_interface: true,
                allowed_tcp_ports: &TCP_PORTS,
                allowed_udp_ports: &EMPTY_UDP,
                incoming_udp_port: Some(51821),
            }),
        };
        let err = validate_vpn_links(&[link], false).unwrap_err();
        assert!(err.to_string().contains("trust_interface must be false"));
    }

    // ── No profile skips profile-specific checks ──────────────────────────────

    #[test]
    fn no_profile_allows_trust_interface() {
        let ips = valid_allowed_ips();
        static TCP_PORTS: [u32; 1] = [6443];
        static EMPTY_UDP: [u32; 0] = [];
        let link = VpnLink {
            name: "wg-test",
            private_key_file: Some("/tmp/key"),
            listen_port: Some(51821),
            address: Some("10.100.1.1/24"),
            profile: None,
            persistent_keepalive: None,
            peers: vec![VpnPeer {
                public_key: Some("AAAA"),
                endpoint: Some("1.2.3.4:51820"),
                allowed_ips: &ips,
                persistent_keepalive: None,
                preshared_key_file: Some("/tmp/psk"),
            }],
            firewall: Some(VpnFirewall {
                trust_interface: true,
                allowed_tcp_ports: &TCP_PORTS,
                allowed_udp_ports: &EMPTY_UDP,
                incoming_udp_port: Some(51821),
            }),
        };
        assert!(validate_vpn_links(&[link], false).is_ok());
    }
}
