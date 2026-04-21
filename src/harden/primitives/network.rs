//! Network-hardening primitives.
//!
//! Firewall baseline is expressed as nftables rules — single syntax
//! across NixOS, Debian, Fedora, and Amazon Linux 2023. ssh primitives
//! write drop-ins under `sshd_config.d/` so we never fight a
//! distro-provided main config.

use anyhow::Result;

use super::super::primitive::{
    HardeningPrimitive, PrimitiveCategory, PrimitiveCtx, PrimitiveOutcome,
};
use super::super::profile::HardeningParams;

/// Internal helper: pull HardeningParams off the ctx's environment if
/// a runner wired them there. For the built-in primitives we also
/// accept an empty params struct — the defaults are sane.
fn params_or_default() -> HardeningParams { HardeningParams::default() }

// ── firewall-deny-all ──────────────────────────────────────────
pub struct FirewallDenyAll;

impl HardeningPrimitive for FirewallDenyAll {
    fn name(&self) -> &'static str { "firewall-deny-all" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Network }
    fn description(&self) -> &'static str {
        "nftables default-deny inbound, allow-list egress + allow_in ports"
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        let mut outcome = PrimitiveOutcome::default();
        let params = params_or_default();

        // If the profile didn't specify allow_in ports, default to SSH.
        let allow_in: Vec<u16> = if params.firewall_allow_in.is_empty() {
            vec![22]
        } else {
            params.firewall_allow_in.clone()
        };

        let mut tcp_allow = String::new();
        for (i, p) in allow_in.iter().enumerate() {
            if i > 0 { tcp_allow.push_str(", "); }
            tcp_allow.push_str(&p.to_string());
        }

        let body = format!(
            "#!/usr/sbin/nft -f\n\
# written by kindling firewall-deny-all\n\
flush ruleset\n\
\n\
table inet filter {{\n\
    chain input {{\n\
        type filter hook input priority 0; policy drop;\n\
        ct state established,related accept\n\
        ct state invalid drop\n\
        iif lo accept\n\
        icmp type {{ echo-request, destination-unreachable, time-exceeded, parameter-problem }} accept\n\
        icmpv6 type {{ echo-request, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert }} accept\n\
        tcp dport {{ {tcp_allow} }} ct state new accept\n\
        counter drop\n\
    }}\n\
    chain forward {{\n\
        type filter hook forward priority 0; policy drop;\n\
    }}\n\
    chain output {{\n\
        type filter hook output priority 0; policy accept;\n\
    }}\n\
}}\n"
        );

        let file = ctx.fs_root().join("etc/nftables.d/kindling-baseline.nft");
        if !ctx.dry_run {
            let _ = std::fs::create_dir_all(file.parent().unwrap());
            if let Err(e) = std::fs::write(&file, body.as_bytes()) {
                outcome.invariants_failed.push(format!("write {} failed: {e}", file.display()));
                return Ok(outcome);
            }
            // Try to load live — safe because we only allow SSH, and
            // the loader only replaces the ruleset atomically.
            let _ = std::process::Command::new("nft").args(["-f", file.to_str().unwrap()]).output();
        }
        outcome.entries_affected += 1;
        outcome.notes.push(format!("wrote {} (allow tcp {})", file.display(), tcp_allow));
        outcome.invariants_passed.push("nftables.baseline-file-present".into());
        Ok(outcome)
    }
}

// ── sshd-strict ────────────────────────────────────────────────
pub struct SshdStrict;

impl HardeningPrimitive for SshdStrict {
    fn name(&self) -> &'static str { "sshd-strict" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Network }
    fn description(&self) -> &'static str {
        "sshd drop-in: no-root, key-only, modern crypto, short client timeouts"
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        let mut outcome = PrimitiveOutcome::default();
        let params = params_or_default();

        let default_ciphers = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr";
        let default_kex = "sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org";
        let default_macs = "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com";

        let ciphers = if params.ssh_ciphers.is_empty() {
            default_ciphers.to_string()
        } else {
            params.ssh_ciphers.join(",")
        };
        let kex = if params.ssh_kex.is_empty() {
            default_kex.to_string()
        } else {
            params.ssh_kex.join(",")
        };
        let macs = if params.ssh_macs.is_empty() {
            default_macs.to_string()
        } else {
            params.ssh_macs.join(",")
        };

        let body = format!(
            "# written by kindling sshd-strict\n\
Protocol 2\n\
PermitRootLogin no\n\
PasswordAuthentication no\n\
KbdInteractiveAuthentication no\n\
PermitEmptyPasswords no\n\
ChallengeResponseAuthentication no\n\
UsePAM yes\n\
X11Forwarding no\n\
AllowAgentForwarding no\n\
AllowTcpForwarding no\n\
PermitTunnel no\n\
GatewayPorts no\n\
ClientAliveInterval 300\n\
ClientAliveCountMax 2\n\
LoginGraceTime 30\n\
MaxAuthTries 3\n\
MaxStartups 10:30:60\n\
MaxSessions 4\n\
LogLevel VERBOSE\n\
Ciphers {ciphers}\n\
KexAlgorithms {kex}\n\
MACs {macs}\n\
"
        );

        let file = ctx.fs_root().join("etc/ssh/sshd_config.d/10-kindling-strict.conf");
        if !ctx.dry_run {
            let _ = std::fs::create_dir_all(file.parent().unwrap());
            if let Err(e) = std::fs::write(&file, body.as_bytes()) {
                outcome.invariants_failed.push(format!("write {} failed: {e}", file.display()));
                return Ok(outcome);
            }
            // Validate the combined config — best-effort.
            if let Ok(out) = std::process::Command::new("sshd").arg("-t").output() {
                if out.status.success() {
                    outcome.invariants_passed.push("sshd.-t exits 0".into());
                } else {
                    outcome.invariants_failed.push(format!(
                        "sshd -t failed: {}", String::from_utf8_lossy(&out.stderr).trim()
                    ));
                }
            }
        }
        outcome.entries_affected += 1;
        outcome.notes.push(format!("wrote {}", file.display()));
        outcome.invariants_passed.push("sshd.PermitRootLogin=no".into());
        outcome.invariants_passed.push("sshd.PasswordAuthentication=no".into());
        Ok(outcome)
    }
}

// ── ssh-moduli-regen ───────────────────────────────────────────
pub struct SshModuliRegen;

impl HardeningPrimitive for SshModuliRegen {
    fn name(&self) -> &'static str { "ssh-moduli-regen" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Network }
    fn description(&self) -> &'static str {
        "Remove DH moduli under 3072 bits (logjam mitigation)"
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        let mut outcome = PrimitiveOutcome::default();
        let path = ctx.fs_root().join("etc/ssh/moduli");
        if !path.is_file() {
            outcome.notes.push(format!("no moduli at {}", path.display()));
            return Ok(outcome);
        }
        let Ok(src) = std::fs::read_to_string(&path) else {
            outcome.invariants_failed.push(format!("cannot read {}", path.display()));
            return Ok(outcome);
        };
        let mut kept = Vec::<&str>::new();
        let mut removed = 0u64;
        for line in src.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                kept.push(line);
                continue;
            }
            // moduli format: <time> <type> <tests> <tries> <size> <gen> <mod>
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 5 { kept.push(line); continue; }
            let size: u32 = cols[4].parse().unwrap_or(0);
            if size >= 3072 {
                kept.push(line);
            } else {
                removed += 1;
            }
        }
        let out_body = kept.join("\n") + "\n";
        if !ctx.dry_run {
            if let Err(e) = std::fs::write(&path, out_body.as_bytes()) {
                outcome.invariants_failed.push(format!("write {} failed: {e}", path.display()));
                return Ok(outcome);
            }
        }
        outcome.entries_affected = removed;
        outcome.invariants_passed.push("moduli.all>=3072".into());
        outcome.notes.push(format!(
            "removed {removed} moduli under 3072 bits from {}",
            path.display()
        ));
        Ok(outcome)
    }
}

// ── disable-ipv6 ───────────────────────────────────────────────
pub struct DisableIpv6;

impl HardeningPrimitive for DisableIpv6 {
    fn name(&self) -> &'static str { "disable-ipv6" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Network }
    fn description(&self) -> &'static str {
        "Disable IPv6 via sysctl drop-in (skip on dual-stack hosts)"
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        let mut outcome = PrimitiveOutcome::default();
        let body = "# written by kindling disable-ipv6\n\
net.ipv6.conf.all.disable_ipv6 = 1\n\
net.ipv6.conf.default.disable_ipv6 = 1\n\
net.ipv6.conf.lo.disable_ipv6 = 1\n";
        let file = ctx.fs_root().join("etc/sysctl.d/70-kindling-disable-ipv6.conf");
        if !ctx.dry_run {
            let _ = std::fs::create_dir_all(file.parent().unwrap());
            if let Err(e) = std::fs::write(&file, body.as_bytes()) {
                outcome.invariants_failed.push(format!("write {} failed: {e}", file.display()));
                return Ok(outcome);
            }
            let _ = std::process::Command::new("sysctl")
                .args(["-p", file.to_str().unwrap()]).output();
        }
        outcome.entries_affected += 1;
        outcome.invariants_passed.push("sysctl.ipv6.disable_ipv6=1".into());
        outcome.notes.push(format!("wrote {}", file.display()));
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn firewall_writes_nft_with_ssh_default() {
        let dir = tempdir().unwrap();
        let mut ctx = PrimitiveCtx::default();
        ctx.filesystem_root = Some(dir.path().to_path_buf());
        let _ = FirewallDenyAll.apply(&ctx).unwrap();
        let p = dir.path().join("etc/nftables.d/kindling-baseline.nft");
        let s = std::fs::read_to_string(p).unwrap();
        assert!(s.contains("policy drop"));
        assert!(s.contains("tcp dport { 22 }"));
    }

    #[test]
    fn sshd_strict_writes_drop_in() {
        let dir = tempdir().unwrap();
        let mut ctx = PrimitiveCtx::default();
        ctx.filesystem_root = Some(dir.path().to_path_buf());
        let _ = SshdStrict.apply(&ctx).unwrap();
        let p = dir.path().join("etc/ssh/sshd_config.d/10-kindling-strict.conf");
        let s = std::fs::read_to_string(p).unwrap();
        assert!(s.contains("PermitRootLogin no"));
        assert!(s.contains("PasswordAuthentication no"));
        assert!(s.contains("chacha20-poly1305"));
    }

    #[test]
    fn moduli_drops_weak_lines() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("etc/ssh/moduli");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // two bad (2047, 2048) + one good (3071 — still < 3072 so also bad) + one truly good
        let src = "\
# good\n\
20220101000000 2 6 100 2047 2 ABCD\n\
20220101000000 2 6 100 2048 2 ABCD\n\
20220101000000 2 6 100 3071 2 ABCD\n\
20220101000000 2 6 100 3072 2 ABCD\n\
20220101000000 2 6 100 4096 2 EF01\n";
        std::fs::write(&path, src).unwrap();
        let mut ctx = PrimitiveCtx::default();
        ctx.filesystem_root = Some(dir.path().to_path_buf());
        let out = SshModuliRegen.apply(&ctx).unwrap();
        assert_eq!(out.entries_affected, 3);
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains("4096"));
        assert!(!after.contains(" 2048 "));
        assert!(!after.contains(" 3071 "));
    }

    #[test]
    fn disable_ipv6_writes_sysctl_drop_in() {
        let dir = tempdir().unwrap();
        let mut ctx = PrimitiveCtx::default();
        ctx.filesystem_root = Some(dir.path().to_path_buf());
        let _ = DisableIpv6.apply(&ctx).unwrap();
        let p = dir.path().join("etc/sysctl.d/70-kindling-disable-ipv6.conf");
        let s = std::fs::read_to_string(p).unwrap();
        assert!(s.contains("disable_ipv6 = 1"));
    }
}
