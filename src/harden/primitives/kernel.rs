//! Kernel-hardening primitives — lockdown, sysctls, module blacklists.
//!
//! We prefer "declarative" changes: write a drop-in under
//! /etc/sysctl.d/, /etc/modprobe.d/, or /etc/kernel/cmdline.d/ rather
//! than poking /proc directly. This makes the result reproducible
//! across reboots and legible to anyone `ls`-ing the config dirs.

use anyhow::Result;
use std::collections::BTreeMap;

use super::super::primitive::{
    HardeningPrimitive, PrimitiveCategory, PrimitiveCtx, PrimitiveOutcome,
};

// ── kernel-lockdown ────────────────────────────────────────────
pub struct KernelLockdown;

impl HardeningPrimitive for KernelLockdown {
    fn name(&self) -> &'static str { "kernel-lockdown" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Kernel }
    fn description(&self) -> &'static str {
        "Enable kernel lockdown=confidentiality via cmdline drop-in"
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        let mut outcome = PrimitiveOutcome::default();
        let root = ctx.fs_root();
        let dir = root.join("etc/kernel/cmdline.d");
        let file = dir.join("10-kindling-lockdown.conf");
        let body = "# written by kindling kernel-lockdown\n\
lockdown=confidentiality\n";
        if !ctx.dry_run {
            let _ = std::fs::create_dir_all(&dir);
            if let Err(e) = std::fs::write(&file, body) {
                outcome.invariants_failed.push(format!("write {} failed: {e}", file.display()));
                return Ok(outcome);
            }
        }
        outcome.entries_affected += 1;
        outcome.invariants_passed.push("cmdline:lockdown=confidentiality".into());
        outcome.notes.push(format!("wrote {}", file.display()));

        // Check current state if available.
        if let Ok(s) = std::fs::read_to_string("/sys/kernel/security/lockdown") {
            if s.contains("[confidentiality]") {
                outcome.invariants_passed.push("runtime:lockdown=confidentiality".into());
            } else if s.contains("[integrity]") {
                outcome.invariants_failed.push("runtime:lockdown=integrity (want confidentiality)".into());
            } else {
                outcome.invariants_failed.push(format!("runtime:lockdown unset ({})", s.trim()));
            }
        }
        Ok(outcome)
    }
}

// ── sysctl-baseline ────────────────────────────────────────────
pub struct SysctlBaseline;

impl HardeningPrimitive for SysctlBaseline {
    fn name(&self) -> &'static str { "sysctl-baseline" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Kernel }
    fn description(&self) -> &'static str {
        "CIS-aligned sysctl defaults: rp_filter, kptr_restrict, unprivileged_bpf, etc."
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        // Kept intentionally conservative — these are safe for server
        // workloads and map to CIS Level 1.
        let mut sysctls: BTreeMap<&str, &str> = BTreeMap::new();
        // network
        sysctls.insert("net.ipv4.conf.all.rp_filter", "1");
        sysctls.insert("net.ipv4.conf.default.rp_filter", "1");
        sysctls.insert("net.ipv4.conf.all.accept_redirects", "0");
        sysctls.insert("net.ipv4.conf.default.accept_redirects", "0");
        sysctls.insert("net.ipv4.conf.all.secure_redirects", "0");
        sysctls.insert("net.ipv4.conf.default.secure_redirects", "0");
        sysctls.insert("net.ipv4.conf.all.accept_source_route", "0");
        sysctls.insert("net.ipv4.conf.default.accept_source_route", "0");
        sysctls.insert("net.ipv4.conf.all.log_martians", "1");
        sysctls.insert("net.ipv4.conf.default.log_martians", "1");
        sysctls.insert("net.ipv4.icmp_echo_ignore_broadcasts", "1");
        sysctls.insert("net.ipv4.icmp_ignore_bogus_error_responses", "1");
        sysctls.insert("net.ipv4.tcp_syncookies", "1");
        sysctls.insert("net.ipv6.conf.all.accept_redirects", "0");
        sysctls.insert("net.ipv6.conf.default.accept_redirects", "0");
        sysctls.insert("net.ipv6.conf.all.accept_source_route", "0");
        sysctls.insert("net.ipv6.conf.default.accept_source_route", "0");
        // kernel info leaks
        sysctls.insert("kernel.kptr_restrict", "2");
        sysctls.insert("kernel.dmesg_restrict", "1");
        sysctls.insert("kernel.printk", "3 3 3 3");
        sysctls.insert("kernel.unprivileged_bpf_disabled", "1");
        sysctls.insert("net.core.bpf_jit_harden", "2");
        sysctls.insert("kernel.kexec_load_disabled", "1");
        sysctls.insert("kernel.sysrq", "0");
        // ptrace
        sysctls.insert("kernel.yama.ptrace_scope", "2");
        // fs
        sysctls.insert("fs.protected_hardlinks", "1");
        sysctls.insert("fs.protected_symlinks", "1");
        sysctls.insert("fs.protected_fifos", "2");
        sysctls.insert("fs.protected_regular", "2");
        sysctls.insert("fs.suid_dumpable", "0");

        let mut body = String::from("# written by kindling sysctl-baseline\n");
        for (k, v) in &sysctls {
            body.push_str(k);
            body.push_str(" = ");
            body.push_str(v);
            body.push('\n');
        }

        let mut outcome = PrimitiveOutcome::default();
        let dir = ctx.fs_root().join("etc/sysctl.d");
        let file = dir.join("60-kindling-baseline.conf");
        if !ctx.dry_run {
            let _ = std::fs::create_dir_all(&dir);
            if let Err(e) = std::fs::write(&file, body.as_bytes()) {
                outcome.invariants_failed.push(format!("write {} failed: {e}", file.display()));
                return Ok(outcome);
            }
            // Apply live — best-effort. Some sysctls may fail on
            // kernels that don't support them (container/old).
            let _ = std::process::Command::new("sysctl").args(["-p", file.to_str().unwrap()]).output();
        }
        outcome.entries_affected = sysctls.len() as u64;
        outcome.notes.push(format!(
            "wrote {} ({} sysctls)", file.display(), sysctls.len()
        ));
        outcome.invariants_passed.push("sysctl.baseline-file-present".into());
        Ok(outcome)
    }
}

// ── blacklist-modules ──────────────────────────────────────────
pub struct BlacklistModules;

impl HardeningPrimitive for BlacklistModules {
    fn name(&self) -> &'static str { "blacklist-modules" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Kernel }
    fn description(&self) -> &'static str {
        "Blacklist rarely-used filesystems + protocols (CIS Level 1)"
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        // CIS baseline: unused filesystems and obscure network protos.
        // Keep the list tight — we DON'T disable things hypervisors or
        // cloud guests need (ext4, xfs, vfat, etc).
        let modules = [
            // filesystems
            "cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "squashfs", "udf",
            // legacy / attack-surface network
            "dccp", "sctp", "rds", "tipc",
            // misc
            "firewire-core", "thunderbolt", "bluetooth",
        ];

        let mut outcome = PrimitiveOutcome::default();
        let dir = ctx.fs_root().join("etc/modprobe.d");
        let file = dir.join("kindling-blacklist.conf");

        let mut body = String::from("# written by kindling blacklist-modules\n");
        for m in &modules {
            body.push_str(&format!("install {m} /bin/false\nblacklist {m}\n"));
        }
        if !ctx.dry_run {
            let _ = std::fs::create_dir_all(&dir);
            if let Err(e) = std::fs::write(&file, body.as_bytes()) {
                outcome.invariants_failed.push(format!("write {} failed: {e}", file.display()));
                return Ok(outcome);
            }
        }
        outcome.entries_affected = modules.len() as u64;
        outcome.notes.push(format!("wrote {} ({} modules)", file.display(), modules.len()));
        outcome.invariants_passed.push("modprobe.blacklist-present".into());
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn lockdown_writes_cmdline_drop_in() {
        let dir = tempdir().unwrap();
        let mut ctx = PrimitiveCtx::default();
        ctx.filesystem_root = Some(dir.path().to_path_buf());
        let _ = KernelLockdown.apply(&ctx).unwrap();
        let p = dir.path().join("etc/kernel/cmdline.d/10-kindling-lockdown.conf");
        assert!(p.exists());
        let s = std::fs::read_to_string(p).unwrap();
        assert!(s.contains("lockdown=confidentiality"));
    }

    #[test]
    fn sysctl_baseline_writes_expected_keys() {
        let dir = tempdir().unwrap();
        let mut ctx = PrimitiveCtx::default();
        ctx.filesystem_root = Some(dir.path().to_path_buf());
        let out = SysctlBaseline.apply(&ctx).unwrap();
        assert!(out.entries_affected > 20);
        let p = dir.path().join("etc/sysctl.d/60-kindling-baseline.conf");
        let s = std::fs::read_to_string(p).unwrap();
        assert!(s.contains("kernel.kptr_restrict = 2"));
        assert!(s.contains("net.ipv4.tcp_syncookies = 1"));
    }

    #[test]
    fn blacklist_modules_writes_modprobe_entries() {
        let dir = tempdir().unwrap();
        let mut ctx = PrimitiveCtx::default();
        ctx.filesystem_root = Some(dir.path().to_path_buf());
        let _ = BlacklistModules.apply(&ctx).unwrap();
        let p = dir.path().join("etc/modprobe.d/kindling-blacklist.conf");
        let s = std::fs::read_to_string(p).unwrap();
        assert!(s.contains("blacklist cramfs"));
        assert!(s.contains("install dccp /bin/false"));
    }
}
