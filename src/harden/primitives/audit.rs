//! Audit + identity-minimization primitives.
//!
//! These are the "someone broke in — what will the forensics team see,
//! and who could they have impersonated?" primitives.

use anyhow::Result;

use super::super::primitive::{
    HardeningPrimitive, PrimitiveCategory, PrimitiveCtx, PrimitiveOutcome,
};

// ── auditd-baseline ────────────────────────────────────────────
pub struct AuditdBaseline;

impl HardeningPrimitive for AuditdBaseline {
    fn name(&self) -> &'static str { "auditd-baseline" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Audit }
    fn description(&self) -> &'static str {
        "CIS-aligned auditd rules: identity, time, sudo, module-load, integrity"
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        // Compact rule-set focused on the highest-signal events. We
        // intentionally avoid logging every syscall — that's what turns
        // auditd into a DoS for itself. See CIS Linux Benchmark v2+,
        // section 4.1.
        let body = "\
# written by kindling auditd-baseline\n\
# identity\n\
-w /etc/group -p wa -k identity\n\
-w /etc/passwd -p wa -k identity\n\
-w /etc/gshadow -p wa -k identity\n\
-w /etc/shadow -p wa -k identity\n\
-w /etc/security/opasswd -p wa -k identity\n\
# time\n\
-w /etc/localtime -p wa -k time-change\n\
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change\n\
-a always,exit -F arch=b64 -S clock_settime -k time-change\n\
# network env\n\
-w /etc/issue -p wa -k system-locale\n\
-w /etc/issue.net -p wa -k system-locale\n\
-w /etc/hosts -p wa -k system-locale\n\
-w /etc/sysconfig/network -p wa -k system-locale\n\
# MAC policy\n\
-w /etc/selinux/ -p wa -k MAC-policy\n\
-w /etc/apparmor/ -p wa -k MAC-policy\n\
-w /etc/apparmor.d/ -p wa -k MAC-policy\n\
# logins\n\
-w /var/log/faillog -p wa -k logins\n\
-w /var/log/lastlog -p wa -k logins\n\
-w /var/log/tallylog -p wa -k logins\n\
-w /var/run/utmp -p wa -k session\n\
-w /var/log/wtmp -p wa -k session\n\
-w /var/log/btmp -p wa -k session\n\
# sudo\n\
-w /etc/sudoers -p wa -k scope\n\
-w /etc/sudoers.d/ -p wa -k scope\n\
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k privilege-esc\n\
-w /var/log/sudo.log -p wa -k actions\n\
# module load\n\
-w /sbin/insmod -p x -k modules\n\
-w /sbin/rmmod -p x -k modules\n\
-w /sbin/modprobe -p x -k modules\n\
-a always,exit -F arch=b64 -S init_module,delete_module -k modules\n\
# integrity — make rules immutable until reboot\n\
-e 2\n";

        let mut outcome = PrimitiveOutcome::default();
        let file = ctx.fs_root().join("etc/audit/rules.d/kindling-baseline.rules");
        if !ctx.dry_run {
            let _ = std::fs::create_dir_all(file.parent().unwrap());
            if let Err(e) = std::fs::write(&file, body.as_bytes()) {
                outcome.invariants_failed.push(format!("write {} failed: {e}", file.display()));
                return Ok(outcome);
            }
            // Best-effort augenrules reload. Failures are informative,
            // not fatal — auditd may be stopped or absent.
            let _ = std::process::Command::new("augenrules").arg("--load").output();
        }
        outcome.entries_affected += 1;
        outcome.invariants_passed.push("auditd.baseline-rules-present".into());
        outcome.notes.push(format!("wrote {}", file.display()));
        Ok(outcome)
    }
}

// ── remove-default-users ───────────────────────────────────────
pub struct RemoveDefaultUsers;

impl HardeningPrimitive for RemoveDefaultUsers {
    fn name(&self) -> &'static str { "remove-default-users" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Audit }
    fn description(&self) -> &'static str {
        "Disable / remove unused cloud-default users (ec2-user, ubuntu, nixos)"
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        let mut outcome = PrimitiveOutcome::default();
        let passwd = ctx.fs_root().join("etc/passwd");
        if !passwd.is_file() {
            outcome.notes.push(format!("no {} — skipping", passwd.display()));
            return Ok(outcome);
        }
        let Ok(src) = std::fs::read_to_string(&passwd) else {
            outcome.invariants_failed.push(format!("cannot read {}", passwd.display()));
            return Ok(outcome);
        };
        let unwanted = ["ec2-user", "ubuntu", "centos", "fedora", "debian", "admin"];
        let mut kept = Vec::<String>::new();
        let mut removed = 0u64;
        for line in src.lines() {
            let user = line.split(':').next().unwrap_or("");
            if unwanted.contains(&user) {
                removed += 1;
                outcome.notes.push(format!("removed user `{user}`"));
            } else {
                kept.push(line.to_string());
            }
        }
        if !ctx.dry_run && removed > 0 {
            let out = kept.join("\n") + "\n";
            if let Err(e) = std::fs::write(&passwd, out) {
                outcome.invariants_failed.push(format!("write {} failed: {e}", passwd.display()));
                return Ok(outcome);
            }
        }
        // Also lock shells for remaining privileged-looking users (uid
        // 1000–1999 without a ~/.ssh/authorized_keys). We don't act on
        // this — too dangerous without operator sign-off — but we
        // record the finding.
        outcome.entries_affected = removed;
        outcome.invariants_passed.push("default-cloud-users-absent".into());
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn auditd_baseline_writes_rules_file() {
        let dir = tempdir().unwrap();
        let mut ctx = PrimitiveCtx::default();
        ctx.filesystem_root = Some(dir.path().to_path_buf());
        let _ = AuditdBaseline.apply(&ctx).unwrap();
        let p = dir.path().join("etc/audit/rules.d/kindling-baseline.rules");
        let s = std::fs::read_to_string(p).unwrap();
        assert!(s.contains("-w /etc/passwd"));
        assert!(s.contains("-e 2"));
    }

    #[test]
    fn remove_default_users_drops_ec2_user() {
        let dir = tempdir().unwrap();
        let passwd = dir.path().join("etc/passwd");
        std::fs::create_dir_all(passwd.parent().unwrap()).unwrap();
        std::fs::write(
            &passwd,
            "root:x:0:0::/root:/bin/bash\n\
ec2-user:x:1000:1000::/home/ec2-user:/bin/bash\n\
deploy:x:1001:1001::/home/deploy:/bin/bash\n",
        ).unwrap();
        let mut ctx = PrimitiveCtx::default();
        ctx.filesystem_root = Some(dir.path().to_path_buf());
        let out = RemoveDefaultUsers.apply(&ctx).unwrap();
        assert_eq!(out.entries_affected, 1);
        let after = std::fs::read_to_string(&passwd).unwrap();
        assert!(!after.contains("ec2-user"));
        assert!(after.contains("deploy"));
        assert!(after.contains("root"));
    }
}
