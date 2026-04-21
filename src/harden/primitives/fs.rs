//! Filesystem-hardening primitives.
//!
//! These mutate mount options and directory placement to reduce the
//! blast radius of a compromised process. On systemd hosts we write
//! drop-in units rather than editing /etc/fstab so the change survives
//! NixOS rebuilds without fighting the generator.

use anyhow::Result;
use std::path::Path;

use super::super::primitive::{
    HardeningPrimitive, PrimitiveCategory, PrimitiveCtx, PrimitiveOutcome,
};

// ── tmpfs-sensitive-dirs ───────────────────────────────────────
pub struct TmpfsSensitiveDirs;

impl HardeningPrimitive for TmpfsSensitiveDirs {
    fn name(&self) -> &'static str { "tmpfs-sensitive-dirs" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Filesystem }
    fn description(&self) -> &'static str {
        "Mount /tmp and /var/tmp as tmpfs with nodev,nosuid,noexec"
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        let mut outcome = PrimitiveOutcome::default();
        let root = ctx.fs_root();

        // systemd mount units for /tmp and /var/tmp. Idempotent — we
        // skip if the unit already exists (NixOS may have rendered its
        // own).
        let units: [(&str, &str, &str); 2] = [
            (
                "tmp.mount",
                "/tmp",
                "[Mount]\nWhat=tmpfs\nWhere=/tmp\nType=tmpfs\nOptions=mode=1777,strictatime,nodev,nosuid,noexec,size=50%\n",
            ),
            (
                "var-tmp.mount",
                "/var/tmp",
                "[Mount]\nWhat=tmpfs\nWhere=/var/tmp\nType=tmpfs\nOptions=mode=1777,strictatime,nodev,nosuid,noexec,size=25%\n",
            ),
        ];

        let dst_dir = root.join("etc/systemd/system");
        if !ctx.dry_run {
            let _ = std::fs::create_dir_all(&dst_dir);
        }
        for (unit_name, where_, body) in units {
            let dst = dst_dir.join(unit_name);
            let header = format!(
                "# written by kindling tmpfs-sensitive-dirs\n[Unit]\nDescription=tmpfs at {where_}\n\n"
            );
            let full = format!("{header}{body}");
            if dst.exists() {
                outcome.notes.push(format!("{} already present — skipped", dst.display()));
                continue;
            }
            if !ctx.dry_run {
                if let Err(e) = std::fs::write(&dst, full.as_bytes()) {
                    outcome.invariants_failed.push(format!("write {} failed: {e}", dst.display()));
                    continue;
                }
            }
            outcome.entries_affected += 1;
            outcome.notes.push(format!("wrote {}", dst.display()));
            outcome.invariants_passed.push(format!("unit-present:{unit_name}"));
        }
        Ok(outcome)
    }
}

// ── remount-readonly ───────────────────────────────────────────
pub struct RemountReadonly;

impl HardeningPrimitive for RemountReadonly {
    fn name(&self) -> &'static str { "remount-readonly" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Filesystem }
    fn description(&self) -> &'static str {
        "Record /nix/store + /boot remount-ro intent (applied at next boot)"
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        // Doing a live `mount -o remount,ro` on /nix/store will break
        // anything holding an open write fd (installer itself, systemd,
        // nix-daemon). Instead: emit a drop-in that remounts read-only
        // at the end of boot. NixOS users should normally set
        // `fileSystems."/nix/store".options = [ "ro" ]` at build time.
        let mut outcome = PrimitiveOutcome::default();
        let root = ctx.fs_root();
        let drop_in = root.join("etc/systemd/system/nix-store-ro.service");
        let body = "# written by kindling remount-readonly\n\
[Unit]\n\
Description=Remount /nix/store read-only after multi-user.target\n\
After=multi-user.target\n\
DefaultDependencies=no\n\
\n\
[Service]\n\
Type=oneshot\n\
ExecStart=/bin/mount -o remount,ro /nix/store\n\
RemainAfterExit=yes\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n";
        if !ctx.dry_run {
            let _ = std::fs::create_dir_all(drop_in.parent().unwrap());
            let _ = std::fs::write(&drop_in, body);
        }
        outcome.entries_affected += 1;
        outcome.notes.push(format!("wrote {}", drop_in.display()));
        outcome.notes.push(
            "prefer build-time `fileSystems.\"/nix/store\".options = [\"ro\"]` where possible".into(),
        );

        // Inspect existing mounts for noexec/nodev/nosuid.
        if let Ok(mounts) = std::fs::read_to_string(Path::new("/proc/mounts")) {
            for line in mounts.lines() {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() < 4 { continue; }
                let mp = cols[1];
                let opts = cols[3];
                for check in ["/home", "/var", "/tmp", "/dev/shm"] {
                    if mp == check {
                        for flag in ["nodev", "nosuid", "noexec"] {
                            if opts.contains(flag) {
                                outcome.invariants_passed.push(format!("{mp}:{flag}"));
                            } else {
                                outcome.invariants_failed.push(format!("{mp}:missing:{flag}"));
                            }
                        }
                    }
                }
            }
        }
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn tmpfs_writes_unit_files() {
        let dir = tempdir().unwrap();
        let mut ctx = PrimitiveCtx::default();
        ctx.filesystem_root = Some(dir.path().to_path_buf());
        let out = TmpfsSensitiveDirs.apply(&ctx).unwrap();
        assert!(dir.path().join("etc/systemd/system/tmp.mount").exists());
        assert!(dir.path().join("etc/systemd/system/var-tmp.mount").exists());
        assert_eq!(out.entries_affected, 2);
    }

    #[test]
    fn tmpfs_dry_run_writes_nothing() {
        let dir = tempdir().unwrap();
        let mut ctx = PrimitiveCtx::dry();
        ctx.filesystem_root = Some(dir.path().to_path_buf());
        let _ = TmpfsSensitiveDirs.apply(&ctx).unwrap();
        assert!(!dir.path().join("etc/systemd/system/tmp.mount").exists());
    }

    #[test]
    fn remount_readonly_writes_service() {
        let dir = tempdir().unwrap();
        let mut ctx = PrimitiveCtx::default();
        ctx.filesystem_root = Some(dir.path().to_path_buf());
        let _ = RemountReadonly.apply(&ctx).unwrap();
        assert!(dir.path().join("etc/systemd/system/nix-store-ro.service").exists());
    }
}
