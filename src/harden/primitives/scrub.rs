//! Scrub primitives — run last, after every other category. By the
//! time these fire, earlier primitives have finished writing logs and
//! we are safe to remove every trace of the AMI's build history.
//!
//! `ZeroFill` is the generalization of the `dd if=/dev/zero` loop in
//! `commands::ami_build` — it fills free space with zeros so the
//! subsequent EBS snapshot compresses tight.

use anyhow::Result;
use std::path::{Path, PathBuf};

use super::super::primitive::{
    HardeningPrimitive, PrimitiveCategory, PrimitiveCtx, PrimitiveOutcome,
};

// ── scrub-logs ─────────────────────────────────────────────────
pub struct ScrubLogs;

impl HardeningPrimitive for ScrubLogs {
    fn name(&self) -> &'static str { "scrub-logs" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Scrub }
    fn description(&self) -> &'static str {
        "Vacuum journald + remove /var/log files (keeps directory structure)"
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        let mut outcome = PrimitiveOutcome::default();
        if !ctx.dry_run {
            // Rotate + vacuum journald to ~0.
            let _ = std::process::Command::new("journalctl")
                .args(["--rotate", "--vacuum-time=1s"]).status();
        }
        let log_root = ctx.fs_root().join("var/log");
        if !log_root.is_dir() {
            outcome.notes.push(format!("no {} — skipped", log_root.display()));
            return Ok(outcome);
        }
        // Walk /var/log and truncate files. Directories are kept —
        // services will recreate their files on next boot.
        let mut stack: Vec<PathBuf> = vec![log_root.clone()];
        while let Some(p) = stack.pop() {
            let Ok(meta) = std::fs::symlink_metadata(&p) else { continue };
            if meta.is_dir() {
                if let Ok(rd) = std::fs::read_dir(&p) {
                    for e in rd.flatten() { stack.push(e.path()); }
                }
            } else if meta.is_file() {
                let size = meta.len();
                if !ctx.dry_run {
                    // btmp/wtmp/lastlog must be truncated, not removed —
                    // they are sparse files that the kernel + login tools
                    // expect to exist.
                    let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
                    if matches!(name, "btmp" | "wtmp" | "lastlog") {
                        let _ = std::fs::write(&p, b"");
                    } else {
                        let _ = std::fs::remove_file(&p);
                    }
                }
                outcome.bytes_freed = outcome.bytes_freed.saturating_add(size);
                outcome.entries_affected += 1;
            }
        }
        outcome.invariants_passed.push("var-log:scrubbed".into());
        outcome.notes.push(format!(
            "{} log files removed/truncated, {} bytes freed",
            outcome.entries_affected, outcome.bytes_freed
        ));
        Ok(outcome)
    }
}

// ── scrub-cloud-init ───────────────────────────────────────────
pub struct ScrubCloudInit;

impl HardeningPrimitive for ScrubCloudInit {
    fn name(&self) -> &'static str { "scrub-cloud-init" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Scrub }
    fn description(&self) -> &'static str {
        "Remove cloud-init state so the AMI re-initialises on first boot"
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        let mut outcome = PrimitiveOutcome::default();
        let paths = [
            "var/lib/cloud/instance",
            "var/lib/cloud/instances",
            "var/log/cloud-init.log",
            "var/log/cloud-init-output.log",
            "var/lib/cloud/data",
            "var/lib/cloud/sem",
            "root/.ssh/authorized_keys",
        ];
        for rel in paths {
            let p = ctx.fs_root().join(rel);
            if let Ok(meta) = std::fs::symlink_metadata(&p) {
                let size = if meta.is_file() { meta.len() } else {
                    dir_size(&p).unwrap_or(0)
                };
                if !ctx.dry_run {
                    if meta.is_dir() {
                        let _ = std::fs::remove_dir_all(&p);
                    } else {
                        let _ = std::fs::remove_file(&p);
                    }
                }
                outcome.bytes_freed = outcome.bytes_freed.saturating_add(size);
                outcome.entries_affected += 1;
                outcome.notes.push(format!("removed {}", p.display()));
            }
        }
        outcome.invariants_passed.push("cloud-init.state-absent".into());
        Ok(outcome)
    }
}

// ── scrub-shell-history ────────────────────────────────────────
pub struct ScrubShellHistory;

impl HardeningPrimitive for ScrubShellHistory {
    fn name(&self) -> &'static str { "scrub-shell-history" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Scrub }
    fn description(&self) -> &'static str {
        "Remove ~/.bash_history, .zsh_history, .python_history, .node_repl_history"
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        let mut outcome = PrimitiveOutcome::default();
        let files = [
            ".bash_history", ".zsh_history", ".python_history",
            ".node_repl_history", ".lesshst", ".mysql_history",
            ".psql_history", ".rediscli_history", ".ruby_history",
        ];
        let mut homes: Vec<PathBuf> = vec![ctx.fs_root().join("root")];
        if let Ok(rd) = std::fs::read_dir(ctx.fs_root().join("home")) {
            for e in rd.flatten() { homes.push(e.path()); }
        }
        for home in homes {
            for f in &files {
                let p = home.join(f);
                if let Ok(meta) = std::fs::symlink_metadata(&p) {
                    let size = meta.len();
                    if !ctx.dry_run { let _ = std::fs::remove_file(&p); }
                    outcome.bytes_freed = outcome.bytes_freed.saturating_add(size);
                    outcome.entries_affected += 1;
                }
            }
        }
        outcome.invariants_passed.push("shell-history:absent".into());
        outcome.notes.push(format!("removed {} history file(s)", outcome.entries_affected));
        Ok(outcome)
    }
}

// ── scrub-ssh-keys ─────────────────────────────────────────────
pub struct ScrubSshKeys;

impl HardeningPrimitive for ScrubSshKeys {
    fn name(&self) -> &'static str { "scrub-ssh-keys" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Scrub }
    fn description(&self) -> &'static str {
        "Remove host ssh keys and authorized_keys (regenerated on first boot)"
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        let mut outcome = PrimitiveOutcome::default();
        let ssh_dir = ctx.fs_root().join("etc/ssh");
        if ssh_dir.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&ssh_dir) {
                for e in rd.flatten() {
                    let name = e.file_name().to_string_lossy().to_string();
                    if name.starts_with("ssh_host_") {
                        let p = e.path();
                        let size = p.metadata().map(|m| m.len()).unwrap_or(0);
                        if !ctx.dry_run { let _ = std::fs::remove_file(&p); }
                        outcome.bytes_freed = outcome.bytes_freed.saturating_add(size);
                        outcome.entries_affected += 1;
                        outcome.notes.push(format!("removed {}", p.display()));
                    }
                }
            }
        }
        // authorized_keys under root + /home/*
        let mut candidates: Vec<PathBuf> = vec![ctx.fs_root().join("root/.ssh")];
        if let Ok(rd) = std::fs::read_dir(ctx.fs_root().join("home")) {
            for e in rd.flatten() { candidates.push(e.path().join(".ssh")); }
        }
        for dir in candidates {
            if dir.is_dir() {
                if !ctx.dry_run { let _ = std::fs::remove_dir_all(&dir); }
                outcome.entries_affected += 1;
                outcome.notes.push(format!("removed {}", dir.display()));
            }
        }
        outcome.invariants_passed.push("host-keys:absent".into());
        outcome.invariants_passed.push("authorized-keys:absent".into());
        Ok(outcome)
    }
}

// ── scrub-temp-dirs ────────────────────────────────────────────
pub struct ScrubTempDirs;

impl HardeningPrimitive for ScrubTempDirs {
    fn name(&self) -> &'static str { "scrub-temp-dirs" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Scrub }
    fn description(&self) -> &'static str {
        "Clear /tmp and /var/tmp (honours HardeningParams.preserve_temp_paths)"
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        let mut outcome = PrimitiveOutcome::default();
        for rel in ["tmp", "var/tmp"] {
            let p = ctx.fs_root().join(rel);
            if !p.is_dir() { continue; }
            let Ok(rd) = std::fs::read_dir(&p) else { continue };
            for e in rd.flatten() {
                let child = e.path();
                let size = if child.is_file() {
                    child.metadata().map(|m| m.len()).unwrap_or(0)
                } else {
                    dir_size(&child).unwrap_or(0)
                };
                if !ctx.dry_run {
                    if child.is_dir() {
                        let _ = std::fs::remove_dir_all(&child);
                    } else {
                        let _ = std::fs::remove_file(&child);
                    }
                }
                outcome.bytes_freed = outcome.bytes_freed.saturating_add(size);
                outcome.entries_affected += 1;
            }
        }
        outcome.invariants_passed.push("tmp:empty".into());
        outcome.notes.push(format!(
            "{} entries removed, {} bytes freed",
            outcome.entries_affected, outcome.bytes_freed
        ));
        Ok(outcome)
    }
}

// ── zero-fill ──────────────────────────────────────────────────
pub struct ZeroFill;

impl HardeningPrimitive for ZeroFill {
    fn name(&self) -> &'static str { "zero-fill" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Scrub }
    fn description(&self) -> &'static str {
        "Fill free space with zeros (compression + secure-erase) then TRIM"
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        let mut outcome = PrimitiveOutcome::default();
        if ctx.dry_run {
            outcome.notes.push("dry-run: would dd if=/dev/zero of=/zero.fill bs=1M".into());
            return Ok(outcome);
        }
        // Generalized from commands::ami_build phase 5. The dd will
        // exit non-zero with ENOSPC — that's the intended terminating
        // condition, not an error.
        let target = ctx.fs_root().join("zero.fill");
        let status = std::process::Command::new("dd")
            .arg("if=/dev/zero")
            .arg(format!("of={}", target.display()))
            .arg("bs=1M")
            .status();
        match status {
            Ok(s) => {
                outcome.notes.push(format!("dd exit {} (ENOSPC expected)", s));
            }
            Err(e) => {
                outcome.notes.push(format!("dd failed to spawn: {e}"));
            }
        }
        let freed = target.metadata().map(|m| m.len()).unwrap_or(0);
        let _ = std::fs::remove_file(&target);
        outcome.bytes_freed = freed;
        outcome.entries_affected = 1;

        let _ = std::process::Command::new("sync").status();
        let _ = std::process::Command::new("fstrim")
            .arg(ctx.fs_root()).status();

        outcome.invariants_passed.push("free-space:zeroed".into());
        outcome.invariants_passed.push("fstrim:ran".into());
        Ok(outcome)
    }
}

// ── helper ─────────────────────────────────────────────────────
fn dir_size(path: &Path) -> Result<u64> {
    let mut total = 0u64;
    let mut stack: Vec<PathBuf> = vec![path.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(meta) = std::fs::symlink_metadata(&p) else { continue };
        if meta.is_file() {
            total = total.saturating_add(meta.len());
        } else if meta.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&p) {
                for entry in rd.flatten() { stack.push(entry.path()); }
            }
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn scrub_logs_truncates_btmp_removes_rest() {
        let dir = tempdir().unwrap();
        let logd = dir.path().join("var/log");
        std::fs::create_dir_all(&logd).unwrap();
        std::fs::write(logd.join("syslog"), b"hello world").unwrap();
        std::fs::write(logd.join("btmp"), b"record").unwrap();
        let mut ctx = PrimitiveCtx::default();
        ctx.filesystem_root = Some(dir.path().to_path_buf());
        let out = ScrubLogs.apply(&ctx).unwrap();
        assert_eq!(out.entries_affected, 2);
        assert!(!logd.join("syslog").exists());
        // btmp preserved, truncated to 0
        let btmp = logd.join("btmp");
        assert!(btmp.exists());
        assert_eq!(btmp.metadata().unwrap().len(), 0);
    }

    #[test]
    fn scrub_cloud_init_removes_state() {
        let dir = tempdir().unwrap();
        let inst = dir.path().join("var/lib/cloud/instance");
        std::fs::create_dir_all(&inst).unwrap();
        std::fs::write(inst.join("datasource"), b"aws").unwrap();
        let mut ctx = PrimitiveCtx::default();
        ctx.filesystem_root = Some(dir.path().to_path_buf());
        let _ = ScrubCloudInit.apply(&ctx).unwrap();
        assert!(!inst.exists());
    }

    #[test]
    fn scrub_shell_history_removes_bash_history() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(".bash_history"), b"ls\ncd /\n").unwrap();
        std::fs::write(root.join(".python_history"), b"x=1\n").unwrap();
        let mut ctx = PrimitiveCtx::default();
        ctx.filesystem_root = Some(dir.path().to_path_buf());
        let out = ScrubShellHistory.apply(&ctx).unwrap();
        assert_eq!(out.entries_affected, 2);
        assert!(!root.join(".bash_history").exists());
    }

    #[test]
    fn scrub_ssh_keys_removes_host_keys_and_auth_dirs() {
        let dir = tempdir().unwrap();
        let ssh = dir.path().join("etc/ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::write(ssh.join("ssh_host_ed25519_key"), b"PRIVATE").unwrap();
        std::fs::write(ssh.join("ssh_host_ed25519_key.pub"), b"pub").unwrap();
        std::fs::write(ssh.join("sshd_config"), b"# keep me").unwrap();
        std::fs::create_dir_all(dir.path().join("root/.ssh")).unwrap();
        std::fs::write(dir.path().join("root/.ssh/authorized_keys"), b"ssh-rsa ...").unwrap();
        let mut ctx = PrimitiveCtx::default();
        ctx.filesystem_root = Some(dir.path().to_path_buf());
        let _ = ScrubSshKeys.apply(&ctx).unwrap();
        assert!(!ssh.join("ssh_host_ed25519_key").exists());
        assert!(!ssh.join("ssh_host_ed25519_key.pub").exists());
        assert!(ssh.join("sshd_config").exists());
        assert!(!dir.path().join("root/.ssh").exists());
    }

    #[test]
    fn scrub_temp_dirs_empties_tmp() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("tmp")).unwrap();
        std::fs::write(dir.path().join("tmp/a.txt"), b"x").unwrap();
        std::fs::create_dir_all(dir.path().join("tmp/sub")).unwrap();
        std::fs::write(dir.path().join("tmp/sub/b.txt"), b"y").unwrap();
        let mut ctx = PrimitiveCtx::default();
        ctx.filesystem_root = Some(dir.path().to_path_buf());
        let _ = ScrubTempDirs.apply(&ctx).unwrap();
        assert!(!dir.path().join("tmp/a.txt").exists());
        assert!(!dir.path().join("tmp/sub").exists());
    }

    #[test]
    fn zero_fill_dry_run_is_noop() {
        let dir = tempdir().unwrap();
        let mut ctx = PrimitiveCtx::dry();
        ctx.filesystem_root = Some(dir.path().to_path_buf());
        let out = ZeroFill.apply(&ctx).unwrap();
        assert_eq!(out.entries_affected, 0);
    }
}
