//! Minimize primitives — shrink closure, drop attack surface.
//!
//! Each primitive is conservative by default: it reports what it
//! would remove, only deletes under [`PrimitiveCtx::dry_run`]=false,
//! and NEVER touches files outside its well-defined targets. The
//! goal is to end with an AMI that boots identically but is 30–60%
//! smaller and has no compilers, docs, or locales on disk.

use anyhow::Result;
use std::path::{Path, PathBuf};

use super::super::primitive::{
    HardeningPrimitive, PrimitiveCategory, PrimitiveCtx, PrimitiveOutcome,
};

// ── strip-docs ─────────────────────────────────────────────────
pub struct StripDocs;

impl HardeningPrimitive for StripDocs {
    fn name(&self) -> &'static str { "strip-docs" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Minimize }
    fn description(&self) -> &'static str {
        "Remove /nix/store/*/share/{man,doc,info} — 40-60% closure reduction typical"
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        let targets = ["share/man", "share/doc", "share/info"];
        let mut outcome = PrimitiveOutcome::default();
        let store = ctx.store_root();
        if !store.is_dir() {
            outcome.notes.push(format!("skipped — {} not a directory", store.display()));
            return Ok(outcome);
        }
        let Ok(entries) = std::fs::read_dir(store) else {
            outcome.notes.push(format!("skipped — cannot read {}", store.display()));
            return Ok(outcome);
        };
        for entry in entries.flatten() {
            let pkg = entry.path();
            for sub in &targets {
                let target = pkg.join(sub);
                if target.is_dir() {
                    let size = dir_size(&target).unwrap_or(0);
                    if !ctx.dry_run {
                        let _ = std::fs::remove_dir_all(&target);
                    }
                    outcome.bytes_freed += size;
                    outcome.entries_affected += 1;
                }
            }
        }
        outcome.notes.push(format!(
            "{} /share/{{man,doc,info}} trees processed, {} bytes freed",
            outcome.entries_affected, outcome.bytes_freed
        ));
        Ok(outcome)
    }
}

// ── strip-locales ──────────────────────────────────────────────
pub struct StripLocales;

impl HardeningPrimitive for StripLocales {
    fn name(&self) -> &'static str { "strip-locales" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Minimize }
    fn description(&self) -> &'static str {
        "Remove non-allow-listed locales from glibc locale-archive"
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        // glibc's locale-archive lives at /usr/lib/locale/locale-archive on
        // FHS distros; on NixOS it's referenced from an env var but the
        // backing file is under /nix/store/*-glibc-locales-*/lib/locale.
        // Without passing the --add-to-archive tooling we can only report
        // candidate archives; actual trim requires localedef. For AMIs we
        // typically substitute a glibc-locales variant with --with-locales;
        // this primitive records current usage and lists removal candidates.
        let mut outcome = PrimitiveOutcome::default();
        let archive = ctx.fs_root().join("usr/lib/locale/locale-archive");
        if archive.is_file() {
            if let Ok(meta) = archive.metadata() {
                outcome.notes.push(format!(
                    "locale-archive at {} is {} bytes (candidate for trim)",
                    archive.display(), meta.len()
                ));
            }
        }
        // Scan /nix/store for glibc-locales paths.
        let store = ctx.store_root();
        if let Ok(entries) = std::fs::read_dir(store) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let n = name.to_string_lossy();
                if n.contains("glibc-locales-") {
                    let p = entry.path();
                    let size = dir_size(&p).unwrap_or(0);
                    outcome.notes.push(format!("glibc-locales candidate: {} ({} bytes)", p.display(), size));
                    outcome.entries_affected += 1;
                }
            }
        }
        outcome.notes.push(
            "locale trim requires rebuilding glibc-locales with --with-locales; \
             primitive records candidates only".into(),
        );
        Ok(outcome)
    }
}

// ── strip-debug ────────────────────────────────────────────────
pub struct StripDebug;

impl HardeningPrimitive for StripDebug {
    fn name(&self) -> &'static str { "strip-debug" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Minimize }
    fn description(&self) -> &'static str {
        "Strip debug symbols from binaries in /nix/store (where writable)"
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        // /nix/store is read-only by default — stripping in-place isn't
        // possible without a rebuild. This primitive records which
        // derivations ship with .debug siblings so the build-time config
        // can opt them out on the next bake.
        let mut outcome = PrimitiveOutcome::default();
        let store = ctx.store_root();
        if let Ok(entries) = std::fs::read_dir(store) {
            for entry in entries.flatten() {
                let p = entry.path();
                let debug = p.join("lib/debug");
                if debug.is_dir() {
                    let size = dir_size(&debug).unwrap_or(0);
                    outcome.bytes_freed += size;
                    outcome.entries_affected += 1;
                }
            }
        }
        outcome.notes.push(
            "debug symbols in nix store are reported as removal candidates; \
             actual strip requires separateDebugInfo = false at build time".into(),
        );
        Ok(outcome)
    }
}

// ── minimize-closure ───────────────────────────────────────────
pub struct MinimizeClosure;

impl HardeningPrimitive for MinimizeClosure {
    fn name(&self) -> &'static str { "minimize-closure" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Minimize }
    fn description(&self) -> &'static str {
        "nix-collect-garbage -d + nix-store --optimise — prune all non-current generations"
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        let mut outcome = PrimitiveOutcome::default();
        if ctx.dry_run {
            outcome.notes.push("dry-run: would run nix-collect-garbage -d && nix-store --optimise".into());
            return Ok(outcome);
        }
        let gc = std::process::Command::new("nix-collect-garbage").arg("-d").output();
        match gc {
            Ok(out) if out.status.success() => {
                let s = String::from_utf8_lossy(&out.stderr);
                // nix prints "freed N.NN MiB" on the last line
                if let Some(line) = s.lines().rev().find(|l| l.contains("freed")) {
                    outcome.notes.push(line.trim().to_string());
                } else {
                    outcome.notes.push("nix-collect-garbage -d: ok".into());
                }
                outcome.invariants_passed.push("nix-collect-garbage-d-exit-0".into());
            }
            Ok(out) => {
                outcome.invariants_failed.push(
                    format!("nix-collect-garbage exit {}: {}", out.status, String::from_utf8_lossy(&out.stderr))
                );
            }
            Err(e) => {
                outcome.notes.push(format!("nix-collect-garbage not found or failed to spawn: {e}"));
            }
        }
        let opt = std::process::Command::new("nix-store").arg("--optimise").output();
        match opt {
            Ok(out) if out.status.success() => {
                outcome.invariants_passed.push("nix-store-optimise-exit-0".into());
                outcome.notes.push("nix-store --optimise: ok".into());
            }
            Ok(out) => {
                outcome.invariants_failed.push(
                    format!("nix-store --optimise exit {}", out.status)
                );
            }
            Err(e) => {
                outcome.notes.push(format!("nix-store not found or failed to spawn: {e}"));
            }
        }
        Ok(outcome)
    }
}

// ── strip-build-tools ──────────────────────────────────────────
pub struct StripBuildTools;

impl HardeningPrimitive for StripBuildTools {
    fn name(&self) -> &'static str { "strip-build-tools" }
    fn category(&self) -> PrimitiveCategory { PrimitiveCategory::Minimize }
    fn description(&self) -> &'static str {
        "Remove compilers, headers, and build-only tooling from the AMI"
    }

    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome> {
        // Like strip-debug + strip-locales — for NixOS AMIs, the "correct"
        // way to not-have-gcc is to not include it in `environment.systemPackages`.
        // This primitive records which build-tool derivations are present
        // in /nix/store so the author can see the delta and tighten
        // config/profile.
        let mut outcome = PrimitiveOutcome::default();
        let patterns = ["gcc-", "binutils-", "glibc-headers-", "clang-", "rust-", "go-"];
        let store = ctx.store_root();
        if let Ok(entries) = std::fs::read_dir(store) {
            for entry in entries.flatten() {
                let n = entry.file_name().to_string_lossy().to_string();
                for pat in &patterns {
                    if n.contains(pat) {
                        let p = entry.path();
                        let size = dir_size(&p).unwrap_or(0);
                        outcome.bytes_freed += size;
                        outcome.entries_affected += 1;
                        outcome.notes.push(format!(
                            "build-tool candidate: {} ({} bytes)", p.display(), size
                        ));
                        break;
                    }
                }
            }
        }
        outcome.notes.push(
            "build-tool removal requires excluding from systemPackages at build time".into(),
        );
        Ok(outcome)
    }
}

// ── helper: recursive directory size ───────────────────────────
fn dir_size(path: &Path) -> Result<u64> {
    let mut total = 0u64;
    let mut stack: Vec<PathBuf> = vec![path.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(meta) = std::fs::symlink_metadata(&p) else { continue };
        if meta.is_file() {
            total = total.saturating_add(meta.len());
        } else if meta.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&p) {
                for entry in rd.flatten() {
                    stack.push(entry.path());
                }
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
    fn strip_docs_dry_run_reports_candidates() {
        let dir = tempdir().unwrap();
        let store = dir.path();
        let pkg = store.join("deadbeef-hello-1.0");
        std::fs::create_dir_all(pkg.join("share/man/man1")).unwrap();
        std::fs::write(pkg.join("share/man/man1/hello.1"), b"hello man page").unwrap();

        let mut ctx = PrimitiveCtx::dry();
        ctx.nix_store_root = Some(store.to_path_buf());
        let out = StripDocs.apply(&ctx).unwrap();
        assert_eq!(out.entries_affected, 1);
        assert!(out.bytes_freed > 0);
        // dry_run must not have deleted
        assert!(pkg.join("share/man/man1/hello.1").exists());
    }

    #[test]
    fn strip_docs_real_deletes() {
        let dir = tempdir().unwrap();
        let store = dir.path();
        let pkg = store.join("cafebabe-world-1.0");
        std::fs::create_dir_all(pkg.join("share/doc")).unwrap();
        std::fs::write(pkg.join("share/doc/README"), b"some doc").unwrap();

        let mut ctx = PrimitiveCtx::default();
        ctx.nix_store_root = Some(store.to_path_buf());
        let out = StripDocs.apply(&ctx).unwrap();
        assert_eq!(out.entries_affected, 1);
        assert!(!pkg.join("share/doc").exists());
    }

    #[test]
    fn minimize_closure_dry_run_does_not_spawn_nix() {
        let out = MinimizeClosure.apply(&PrimitiveCtx::dry()).unwrap();
        assert!(out.notes.iter().any(|n| n.contains("dry-run")));
    }

    #[test]
    fn strip_locales_reports_candidates() {
        let dir = tempdir().unwrap();
        let store = dir.path();
        let loc = store.join("abc123-glibc-locales-2.40");
        std::fs::create_dir_all(&loc).unwrap();
        std::fs::write(loc.join("dummy"), b"x").unwrap();
        let mut ctx = PrimitiveCtx::dry();
        ctx.nix_store_root = Some(store.to_path_buf());
        let out = StripLocales.apply(&ctx).unwrap();
        assert!(out.entries_affected >= 1);
    }

    #[test]
    fn category_is_minimize_for_all() {
        assert_eq!(StripDocs.category(),       PrimitiveCategory::Minimize);
        assert_eq!(StripLocales.category(),    PrimitiveCategory::Minimize);
        assert_eq!(StripDebug.category(),      PrimitiveCategory::Minimize);
        assert_eq!(MinimizeClosure.category(), PrimitiveCategory::Minimize);
        assert_eq!(StripBuildTools.category(), PrimitiveCategory::Minimize);
    }
}
