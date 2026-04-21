//! `kindling harden` — apply one or more hardening profiles to the
//! host and emit a [`HardeningReport`](crate::harden::HardeningReport).
//!
//! Profiles are loaded as YAML or JSON (auto-detected by extension).
//! Multiple `--profile` flags stack in order; `compose` dedupes
//! primitives and merges params. `--dry-run` lets operators inspect
//! what would change before committing.
//!
//! Typical usage during an AMI build (phase 5 of ami-build):
//!
//! ```sh
//! kindling harden \
//!     --profile /etc/kindling/profiles/base.yaml \
//!     --profile /etc/kindling/profiles/hardened.yaml \
//!     --profile /etc/kindling/profiles/ami-snapshot.yaml \
//!     --format json > /var/log/kindling/hardening-report.json
//! ```

use anyhow::{anyhow, Context, Result};
use clap::Args;
use std::path::{Path, PathBuf};

use crate::harden::{
    compose, render_report, run, HardeningProfile, PrimitiveCtx, ReportStatus,
};

#[derive(Debug, Args)]
pub struct HardenArgs {
    /// Path to a profile file (yaml or json). Repeatable; stack is
    /// composed in declaration order.
    #[arg(long = "profile", value_name = "PATH")]
    pub profiles: Vec<PathBuf>,

    /// Describe what would change without mutating the filesystem.
    #[arg(long)]
    pub dry_run: bool,

    /// Output format — `text` (default) or `json`.
    #[arg(long, default_value = "text")]
    pub format: String,

    /// Override /nix/store for tests (unit / staging).
    #[arg(long)]
    pub nix_store_root: Option<PathBuf>,

    /// Override `/` for tests (unit / staging).
    #[arg(long)]
    pub filesystem_root: Option<PathBuf>,

    /// Exit non-zero when the report status is Degraded or Failed.
    /// Default: only non-zero on Failed.
    #[arg(long)]
    pub strict: bool,
}

pub fn run_cmd(args: HardenArgs) -> Result<()> {
    if args.profiles.is_empty() {
        return Err(anyhow!(
            "at least one --profile is required (e.g. --profile /etc/kindling/profiles/base.yaml)"
        ));
    }

    let mut loaded: Vec<HardeningProfile> = Vec::with_capacity(args.profiles.len());
    for p in &args.profiles {
        loaded.push(load_profile(p).with_context(|| format!("load profile {}", p.display()))?);
    }
    let refs: Vec<&HardeningProfile> = loaded.iter().collect();
    let plan = compose(&refs);

    let ctx = PrimitiveCtx {
        dry_run: args.dry_run,
        nix_store_root: args.nix_store_root,
        filesystem_root: args.filesystem_root,
    };

    let report = run(&plan, &ctx)?;

    match args.format.as_str() {
        "json" => println!("{}", serde_json::to_string_pretty(&report)?),
        _ => println!("{}", render_report(&report)),
    }

    let exit_code = match (report.status, args.strict) {
        (ReportStatus::Failed, _) => 2,
        (ReportStatus::Degraded, true) => 1,
        _ => 0,
    };
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

fn load_profile(path: &Path) -> Result<HardeningProfile> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let parsed: HardeningProfile = match ext.as_str() {
        "json" => serde_json::from_str(&body).context("parse profile json")?,
        // Default (yaml / yml / unknown) → yaml, because YAML is a
        // superset of JSON for our schema.
        _ => serde_yaml::from_str(&body).context("parse profile yaml")?,
    };
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn loads_yaml_profile() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("base.yaml");
        std::fs::write(
            &p,
            "name: base\nminimize:\n  - strip-docs\non_failure: warn\n",
        )
        .unwrap();
        let prof = load_profile(&p).unwrap();
        assert_eq!(prof.name, "base");
        assert_eq!(prof.minimize, vec!["strip-docs"]);
    }

    #[test]
    fn loads_json_profile() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("base.json");
        std::fs::write(
            &p,
            r#"{"name":"base","minimize":["strip-docs"],"on_failure":"warn"}"#,
        )
        .unwrap();
        let prof = load_profile(&p).unwrap();
        assert_eq!(prof.name, "base");
    }
}
