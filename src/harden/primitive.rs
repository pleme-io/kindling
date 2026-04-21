//! Typed hardening primitive trait + report shape.
//!
//! Every hardening action (scrub-logs, strip-docs, sshd-strict, …)
//! implements [`HardeningPrimitive`]. The runner walks a profile's
//! primitive list, executes each, and collects a [`HardeningReport`]
//! summarising what happened — size deltas, invariants checked,
//! failures — so ami-forge's pipeline gate can refuse to promote an
//! AMI whose profile didn't pass.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// A single hardening action. Implementations must be idempotent —
/// running a primitive twice on the same host is never worse than
/// running it once. This lets profiles stack freely and lets
/// operators re-trigger cleanups at runtime without surprises.
pub trait HardeningPrimitive: Send + Sync {
    /// Stable identifier used in profiles and CLI args, e.g.
    /// `"scrub-logs"`, `"strip-docs"`. Kebab-case.
    fn name(&self) -> &'static str;

    /// Which broad category this falls under — drives ordering
    /// (minimize runs before scrub runs before zero-fill) and lets
    /// reports be grouped. See [`PrimitiveCategory`].
    fn category(&self) -> PrimitiveCategory;

    /// A one-line human-readable description, shown in reports.
    fn description(&self) -> &'static str;

    /// Run the primitive, producing a [`PrimitiveOutcome`]. Errors
    /// should be returned rather than panicked — the runner decides
    /// whether a single failure is fatal or should be downgraded to
    /// a warning (configurable per-profile).
    fn apply(&self, ctx: &PrimitiveCtx) -> Result<PrimitiveOutcome>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrimitiveCategory {
    /// Reduce image footprint — smaller closures, less to audit.
    Minimize,
    /// Harden filesystem mounts / permissions.
    Filesystem,
    /// Kernel lockdown + sysctls + module blacklists.
    Kernel,
    /// Network baseline: firewall, sshd, ipv6, etc.
    Network,
    /// Auditd rules + identity minimization.
    Audit,
    /// Secure erase + log/history/ssh-key wipe — always last so
    /// earlier primitives' output isn't scrubbed before we report.
    Scrub,
}

impl PrimitiveCategory {
    /// Recommended execution order. The runner uses this to sort
    /// the flattened primitive list from a profile stack.
    pub fn rank(self) -> u8 {
        match self {
            Self::Minimize   => 0,
            Self::Filesystem => 1,
            Self::Kernel     => 2,
            Self::Network    => 3,
            Self::Audit      => 4,
            Self::Scrub      => 5,
        }
    }
}

/// Context handed to each primitive. Keeps the primitive decoupled
/// from CLI args and configuration loaders — callers pass in what
/// changes per-invocation (dry-run flag, namespace) and the rest
/// comes from the system.
#[derive(Clone, Debug)]
pub struct PrimitiveCtx {
    /// When true, primitives describe what they would do but don't
    /// mutate the filesystem. Implementations MUST honour this.
    pub dry_run: bool,

    /// Optional override for /nix/store — lets tests point at a
    /// scratch directory instead of the real store.
    pub nix_store_root: Option<std::path::PathBuf>,

    /// Optional override for / — same reasoning as above for
    /// primitives that touch /tmp, /var, etc.
    pub filesystem_root: Option<std::path::PathBuf>,
}

impl Default for PrimitiveCtx {
    fn default() -> Self {
        Self {
            dry_run: false,
            nix_store_root: None,
            filesystem_root: None,
        }
    }
}

impl PrimitiveCtx {
    pub fn dry() -> Self {
        Self { dry_run: true, ..Default::default() }
    }

    /// The effective filesystem root — either the test override or
    /// real `/`.
    pub fn fs_root(&self) -> &std::path::Path {
        self.filesystem_root
            .as_deref()
            .unwrap_or(std::path::Path::new("/"))
    }

    /// The effective nix store — either the test override or
    /// `/nix/store`.
    pub fn store_root(&self) -> &std::path::Path {
        self.nix_store_root
            .as_deref()
            .unwrap_or(std::path::Path::new("/nix/store"))
    }
}

/// What a primitive accomplished. Fields are optional because not
/// every primitive produces every signal — scrub-logs reports
/// `bytes_freed`, sshd-strict reports `invariants_checked`, etc.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PrimitiveOutcome {
    /// Bytes removed from the filesystem. Positive.
    #[serde(default)]
    pub bytes_freed: u64,

    /// Number of filesystem entries (files or dirs) affected.
    #[serde(default)]
    pub entries_affected: u64,

    /// Invariants this primitive checked and passed, e.g.
    /// `"sshd_config: PermitRootLogin=no"`.
    #[serde(default)]
    pub invariants_passed: Vec<String>,

    /// Invariants that failed — the runner can choose to bubble these
    /// up as errors or warnings per the profile's `on_failure`.
    #[serde(default)]
    pub invariants_failed: Vec<String>,

    /// Human-readable notes (one per meaningful sub-action). Appears
    /// in the report alongside the primitive's name.
    #[serde(default)]
    pub notes: Vec<String>,

    /// How long the primitive took to run. Populated by the runner.
    #[serde(default)]
    pub duration: Option<Duration>,
}

impl PrimitiveOutcome {
    /// Shorthand for "this primitive didn't do anything measurable
    /// because the host was already in the desired state".
    pub fn no_op() -> Self { Self::default() }

    /// Merge two outcomes — used when a primitive delegates to
    /// several inner helpers.
    pub fn merge(mut self, other: Self) -> Self {
        self.bytes_freed += other.bytes_freed;
        self.entries_affected += other.entries_affected;
        self.invariants_passed.extend(other.invariants_passed);
        self.invariants_failed.extend(other.invariants_failed);
        self.notes.extend(other.notes);
        // duration is additive where both are populated
        self.duration = match (self.duration, other.duration) {
            (Some(a), Some(b)) => Some(a + b),
            (a, b) => a.or(b),
        };
        self
    }
}

/// Full report after a profile runs. Consumed by ami-forge (as a
/// manifest alongside the AMI) and by the CLI (pretty-printed).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HardeningReport {
    /// Profile names that were stacked, in invocation order.
    pub profiles: Vec<String>,

    /// Per-primitive outcomes.
    pub primitives: Vec<PrimitiveRecord>,

    /// Aggregate totals.
    pub totals: PrimitiveOutcome,

    /// Overall status.
    pub status: ReportStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrimitiveRecord {
    pub name: String,
    pub category: PrimitiveCategory,
    pub outcome: PrimitiveOutcome,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportStatus {
    /// Every primitive ran and no invariants failed.
    #[default]
    Pass,
    /// At least one primitive errored or an invariant failed, but
    /// the profile's ``on_failure`` said to continue.
    Degraded,
    /// Fatal — a primitive errored with ``on_failure = abort``.
    Failed,
}
