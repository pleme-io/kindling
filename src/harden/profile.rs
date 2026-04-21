//! Typed hardening profile — the declarative surface consumers
//! target. A profile is a named set of primitives (by kebab-case
//! name) across the six categories, plus a per-profile failure
//! policy and optional parametric knobs used by some primitives
//! (firewall-allow-list, strip-locale keep-list, etc.).
//!
//! Profiles compose via set union; ``compose`` below flattens a
//! stack (e.g. [base, hardened, ami-snapshot]) into a deduplicated,
//! topologically-ordered run plan. The schema is serde-derived so
//! shikumi's provider chain reads the same struct from lisp / yaml
//! / json / nix / toml — consumers pick whichever format matches
//! the surrounding config style.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct HardeningProfile {
    /// Human-facing name. Emitted in reports and used in logs so
    /// an operator can see which profile fired which primitive.
    pub name: String,

    /// Short description for CLI help + reports.
    #[serde(default)]
    pub description: String,

    /// Primitive categories — each is a list of primitive names
    /// (kebab-case, matching the registry). Duplicates across
    /// categories or across composed profiles are deduplicated by
    /// the composer.
    #[serde(default)]
    pub minimize: Vec<String>,
    #[serde(default)]
    pub fs: Vec<String>,
    #[serde(default)]
    pub kernel: Vec<String>,
    #[serde(default)]
    pub network: Vec<String>,
    #[serde(default)]
    pub audit: Vec<String>,
    #[serde(default)]
    pub scrub: Vec<String>,

    /// Parametric knobs consumed by specific primitives. Keeps the
    /// primitive schema flat — no nested "primitive-config" field
    /// needed on every primitive variant.
    #[serde(default)]
    pub params: HardeningParams,

    /// What to do when a primitive errors or an invariant fails.
    #[serde(default)]
    pub on_failure: FailurePolicy,
}

impl Default for HardeningProfile {
    fn default() -> Self {
        Self {
            name: "unnamed".to_string(),
            description: String::new(),
            minimize: vec![],
            fs: vec![],
            kernel: vec![],
            network: vec![],
            audit: vec![],
            scrub: vec![],
            params: HardeningParams::default(),
            on_failure: FailurePolicy::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct HardeningParams {
    /// Locales to keep when `strip-locales` runs. Everything else
    /// is removed from glibc's locale-archive.
    pub keep_locales: Vec<String>,

    /// Paths to preserve from `scrub-temp-dirs` even if they're
    /// normally cleaned. Useful when a build system puts something
    /// persistent under /var/tmp.
    pub preserve_temp_paths: Vec<String>,

    /// Ports the firewall profile's `firewall-deny-all` should
    /// explicitly allow inbound. Empty → SSH (22) only.
    pub firewall_allow_in: Vec<u16>,

    /// sshd_config allow-listed ciphers / kex / macs. When empty
    /// the primitive uses a curated modern default.
    #[serde(default)]
    pub ssh_ciphers: Vec<String>,
    #[serde(default)]
    pub ssh_kex: Vec<String>,
    #[serde(default)]
    pub ssh_macs: Vec<String>,

    /// Kernel modules to blacklist beyond the built-in baseline.
    pub extra_blacklist_modules: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailurePolicy {
    /// Any primitive error aborts the whole profile run.
    #[default]
    Abort,
    /// Log the error as a warning and keep going.
    Warn,
    /// Require every primitive in the profile to pass every
    /// declared invariant — stricter than Abort because Abort only
    /// trips on Err returns.
    StrictInvariants,
}

impl HardeningProfile {
    /// Flatten every primitive-name in the profile into a single
    /// deduplicated set, tagged by its category. Order within a
    /// category is preserved from the declaration order.
    pub fn flatten(&self) -> Vec<(super::PrimitiveCategory, String)> {
        use super::PrimitiveCategory::*;
        let mut out: Vec<(super::PrimitiveCategory, String)> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for (cat, list) in [
            (Minimize,   &self.minimize),
            (Filesystem, &self.fs),
            (Kernel,     &self.kernel),
            (Network,    &self.network),
            (Audit,      &self.audit),
            (Scrub,      &self.scrub),
        ] {
            for name in list {
                if seen.insert(name.clone()) {
                    out.push((cat, name.clone()));
                }
            }
        }
        out
    }
}

/// Compose a stack of profiles into a single deduplicated plan.
/// Order rules:
///   1. Primitives group by category (Minimize first, Scrub last).
///   2. Within a category, the FIRST profile that mentions a
///      primitive wins its position — later mentions are skipped.
///   3. Params merge key-by-key; later profiles override earlier
///      scalars, extend earlier lists.
///   4. FailurePolicy uses the strictest (StrictInvariants >
///      Abort > Warn) across the stack.
pub fn compose(profiles: &[&HardeningProfile]) -> ComposedPlan {
    use super::PrimitiveCategory;
    let mut all: Vec<(PrimitiveCategory, String)> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for p in profiles {
        for (cat, name) in p.flatten() {
            if seen.insert(name.clone()) {
                all.push((cat, name));
            }
        }
    }
    // Stable sort by category rank so Minimize runs first, Scrub
    // last. within-category order is declaration order.
    all.sort_by_key(|(c, _)| c.rank());

    let mut params = HardeningParams::default();
    let mut policy = FailurePolicy::Warn;
    for p in profiles {
        merge_params(&mut params, &p.params);
        policy = strictest_policy(policy, p.on_failure);
    }

    ComposedPlan {
        primitives: all,
        params,
        on_failure: policy,
        profile_names: profiles.iter().map(|p| p.name.clone()).collect(),
    }
}

fn merge_params(dst: &mut HardeningParams, src: &HardeningParams) {
    extend_unique(&mut dst.keep_locales,            &src.keep_locales);
    extend_unique(&mut dst.preserve_temp_paths,     &src.preserve_temp_paths);
    extend_unique_u16(&mut dst.firewall_allow_in,   &src.firewall_allow_in);
    replace_if_set(&mut dst.ssh_ciphers,            &src.ssh_ciphers);
    replace_if_set(&mut dst.ssh_kex,                &src.ssh_kex);
    replace_if_set(&mut dst.ssh_macs,               &src.ssh_macs);
    extend_unique(&mut dst.extra_blacklist_modules, &src.extra_blacklist_modules);
}

fn extend_unique<T: Clone + Eq>(dst: &mut Vec<T>, src: &[T]) {
    for item in src {
        if !dst.contains(item) { dst.push(item.clone()); }
    }
}

fn extend_unique_u16(dst: &mut Vec<u16>, src: &[u16]) {
    for item in src {
        if !dst.contains(item) { dst.push(*item); }
    }
}

fn replace_if_set<T: Clone>(dst: &mut Vec<T>, src: &[T]) {
    if !src.is_empty() { *dst = src.to_vec(); }
}

fn strictest_policy(a: FailurePolicy, b: FailurePolicy) -> FailurePolicy {
    use FailurePolicy::*;
    match (a, b) {
        (StrictInvariants, _) | (_, StrictInvariants) => StrictInvariants,
        (Abort, _) | (_, Abort)                       => Abort,
        _                                             => Warn,
    }
}

/// Execution plan assembled from one-or-more profiles.
#[derive(Clone, Debug)]
pub struct ComposedPlan {
    pub primitives: Vec<(super::PrimitiveCategory, String)>,
    pub params: HardeningParams,
    pub on_failure: FailurePolicy,
    pub profile_names: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::PrimitiveCategory;

    fn p(name: &str, mins: &[&str], scrubs: &[&str]) -> HardeningProfile {
        HardeningProfile {
            name: name.to_string(),
            minimize: mins.iter().map(|s| s.to_string()).collect(),
            scrub:    scrubs.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn flatten_preserves_order_within_category() {
        let prof = p("x", &["strip-docs", "strip-locales"], &["scrub-logs"]);
        let flat = prof.flatten();
        assert_eq!(flat[0].1, "strip-docs");
        assert_eq!(flat[1].1, "strip-locales");
        assert_eq!(flat[2].1, "scrub-logs");
    }

    #[test]
    fn flatten_dedupes() {
        let prof = HardeningProfile {
            name: "x".into(),
            minimize: vec!["strip-docs".into(), "strip-docs".into()],
            ..Default::default()
        };
        assert_eq!(prof.flatten().len(), 1);
    }

    #[test]
    fn compose_orders_minimize_before_scrub() {
        let a = p("a", &[], &["scrub-logs"]);
        let b = p("b", &["strip-docs"], &[]);
        let plan = compose(&[&a, &b]);
        // Minimize (rank 0) must come before Scrub (rank 5).
        let positions: Vec<_> = plan.primitives.iter().map(|(c, _)| c.rank()).collect();
        let mut sorted = positions.clone();
        sorted.sort();
        assert_eq!(positions, sorted);
    }

    #[test]
    fn compose_dedupes_across_profiles() {
        let a = p("a", &["strip-docs"], &[]);
        let b = p("b", &["strip-docs", "strip-locales"], &[]);
        let plan = compose(&[&a, &b]);
        let names: Vec<_> = plan.primitives.iter().map(|(_, n)| n.clone()).collect();
        assert_eq!(names, vec!["strip-docs", "strip-locales"]);
    }

    #[test]
    fn compose_strictest_policy_wins() {
        let mut a = HardeningProfile { name: "a".into(), ..Default::default() };
        a.on_failure = FailurePolicy::Warn;
        let mut b = HardeningProfile { name: "b".into(), ..Default::default() };
        b.on_failure = FailurePolicy::StrictInvariants;
        let plan = compose(&[&a, &b]);
        assert_eq!(plan.on_failure, FailurePolicy::StrictInvariants);
    }

    #[test]
    fn compose_merges_params_lists_unique() {
        let mut a = HardeningProfile { name: "a".into(), ..Default::default() };
        a.params.keep_locales = vec!["en_US.UTF-8".into()];
        let mut b = HardeningProfile { name: "b".into(), ..Default::default() };
        b.params.keep_locales = vec!["en_US.UTF-8".into(), "C".into()];
        let plan = compose(&[&a, &b]);
        assert_eq!(plan.params.keep_locales, vec!["en_US.UTF-8", "C"]);
    }

    #[test]
    fn category_ordering() {
        assert!(PrimitiveCategory::Minimize.rank() < PrimitiveCategory::Scrub.rank());
        assert!(PrimitiveCategory::Filesystem.rank() < PrimitiveCategory::Kernel.rank());
    }
}
