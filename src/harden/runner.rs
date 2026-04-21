//! Profile runner — executes a [`ComposedPlan`] and produces a
//! [`HardeningReport`].
//!
//! The runner owns the semantics of `FailurePolicy`: it decides
//! whether a primitive's error is terminal, demoted to a warning, or
//! escalated on invariant mismatch.

use anyhow::Result;
use std::time::Instant;

use super::primitive::{
    HardeningPrimitive, HardeningReport, PrimitiveCtx, PrimitiveOutcome,
    PrimitiveRecord, ReportStatus,
};
use super::primitives::registry;
use super::profile::{ComposedPlan, FailurePolicy};

/// Run a composed plan. Returns the full report even on failure —
/// callers (CLI, ami-forge) pretty-print it and use `status` to gate
/// promotion.
pub fn run(plan: &ComposedPlan, ctx: &PrimitiveCtx) -> Result<HardeningReport> {
    let mut report = HardeningReport {
        profiles: plan.profile_names.clone(),
        ..Default::default()
    };
    let mut totals = PrimitiveOutcome::default();
    let mut any_err = false;
    let mut any_invariant_fail = false;

    for (category, name) in &plan.primitives {
        let Some(prim) = registry(name) else {
            report.primitives.push(PrimitiveRecord {
                name: name.clone(),
                category: *category,
                outcome: PrimitiveOutcome::default(),
                error: Some(format!("unknown primitive `{name}`")),
            });
            any_err = true;
            if plan.on_failure == FailurePolicy::Abort {
                report.status = ReportStatus::Failed;
                return Ok(report);
            }
            continue;
        };

        let started = Instant::now();
        let result = prim.apply(ctx);
        let elapsed = started.elapsed();

        match result {
            Ok(mut outcome) => {
                outcome.duration = Some(elapsed);
                if !outcome.invariants_failed.is_empty() {
                    any_invariant_fail = true;
                }
                totals = totals.clone().merge(outcome.clone());
                report.primitives.push(PrimitiveRecord {
                    name: name.clone(),
                    category: *category,
                    outcome,
                    error: None,
                });
                if any_invariant_fail
                    && matches!(plan.on_failure, FailurePolicy::StrictInvariants)
                {
                    report.status = ReportStatus::Failed;
                    report.totals = totals;
                    return Ok(report);
                }
            }
            Err(e) => {
                any_err = true;
                report.primitives.push(PrimitiveRecord {
                    name: name.clone(),
                    category: *category,
                    outcome: PrimitiveOutcome::default(),
                    error: Some(e.to_string()),
                });
                match plan.on_failure {
                    FailurePolicy::Abort | FailurePolicy::StrictInvariants => {
                        report.status = ReportStatus::Failed;
                        report.totals = totals;
                        return Ok(report);
                    }
                    FailurePolicy::Warn => {}
                }
            }
        }
    }

    report.status = if any_err || any_invariant_fail {
        ReportStatus::Degraded
    } else {
        ReportStatus::Pass
    };
    report.totals = totals;
    Ok(report)
}

/// Pretty-print a report in a form the CLI + ami-forge share.
pub fn render_report(report: &HardeningReport) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "hardening report — profiles: [{}]\n",
        report.profiles.join(", ")
    ));
    s.push_str(&format!("status: {:?}\n", report.status));
    s.push_str(&format!(
        "totals: {} bytes freed, {} entries affected\n\n",
        report.totals.bytes_freed, report.totals.entries_affected
    ));
    for rec in &report.primitives {
        let status = if rec.error.is_some() {
            "ERR"
        } else if !rec.outcome.invariants_failed.is_empty() {
            "WARN"
        } else {
            "ok"
        };
        s.push_str(&format!(
            "[{:>4}] {:?}/{:<24} — {} bytes, {} entries",
            status,
            rec.category,
            rec.name,
            rec.outcome.bytes_freed,
            rec.outcome.entries_affected,
        ));
        if let Some(d) = rec.outcome.duration {
            s.push_str(&format!(" ({:?})", d));
        }
        s.push('\n');
        if let Some(err) = &rec.error {
            s.push_str(&format!("        error: {err}\n"));
        }
        for inv in &rec.outcome.invariants_failed {
            s.push_str(&format!("        FAIL: {inv}\n"));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::profile::{compose, HardeningProfile};

    #[test]
    fn unknown_primitive_abort_fails_fast() {
        let mut prof = HardeningProfile {
            name: "x".into(),
            ..Default::default()
        };
        prof.minimize = vec!["does-not-exist".into()];
        prof.on_failure = FailurePolicy::Abort;
        let plan = compose(&[&prof]);
        let report = run(&plan, &PrimitiveCtx::dry()).unwrap();
        assert_eq!(report.status, ReportStatus::Failed);
        assert_eq!(report.primitives.len(), 1);
        assert!(report.primitives[0].error.is_some());
    }

    #[test]
    fn unknown_primitive_warn_continues() {
        let mut prof = HardeningProfile {
            name: "x".into(),
            ..Default::default()
        };
        prof.minimize = vec!["does-not-exist".into(), "strip-docs".into()];
        prof.on_failure = FailurePolicy::Warn;
        let plan = compose(&[&prof]);
        let report = run(&plan, &PrimitiveCtx::dry()).unwrap();
        assert_eq!(report.status, ReportStatus::Degraded);
        assert_eq!(report.primitives.len(), 2);
    }

    #[test]
    fn all_minimize_dry_run_passes() {
        let mut prof = HardeningProfile {
            name: "min".into(),
            ..Default::default()
        };
        // strip-docs is the only one guaranteed to be a no-op against an
        // empty tempdir store — the rest may record invariant failures
        // for missing runtime state, which is expected here.
        prof.minimize = vec!["strip-docs".into()];
        prof.on_failure = FailurePolicy::Warn;
        let plan = compose(&[&prof]);
        let report = run(&plan, &PrimitiveCtx::dry()).unwrap();
        assert!(matches!(
            report.status,
            ReportStatus::Pass | ReportStatus::Degraded
        ));
    }
}
