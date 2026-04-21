//! Hardening subsystem.
//!
//! Public surface:
//!
//! - [`HardeningPrimitive`] / [`PrimitiveCategory`] / [`PrimitiveCtx`] /
//!   [`PrimitiveOutcome`] — the building blocks a primitive
//!   implementation needs.
//! - [`HardeningProfile`] / [`HardeningParams`] / [`FailurePolicy`] /
//!   [`ComposedPlan`] — the declarative surface a profile authors.
//! - [`compose`] — flatten + dedup a stack of profiles.
//! - [`run`] / [`render_report`] — execute a plan and format its
//!   report.
//! - [`registry`] / [`all_names`] — enumerate or look up primitives.
//!
//! See the `harden` CLI subcommand in `commands::harden` for the
//! consumer-facing entry point.

pub mod primitive;
pub mod primitives;
pub mod profile;
pub mod runner;

pub use primitive::{
    HardeningPrimitive, HardeningReport, PrimitiveCategory, PrimitiveCtx,
    PrimitiveOutcome, PrimitiveRecord, ReportStatus,
};
pub use primitives::{all_names, registry};
pub use profile::{
    compose, ComposedPlan, FailurePolicy, HardeningParams, HardeningProfile,
};
pub use runner::{render_report, run};
