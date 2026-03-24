//! Server mode — K3s/Kubernetes cluster bootstrap and monitoring.
//!
//! Submodules:
//! - `cluster_config` — parse cloud-init JSON into ClusterConfig
//! - `bootstrap` — state machine for bootstrap orchestration
//! - `health` — K3s API + FluxCD health polling
//! - `daemon` — HTTP/GraphQL daemon server (pre-existing)

pub mod bootstrap;
pub mod cluster_config;
pub mod daemon;
pub mod health;
