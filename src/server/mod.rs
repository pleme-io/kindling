//! Server mode — K3s/Kubernetes cluster bootstrap and monitoring.
//!
//! Submodules:
//! - `cluster_config` — parse cloud-init JSON into ClusterConfig
//! - `bootstrap` — state machine for bootstrap orchestration
//! - `persistent_state` — EBS volume attach + mount before k3s
//! - `kubeadm` — kubeadm config generation for upstream Kubernetes
//! - `health` — K3s API + FluxCD health polling
//! - `daemon` — HTTP/GraphQL daemon server (pre-existing)

pub mod bootstrap;
pub mod cluster_config;
pub mod daemon;
pub mod health;
pub mod kubeadm;
// persistent_state pulls in aws-sdk-ec2 (~600k LoC after macro expansion)
// and is the build-time bottleneck for kindling. Gated behind the `aws`
// cargo feature (default-enabled; AMI consumers keep the module, kasou-VM
// consumers build with --no-default-features and skip the dep entirely).
#[cfg(feature = "aws")]
pub mod persistent_state;
pub mod wireguard_fast;
