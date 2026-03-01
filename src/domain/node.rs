//! Node — unified model combining declared identity and runtime report.
//!
//! A `Node` represents a single machine in the fleet, with both its desired
//! state (NodeIdentity from YAML) and actual state (NodeReport from runtime).

use async_graphql::{Enum, SimpleObject};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::node_identity::NodeIdentity;

use super::node_report::NodeReport;

/// A fleet node combining desired and actual state.
#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct Node {
    pub identity: NodeIdentity,
    pub report: Option<NodeReport>,
    pub status: NodeStatus,
    pub last_seen: Option<DateTime<Utc>>,
    pub first_seen: DateTime<Utc>,
    pub drift: Vec<DriftItem>,
}

/// Node connectivity/health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Enum)]
pub enum NodeStatus {
    Online,
    Offline,
    Degraded,
    Maintenance,
    Unknown,
}

impl Default for NodeStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

/// A single drift between declared (identity) and actual (report) state.
#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
pub struct DriftItem {
    pub category: String,
    pub field: String,
    pub expected: Option<String>,
    pub actual: Option<String>,
    pub severity: DriftSeverity,
}

/// Drift severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Enum)]
pub enum DriftSeverity {
    Info,
    Warning,
    Critical,
}
