//! CLI handlers for `kindling server bootstrap` and `kindling server status`.

use anyhow::{bail, Result};
use std::path::PathBuf;

use crate::server::bootstrap;

/// Run the server bootstrap sequence.
pub fn run_bootstrap(config: &str) -> Result<()> {
    let config_path = PathBuf::from(config);
    if !config_path.exists() {
        bail!(
            "cluster config not found at {}\n   \
             Expected cloud-init to write this file at boot.",
            config_path.display()
        );
    }
    bootstrap::run(&config_path)
}

/// Print server bootstrap status.
pub fn run_status() -> Result<()> {
    bootstrap::status()
}
