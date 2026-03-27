//! CLI handler for `kindling init` — read cloud userdata, extract config, bootstrap.
//!
//! Replaces the two-service dance of `amazon-init` + `kindling-server-bootstrap`
//! with a single unified entry point. Reads EC2 userdata (JSON or bash script
//! containing a heredoc), writes the cluster config JSON, then delegates to the
//! existing bootstrap state machine.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::server::bootstrap;

/// Arguments for `kindling init`.
#[derive(clap::Args)]
pub struct InitArgs {
    /// Path to userdata file
    #[arg(long, default_value = "/etc/ec2-metadata/user-data")]
    pub userdata: PathBuf,

    /// Path to write cluster-config.json
    #[arg(long, default_value = "/etc/pangea/cluster-config.json")]
    pub config_out: PathBuf,
}

/// Detected userdata format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UserdataFormat {
    Json,
    BashScript,
    Unknown,
}

/// Run the `kindling init` flow: read userdata, extract config, bootstrap.
pub fn run(args: InitArgs) -> Result<()> {
    tracing::info!(userdata = %args.userdata.display(), "starting kindling init");

    let content = fs::read_to_string(&args.userdata)
        .with_context(|| format!("failed to read userdata from {}", args.userdata.display()))?;

    if content.trim().is_empty() {
        bail!(
            "userdata file is empty: {}",
            args.userdata.display()
        );
    }

    let format = detect_format(&content);
    tracing::info!(?format, "detected userdata format");

    let json = match format {
        UserdataFormat::Json => {
            // Validate it is actually parseable JSON
            serde_json::from_str::<serde_json::Value>(&content)
                .context("userdata looks like JSON but failed to parse")?;
            content.clone()
        }
        UserdataFormat::BashScript => {
            extract_json_from_heredoc(&content)
                .context("failed to extract JSON from bash userdata heredoc")?
        }
        UserdataFormat::Unknown => {
            bail!(
                "unrecognised userdata format (expected JSON object or bash script): {}",
                args.userdata.display()
            );
        }
    };

    write_config(&json, &args.config_out)?;
    tracing::info!(path = %args.config_out.display(), "cluster config written");

    // Delegate to the existing bootstrap state machine
    bootstrap::run(&args.config_out)
}

/// Detect whether the userdata content is raw JSON or a bash script.
fn detect_format(content: &str) -> UserdataFormat {
    let trimmed = content.trim_start();
    if trimmed.starts_with('{') {
        UserdataFormat::Json
    } else if trimmed.starts_with("#!") {
        UserdataFormat::BashScript
    } else {
        UserdataFormat::Unknown
    }
}

/// Extract JSON from a bash heredoc of the form:
///
/// ```bash
/// cat << 'PANGEA_CONFIG_EOF' > /some/path
/// { ... }
/// PANGEA_CONFIG_EOF
/// ```
///
/// Supports both `<<` and `<< ` with optional quoting of the delimiter.
fn extract_json_from_heredoc(script: &str) -> Result<String> {
    // Find the heredoc start marker. We look for lines containing the
    // PANGEA_CONFIG_EOF delimiter in a heredoc redirect.
    let delimiter = "PANGEA_CONFIG_EOF";

    let mut lines = script.lines();
    let mut found_start = false;

    // Scan for the heredoc opening line
    while let Some(line) = lines.next() {
        // Match patterns like:
        //   cat << 'PANGEA_CONFIG_EOF' > /path
        //   cat <<'PANGEA_CONFIG_EOF'
        //   cat <<PANGEA_CONFIG_EOF
        if line.contains("<<") && line.contains(delimiter) {
            found_start = true;
            break;
        }
    }

    if !found_start {
        bail!(
            "no heredoc with delimiter '{}' found in bash script",
            delimiter
        );
    }

    // Capture lines until the closing delimiter
    let mut captured = Vec::new();
    let mut found_end = false;

    for line in lines {
        let trimmed = line.trim();
        if trimmed == delimiter {
            found_end = true;
            break;
        }
        captured.push(line);
    }

    if !found_end {
        bail!(
            "heredoc opened with '{}' but closing delimiter was never found",
            delimiter
        );
    }

    let json_text = captured.join("\n");

    // Validate the captured text is valid JSON
    serde_json::from_str::<serde_json::Value>(&json_text)
        .context("heredoc content is not valid JSON")?;

    Ok(json_text)
}

/// Write the config JSON to disk with proper permissions (0640).
fn write_config(json: &str, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    fs::write(path, json)
        .with_context(|| format!("failed to write config to {}", path.display()))?;

    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o640))
        .with_context(|| format!("failed to set permissions on {}", path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_format_json() {
        let json = r#"{"cluster_name": "test"}"#;
        assert_eq!(detect_format(json), UserdataFormat::Json);
    }

    #[test]
    fn detect_format_json_with_whitespace() {
        let json = "  \n  { \"cluster_name\": \"test\" }";
        assert_eq!(detect_format(json), UserdataFormat::Json);
    }

    #[test]
    fn detect_format_bash() {
        let bash = "#!/bin/bash\necho hello\n";
        assert_eq!(detect_format(bash), UserdataFormat::BashScript);
    }

    #[test]
    fn detect_format_bash_env() {
        let bash = "#!/usr/bin/env bash\necho hello\n";
        assert_eq!(detect_format(bash), UserdataFormat::BashScript);
    }

    #[test]
    fn detect_format_empty() {
        assert_eq!(detect_format(""), UserdataFormat::Unknown);
    }

    #[test]
    fn detect_format_unknown() {
        assert_eq!(detect_format("some random text"), UserdataFormat::Unknown);
    }

    #[test]
    fn extract_heredoc_basic() {
        let script = r#"#!/bin/bash
set -euo pipefail

cat << 'PANGEA_CONFIG_EOF' > /etc/pangea/cluster-config.json
{
  "cluster_name": "ryn-k3s",
  "role": "server",
  "distribution": "k3s"
}
PANGEA_CONFIG_EOF

echo "done"
"#;
        let json = extract_json_from_heredoc(script).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["cluster_name"], "ryn-k3s");
        assert_eq!(parsed["role"], "server");
        assert_eq!(parsed["distribution"], "k3s");
    }

    #[test]
    fn extract_heredoc_no_quotes_on_delimiter() {
        let script = r#"#!/bin/bash
cat <<PANGEA_CONFIG_EOF > /etc/pangea/cluster-config.json
{"cluster_name": "test"}
PANGEA_CONFIG_EOF
"#;
        let json = extract_json_from_heredoc(script).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["cluster_name"], "test");
    }

    #[test]
    fn extract_heredoc_complex_config() {
        let script = r#"#!/bin/bash
set -euo pipefail

# Some preamble
export FOO=bar

cat << 'PANGEA_CONFIG_EOF' > /etc/pangea/cluster-config.json
{
  "cluster_name": "prod-cluster",
  "role": "server",
  "distribution": "k3s",
  "profile": "cloud-server",
  "node_index": 0,
  "cluster_init": true,
  "fluxcd": {
    "source_url": "https://github.com/pleme-io/k8s",
    "branch": "main"
  },
  "bootstrap_secrets": {
    "sops_age_key": "AGE-SECRET-KEY-1ABCDEF"
  }
}
PANGEA_CONFIG_EOF

systemctl start kindling-init
"#;
        let json = extract_json_from_heredoc(script).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["cluster_name"], "prod-cluster");
        assert!(parsed["fluxcd"].is_object());
        assert_eq!(
            parsed["bootstrap_secrets"]["sops_age_key"],
            "AGE-SECRET-KEY-1ABCDEF"
        );
    }

    #[test]
    fn extract_heredoc_invalid_json() {
        let script = r#"#!/bin/bash
cat << 'PANGEA_CONFIG_EOF' > /etc/pangea/cluster-config.json
this is not json at all
PANGEA_CONFIG_EOF
"#;
        let result = extract_json_from_heredoc(script);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("not valid JSON"),
            "expected 'not valid JSON' in error, got: {}",
            err_msg
        );
    }

    #[test]
    fn extract_heredoc_missing_delimiter() {
        let script = r#"#!/bin/bash
echo "no heredoc here"
"#;
        let result = extract_json_from_heredoc(script);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("no heredoc"),
            "expected 'no heredoc' in error, got: {}",
            err_msg
        );
    }

    #[test]
    fn extract_heredoc_unclosed() {
        let script = r#"#!/bin/bash
cat << 'PANGEA_CONFIG_EOF' > /etc/pangea/cluster-config.json
{"cluster_name": "test"}
"#;
        let result = extract_json_from_heredoc(script);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("closing delimiter"),
            "expected 'closing delimiter' in error, got: {}",
            err_msg
        );
    }

    #[test]
    fn write_config_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b").join("config.json");

        write_config(r#"{"cluster_name":"test"}"#, &nested).unwrap();

        assert!(nested.exists());
        let content = fs::read_to_string(&nested).unwrap();
        assert!(content.contains("cluster_name"));
    }

    #[test]
    #[cfg(unix)]
    fn write_config_sets_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");

        write_config(r#"{"cluster_name":"test"}"#, &path).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }
}
