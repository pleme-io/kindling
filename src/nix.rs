use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Serialize)]
pub struct NixStatus {
    pub installed: bool,
    pub version: Option<semver::Version>,
    pub nix_path: Option<PathBuf>,
}

pub fn detect() -> NixStatus {
    // Check PATH first
    if let Some(path) = find_in_path("nix") {
        return status_from_path(&path);
    }

    // Check well-known locations
    let well_known = [
        "/nix/var/nix/profiles/default/bin/nix",
        "/run/current-system/sw/bin/nix",
    ];

    for location in &well_known {
        let path = PathBuf::from(location);
        if path.exists() {
            return status_from_path(&path);
        }
    }

    // Check home profile
    if let Some(home) = dirs::home_dir() {
        let path = home.join(".nix-profile/bin/nix");
        if path.exists() {
            return status_from_path(&path);
        }
    }

    NixStatus {
        installed: false,
        version: None,
        nix_path: None,
    }
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|path| path.is_file())
    })
}

fn status_from_path(path: &Path) -> NixStatus {
    let version = parse_version(path);
    NixStatus {
        installed: true,
        version,
        nix_path: Some(path.to_path_buf()),
    }
}

fn parse_version(nix_path: &Path) -> Option<semver::Version> {
    let output = Command::new(nix_path)
        .arg("--version")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_version_string(&stdout)
}

/// Parse a Nix version from its `--version` output.
///
/// Handles formats like `"nix (Nix) 2.24.12"`.
fn parse_version_string(output: &str) -> Option<semver::Version> {
    let version_str = output.trim().rsplit(' ').next()?;
    semver::Version::parse(version_str).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_string_standard() {
        let v = parse_version_string("nix (Nix) 2.24.12").unwrap();
        assert_eq!(v.major, 2);
        assert_eq!(v.minor, 24);
        assert_eq!(v.patch, 12);
    }

    #[test]
    fn parse_version_string_with_trailing_newline() {
        let v = parse_version_string("nix (Nix) 2.18.0\n").unwrap();
        assert_eq!(v, semver::Version::new(2, 18, 0));
    }

    #[test]
    fn parse_version_string_empty() {
        assert!(parse_version_string("").is_none());
    }

    #[test]
    fn parse_version_string_garbage() {
        assert!(parse_version_string("not a version").is_none());
    }

    #[test]
    fn detect_returns_status() {
        let status = detect();
        // We can't assert installed/not-installed since CI may not have Nix,
        // but we can verify the struct is well-formed.
        if status.installed {
            assert!(status.nix_path.is_some());
        } else {
            assert!(status.version.is_none());
        }
    }

    #[test]
    fn nix_status_serializes() {
        let status = NixStatus {
            installed: true,
            version: Some(semver::Version::new(2, 24, 0)),
            nix_path: Some(PathBuf::from("/nix/store/bin/nix")),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"installed\":true"));
        assert!(json.contains("2.24.0"));
    }

    #[test]
    fn nix_status_uninstalled_serializes() {
        let status = NixStatus {
            installed: false,
            version: None,
            nix_path: None,
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"installed\":false"));
    }
}
