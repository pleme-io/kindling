use serde::Serialize;
use std::path::PathBuf;
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

fn status_from_path(path: &PathBuf) -> NixStatus {
    let version = parse_version(path);
    NixStatus {
        installed: true,
        version,
        nix_path: Some(path.clone()),
    }
}

fn parse_version(nix_path: &PathBuf) -> Option<semver::Version> {
    let output = Command::new(nix_path)
        .arg("--version")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Format: "nix (Nix) 2.24.12"
    let version_str = stdout.trim().rsplit(' ').next()?;
    semver::Version::parse(version_str).ok()
}
