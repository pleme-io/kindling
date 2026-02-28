use anyhow::{bail, Result};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy)]
pub enum Os {
    MacOS,
    Linux,
}

#[derive(Debug, Clone, Copy)]
pub enum Arch {
    X86_64,
    Aarch64,
}

#[derive(Debug, Clone, Copy)]
pub enum Backend {
    Upstream,
    Determinate,
}

impl FromStr for Backend {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "upstream" => Ok(Backend::Upstream),
            "determinate" => Ok(Backend::Determinate),
            other => bail!("unknown backend '{}' (expected 'upstream' or 'determinate')", other),
        }
    }
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Backend::Upstream => write!(f, "upstream"),
            Backend::Determinate => write!(f, "determinate"),
        }
    }
}

#[derive(Debug)]
pub struct Platform {
    pub os: Os,
    pub arch: Arch,
    pub is_wsl: bool,
}

impl Platform {
    pub fn target_triple(&self) -> &'static str {
        match (&self.os, &self.arch) {
            (Os::MacOS, Arch::X86_64) => "x86_64-darwin",
            (Os::MacOS, Arch::Aarch64) => "aarch64-darwin",
            (Os::Linux, Arch::X86_64) => "x86_64-linux",
            (Os::Linux, Arch::Aarch64) => "aarch64-linux",
        }
    }
}

pub fn detect() -> Result<Platform> {
    let os = match std::env::consts::OS {
        "macos" => Os::MacOS,
        "linux" => Os::Linux,
        other => bail!("unsupported OS: {}", other),
    };

    let arch = match std::env::consts::ARCH {
        "x86_64" => Arch::X86_64,
        "aarch64" => Arch::Aarch64,
        other => bail!("unsupported architecture: {}", other),
    };

    let is_wsl = matches!(os, Os::Linux) && detect_wsl();

    Ok(Platform { os, arch, is_wsl })
}

fn detect_wsl() -> bool {
    std::fs::read_to_string("/proc/version")
        .map(|v| {
            let lower = v.to_lowercase();
            lower.contains("microsoft") || lower.contains("wsl")
        })
        .unwrap_or(false)
}

pub fn installer_url(platform: &Platform, backend: &Backend) -> String {
    let target = platform.target_triple();
    match backend {
        Backend::Upstream => format!(
            "https://github.com/NixOS/nix-installer/releases/latest/download/nix-installer-{}",
            target
        ),
        Backend::Determinate => format!(
            "https://install.determinate.systems/nix/nix-installer-{}",
            target
        ),
    }
}

pub fn has_systemd() -> bool {
    std::path::Path::new("/run/systemd/system").exists()
}
