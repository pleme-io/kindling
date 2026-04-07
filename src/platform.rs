use anyhow::{bail, Result};
use serde::Serialize;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, Serialize)]
pub enum Os {
    MacOS,
    Linux,
}

#[derive(Debug, Clone, Copy, Serialize)]
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

#[derive(Debug, Serialize)]
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── Backend FromStr tests ──────────────────────────────

    #[test]
    fn backend_parse_upstream() {
        let b: Backend = "upstream".parse().unwrap();
        assert!(matches!(b, Backend::Upstream));
    }

    #[test]
    fn backend_parse_determinate() {
        let b: Backend = "determinate".parse().unwrap();
        assert!(matches!(b, Backend::Determinate));
    }

    #[test]
    fn backend_parse_unknown_fails() {
        let result: Result<Backend> = "nixpkgs".parse();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unknown backend"));
        assert!(err.contains("nixpkgs"));
    }

    #[test]
    fn backend_parse_empty_fails() {
        let result: Result<Backend> = "".parse();
        assert!(result.is_err());
    }

    #[test]
    fn backend_parse_case_sensitive() {
        let result: Result<Backend> = "Upstream".parse();
        assert!(result.is_err(), "parsing should be case-sensitive");
    }

    // ── Backend Display tests ──────────────────────────────

    #[test]
    fn backend_display_upstream() {
        assert_eq!(Backend::Upstream.to_string(), "upstream");
    }

    #[test]
    fn backend_display_determinate() {
        assert_eq!(Backend::Determinate.to_string(), "determinate");
    }

    #[test]
    fn backend_roundtrip_display_parse() {
        for original in [Backend::Upstream, Backend::Determinate] {
            let s = original.to_string();
            let parsed: Backend = s.parse().unwrap();
            assert_eq!(parsed.to_string(), original.to_string());
        }
    }

    // ── Platform target_triple tests ──────────────────────────────

    #[test]
    fn target_triple_linux_x86_64() {
        let p = Platform { os: Os::Linux, arch: Arch::X86_64, is_wsl: false };
        assert_eq!(p.target_triple(), "x86_64-linux");
    }

    #[test]
    fn target_triple_linux_aarch64() {
        let p = Platform { os: Os::Linux, arch: Arch::Aarch64, is_wsl: false };
        assert_eq!(p.target_triple(), "aarch64-linux");
    }

    #[test]
    fn target_triple_macos_x86_64() {
        let p = Platform { os: Os::MacOS, arch: Arch::X86_64, is_wsl: false };
        assert_eq!(p.target_triple(), "x86_64-darwin");
    }

    #[test]
    fn target_triple_macos_aarch64() {
        let p = Platform { os: Os::MacOS, arch: Arch::Aarch64, is_wsl: false };
        assert_eq!(p.target_triple(), "aarch64-darwin");
    }

    // ── installer_url tests ──────────────────────────────

    #[test]
    fn installer_url_upstream_linux() {
        let p = Platform { os: Os::Linux, arch: Arch::X86_64, is_wsl: false };
        let url = installer_url(&p, &Backend::Upstream);
        assert!(url.contains("NixOS/nix-installer"));
        assert!(url.contains("x86_64-linux"));
    }

    #[test]
    fn installer_url_determinate_macos() {
        let p = Platform { os: Os::MacOS, arch: Arch::Aarch64, is_wsl: false };
        let url = installer_url(&p, &Backend::Determinate);
        assert!(url.contains("install.determinate.systems"));
        assert!(url.contains("aarch64-darwin"));
    }

    #[test]
    fn installer_url_uses_correct_triple() {
        let p = Platform { os: Os::Linux, arch: Arch::Aarch64, is_wsl: false };
        let url = installer_url(&p, &Backend::Upstream);
        assert!(url.ends_with("aarch64-linux"));
    }

    // ── detect tests ──────────────────────────────

    #[test]
    fn detect_returns_current_platform() {
        let p = detect().unwrap();
        #[cfg(target_os = "linux")]
        assert!(matches!(p.os, Os::Linux));
        #[cfg(target_os = "macos")]
        assert!(matches!(p.os, Os::MacOS));
    }
}
