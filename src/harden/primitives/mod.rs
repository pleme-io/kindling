//! Hardening primitive implementations, grouped by category.
//!
//! Each submodule owns one category's primitives. Every primitive
//! is a zero-sized struct implementing [`HardeningPrimitive`]; the
//! runner composes an instance by name via [`registry`].
//!
//! Module layout:
//!
//! - [`minimize`] — closure size + attack-surface reduction
//! - [`fs`]       — filesystem mount hardening
//! - [`kernel`]   — sysctls, lockdown, module blacklists
//! - [`network`]  — firewall, sshd, ipv6
//! - [`audit`]    — auditd, identity minimization
//! - [`scrub`]    — log/history/ssh-key wipe + secure-erase
//!
//! The top-level [`registry`] function returns a concrete
//! primitive by name; new primitives are registered here.

use super::primitive::HardeningPrimitive;

pub mod audit;
pub mod fs;
pub mod kernel;
pub mod minimize;
pub mod network;
pub mod scrub;

/// Look up a primitive implementation by its kebab-case name.
/// Returns `None` for unknown names; callers should surface that
/// as a profile-validation error.
pub fn registry(name: &str) -> Option<Box<dyn HardeningPrimitive>> {
    match name {
        // minimize
        "strip-docs"          => Some(Box::new(minimize::StripDocs)),
        "strip-locales"       => Some(Box::new(minimize::StripLocales)),
        "strip-debug"         => Some(Box::new(minimize::StripDebug)),
        "minimize-closure"    => Some(Box::new(minimize::MinimizeClosure)),
        "strip-build-tools"   => Some(Box::new(minimize::StripBuildTools)),

        // filesystem
        "tmpfs-sensitive-dirs" => Some(Box::new(fs::TmpfsSensitiveDirs)),
        "remount-readonly"     => Some(Box::new(fs::RemountReadonly)),

        // kernel
        "kernel-lockdown"    => Some(Box::new(kernel::KernelLockdown)),
        "sysctl-baseline"    => Some(Box::new(kernel::SysctlBaseline)),
        "blacklist-modules"  => Some(Box::new(kernel::BlacklistModules)),

        // network
        "firewall-deny-all"  => Some(Box::new(network::FirewallDenyAll)),
        "sshd-strict"        => Some(Box::new(network::SshdStrict)),
        "ssh-moduli-regen"   => Some(Box::new(network::SshModuliRegen)),
        "disable-ipv6"       => Some(Box::new(network::DisableIpv6)),

        // audit
        "auditd-baseline"       => Some(Box::new(audit::AuditdBaseline)),
        "remove-default-users"  => Some(Box::new(audit::RemoveDefaultUsers)),

        // scrub
        "scrub-logs"           => Some(Box::new(scrub::ScrubLogs)),
        "scrub-cloud-init"     => Some(Box::new(scrub::ScrubCloudInit)),
        "scrub-shell-history"  => Some(Box::new(scrub::ScrubShellHistory)),
        "scrub-ssh-keys"       => Some(Box::new(scrub::ScrubSshKeys)),
        "scrub-temp-dirs"      => Some(Box::new(scrub::ScrubTempDirs)),
        "zero-fill"            => Some(Box::new(scrub::ZeroFill)),

        _ => None,
    }
}

/// Every registered primitive name (used for CLI completions +
/// profile validation).
pub fn all_names() -> &'static [&'static str] {
    &[
        "strip-docs",
        "strip-locales",
        "strip-debug",
        "minimize-closure",
        "strip-build-tools",
        "tmpfs-sensitive-dirs",
        "remount-readonly",
        "kernel-lockdown",
        "sysctl-baseline",
        "blacklist-modules",
        "firewall-deny-all",
        "sshd-strict",
        "ssh-moduli-regen",
        "disable-ipv6",
        "auditd-baseline",
        "remove-default-users",
        "scrub-logs",
        "scrub-cloud-init",
        "scrub-shell-history",
        "scrub-ssh-keys",
        "scrub-temp-dirs",
        "zero-fill",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_named_primitive_resolves() {
        for name in all_names() {
            assert!(registry(name).is_some(), "primitive `{name}` in all_names() but not registry()");
        }
    }

    #[test]
    fn unknown_primitive_returns_none() {
        assert!(registry("nope").is_none());
        assert!(registry("").is_none());
    }
}
