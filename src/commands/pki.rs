//! Deterministic PKI bootstrap for the pleme-io k3s fleet.
//!
//! Two operator-facing subcommands:
//!
//! * `kindling pki mint --cluster <name>` — runs ONCE per cluster, generates
//!   the full set of k3s server-side PKI roots + an admin client cert via
//!   rcgen, emits sops-mergeable YAML to stdout. The operator pipes it into
//!   `sops --set` (or merges by hand) into the fleet `secrets.yaml`.
//!
//! * `kindling pki seed --source sops-nix --cluster <name>` — runs on every
//!   VM boot from a `Before=k3s.service` oneshot. Reads the sops-nix-decrypted
//!   files from `/run/secrets/clusters/<name>/tls/*` and writes them into
//!   `/var/lib/rancher/k3s/server/tls/*` per the SECRET_TARGETS table that
//!   `server/bootstrap.rs` already owns for the AMI/EC2 path. The seed table
//!   below is the *strict subset* of bootstrap's table that lives under the
//!   k3s TLS dir — both share the same path constants, so a k3s version bump
//!   that moves a file is a single-edit change.
//!
//! The whole point: AMI clusters bootstrap via `kindling init` from EC2
//! userdata; kasou-VM clusters bootstrap via `kindling pki seed` from
//! sops-nix. Same PKI shape, two input sources, one substrate primitive.

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};
use time::OffsetDateTime;

/// The single source of truth for which k3s PKI files engenho's deterministic
/// init must seed. Each entry maps a sops-encrypted YAML key (relative to
/// `clusters/<name>/tls/`) to the on-disk path k3s reads at startup and the
/// file mode it expects.
///
/// Kept in sync with `server/bootstrap.rs`'s SECRET_TARGETS PKI rows by
/// construction — if k3s ever moves these paths, fix in both places (or
/// extract a shared crate, the eventual destination per the substrate's
/// "solve once" rule). For now the duplication is two short tables.
struct PkiTarget {
    /// Key under `clusters/<name>/tls/` in sops + filename under
    /// `/run/secrets/clusters/<name>/tls/` after sops-nix decryption.
    sops_key: &'static str,
    /// Destination path k3s reads at startup.
    dest:     &'static str,
    /// Unix file mode (0o600 for keys, 0o644 for certs that k3s rereads
    /// from a non-root sub-process).
    mode:     u32,
}

const TLS_DIR: &str = "/var/lib/rancher/k3s/server/tls";

const PKI_TARGETS: &[PkiTarget] = &[
    PkiTarget {
        sops_key: "server-ca-crt",
        dest:     "/var/lib/rancher/k3s/server/tls/server-ca.crt",
        mode:     0o644,
    },
    PkiTarget {
        sops_key: "server-ca-key",
        dest:     "/var/lib/rancher/k3s/server/tls/server-ca.key",
        mode:     0o600,
    },
    PkiTarget {
        sops_key: "client-ca-crt",
        dest:     "/var/lib/rancher/k3s/server/tls/client-ca.crt",
        mode:     0o644,
    },
    PkiTarget {
        sops_key: "client-ca-key",
        dest:     "/var/lib/rancher/k3s/server/tls/client-ca.key",
        mode:     0o600,
    },
    PkiTarget {
        sops_key: "request-header-ca-crt",
        dest:     "/var/lib/rancher/k3s/server/tls/request-header-ca.crt",
        mode:     0o644,
    },
    PkiTarget {
        sops_key: "request-header-ca-key",
        dest:     "/var/lib/rancher/k3s/server/tls/request-header-ca.key",
        mode:     0o600,
    },
    PkiTarget {
        sops_key: "service-key",
        dest:     "/var/lib/rancher/k3s/server/tls/service.key",
        mode:     0o600,
    },
];

// ─────────────────────────────────────────────────────────────────────────
// `kindling pki mint --cluster <name>`
// ─────────────────────────────────────────────────────────────────────────

pub fn run_mint(cluster: &str, admin_cn: &str, validity_days: u32) -> Result<()> {
    if cluster.is_empty() || cluster.contains(['/', '\\', '\0']) {
        return Err(anyhow!("--cluster must be a non-empty path-safe identifier"));
    }
    let validity_secs = u64::from(validity_days) * 86_400;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before unix epoch")?
        .as_secs();
    let not_before = unix_to_offsetdatetime(now)?;
    let not_after = unix_to_offsetdatetime(now + validity_secs)?;

    let server_ca = mint_ca("k3s-server-ca", not_before, not_after)?;
    let client_ca = mint_ca("k3s-client-ca", not_before, not_after)?;
    let request_header_ca =
        mint_ca("k3s-request-header-ca", not_before, not_after)?;
    let service_key = KeyPair::generate()?;

    // Admin client cert (CN=system:admin, O=system:masters) signed by the
    // client CA. This is the cert the Mac-side kubeconfig embeds.
    let mut admin_params = CertificateParams::default();
    admin_params.not_before = not_before;
    admin_params.not_after = not_after;
    admin_params.distinguished_name = DistinguishedName::new();
    admin_params
        .distinguished_name
        .push(DnType::CommonName, admin_cn);
    admin_params
        .distinguished_name
        .push(DnType::OrganizationName, "system:masters");
    admin_params.is_ca = IsCa::NoCa;
    admin_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    admin_params.extended_key_usages =
        vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let admin_key = KeyPair::generate()?;
    let admin_cert = admin_params
        .signed_by(&admin_key, &client_ca.cert, &client_ca.key)?;

    print_sops_yaml(
        cluster,
        &server_ca,
        &client_ca,
        &request_header_ca,
        &service_key,
        &MintedLeaf {
            cert_pem: admin_cert.pem(),
            key_pem:  admin_key.serialize_pem(),
        },
    );
    Ok(())
}

struct MintedCa {
    cert: rcgen::Certificate,
    key:  KeyPair,
}

struct MintedLeaf {
    cert_pem: String,
    key_pem:  String,
}

fn mint_ca(
    cn: &str,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> Result<MintedCa> {
    let mut params = CertificateParams::default();
    params.not_before = not_before;
    params.not_after = not_after;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, cn);
    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    Ok(MintedCa { cert, key })
}

/// Emit a sops-mergeable YAML block on stdout. The operator pastes this into
/// `nix/secrets.yaml` under `clusters.<name>.tls.*` and re-encrypts via
/// `sops updatekeys`.
fn print_sops_yaml(
    cluster: &str,
    server_ca: &MintedCa,
    client_ca: &MintedCa,
    request_header_ca: &MintedCa,
    service_key: &KeyPair,
    admin: &MintedLeaf,
) {
    println!("# Generated by `kindling pki mint --cluster {cluster}`.");
    println!("# Merge this under `clusters:` in nix/secrets.yaml, then");
    println!("# `sops --encrypt --in-place secrets.yaml`.");
    println!("clusters:");
    println!("  {cluster}:");
    println!("    tls:");
    print_pem("server-ca-crt", &server_ca.cert.pem());
    print_pem("server-ca-key", &server_ca.key.serialize_pem());
    print_pem("client-ca-crt", &client_ca.cert.pem());
    print_pem("client-ca-key", &client_ca.key.serialize_pem());
    print_pem("request-header-ca-crt", &request_header_ca.cert.pem());
    print_pem("request-header-ca-key", &request_header_ca.key.serialize_pem());
    print_pem("service-key", &service_key.serialize_pem());
    print_pem("admin-crt", &admin.cert_pem);
    print_pem("admin-key", &admin.key_pem);
}

fn print_pem(key: &str, pem: &str) {
    println!("      {key}: |");
    for line in pem.lines() {
        println!("        {line}");
    }
}

fn unix_to_offsetdatetime(unix_secs: u64) -> Result<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(
        i64::try_from(unix_secs).context("unix timestamp out of i64 range")?,
    )
    .context("OffsetDateTime rejected timestamp")
}

// ─────────────────────────────────────────────────────────────────────────
// `kindling pki seed --source sops-nix --cluster <name>`
// ─────────────────────────────────────────────────────────────────────────

pub fn run_seed(source: &str, cluster: &str) -> Result<()> {
    match source {
        "sops-nix" => seed_from_sops_nix(cluster),
        other => Err(anyhow!(
            "unknown --source {other} (supported: sops-nix)"
        )),
    }
}

fn seed_from_sops_nix(cluster: &str) -> Result<()> {
    if cluster.is_empty() || cluster.contains(['/', '\\', '\0']) {
        return Err(anyhow!("--cluster must be a non-empty path-safe identifier"));
    }
    let src_root: PathBuf = format!("/run/secrets/clusters/{cluster}/tls").into();
    if !src_root.is_dir() {
        // Match kindling-init.service's ExecCondition shape: cleanly
        // exit-zero when sops-nix has nothing for this cluster (e.g.
        // during AMI build, or on a kasou VM whose cluster name was
        // changed mid-flight). k3s then falls back to auto-generation,
        // same behaviour as today's broken pre-fix state — but the
        // operator-visible signal is in stderr.
        eprintln!(
            "kindling pki seed: no sops-nix secrets under {} — skipping (k3s will auto-generate CA)",
            src_root.display()
        );
        return Ok(());
    }

    let tls_dir = Path::new(TLS_DIR);
    fs::create_dir_all(tls_dir)
        .with_context(|| format!("create {}", tls_dir.display()))?;
    fs::set_permissions(tls_dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod {} to 0700", tls_dir.display()))?;

    let mut seeded = 0u32;
    for target in PKI_TARGETS {
        let src = src_root.join(target.sops_key);
        if !src.exists() {
            // A partially-seeded sops bundle is an operator error, not a
            // recoverable runtime state. Bail loudly so the systemd
            // unit fails closed; k3s won't start, and the operator sees
            // the missing key in `journalctl -u kindling-pki-seed`.
            return Err(anyhow!(
                "missing sops secret {} for cluster {cluster} — re-run `kindling pki mint` and update sops",
                src.display()
            ));
        }
        let bytes = fs::read(&src).with_context(|| format!("read {}", src.display()))?;
        fs::write(target.dest, &bytes)
            .with_context(|| format!("write {}", target.dest))?;
        fs::set_permissions(
            target.dest,
            std::fs::Permissions::from_mode(target.mode),
        )
        .with_context(|| format!("chmod {} to {:o}", target.dest, target.mode))?;
        seeded += 1;
    }
    eprintln!(
        "kindling pki seed: wrote {seeded} files from sops-nix to {TLS_DIR}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pki_targets_all_under_tls_dir() {
        for target in PKI_TARGETS {
            assert!(
                target.dest.starts_with(TLS_DIR),
                "PKI_TARGETS[{}].dest={} must live under {TLS_DIR} so a single chmod 0700 covers the bag",
                target.sops_key,
                target.dest,
            );
        }
    }

    #[test]
    fn pki_targets_distinct_sops_keys() {
        let mut seen = std::collections::HashSet::new();
        for target in PKI_TARGETS {
            assert!(
                seen.insert(target.sops_key),
                "duplicate sops_key {} in PKI_TARGETS",
                target.sops_key
            );
        }
    }

    #[test]
    fn pki_targets_distinct_dests() {
        let mut seen = std::collections::HashSet::new();
        for target in PKI_TARGETS {
            assert!(
                seen.insert(target.dest),
                "duplicate dest {} in PKI_TARGETS",
                target.dest
            );
        }
    }

    #[test]
    fn unknown_source_errors() {
        let r = run_seed("ec2-userdata", "engenho-local");
        assert!(r.is_err());
        assert!(format!("{}", r.unwrap_err()).contains("unknown --source"));
    }
}
