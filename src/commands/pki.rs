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

use base64::Engine as _;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rsa::pkcs8::EncodePrivateKey as _;
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
///
/// Values are **base64-encoded PEM** to match the fleet's established
/// convention — cid-k3s and ryn-k3s already store TLS this way, and
/// kindling's AMI-path SECRET_TARGETS uses `base64_decode: true` for
/// the same shape. `kindling pki seed --source sops-nix` decodes on
/// the way out before writing PEM bytes to k3s' TLS dir.
///
/// 4-space indent step matches the pleme-io fleet `secrets.yaml`
/// convention; mismatched indent would still parse but sops would
/// re-emit on encrypt and dirty the diff.
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
    println!("# Values are base64-encoded PEM — `kindling pki seed`");
    println!("# decodes on the VM before writing to /var/lib/rancher/k3s/server/tls/.");
    println!("clusters:");
    println!("    {cluster}:");
    println!("        tls:");
    print_b64("server-ca-crt", &server_ca.cert.pem());
    print_b64("server-ca-key", &server_ca.key.serialize_pem());
    print_b64("client-ca-crt", &client_ca.cert.pem());
    print_b64("client-ca-key", &client_ca.key.serialize_pem());
    print_b64("request-header-ca-crt", &request_header_ca.cert.pem());
    print_b64("request-header-ca-key", &request_header_ca.key.serialize_pem());
    print_b64("service-key", &service_key.serialize_pem());
    print_b64("admin-crt", &admin.cert_pem);
    print_b64("admin-key", &admin.key_pem);
}

fn print_b64(key: &str, pem: &str) {
    let encoded = base64::engine::general_purpose::STANDARD.encode(pem.as_bytes());
    println!("            {key}: {encoded}");
}

fn unix_to_offsetdatetime(unix_secs: u64) -> Result<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(
        i64::try_from(unix_secs).context("unix timestamp out of i64 range")?,
    )
    .context("OffsetDateTime rejected timestamp")
}

// ─────────────────────────────────────────────────────────────────────────
// `kindling pki provision --cluster <name> --secrets-file <path>`
// ─────────────────────────────────────────────────────────────────────────
//
// Read-first, idempotent, atomic provisioning of a cluster's full TLS bag
// inside an existing sops-encrypted file. Re-running for an already-
// provisioned cluster is a no-op; running for a new cluster generates the
// 9-PEM bag once and re-encrypts in place. `--rotate` forces regeneration.
//
// The substrate compounding move: declaration (`pleme.fleet.clusters.<name>`)
// + one command = ready for `nix run .#rebuild`. Materials for the same
// cluster name persist across reruns, so a `kindling pki provision`
// against a known cluster is the cheapest possible no-op.

/// All 9 PKI keys that live under `clusters/<name>/tls/` in sops. The
/// substrate's "bag" — every entry is base64-encoded PEM.
const PKI_BAG_KEYS: &[&str] = &[
    "server-ca-crt",
    "server-ca-key",
    "client-ca-crt",
    "client-ca-key",
    "request-header-ca-crt",
    "request-header-ca-key",
    "service-key",
    "admin-crt",
    "admin-key",
];

pub fn run_provision(
    cluster: &str,
    secrets_file: &Path,
    admin_cn: &str,
    validity_days: u32,
    rotate: bool,
) -> Result<()> {
    if cluster.is_empty() || cluster.contains(['/', '\\', '\0']) {
        return Err(anyhow!("--cluster must be a non-empty path-safe identifier"));
    }
    if !secrets_file.exists() {
        return Err(anyhow!(
            "--secrets-file {} does not exist",
            secrets_file.display()
        ));
    }

    // 1. Decrypt + parse current state.
    let plaintext = sops_decrypt(secrets_file)?;
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(&plaintext).context("parse decrypted secrets.yaml")?;

    // 2. Inspect what's already under clusters.<name>.tls.
    let present = inspect_bag(&doc, cluster);
    let missing: Vec<&str> = PKI_BAG_KEYS
        .iter()
        .copied()
        .filter(|k| !present.contains(*k))
        .collect();

    if missing.is_empty() && !rotate {
        eprintln!(
            "kindling pki provision: cluster {cluster}'s TLS bag is complete — no changes"
        );
        return Ok(());
    }
    if !missing.is_empty() && missing.len() < PKI_BAG_KEYS.len() && !rotate {
        return Err(anyhow!(
            "cluster {cluster}'s TLS bag is partially populated ({}/{} keys present, missing: {:?}). \
             Pass --rotate to regenerate the full bag (will invalidate kubeconfigs).",
            PKI_BAG_KEYS.len() - missing.len(),
            PKI_BAG_KEYS.len(),
            missing
        ));
    }

    eprintln!(
        "kindling pki provision: {} TLS bag for cluster {cluster}",
        if rotate { "rotating" } else { "minting fresh" }
    );

    // 3. Mint the full bag + write under clusters.<name>.tls.
    let bag = mint_full_bag(admin_cn, validity_days)?;
    write_bag_to_doc(&mut doc, cluster, &bag)?;

    // 4. Atomic re-encrypt: backup → write plaintext → sops encrypt → verify → cleanup.
    let new_plaintext =
        serde_yaml::to_string(&doc).context("serialize updated secrets")?;
    sops_encrypt_in_place(secrets_file, &new_plaintext)?;

    // 5. Verify: decrypt the new file + confirm every expected key landed.
    let verify = sops_decrypt(secrets_file)?;
    let verify_doc: serde_yaml::Value =
        serde_yaml::from_str(&verify).context("parse re-encrypted secrets")?;
    let verify_present = inspect_bag(&verify_doc, cluster);
    for key in PKI_BAG_KEYS {
        if !verify_present.contains(*key) {
            return Err(anyhow!(
                "post-write verification failed: clusters.{cluster}.tls.{key} not visible after sops re-encrypt"
            ));
        }
    }

    eprintln!(
        "kindling pki provision: wrote {} keys under clusters.{cluster}.tls",
        PKI_BAG_KEYS.len()
    );
    Ok(())
}

/// What's already populated under `clusters.<name>.tls.*` in the parsed
/// secrets doc. Returns an empty set if any path segment is missing — a
/// fresh cluster looks exactly the same as a partially-populated one
/// with zero keys.
fn inspect_bag(doc: &serde_yaml::Value, cluster: &str) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    let clusters = doc.get("clusters").and_then(|v| v.as_mapping());
    let Some(clusters) = clusters else { return set; };
    let entry = clusters.get(serde_yaml::Value::String(cluster.to_string()));
    let Some(entry) = entry.and_then(|v| v.as_mapping()) else { return set; };
    let tls = entry.get(serde_yaml::Value::String("tls".to_string()));
    let Some(tls) = tls.and_then(|v| v.as_mapping()) else { return set; };
    for k in PKI_BAG_KEYS {
        if tls.contains_key(serde_yaml::Value::String((*k).to_string())) {
            set.insert((*k).to_string());
        }
    }
    set
}

/// Write the freshly-minted bag into `doc.clusters.<cluster>.tls`,
/// creating intermediate keys as needed. Replaces any existing value
/// at each key (assumes the caller has determined a regenerate is
/// safe — partial-state safety lives in `run_provision`).
fn write_bag_to_doc(
    doc: &mut serde_yaml::Value,
    cluster: &str,
    bag: &MintedBag,
) -> Result<()> {
    let root = doc.as_mapping_mut().ok_or_else(|| anyhow!("secrets.yaml root is not a mapping"))?;
    let clusters = root
        .entry(serde_yaml::Value::String("clusters".to_string()))
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    let clusters_map = clusters
        .as_mapping_mut()
        .ok_or_else(|| anyhow!("`clusters` is not a mapping"))?;
    let cluster_v = clusters_map
        .entry(serde_yaml::Value::String(cluster.to_string()))
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    let cluster_map = cluster_v
        .as_mapping_mut()
        .ok_or_else(|| anyhow!("`clusters.{cluster}` is not a mapping"))?;
    let tls_v = cluster_map
        .entry(serde_yaml::Value::String("tls".to_string()))
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    let tls_map = tls_v
        .as_mapping_mut()
        .ok_or_else(|| anyhow!("`clusters.{cluster}.tls` is not a mapping"))?;
    let pairs: &[(&str, &str)] = &[
        ("server-ca-crt", &bag.server_ca_crt),
        ("server-ca-key", &bag.server_ca_key),
        ("client-ca-crt", &bag.client_ca_crt),
        ("client-ca-key", &bag.client_ca_key),
        ("request-header-ca-crt", &bag.request_header_ca_crt),
        ("request-header-ca-key", &bag.request_header_ca_key),
        ("service-key", &bag.service_key),
        ("admin-crt", &bag.admin_crt),
        ("admin-key", &bag.admin_key),
    ];
    for (k, v) in pairs {
        tls_map.insert(
            serde_yaml::Value::String((*k).to_string()),
            serde_yaml::Value::String((*v).to_string()),
        );
    }
    Ok(())
}

/// Self-contained mint of every PEM in the bag. Values are
/// base64-encoded PEM, matching the on-disk sops convention + the
/// AMI-path SECRET_TARGETS shape.
struct MintedBag {
    server_ca_crt:         String,
    server_ca_key:         String,
    client_ca_crt:         String,
    client_ca_key:         String,
    request_header_ca_crt: String,
    request_header_ca_key: String,
    service_key:           String,
    admin_crt:             String,
    admin_key:             String,
}

fn mint_full_bag(admin_cn: &str, validity_days: u32) -> Result<MintedBag> {
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
    // RSA-2048 for the k3s service-account signing key. The k3s
    // apiserver --service-account-key-file loader rejects ECDSA in
    // PKCS#8 ("data does not contain any valid RSA or ECDSA public
    // keys") even though PKCS#8 ECDSA is structurally valid. Matches
    // the auto-generated shape k3s itself produces.
    // Use rsa's bundled rand_core OsRng to avoid the rand 0.8/0.9 split:
    // kindling pins rand = "0.9" (newer ThreadRng implements rand_core 0.9's
    // trait), but rsa = "0.9" wants rand_core 0.6's CryptoRngCore.
    let mut rng = rsa::rand_core::OsRng;
    let service_key_rsa = rsa::RsaPrivateKey::new(&mut rng, 2048)
        .context("generate RSA-2048 for service-account signing")?;
    let service_key_pem = service_key_rsa
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .context("encode service-account key as PKCS#8 PEM")?
        .to_string();

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

    let b64 = |pem: String| base64::engine::general_purpose::STANDARD.encode(pem.as_bytes());
    Ok(MintedBag {
        server_ca_crt:         b64(server_ca.cert.pem()),
        server_ca_key:         b64(server_ca.key.serialize_pem()),
        client_ca_crt:         b64(client_ca.cert.pem()),
        client_ca_key:         b64(client_ca.key.serialize_pem()),
        request_header_ca_crt: b64(request_header_ca.cert.pem()),
        request_header_ca_key: b64(request_header_ca.key.serialize_pem()),
        service_key:           b64(service_key_pem),
        admin_crt:             b64(admin_cert.pem()),
        admin_key:             b64(admin_key.serialize_pem()),
    })
}

// ── sops subprocess wrappers ───────────────────────────────────────────

fn sops_decrypt(path: &Path) -> Result<String> {
    let out = std::process::Command::new("sops")
        .arg("-d")
        .arg(path)
        .output()
        .context("invoke sops -d (sops binary not in PATH?)")?;
    if !out.status.success() {
        return Err(anyhow!(
            "sops -d {} failed: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    String::from_utf8(out.stdout).context("sops -d output not UTF-8")
}

/// Replace `path`'s ciphertext with sops-encrypted form of `new_plaintext`.
/// Safety: keeps a `.kindling-bak` of the original ciphertext until the
/// re-encrypt succeeds, so a crash mid-flight leaves the file recoverable.
/// The plaintext only ever exists briefly on disk under the secrets.yaml
/// name (so sops creation_rules apply) — same directory as the encrypted
/// file, mode 0600.
fn sops_encrypt_in_place(path: &Path, new_plaintext: &str) -> Result<()> {
    let dir = path.parent().ok_or_else(|| anyhow!("path has no parent"))?;
    let basename = path
        .file_name()
        .ok_or_else(|| anyhow!("path has no filename"))?;
    let bak_path = dir.join(format!("{}.kindling-bak", basename.to_string_lossy()));

    // Step 1: backup current ciphertext.
    std::fs::copy(path, &bak_path)
        .with_context(|| format!("backup {} → {}", path.display(), bak_path.display()))?;

    // Step 2: write plaintext at the target path (so .sops.yaml regex matches).
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("open {} for write", path.display()))?;
        use std::io::Write as _;
        f.write_all(new_plaintext.as_bytes())
            .with_context(|| format!("write plaintext to {}", path.display()))?;
        f.flush().ok();
    }

    // Step 3: sops encrypt in place. Run with cwd=dir so creation_rules
    // path_regex matches the basename relative to the .sops.yaml location.
    let out = std::process::Command::new("sops")
        .arg("--encrypt")
        .arg("--in-place")
        .arg(basename)
        .current_dir(dir)
        .output()
        .context("invoke sops --encrypt --in-place")?;
    if !out.status.success() {
        // Recovery: restore ciphertext from backup so the operator's
        // secrets file is never left as plaintext on a failed encrypt.
        let _ = std::fs::copy(&bak_path, path);
        return Err(anyhow!(
            "sops --encrypt --in-place failed: {} — original ciphertext restored from {}",
            String::from_utf8_lossy(&out.stderr),
            bak_path.display()
        ));
    }

    // Step 4: cleanup backup on success.
    let _ = std::fs::remove_file(&bak_path);
    Ok(())
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
        let raw = fs::read(&src).with_context(|| format!("read {}", src.display()))?;
        // Sops stores the materials base64-encoded (matches the fleet
        // convention + kindling's AMI-path SECRET_TARGETS base64_decode
        // shape). Trim whitespace so trailing newlines don't break
        // the decoder.
        let trimmed = std::str::from_utf8(&raw)
            .with_context(|| format!("{} is not UTF-8", src.display()))?
            .trim();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .with_context(|| format!("base64-decode {}", src.display()))?;
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

    #[test]
    fn inspect_bag_empty_when_cluster_absent() {
        let doc: serde_yaml::Value = serde_yaml::from_str("other: 1").unwrap();
        let present = inspect_bag(&doc, "engenho-local");
        assert!(present.is_empty());
    }

    #[test]
    fn inspect_bag_empty_when_tls_absent() {
        let doc: serde_yaml::Value = serde_yaml::from_str(
            "clusters:\n  engenho-local:\n    server-token: hex\n",
        )
        .unwrap();
        let present = inspect_bag(&doc, "engenho-local");
        assert!(present.is_empty());
    }

    #[test]
    fn inspect_bag_lists_present_keys() {
        let doc: serde_yaml::Value = serde_yaml::from_str(
            "clusters:\n  engenho-local:\n    tls:\n      server-ca-crt: AAA\n      admin-key: BBB\n",
        )
        .unwrap();
        let present = inspect_bag(&doc, "engenho-local");
        assert_eq!(present.len(), 2);
        assert!(present.contains("server-ca-crt"));
        assert!(present.contains("admin-key"));
        assert!(!present.contains("admin-crt"));
    }

    #[test]
    fn write_bag_creates_intermediate_keys() {
        let mut doc: serde_yaml::Value = serde_yaml::from_str("other: 1").unwrap();
        // Force `doc` to be a mapping (serde_yaml might return a Tag-y shape).
        if doc.as_mapping().is_none() {
            doc = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        }
        let bag = MintedBag {
            server_ca_crt:         "sca".into(),
            server_ca_key:         "sck".into(),
            client_ca_crt:         "cca".into(),
            client_ca_key:         "cck".into(),
            request_header_ca_crt: "rca".into(),
            request_header_ca_key: "rck".into(),
            service_key:           "svk".into(),
            admin_crt:             "ac".into(),
            admin_key:             "ak".into(),
        };
        write_bag_to_doc(&mut doc, "engenho-local", &bag).unwrap();
        let yaml = serde_yaml::to_string(&doc).unwrap();
        assert!(yaml.contains("engenho-local:"));
        assert!(yaml.contains("server-ca-crt: sca"));
        assert!(yaml.contains("admin-key: ak"));
        // Round-trip back through inspect_bag.
        let reparsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let present = inspect_bag(&reparsed, "engenho-local");
        assert_eq!(present.len(), PKI_BAG_KEYS.len());
    }

    #[test]
    fn write_bag_replaces_existing_values() {
        let mut doc: serde_yaml::Value = serde_yaml::from_str(
            "clusters:\n  engenho-local:\n    tls:\n      server-ca-crt: OLD\n",
        )
        .unwrap();
        let bag = MintedBag {
            server_ca_crt:         "NEW".into(),
            server_ca_key:         "n".into(),
            client_ca_crt:         "n".into(),
            client_ca_key:         "n".into(),
            request_header_ca_crt: "n".into(),
            request_header_ca_key: "n".into(),
            service_key:           "n".into(),
            admin_crt:             "n".into(),
            admin_key:             "n".into(),
        };
        write_bag_to_doc(&mut doc, "engenho-local", &bag).unwrap();
        let yaml = serde_yaml::to_string(&doc).unwrap();
        assert!(yaml.contains("server-ca-crt: NEW"));
        assert!(!yaml.contains("server-ca-crt: OLD"));
    }

    #[test]
    fn mint_full_bag_produces_valid_base64_pem() {
        let bag = mint_full_bag("system:admin", 365).unwrap();
        for (name, v) in [
            ("server_ca_crt", &bag.server_ca_crt),
            ("server_ca_key", &bag.server_ca_key),
            ("client_ca_crt", &bag.client_ca_crt),
            ("client_ca_key", &bag.client_ca_key),
            ("request_header_ca_crt", &bag.request_header_ca_crt),
            ("request_header_ca_key", &bag.request_header_ca_key),
            ("service_key", &bag.service_key),
            ("admin_crt", &bag.admin_crt),
            ("admin_key", &bag.admin_key),
        ] {
            assert!(!v.is_empty(), "{name} value empty");
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(v)
                .unwrap_or_else(|e| panic!("{name} not base64: {e}"));
            let pem = std::str::from_utf8(&decoded)
                .unwrap_or_else(|e| panic!("{name} decoded bytes not UTF-8: {e}"));
            assert!(
                pem.contains("-----BEGIN"),
                "{name} decoded value isn't PEM: {pem}"
            );
        }
    }

    #[test]
    fn base64_roundtrip_pem() {
        use base64::Engine as _;
        // The on-the-wire shape `kindling pki mint` emits → what `kindling
        // pki seed` decodes. Both ends use STANDARD (RFC 4648) padded base64.
        let pem = "-----BEGIN CERTIFICATE-----\nMIIBdTCCARug\n-----END CERTIFICATE-----\n";
        let encoded = base64::engine::general_purpose::STANDARD.encode(pem.as_bytes());
        // sops + yq may emit a trailing newline; the seed path trims it.
        let with_trailing_ws = format!("{encoded}\n");
        let trimmed = with_trailing_ws.trim();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .expect("base64 roundtrip");
        assert_eq!(decoded, pem.as_bytes());
    }
}
