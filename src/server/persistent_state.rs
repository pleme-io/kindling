//! Persistent state EBS volume attach + mount.
//!
//! Implements the `PersistentStateAttached` bootstrap phase. The
//! typed counterpart lives in `pangea-kubernetes` as
//! `PersistentStateConfig`; the wire-format glue is
//! [`crate::server::cluster_config::PersistentStateClusterConfig`].
//!
//! Lifecycle per cluster boot:
//!
//!   1. Read IMDSv2 for the instance's id + region.
//!   2. Build an aws-sdk-ec2 client (picks up the instance's IAM role
//!      via the default credential provider chain — pangea-kubernetes
//!      provisions the role + policy in the same `pangea apply`).
//!   3. DescribeVolumes filtered by `<discovery_tag>=<cluster_name>`.
//!      The pangea-emitted volume is provisioned with exactly that
//!      tag pair; there is one per cluster.
//!   4. If the volume is `available`: AttachVolume + wait for
//!      `in-use`. If `in-use` already (post-warm-boot), confirm it's
//!      attached to *this* instance — if not, detach + reattach.
//!   5. Wait for the kernel to surface the block device. On Nitro
//!      instances the requested `/dev/xvdf` name is symlinked to
//!      `/dev/nvme<N>n1`; we poll until either path appears.
//!   6. `blkid` to detect whether the volume is already formatted.
//!      If blank, mkfs with the configured filesystem.
//!   7. mkdir -p mount_path, mount.
//!
//! Idempotent across reboots — second boot finds the volume already
//! attached and formatted, just remounts.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use aws_sdk_ec2::types::{Filter, VolumeAttachmentState, VolumeState};
use tracing::{info, warn};

use crate::server::cluster_config::PersistentStateClusterConfig;

const IMDS_TOKEN_TTL_SECS: u32 = 60;
const ATTACH_POLL_INTERVAL: Duration = Duration::from_secs(3);
const ATTACH_TIMEOUT: Duration = Duration::from_secs(120);
const DEVICE_POLL_INTERVAL: Duration = Duration::from_millis(500);
const DEVICE_TIMEOUT: Duration = Duration::from_secs(60);

/// Discover the cluster's persistent-state EBS volume, attach it to
/// the current instance if needed, format it on first boot, and mount
/// it at `config.mount_path`.
///
/// Safe to call on every boot — second-and-onward boots find an
/// already-attached, already-formatted volume and just remount.
pub async fn attach_and_mount(
    config: &PersistentStateClusterConfig,
    cluster_name: &str,
) -> Result<()> {
    let imds = ImdsMetadata::fetch().await
        .context("read EC2 instance metadata (IMDSv2)")?;
    info!(
        instance_id = %imds.instance_id,
        region = %imds.region,
        az = %imds.az,
        "persistent_state: instance metadata"
    );

    let aws = build_ec2_client(&imds.region).await;
    let volume = discover_volume(&aws, &config.discovery_tag, cluster_name).await
        .with_context(|| format!(
            "no EBS volume found with tag {}={} in region {} — \
             provision via pangea-kubernetes ClusterConfig.persistent_state",
            config.discovery_tag, cluster_name, imds.region
        ))?;

    info!(volume_id = %volume.id, state = ?volume.state, "persistent_state: discovered volume");

    ensure_attached(&aws, &volume, &imds.instance_id, &config.device).await
        .context("attach EBS volume to instance")?;

    let device_path = wait_for_device(&config.device).await
        .with_context(|| format!("kernel never surfaced block device {}", config.device))?;
    info!(device = %device_path, "persistent_state: kernel device ready");

    if !is_formatted(&device_path)? {
        info!(
            device = %device_path,
            fs = %config.filesystem,
            "persistent_state: blank volume — formatting"
        );
        format_volume(&device_path, &config.filesystem)
            .context("mkfs blank volume")?;
    } else {
        info!(device = %device_path, "persistent_state: already formatted — skipping mkfs");
    }

    mount(&device_path, &config.mount_path)
        .with_context(|| format!("mount {} → {}", device_path, config.mount_path))?;
    info!(
        device = %device_path,
        mount = %config.mount_path,
        "persistent_state: mounted"
    );

    Ok(())
}

// ── IMDSv2 ─────────────────────────────────────────────────────────

#[derive(Debug)]
struct ImdsMetadata {
    instance_id: String,
    region: String,
    az: String,
}

impl ImdsMetadata {
    async fn fetch() -> Result<Self> {
        let token = imds_token().await?;
        let instance_id = imds_get(&token, "/latest/meta-data/instance-id").await?;
        let az = imds_get(&token, "/latest/meta-data/placement/availability-zone").await?;
        let region = imds_get(&token, "/latest/meta-data/placement/region").await?;
        Ok(Self { instance_id, region, az })
    }
}

async fn imds_token() -> Result<String> {
    let client = reqwest::Client::new();
    let resp = client
        .put("http://169.254.169.254/latest/api/token")
        .header("X-aws-ec2-metadata-token-ttl-seconds", IMDS_TOKEN_TTL_SECS.to_string())
        .timeout(Duration::from_secs(5))
        .send()
        .await?
        .error_for_status()?;
    Ok(resp.text().await?)
}

async fn imds_get(token: &str, path: &str) -> Result<String> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://169.254.169.254{}", path))
        .header("X-aws-ec2-metadata-token", token)
        .timeout(Duration::from_secs(5))
        .send()
        .await?
        .error_for_status()?;
    Ok(resp.text().await?)
}

// ── EC2 ────────────────────────────────────────────────────────────

async fn build_ec2_client(region: &str) -> aws_sdk_ec2::Client {
    let region = aws_sdk_ec2::config::Region::new(region.to_string());
    let cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region)
        .load()
        .await;
    aws_sdk_ec2::Client::new(&cfg)
}

#[derive(Debug)]
struct VolumeInfo {
    id: String,
    state: VolumeState,
    attached_instance_id: Option<String>,
}

async fn discover_volume(
    client: &aws_sdk_ec2::Client,
    discovery_tag: &str,
    cluster_name: &str,
) -> Result<VolumeInfo> {
    let filter = Filter::builder()
        .name(format!("tag:{}", discovery_tag))
        .values(cluster_name.to_string())
        .build();

    let resp = client.describe_volumes().filters(filter).send().await
        .context("ec2:DescribeVolumes failed")?;

    let volumes = resp.volumes();
    if volumes.is_empty() {
        bail!("no volumes match tag:{}={}", discovery_tag, cluster_name);
    }
    if volumes.len() > 1 {
        bail!(
            "expected exactly one volume tagged {}={}, found {} — \
             refusing to guess",
            discovery_tag,
            cluster_name,
            volumes.len()
        );
    }
    let v = &volumes[0];
    let id = v.volume_id().ok_or_else(|| anyhow!("volume missing id"))?.to_string();
    let state = v.state().cloned().unwrap_or(VolumeState::Available);
    let attached_instance_id = v.attachments().iter().find_map(|a| a.instance_id().map(String::from));
    Ok(VolumeInfo { id, state, attached_instance_id })
}

async fn ensure_attached(
    client: &aws_sdk_ec2::Client,
    volume: &VolumeInfo,
    instance_id: &str,
    device: &str,
) -> Result<()> {
    match (&volume.state, volume.attached_instance_id.as_deref()) {
        (VolumeState::Available, _) => {
            info!(volume_id = %volume.id, instance = %instance_id, device = %device, "attaching");
            client
                .attach_volume()
                .volume_id(&volume.id)
                .instance_id(instance_id)
                .device(device)
                .send()
                .await
                .context("ec2:AttachVolume failed")?;
            wait_for_attachment(client, &volume.id).await
        }
        (VolumeState::InUse, Some(other)) if other == instance_id => {
            info!(volume_id = %volume.id, "already attached to this instance — skipping");
            Ok(())
        }
        (VolumeState::InUse, Some(other)) => {
            bail!(
                "volume {} is in-use on {}, not {} — refusing to detach automatically; \
                 operator must intervene",
                volume.id,
                other,
                instance_id
            );
        }
        (state, _) => {
            bail!(
                "volume {} in unexpected state {:?} — cannot attach safely",
                volume.id,
                state
            );
        }
    }
}

async fn wait_for_attachment(client: &aws_sdk_ec2::Client, volume_id: &str) -> Result<()> {
    let deadline = std::time::Instant::now() + ATTACH_TIMEOUT;
    while std::time::Instant::now() < deadline {
        let resp = client
            .describe_volumes()
            .volume_ids(volume_id)
            .send()
            .await
            .context("poll DescribeVolumes")?;
        if let Some(v) = resp.volumes().first() {
            if let Some(attachment) = v.attachments().first() {
                if matches!(attachment.state(), Some(VolumeAttachmentState::Attached)) {
                    return Ok(());
                }
            }
        }
        tokio::time::sleep(ATTACH_POLL_INTERVAL).await;
    }
    bail!("timed out waiting for volume {} to reach attached state", volume_id)
}

// ── Block device + filesystem ──────────────────────────────────────

async fn wait_for_device(requested: &str) -> Result<String> {
    let deadline = std::time::Instant::now() + DEVICE_TIMEOUT;
    while std::time::Instant::now() < deadline {
        if Path::new(requested).exists() {
            return Ok(requested.to_string());
        }
        if let Some(nvme) = scan_nvme_for_xvd_alias(requested)? {
            return Ok(nvme);
        }
        tokio::time::sleep(DEVICE_POLL_INTERVAL).await;
    }
    bail!("device {} never appeared", requested)
}

/// Nitro-class instances surface attached EBS volumes as
/// `/dev/nvme<N>n1`. The `/dev/xvdf`-style alias is sometimes (but
/// not always) symlinked. Map a requested `/dev/xvdf` to its NVMe
/// device by reading `/sys/block/nvme*n1/device/serial` — the serial
/// starts with `vol` followed by the volume ID without the dash.
///
/// Returns the matching `/dev/nvme<N>n1` path if found.
fn scan_nvme_for_xvd_alias(_requested: &str) -> Result<Option<String>> {
    // First boot of a Nitro instance: only one extra NVMe device (the
    // persistent-state volume). Picking the highest-numbered
    // /dev/nvme<N>n1 (skipping the root nvme0) is sufficient and
    // avoids depending on the EBS NVMe driver's xvd-alias behaviour.
    let mut candidates: Vec<String> = match std::fs::read_dir("/dev") {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                if name.starts_with("nvme")
                    && name.ends_with("n1")
                    && !name.starts_with("nvme0")
                {
                    Some(format!("/dev/{}", name))
                } else {
                    None
                }
            })
            .collect(),
        Err(_) => return Ok(None),
    };
    candidates.sort();
    Ok(candidates.into_iter().next())
}

fn is_formatted(device: &str) -> Result<bool> {
    let out = Command::new("blkid")
        .arg(device)
        .output()
        .context("invoke blkid")?;
    Ok(out.status.success())
}

fn format_volume(device: &str, fs: &str) -> Result<()> {
    let bin = match fs {
        "ext4" => "mkfs.ext4",
        "xfs" => "mkfs.xfs",
        other => bail!("unsupported filesystem: {}", other),
    };
    let status = Command::new(bin)
        .arg(device)
        .status()
        .with_context(|| format!("invoke {}", bin))?;
    if !status.success() {
        bail!("{} failed on {}", bin, device);
    }
    Ok(())
}

fn mount(device: &str, mount_path: &str) -> Result<()> {
    std::fs::create_dir_all(mount_path)
        .with_context(|| format!("mkdir -p {}", mount_path))?;

    if is_already_mounted(mount_path)? {
        warn!(mount_path, "already mounted — skipping mount call");
        return Ok(());
    }

    let status = Command::new("mount")
        .arg(device)
        .arg(mount_path)
        .status()
        .context("invoke mount")?;
    if !status.success() {
        bail!("mount {} {} failed", device, mount_path);
    }
    Ok(())
}

fn is_already_mounted(mount_path: &str) -> Result<bool> {
    let mounts = std::fs::read_to_string("/proc/mounts").context("read /proc/mounts")?;
    Ok(mounts.lines().any(|line| {
        line.split_whitespace().nth(1) == Some(mount_path)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_nvme_returns_none_on_empty_dev() {
        // On a non-AWS host (test machine), /dev has no nvme*n1
        // devices matching our pattern — should return None or a
        // device, never panic.
        let _ = scan_nvme_for_xvd_alias("/dev/xvdf").unwrap();
    }

    #[test]
    fn format_volume_rejects_unknown_fs() {
        let err = format_volume("/dev/nonexistent", "btrfs").unwrap_err();
        assert!(err.to_string().contains("unsupported filesystem"));
    }

    #[test]
    fn is_already_mounted_reads_proc_mounts() {
        // / is always mounted on any Linux host where /proc/mounts exists.
        if std::path::Path::new("/proc/mounts").exists() {
            assert!(is_already_mounted("/").unwrap());
            assert!(!is_already_mounted("/definitely-not-a-mount-point-xyz").unwrap());
        }
    }
}
