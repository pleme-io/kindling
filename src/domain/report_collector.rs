//! Report collector — gathers runtime state from the local machine.
//!
//! Deep platform-specific probing:
//! - macOS: sysctl, system_profiler, vm_stat, sw_vers, networksetup, pmset, lsof
//! - Linux: /proc/*, /sys/*, ip, ss, lspci, systemctl, uname

use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use tokio::process::Command;
use tracing::warn;

use super::node_report::*;

pub struct ReportCollector;

impl ReportCollector {
    /// Collect a complete runtime report from this machine.
    pub async fn collect() -> Result<NodeReport> {
        let hostname = gethostname();

        let (hardware, os, network, nix, health, security, processes) = tokio::join!(
            Self::collect_hardware(),
            Self::collect_os(),
            Self::collect_network(),
            Self::collect_nix(),
            Self::collect_health(),
            Self::collect_security(),
            Self::collect_processes(),
        );

        let kubernetes = Self::collect_kubernetes().await.ok();

        Ok(NodeReport {
            timestamp: Utc::now(),
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            hostname: hostname.clone(),
            hardware: hardware.unwrap_or_else(|e| {
                warn!(error = %e, "failed to collect hardware info");
                default_hardware()
            }),
            os: os.unwrap_or_else(|e| {
                warn!(error = %e, "failed to collect OS info");
                default_os()
            }),
            network: network.unwrap_or_else(|e| {
                warn!(error = %e, "failed to collect network info");
                default_network()
            }),
            nix: nix.unwrap_or_else(|e| {
                warn!(error = %e, "failed to collect Nix info");
                default_nix()
            }),
            kubernetes,
            health: health.unwrap_or_else(|e| {
                warn!(error = %e, "failed to collect health metrics");
                default_health()
            }),
            security: security.unwrap_or_else(|e| {
                warn!(error = %e, "failed to collect security info");
                default_security()
            }),
            processes: processes.unwrap_or_else(|e| {
                warn!(error = %e, "failed to collect process info");
                default_processes()
            }),
        })
    }

    // ═══════════════════════════════════════════════════════════
    // HARDWARE
    // ═══════════════════════════════════════════════════════════

    async fn collect_hardware() -> Result<HardwareSnapshot> {
        let (cpu_info, mem_info, swap_info, disks, gpus, power) = tokio::join!(
            Self::collect_cpu_info(),
            Self::collect_memory_info(),
            Self::collect_swap_info(),
            Self::collect_disk_info(),
            Self::collect_gpu_info(),
            Self::collect_power_info(),
        );

        let (cpu_model, cpu_vendor, cpu_arch, cpu_cores, cpu_threads, cpu_freq, cpu_cache) =
            cpu_info;
        let (ram_total, ram_available) = mem_info;
        let (swap_total, swap_used) = swap_info;

        Ok(HardwareSnapshot {
            cpu_model,
            cpu_vendor,
            cpu_architecture: cpu_arch,
            cpu_cores,
            cpu_threads,
            cpu_frequency_mhz: cpu_freq,
            cpu_cache_bytes: cpu_cache,
            ram_total_bytes: ram_total,
            ram_available_bytes: ram_available,
            swap_total_bytes: swap_total,
            swap_used_bytes: swap_used,
            disks: disks.unwrap_or_default(),
            gpus: gpus.unwrap_or_default(),
            temperatures: Vec::new(), // requires SMC/hwmon access
            power: power.ok().flatten(),
        })
    }

    // ── CPU ────────────────────────────────────────────────

    #[cfg(target_os = "macos")]
    async fn collect_cpu_info() -> (String, String, String, u32, u32, Option<u64>, Option<u64>) {
        let model = run_cmd("sysctl", &["-n", "machdep.cpu.brand_string"])
            .await
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".into());

        let vendor = run_cmd("sysctl", &["-n", "machdep.cpu.vendor"])
            .await
            .map(|s| s.trim().to_string())
            .or_else(|| {
                // Apple Silicon doesn't have machdep.cpu.vendor
                if model.contains("Apple") {
                    Some("Apple".into())
                } else if model.contains("Intel") {
                    Some("Intel".into())
                } else {
                    Some("unknown".into())
                }
            })
            .unwrap_or_else(|| "unknown".into());

        let arch = run_cmd("uname", &["-m"])
            .await
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".into());

        let cores = run_cmd("sysctl", &["-n", "hw.physicalcpu"])
            .await
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        let threads = run_cmd("sysctl", &["-n", "hw.logicalcpu"])
            .await
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        // Apple Silicon reports frequency differently
        let freq = run_cmd("sysctl", &["-n", "hw.cpufrequency"])
            .await
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|f| f / 1_000_000)
            .or_else(|| {
                // Apple Silicon doesn't expose frequency via sysctl; try
                // hw.cpufrequency_max or fall back to None
                None
            });

        let cache = run_cmd("sysctl", &["-n", "hw.l2cachesize"])
            .await
            .and_then(|s| s.trim().parse::<u64>().ok());

        (model, vendor, arch, cores, threads, freq, cache)
    }

    #[cfg(not(target_os = "macos"))]
    async fn collect_cpu_info() -> (String, String, String, u32, u32, Option<u64>, Option<u64>) {
        let cpuinfo = tokio::fs::read_to_string("/proc/cpuinfo")
            .await
            .unwrap_or_default();

        let model = extract_proc_field(&cpuinfo, "model name")
            .unwrap_or_else(|| "unknown".into());

        let vendor_raw = extract_proc_field(&cpuinfo, "vendor_id")
            .unwrap_or_default();
        let vendor = if vendor_raw.contains("GenuineIntel") {
            "Intel".into()
        } else if vendor_raw.contains("AuthenticAMD") {
            "AMD".into()
        } else {
            vendor_raw
        };

        let arch = run_cmd("uname", &["-m"])
            .await
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".into());

        let threads = cpuinfo
            .lines()
            .filter(|l| l.starts_with("processor"))
            .count() as u32;

        let cores = extract_proc_field(&cpuinfo, "cpu cores")
            .and_then(|s| s.parse().ok())
            .unwrap_or(threads);

        let freq = extract_proc_field(&cpuinfo, "cpu MHz")
            .and_then(|s| s.parse::<f64>().ok())
            .map(|f| f as u64);

        let cache = extract_proc_field(&cpuinfo, "cache size")
            .and_then(|s| {
                let s = s.trim_end_matches(" KB");
                s.parse::<u64>().ok().map(|kb| kb * 1024)
            });

        (model, vendor, arch, cores, threads, freq, cache)
    }

    // ── Memory ─────────────────────────────────────────────

    #[cfg(target_os = "macos")]
    async fn collect_memory_info() -> (u64, u64) {
        let total = run_cmd("sysctl", &["-n", "hw.memsize"])
            .await
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        let page_size = run_cmd("sysctl", &["-n", "hw.pagesize"])
            .await
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(16384);

        let vm_stat_output = run_cmd("vm_stat", &[]).await.unwrap_or_default();
        let free_pages = parse_vm_stat_field(&vm_stat_output, "Pages free");
        let inactive_pages = parse_vm_stat_field(&vm_stat_output, "Pages inactive");
        let speculative_pages = parse_vm_stat_field(&vm_stat_output, "Pages speculative");
        let available = (free_pages + inactive_pages + speculative_pages) * page_size;

        (total, available)
    }

    #[cfg(not(target_os = "macos"))]
    async fn collect_memory_info() -> (u64, u64) {
        let meminfo = tokio::fs::read_to_string("/proc/meminfo")
            .await
            .unwrap_or_default();

        let total = parse_meminfo_kb(&meminfo, "MemTotal") * 1024;
        let available = parse_meminfo_kb(&meminfo, "MemAvailable") * 1024;

        (total, available)
    }

    // ── Swap ───────────────────────────────────────────────

    #[cfg(target_os = "macos")]
    async fn collect_swap_info() -> (u64, u64) {
        let output = run_cmd("sysctl", &["-n", "vm.swapusage"]).await.unwrap_or_default();
        // Format: "total = 2048.00M  used = 512.00M  free = 1536.00M  ..."
        let total = parse_swap_field(&output, "total");
        let used = parse_swap_field(&output, "used");
        (total, used)
    }

    #[cfg(not(target_os = "macos"))]
    async fn collect_swap_info() -> (u64, u64) {
        let meminfo = tokio::fs::read_to_string("/proc/meminfo")
            .await
            .unwrap_or_default();

        let total = parse_meminfo_kb(&meminfo, "SwapTotal") * 1024;
        let free = parse_meminfo_kb(&meminfo, "SwapFree") * 1024;
        (total, total.saturating_sub(free))
    }

    // ── Disks ──────────────────────────────────────────────

    #[cfg(target_os = "macos")]
    async fn collect_disk_info() -> Result<Vec<DiskSnapshot>> {
        // macOS df -kT doesn't exist; use df -k + mount for fs types
        let df_output = run_cmd("df", &["-k"]).await.unwrap_or_default();
        let mount_output = run_cmd("mount", &[]).await.unwrap_or_default();

        // Build mount_point → filesystem map from mount output
        let mut fs_map: HashMap<String, String> = HashMap::new();
        for line in mount_output.lines() {
            // Format: /dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
            if let Some((_, rest)) = line.split_once(" on ") {
                if let Some((mount_point, fs_info)) = rest.split_once(" (") {
                    let fs_type = fs_info
                        .split(',')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    fs_map.insert(mount_point.to_string(), fs_type);
                }
            }
        }

        let mut disks = Vec::new();
        for line in df_output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }

            let device = parts[0].to_string();
            let mount_point = parts[parts.len() - 1].to_string();

            // Skip pseudo-filesystems
            if device == "devfs"
                || device == "map"
                || device.starts_with("map ")
                || mount_point.starts_with("/System/Volumes/VM")
                || mount_point.starts_with("/System/Volumes/Preboot")
                || mount_point.starts_with("/System/Volumes/Update")
                || mount_point.starts_with("/System/Volumes/xarts")
                || mount_point.starts_with("/System/Volumes/iSCPreboot")
                || mount_point.starts_with("/System/Volumes/Hardware")
            {
                continue;
            }

            let total_kb: u64 = parts[1].parse().unwrap_or(0);
            if total_kb == 0 {
                continue;
            }
            let used_kb: u64 = parts[2].parse().unwrap_or(0);
            let available_kb: u64 = parts[3].parse().unwrap_or(0);

            let filesystem = fs_map.get(&mount_point).cloned().unwrap_or_default();

            disks.push(DiskSnapshot {
                device,
                mount_point,
                filesystem,
                total_bytes: total_kb * 1024,
                used_bytes: used_kb * 1024,
                available_bytes: available_kb * 1024,
                smart_healthy: None,
            });
        }
        Ok(disks)
    }

    #[cfg(not(target_os = "macos"))]
    async fn collect_disk_info() -> Result<Vec<DiskSnapshot>> {
        // Linux: df -kT gives filesystem type
        let output = run_cmd("df", &["-kT"]).await.unwrap_or_default();
        let mut disks = Vec::new();

        for line in output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 7 {
                continue;
            }

            let device = parts[0].to_string();
            let filesystem = parts[1].to_string();
            let mount_point = parts[6].to_string();

            // Skip pseudo-filesystems
            if filesystem == "tmpfs"
                || filesystem == "devtmpfs"
                || filesystem == "squashfs"
                || filesystem == "overlay"
                || device == "none"
                || mount_point.starts_with("/snap/")
            {
                continue;
            }

            let total_kb: u64 = parts[2].parse().unwrap_or(0);
            if total_kb == 0 {
                continue;
            }
            let used_kb: u64 = parts[3].parse().unwrap_or(0);
            let available_kb: u64 = parts[4].parse().unwrap_or(0);

            disks.push(DiskSnapshot {
                device,
                mount_point,
                filesystem,
                total_bytes: total_kb * 1024,
                used_bytes: used_kb * 1024,
                available_bytes: available_kb * 1024,
                smart_healthy: None,
            });
        }
        Ok(disks)
    }

    // ── GPU ────────────────────────────────────────────────

    #[cfg(target_os = "macos")]
    async fn collect_gpu_info() -> Result<Vec<GpuSnapshot>> {
        let output = run_cmd(
            "system_profiler",
            &["SPDisplaysDataType", "-json"],
        )
        .await
        .unwrap_or_default();

        let parsed: serde_json::Value =
            serde_json::from_str(&output).unwrap_or(serde_json::Value::Null);

        let mut gpus = Vec::new();

        if let Some(displays) = parsed
            .get("SPDisplaysDataType")
            .and_then(|d| d.as_array())
        {
            for gpu in displays {
                let name = gpu
                    .get("sppci_model")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();

                let vendor = gpu
                    .get("sppci_vendor")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| {
                        if name.contains("Apple") {
                            "Apple".into()
                        } else if name.contains("AMD") || name.contains("Radeon") {
                            "AMD".into()
                        } else if name.contains("Intel") {
                            "Intel".into()
                        } else {
                            "unknown".into()
                        }
                    });

                let vram_str = gpu
                    .get("sppci_vram")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let vram_bytes = parse_vram_string(vram_str);

                let metal = gpu
                    .get("sppci_metal")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                gpus.push(GpuSnapshot {
                    name,
                    vendor,
                    vram_bytes,
                    metal_support: metal,
                });
            }
        }

        Ok(gpus)
    }

    #[cfg(not(target_os = "macos"))]
    async fn collect_gpu_info() -> Result<Vec<GpuSnapshot>> {
        // Try lspci for VGA/3D controllers
        let output = run_cmd("lspci", &["-mm"]).await.unwrap_or_default();
        let mut gpus = Vec::new();

        for line in output.lines() {
            let lower = line.to_lowercase();
            if lower.contains("vga") || lower.contains("3d") || lower.contains("display") {
                // lspci -mm format: Slot "Class" "Vendor" "Device" ...
                let parts: Vec<&str> = line.split('"').collect();
                if parts.len() >= 6 {
                    let vendor = parts[3].to_string();
                    let name = parts[5].to_string();

                    let vendor_short = if vendor.contains("NVIDIA") {
                        "NVIDIA".into()
                    } else if vendor.contains("Advanced Micro") || vendor.contains("AMD") {
                        "AMD".into()
                    } else if vendor.contains("Intel") {
                        "Intel".into()
                    } else {
                        vendor.clone()
                    };

                    gpus.push(GpuSnapshot {
                        name,
                        vendor: vendor_short,
                        vram_bytes: None,
                        metal_support: None,
                    });
                }
            }
        }

        // Fallback: try nvidia-smi for NVIDIA GPUs
        if gpus.is_empty() {
            if let Some(nvidia_output) = run_cmd(
                "nvidia-smi",
                &["--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
            )
            .await
            {
                for line in nvidia_output.lines() {
                    let parts: Vec<&str> = line.split(',').collect();
                    if parts.len() >= 2 {
                        let vram_mb: u64 = parts[1].trim().parse().unwrap_or(0);
                        gpus.push(GpuSnapshot {
                            name: parts[0].trim().to_string(),
                            vendor: "NVIDIA".into(),
                            vram_bytes: Some(vram_mb * 1024 * 1024),
                            metal_support: None,
                        });
                    }
                }
            }
        }

        Ok(gpus)
    }

    // ── Power / Battery ────────────────────────────────────

    #[cfg(target_os = "macos")]
    async fn collect_power_info() -> Result<Option<PowerSnapshot>> {
        let output = run_cmd("pmset", &["-g", "batt"]).await;
        let Some(output) = output else {
            return Ok(None);
        };

        // If no battery (desktop Mac), return None
        if output.contains("No battery") || !output.contains("InternalBattery") {
            return Ok(None);
        }

        let on_battery = output.contains("Battery Power");
        let charging = output.contains("charging");

        // Parse: "InternalBattery-0 (id=...)	72%; charging; 1:23 remaining"
        let charge = output
            .lines()
            .find(|l| l.contains("InternalBattery"))
            .and_then(|l| {
                l.split('\t')
                    .nth(1)
                    .and_then(|s| s.split('%').next())
                    .and_then(|s| s.trim().parse::<f64>().ok())
            });

        let time_remaining = output
            .lines()
            .find(|l| l.contains("remaining"))
            .and_then(|l| {
                // "1:23 remaining"
                l.split_whitespace()
                    .find(|w| w.contains(':'))
                    .and_then(|time| {
                        let parts: Vec<&str> = time.split(':').collect();
                        if parts.len() == 2 {
                            let hours: u64 = parts[0].parse().ok()?;
                            let mins: u64 = parts[1].parse().ok()?;
                            Some(hours * 60 + mins)
                        } else {
                            None
                        }
                    })
            });

        Ok(Some(PowerSnapshot {
            on_battery,
            charge_percent: charge,
            charging,
            time_remaining_minutes: time_remaining,
        }))
    }

    #[cfg(not(target_os = "macos"))]
    async fn collect_power_info() -> Result<Option<PowerSnapshot>> {
        // Check /sys/class/power_supply/BAT0
        let bat_path = "/sys/class/power_supply/BAT0";
        if !tokio::fs::try_exists(bat_path).await.unwrap_or(false) {
            return Ok(None);
        }

        let status = read_sys_file(&format!("{}/status", bat_path)).await;
        let capacity = read_sys_file(&format!("{}/capacity", bat_path))
            .await
            .and_then(|s| s.trim().parse::<f64>().ok());

        let on_battery = status.as_deref() == Some("Discharging");
        let charging = status.as_deref() == Some("Charging");

        Ok(Some(PowerSnapshot {
            on_battery,
            charge_percent: capacity,
            charging,
            time_remaining_minutes: None,
        }))
    }

    // ═══════════════════════════════════════════════════════════
    // OS
    // ═══════════════════════════════════════════════════════════

    #[cfg(target_os = "macos")]
    async fn collect_os() -> Result<OsSnapshot> {
        let (version, build, product_name, kernel, arch, boottime, tz) = tokio::join!(
            run_cmd("sw_vers", &["-productVersion"]),
            run_cmd("sw_vers", &["-buildVersion"]),
            run_cmd("sw_vers", &["-productName"]),
            run_cmd("uname", &["-r"]),
            run_cmd("uname", &["-m"]),
            run_cmd("sysctl", &["-n", "kern.boottime"]),
            Self::detect_timezone(),
        );

        let version = version.unwrap_or_else(|| "unknown".into());
        let kernel = kernel.unwrap_or_else(|| "unknown".into());
        let arch_str = arch.unwrap_or_else(|| "unknown".into());

        let boot_time = boottime.and_then(|s| parse_kern_boottime(&s));
        let uptime_secs = boot_time
            .map(|bt| (Utc::now() - bt).num_seconds().max(0) as u64)
            .unwrap_or(0);

        let hostname = gethostname();
        let triple = format!(
            "{}-darwin",
            if arch_str.trim() == "arm64" { "aarch64" } else { arch_str.trim() }
        );

        // Detect if running in a VM (VMware, Parallels, UTM/QEMU)
        let virtualization = run_cmd("sysctl", &["-n", "machdep.cpu.features"])
            .await
            .and_then(|s| {
                if s.contains("VMM") {
                    Some("vm".to_string())
                } else {
                    None
                }
            });

        Ok(OsSnapshot {
            distribution: "macOS".to_string(),
            version: version.trim().to_string(),
            kernel_version: kernel.trim().to_string(),
            architecture: arch_str.trim().to_string(),
            platform_triple: triple,
            hostname: hostname.clone(),
            product_name: product_name.map(|s| s.trim().to_string()),
            build_id: build.map(|s| s.trim().to_string()),
            systemd_version: None,
            boot_time,
            uptime_secs,
            timezone: tz,
            is_wsl: false,
            virtualization,
        })
    }

    #[cfg(not(target_os = "macos"))]
    async fn collect_os() -> Result<OsSnapshot> {
        let (os_release_str, kernel, arch, uptime_str, tz) = tokio::join!(
            tokio::fs::read_to_string("/etc/os-release"),
            run_cmd("uname", &["-r"]),
            run_cmd("uname", &["-m"]),
            tokio::fs::read_to_string("/proc/uptime"),
            Self::detect_timezone(),
        );

        let os_release = os_release_str.unwrap_or_default();

        let distribution = parse_os_release_field(&os_release, "NAME")
            .unwrap_or_else(|| "Linux".into());
        let version = parse_os_release_field(&os_release, "VERSION_ID")
            .unwrap_or_else(|| "unknown".into());
        let product_name = parse_os_release_field(&os_release, "PRETTY_NAME");
        let build_id = parse_os_release_field(&os_release, "BUILD_ID");

        let kernel = kernel.unwrap_or_else(|| "unknown".into());
        let arch_str = arch.unwrap_or_else(|| "unknown".into());

        let uptime_secs = uptime_str
            .unwrap_or_default()
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<f64>().ok())
            .map(|f| f as u64)
            .unwrap_or(0);

        let boot_time = if uptime_secs > 0 {
            Some(Utc::now() - chrono::Duration::seconds(uptime_secs as i64))
        } else {
            None
        };

        let systemd_version = run_cmd("systemctl", &["--version"])
            .await
            .and_then(|s| {
                s.lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .map(|v| v.to_string())
            });

        let is_wsl = detect_wsl().await;

        // Detect virtualization: systemd-detect-virt, /proc/cpuinfo, DMI
        let virtualization = Self::detect_virtualization_linux().await;

        let hostname = gethostname();
        let triple = format!("{}-linux", arch_str.trim());

        Ok(OsSnapshot {
            distribution,
            version,
            kernel_version: kernel.trim().to_string(),
            architecture: arch_str.trim().to_string(),
            platform_triple: triple,
            hostname: hostname.clone(),
            product_name,
            build_id,
            systemd_version,
            boot_time,
            uptime_secs,
            timezone: tz,
            is_wsl,
            virtualization,
        })
    }

    async fn detect_timezone() -> Option<String> {
        // Try TZ env, then /etc/localtime symlink, then date
        if let Ok(tz) = std::env::var("TZ") {
            if !tz.is_empty() {
                return Some(tz);
            }
        }

        // /etc/localtime is often a symlink to /usr/share/zoneinfo/...
        if let Ok(target) = tokio::fs::read_link("/etc/localtime").await {
            let path = target.to_string_lossy().to_string();
            if let Some(tz) = path.strip_prefix("/usr/share/zoneinfo/") {
                return Some(tz.to_string());
            }
            if let Some(tz) = path.strip_prefix("/var/db/timezone/zoneinfo/") {
                return Some(tz.to_string());
            }
        }

        // Fallback
        run_cmd("date", &["+%Z"])
            .await
            .map(|s| s.trim().to_string())
    }

    #[cfg(not(target_os = "macos"))]
    async fn detect_virtualization_linux() -> Option<String> {
        // Try systemd-detect-virt first
        if let Some(virt) = run_cmd("systemd-detect-virt", &[]).await {
            let v = virt.trim().to_string();
            if v != "none" {
                return Some(v);
            }
        }

        // Check /proc/cpuinfo for hypervisor flag
        if let Ok(cpuinfo) = tokio::fs::read_to_string("/proc/cpuinfo").await {
            if cpuinfo.contains("hypervisor") {
                // Try to identify which
                if let Ok(dmi) =
                    tokio::fs::read_to_string("/sys/class/dmi/id/product_name").await
                {
                    let dmi = dmi.trim().to_lowercase();
                    if dmi.contains("vmware") {
                        return Some("vmware".into());
                    } else if dmi.contains("virtualbox") {
                        return Some("virtualbox".into());
                    } else if dmi.contains("kvm") || dmi.contains("qemu") {
                        return Some("kvm".into());
                    } else if dmi.contains("hyper-v") {
                        return Some("hyper-v".into());
                    }
                }
                return Some("vm".into());
            }
        }

        // Check /.dockerenv for container
        if tokio::fs::try_exists("/.dockerenv").await.unwrap_or(false) {
            return Some("docker".into());
        }

        // Check cgroup for container runtime
        if let Ok(cgroup) = tokio::fs::read_to_string("/proc/1/cgroup").await {
            if cgroup.contains("docker") {
                return Some("docker".into());
            }
            if cgroup.contains("lxc") {
                return Some("lxc".into());
            }
            if cgroup.contains("kubepods") {
                return Some("kubernetes".into());
            }
        }

        None
    }

    // ═══════════════════════════════════════════════════════════
    // NETWORK
    // ═══════════════════════════════════════════════════════════

    #[cfg(target_os = "macos")]
    async fn collect_network() -> Result<NetworkSnapshot> {
        let hostname = gethostname();

        let (ifconfig, netstat, resolv, listening) = tokio::join!(
            run_cmd("ifconfig", &[]),
            run_cmd("netstat", &["-rn"]),
            tokio::fs::read_to_string("/etc/resolv.conf"),
            Self::collect_listening_ports(),
        );

        let ifconfig = ifconfig.unwrap_or_default();
        let interfaces = parse_macos_ifconfig(&ifconfig);

        // Get network traffic bytes from netstat -ib
        let traffic = run_cmd("netstat", &["-ib"]).await.unwrap_or_default();
        let interfaces = enrich_macos_traffic(interfaces, &traffic);

        let netstat = netstat.unwrap_or_default();
        let routes = parse_macos_routes(&netstat);

        let default_gw = routes
            .iter()
            .find(|r| r.destination == "default")
            .and_then(|r| r.gateway.clone());

        let resolv = resolv.unwrap_or_default();
        let dns_resolvers = parse_resolv_conf(&resolv);

        Ok(NetworkSnapshot {
            hostname,
            interfaces,
            routes,
            dns_resolvers,
            default_gateway: default_gw,
            listening_ports: listening.unwrap_or_default(),
        })
    }

    #[cfg(not(target_os = "macos"))]
    async fn collect_network() -> Result<NetworkSnapshot> {
        let hostname = gethostname();

        let (ip_addr, ip_route, resolv, listening) = tokio::join!(
            run_cmd("ip", &["-j", "addr"]),
            run_cmd("ip", &["-j", "route"]),
            tokio::fs::read_to_string("/etc/resolv.conf"),
            Self::collect_listening_ports(),
        );

        let ip_addr = ip_addr.unwrap_or_default();
        let interfaces = parse_linux_ip_addr(&ip_addr);

        // Enrich with traffic from /proc/net/dev
        let interfaces = enrich_linux_traffic(interfaces).await;

        let ip_route = ip_route.unwrap_or_default();
        let routes = parse_linux_routes(&ip_route);

        let default_gw = routes
            .iter()
            .find(|r| r.destination == "default")
            .and_then(|r| r.gateway.clone());

        let resolv = resolv.unwrap_or_default();
        let dns_resolvers = parse_resolv_conf(&resolv);

        Ok(NetworkSnapshot {
            hostname,
            interfaces,
            routes,
            dns_resolvers,
            default_gateway: default_gw,
            listening_ports: listening.unwrap_or_default(),
        })
    }

    // ── Listening ports ────────────────────────────────────

    #[cfg(target_os = "macos")]
    async fn collect_listening_ports() -> Result<Vec<ListeningPort>> {
        // lsof is more reliable on macOS than netstat for listening ports
        let output = run_cmd("lsof", &["-iTCP", "-sTCP:LISTEN", "-nP", "-F", "pcn"])
            .await
            .unwrap_or_default();

        let mut ports = Vec::new();
        let mut current_pid = String::new();
        let mut current_name = String::new();

        for line in output.lines() {
            if let Some(pid) = line.strip_prefix('p') {
                current_pid = pid.to_string();
            } else if let Some(name) = line.strip_prefix('c') {
                current_name = name.to_string();
            } else if let Some(name_field) = line.strip_prefix('n') {
                // n*:8080 or n127.0.0.1:9100
                if let Some(port_str) = name_field.rsplit(':').next() {
                    if let Ok(port) = port_str.parse::<u16>() {
                        let addr = name_field.rsplit(':').nth(1).map(|s| s.to_string());
                        // Avoid duplicates
                        if !ports.iter().any(|p: &ListeningPort| p.port == port) {
                            ports.push(ListeningPort {
                                port,
                                protocol: "tcp".into(),
                                address: addr,
                                process: if current_name.is_empty() {
                                    Some(format!("pid:{}", current_pid))
                                } else {
                                    Some(current_name.clone())
                                },
                            });
                        }
                    }
                }
            }
        }

        // Also check UDP via lsof
        let udp = run_cmd("lsof", &["-iUDP", "-nP", "-F", "pcn"])
            .await
            .unwrap_or_default();
        let mut current_pid = String::new();
        let mut current_name = String::new();

        for line in udp.lines() {
            if let Some(pid) = line.strip_prefix('p') {
                current_pid = pid.to_string();
            } else if let Some(name) = line.strip_prefix('c') {
                current_name = name.to_string();
            } else if let Some(name_field) = line.strip_prefix('n') {
                if let Some(port_str) = name_field.rsplit(':').next() {
                    if let Ok(port) = port_str.parse::<u16>() {
                        let addr = name_field.rsplit(':').nth(1).map(|s| s.to_string());
                        if !ports.iter().any(|p: &ListeningPort| p.port == port && p.protocol == "udp") {
                            ports.push(ListeningPort {
                                port,
                                protocol: "udp".into(),
                                address: addr,
                                process: if current_name.is_empty() {
                                    Some(format!("pid:{}", current_pid))
                                } else {
                                    Some(current_name.clone())
                                },
                            });
                        }
                    }
                }
            }
        }

        ports.sort_by_key(|p| p.port);
        Ok(ports)
    }

    #[cfg(not(target_os = "macos"))]
    async fn collect_listening_ports() -> Result<Vec<ListeningPort>> {
        // ss is the modern replacement for netstat on Linux
        let output = run_cmd("ss", &["-tlnp"]).await.unwrap_or_default();
        let mut ports = Vec::new();

        for line in output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let local = parts[3];
                if let Some(port_str) = local.rsplit(':').next() {
                    if let Ok(port) = port_str.parse::<u16>() {
                        let addr = local.rsplit(':').nth(1).map(|s| s.to_string());
                        let process = parts.get(5).map(|s| {
                            // users:(("process",pid=123,fd=4))
                            s.split('"')
                                .nth(1)
                                .unwrap_or(s)
                                .to_string()
                        });

                        ports.push(ListeningPort {
                            port,
                            protocol: "tcp".into(),
                            address: addr,
                            process,
                        });
                    }
                }
            }
        }

        // UDP
        let udp = run_cmd("ss", &["-ulnp"]).await.unwrap_or_default();
        for line in udp.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let local = parts[3];
                if let Some(port_str) = local.rsplit(':').next() {
                    if let Ok(port) = port_str.parse::<u16>() {
                        let addr = local.rsplit(':').nth(1).map(|s| s.to_string());
                        let process = parts.get(5).map(|s| {
                            s.split('"')
                                .nth(1)
                                .unwrap_or(s)
                                .to_string()
                        });

                        ports.push(ListeningPort {
                            port,
                            protocol: "udp".into(),
                            address: addr,
                            process,
                        });
                    }
                }
            }
        }

        ports.sort_by_key(|p| p.port);
        Ok(ports)
    }

    // ═══════════════════════════════════════════════════════════
    // NIX
    // ═══════════════════════════════════════════════════════════

    async fn collect_nix() -> Result<NixSnapshot> {
        let nix_version = run_cmd("nix", &["--version"])
            .await
            .map(|s| {
                s.trim()
                    .strip_prefix("nix (Nix) ")
                    .unwrap_or(s.trim())
                    .to_string()
            })
            .unwrap_or_else(|| "unknown".into());

        // Store size: use du -sk on macOS (no -sb), du -sb on Linux
        let store_size_bytes = if cfg!(target_os = "macos") {
            run_cmd("du", &["-sk", "/nix/store"])
                .await
                .and_then(|s| s.split_whitespace().next().and_then(|n| n.parse::<u64>().ok()))
                .map(|kb| kb * 1024)
                .unwrap_or(0)
        } else {
            run_cmd("du", &["-sb", "/nix/store"])
                .await
                .and_then(|s| s.split_whitespace().next().and_then(|n| n.parse().ok()))
                .unwrap_or(0)
        };

        // Path count
        let store_path_count = run_cmd("nix", &["path-info", "--all"])
            .await
            .map(|s| s.lines().count() as u64)
            .unwrap_or(0);

        // GC roots count
        let gc_roots_count = run_cmd("nix-store", &["--gc", "--print-roots"])
            .await
            .map(|s| s.lines().count() as u64)
            .unwrap_or(0);

        // Nix config
        let nix_config_json = run_cmd("nix", &["show-config", "--json"]).await;
        let nix_config: serde_json::Value = nix_config_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or(serde_json::Value::Null);

        let substituters = nix_config
            .get("substituters")
            .and_then(|s| s.get("value"))
            .and_then(|s| s.as_str())
            .map(|s| s.split_whitespace().map(|s| s.to_string()).collect())
            .unwrap_or_default();

        let trusted_users = nix_config
            .get("trusted-users")
            .and_then(|s| s.get("value"))
            .and_then(|s| s.as_str())
            .map(|s| s.split_whitespace().map(|s| s.to_string()).collect())
            .unwrap_or_default();

        let max_jobs = nix_config
            .get("max-jobs")
            .and_then(|s| s.get("value"))
            .and_then(|s| {
                if s.is_number() {
                    Some(s.to_string())
                } else {
                    s.as_str().map(|s| s.to_string())
                }
            });

        let sandbox_enabled = nix_config
            .get("sandbox")
            .and_then(|s| s.get("value"))
            .and_then(|s| {
                if s.is_boolean() {
                    s.as_bool()
                } else {
                    s.as_str().map(|s| s == "true" || s == "relaxed")
                }
            })
            .unwrap_or(false);

        // Current system path
        let current_system_path = run_cmd("readlink", &["-f", "/run/current-system"])
            .await
            .map(|s| s.trim().to_string());

        // System generations
        let system_generations = if cfg!(target_os = "macos") {
            // nix-darwin generations in /nix/var/nix/profiles/system-*-link
            run_cmd("ls", &["-1", "/nix/var/nix/profiles/"])
                .await
                .map(|s| {
                    s.lines()
                        .filter(|l| l.starts_with("system-"))
                        .count() as u64
                })
                .unwrap_or(0)
        } else {
            run_cmd("ls", &["-1", "/nix/var/nix/profiles/"])
                .await
                .map(|s| {
                    s.lines()
                        .filter(|l| l.starts_with("system-"))
                        .count() as u64
                })
                .unwrap_or(0)
        };

        // Channels
        let channels = run_cmd("nix-channel", &["--list"])
            .await
            .map(|s| s.lines().map(|l| l.to_string()).collect())
            .unwrap_or_default();

        Ok(NixSnapshot {
            nix_version,
            store_size_bytes,
            store_path_count,
            gc_roots_count,
            last_rebuild_timestamp: None,
            current_system_path,
            substituters,
            system_generations,
            channels,
            trusted_users,
            max_jobs,
            sandbox_enabled,
        })
    }

    // ═══════════════════════════════════════════════════════════
    // KUBERNETES
    // ═══════════════════════════════════════════════════════════

    async fn collect_kubernetes() -> Result<K8sSnapshot> {
        let k3s_version = run_cmd("k3s", &["--version"]).await.and_then(|s| {
            s.lines().next().map(|l| l.trim().to_string())
        });

        let node_json = run_cmd(
            "kubectl",
            &["get", "nodes", "-o", "json", "--request-timeout=5s"],
        )
        .await
        .ok_or_else(|| anyhow::anyhow!("kubectl not available or cluster unreachable"))?;

        let nodes: serde_json::Value = serde_json::from_str(&node_json)?;

        let items = nodes
            .get("items")
            .and_then(|i| i.as_array())
            .cloned()
            .unwrap_or_default();

        let node_ready = items.iter().any(|node| {
            node.get("status")
                .and_then(|s| s.get("conditions"))
                .and_then(|c| c.as_array())
                .map(|conds| {
                    conds.iter().any(|c| {
                        c.get("type").and_then(|t| t.as_str()) == Some("Ready")
                            && c.get("status").and_then(|s| s.as_str()) == Some("True")
                    })
                })
                .unwrap_or(false)
        });

        let conditions: Vec<K8sCondition> = items
            .first()
            .and_then(|n| n.get("status"))
            .and_then(|s| s.get("conditions"))
            .and_then(|c| c.as_array())
            .map(|conds| {
                conds
                    .iter()
                    .map(|c| K8sCondition {
                        condition_type: c
                            .get("type")
                            .and_then(|t| t.as_str())
                            .unwrap_or("unknown")
                            .to_string(),
                        status: c
                            .get("status")
                            .and_then(|s| s.as_str())
                            .unwrap_or("unknown")
                            .to_string(),
                        message: c
                            .get("message")
                            .and_then(|m| m.as_str())
                            .map(|s| s.to_string()),
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Pod + namespace counts
        let (pod_count, namespace_count, resource_info) = tokio::join!(
            async {
                run_cmd("kubectl", &["get", "pods", "-A", "-o", "json", "--request-timeout=5s"])
                    .await
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                    .and_then(|v| v.get("items").and_then(|i| i.as_array()).map(|a| a.len() as u32))
                    .unwrap_or(0)
            },
            async {
                run_cmd("kubectl", &["get", "namespaces", "-o", "json", "--request-timeout=5s"])
                    .await
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                    .and_then(|v| v.get("items").and_then(|i| i.as_array()).map(|a| a.len() as u32))
                    .unwrap_or(0)
            },
            Self::collect_k8s_resources(),
        );

        let (cpu_req, cpu_lim, mem_req, mem_lim) = resource_info;

        // FluxCD detection
        let flux_installed = run_cmd("kubectl", &["get", "ns", "flux-system", "--request-timeout=3s"])
            .await
            .map(|_| true);

        // Helm releases
        let helm_releases = run_cmd("kubectl", &["get", "helmreleases", "-A", "--no-headers", "--request-timeout=3s"])
            .await
            .map(|s| s.lines().count() as u32);

        Ok(K8sSnapshot {
            k3s_version,
            node_ready,
            pod_count,
            namespace_count,
            conditions,
            cpu_requests_millis: cpu_req,
            cpu_limits_millis: cpu_lim,
            memory_requests_bytes: mem_req,
            memory_limits_bytes: mem_lim,
            flux_installed,
            helm_releases,
        })
    }

    async fn collect_k8s_resources() -> (u64, u64, u64, u64) {
        // kubectl top node gives resource usage; describe node gives requests/limits
        let output = run_cmd(
            "kubectl",
            &["describe", "nodes", "--request-timeout=5s"],
        )
        .await
        .unwrap_or_default();

        let mut cpu_req: u64 = 0;
        let mut cpu_lim: u64 = 0;
        let mut mem_req: u64 = 0;
        let mut mem_lim: u64 = 0;

        // Look for "Allocated resources:" section
        let mut in_allocated = false;
        for line in output.lines() {
            if line.contains("Allocated resources:") {
                in_allocated = true;
                continue;
            }
            if in_allocated {
                if line.trim().starts_with("cpu") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 {
                        cpu_req = parse_k8s_cpu(parts[1]);
                        cpu_lim = parse_k8s_cpu(parts[3]);
                    }
                } else if line.trim().starts_with("memory") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 {
                        mem_req = parse_k8s_memory(parts[1]);
                        mem_lim = parse_k8s_memory(parts[3]);
                    }
                } else if line.trim().is_empty() || line.starts_with("Events:") {
                    in_allocated = false;
                }
            }
        }

        (cpu_req, cpu_lim, mem_req, mem_lim)
    }

    // ═══════════════════════════════════════════════════════════
    // HEALTH
    // ═══════════════════════════════════════════════════════════

    #[cfg(target_os = "macos")]
    async fn collect_health() -> Result<HealthMetrics> {
        let load_str = run_cmd("sysctl", &["-n", "vm.loadavg"])
            .await
            .unwrap_or_default();
        let loads: Vec<f64> = load_str
            .trim()
            .trim_start_matches('{')
            .trim_end_matches('}')
            .split_whitespace()
            .filter_map(|s| s.parse().ok())
            .collect();

        let (ram_total, ram_available) = Self::collect_memory_info().await;
        let memory_usage_percent = if ram_total > 0 {
            ((ram_total - ram_available) as f64 / ram_total as f64) * 100.0
        } else {
            0.0
        };

        let (swap_total, swap_used) = Self::collect_swap_info().await;
        let swap_usage_percent = if swap_total > 0 {
            (swap_used as f64 / swap_total as f64) * 100.0
        } else {
            0.0
        };

        // CPU usage via top -l1
        let cpu_usage = run_cmd("top", &["-l", "1", "-n", "0", "-s", "0"])
            .await
            .and_then(|s| {
                s.lines()
                    .find(|l| l.contains("CPU usage"))
                    .and_then(|l| {
                        // "CPU usage: 5.26% user, 3.50% sys, 91.22% idle"
                        l.split("idle")
                            .next()
                            .and_then(|before| {
                                before
                                    .rsplit(',')
                                    .next()
                                    .and_then(|s| {
                                        s.trim()
                                            .trim_end_matches('%')
                                            .trim()
                                            .parse::<f64>()
                                            .ok()
                                    })
                            })
                            .map(|idle| 100.0 - idle)
                    })
            })
            .unwrap_or(0.0);

        let disk_usage = Self::collect_disk_usage().await;

        // File descriptors
        let max_fds = run_cmd("sysctl", &["-n", "kern.maxfiles"])
            .await
            .and_then(|s| s.trim().parse().ok());

        Ok(HealthMetrics {
            load_average_1m: loads.first().copied().unwrap_or(0.0),
            load_average_5m: loads.get(1).copied().unwrap_or(0.0),
            load_average_15m: loads.get(2).copied().unwrap_or(0.0),
            memory_usage_percent,
            swap_usage_percent,
            cpu_usage_percent: cpu_usage,
            disk_usage,
            open_file_descriptors: None,
            max_file_descriptors: max_fds,
        })
    }

    #[cfg(not(target_os = "macos"))]
    async fn collect_health() -> Result<HealthMetrics> {
        let loadavg = tokio::fs::read_to_string("/proc/loadavg")
            .await
            .unwrap_or_default();
        let loads: Vec<f64> = loadavg
            .split_whitespace()
            .take(3)
            .filter_map(|s| s.parse().ok())
            .collect();

        let (ram_total, ram_available) = Self::collect_memory_info().await;
        let memory_usage_percent = if ram_total > 0 {
            ((ram_total - ram_available) as f64 / ram_total as f64) * 100.0
        } else {
            0.0
        };

        let (swap_total, swap_used) = Self::collect_swap_info().await;
        let swap_usage_percent = if swap_total > 0 {
            (swap_used as f64 / swap_total as f64) * 100.0
        } else {
            0.0
        };

        // CPU usage from /proc/stat (instantaneous snapshot — delta between two reads)
        let cpu_usage = Self::sample_cpu_usage_linux().await;

        let disk_usage = Self::collect_disk_usage().await;

        // File descriptors from /proc/sys/fs/file-nr
        let (open_fds, max_fds) =
            tokio::fs::read_to_string("/proc/sys/fs/file-nr")
                .await
                .map(|s| {
                    let parts: Vec<&str> = s.split_whitespace().collect();
                    let open = parts.first().and_then(|s| s.parse().ok());
                    let max = parts.get(2).and_then(|s| s.parse().ok());
                    (open, max)
                })
                .unwrap_or((None, None));

        Ok(HealthMetrics {
            load_average_1m: loads.first().copied().unwrap_or(0.0),
            load_average_5m: loads.get(1).copied().unwrap_or(0.0),
            load_average_15m: loads.get(2).copied().unwrap_or(0.0),
            memory_usage_percent,
            swap_usage_percent,
            cpu_usage_percent: cpu_usage,
            disk_usage,
            open_file_descriptors: open_fds,
            max_file_descriptors: max_fds,
        })
    }

    #[cfg(not(target_os = "macos"))]
    async fn sample_cpu_usage_linux() -> f64 {
        // Read /proc/stat twice with 200ms gap
        let read_cpu_stat = || async {
            tokio::fs::read_to_string("/proc/stat")
                .await
                .ok()
                .and_then(|s| {
                    s.lines().next().and_then(|l| {
                        let parts: Vec<u64> = l
                            .split_whitespace()
                            .skip(1) // skip "cpu"
                            .filter_map(|s| s.parse().ok())
                            .collect();
                        if parts.len() >= 4 {
                            let idle = parts[3];
                            let total: u64 = parts.iter().sum();
                            Some((idle, total))
                        } else {
                            None
                        }
                    })
                })
        };

        let before = read_cpu_stat().await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let after = read_cpu_stat().await;

        match (before, after) {
            (Some((idle1, total1)), Some((idle2, total2))) => {
                let idle_delta = idle2.saturating_sub(idle1) as f64;
                let total_delta = total2.saturating_sub(total1) as f64;
                if total_delta > 0.0 {
                    ((total_delta - idle_delta) / total_delta) * 100.0
                } else {
                    0.0
                }
            }
            _ => 0.0,
        }
    }

    async fn collect_disk_usage() -> Vec<DiskUsage> {
        let output = run_cmd("df", &["-k"]).await.unwrap_or_default();
        let mut usage = Vec::new();

        for line in output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }

            let mount = parts[parts.len() - 1].to_string();
            let device = parts[0];

            if device == "devfs"
                || device == "map"
                || device.starts_with("tmpfs")
                || device == "none"
            {
                continue;
            }

            if let Some(pct_str) = parts.get(4) {
                if let Ok(pct) = pct_str.trim_end_matches('%').parse::<f64>() {
                    usage.push(DiskUsage {
                        mount_point: mount,
                        usage_percent: pct,
                    });
                }
            }
        }
        usage
    }

    // ═══════════════════════════════════════════════════════════
    // PROCESSES
    // ═══════════════════════════════════════════════════════════

    async fn collect_processes() -> Result<ProcessSnapshot> {
        // ps aux gives us everything we need cross-platform
        let output = run_cmd("ps", &["aux"]).await.unwrap_or_default();

        let mut total: u32 = 0;
        let mut running: u32 = 0;
        let mut zombie: u32 = 0;
        let mut procs: Vec<(u32, String, f64, f64)> = Vec::new();

        for line in output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 11 {
                continue;
            }

            total += 1;

            let pid: u32 = parts[1].parse().unwrap_or(0);
            let cpu_pct: f64 = parts[2].parse().unwrap_or(0.0);
            let mem_pct: f64 = parts[3].parse().unwrap_or(0.0);
            let stat = parts[7];
            let name = parts[10..].join(" ");

            if stat.starts_with('R') {
                running += 1;
            }
            if stat.starts_with('Z') {
                zombie += 1;
            }

            procs.push((pid, name, cpu_pct, mem_pct));
        }

        // Top 5 by CPU
        procs.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        let top_cpu: Vec<ProcessInfo> = procs
            .iter()
            .take(5)
            .filter(|p| p.2 > 0.0)
            .map(|(pid, name, cpu, mem)| ProcessInfo {
                pid: *pid,
                name: name.clone(),
                cpu_percent: *cpu,
                memory_percent: *mem,
            })
            .collect();

        // Top 5 by memory
        procs.sort_by(|a, b| b.3.partial_cmp(&a.3).unwrap_or(std::cmp::Ordering::Equal));
        let top_memory: Vec<ProcessInfo> = procs
            .iter()
            .take(5)
            .filter(|p| p.3 > 0.0)
            .map(|(pid, name, cpu, mem)| ProcessInfo {
                pid: *pid,
                name: name.clone(),
                cpu_percent: *cpu,
                memory_percent: *mem,
            })
            .collect();

        Ok(ProcessSnapshot {
            total_processes: total,
            running_processes: running,
            zombie_processes: zombie,
            top_cpu,
            top_memory,
        })
    }

    // ═══════════════════════════════════════════════════════════
    // SECURITY
    // ═══════════════════════════════════════════════════════════

    async fn collect_security() -> Result<SecuritySnapshot> {
        let (ssh_keys, firewall, sshd_info) = tokio::join!(
            Self::collect_ssh_keys(),
            Self::collect_firewall_info(),
            Self::collect_sshd_info(),
        );

        let (firewall_active, firewall_rules_count, firewall_backend) = firewall;
        let (sshd_running, root_login_allowed, password_auth_enabled) = sshd_info;

        Ok(SecuritySnapshot {
            ssh_keys_deployed: ssh_keys,
            tls_certificates: Vec::new(),
            firewall_active,
            firewall_rules_count,
            firewall_backend,
            sshd_running,
            root_login_allowed,
            password_auth_enabled,
        })
    }

    async fn collect_ssh_keys() -> Vec<String> {
        let home = dirs::home_dir().unwrap_or_default();
        let auth_keys_path = home.join(".ssh/authorized_keys");

        if !auth_keys_path.exists() {
            return Vec::new();
        }

        tokio::fs::read_to_string(&auth_keys_path)
            .await
            .map(|s| {
                s.lines()
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(|l| {
                        let parts: Vec<&str> = l.split_whitespace().collect();
                        if parts.len() >= 3 {
                            parts[2].to_string()
                        } else if parts.len() >= 2 {
                            let key = parts[1];
                            let prefix = &key[..8.min(key.len())];
                            format!("{}...{}", prefix, parts[0])
                        } else {
                            "unknown-key".to_string()
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    #[cfg(target_os = "macos")]
    async fn collect_firewall_info() -> (bool, u32, Option<String>) {
        // macOS: Application Firewall (socketfilterfw) and pf
        let alf = run_cmd(
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            &["--getglobalstate"],
        )
        .await
        .unwrap_or_default();

        let alf_enabled = alf.contains("enabled");

        // Check pf
        let pf_enabled = run_cmd("pfctl", &["-s", "info"])
            .await
            .map(|s| s.contains("Status: Enabled"))
            .unwrap_or(false);

        let pf_rules = run_cmd("pfctl", &["-sr"])
            .await
            .map(|s| s.lines().filter(|l| !l.is_empty() && !l.starts_with('#')).count() as u32)
            .unwrap_or(0);

        let active = alf_enabled || pf_enabled;
        let backend = if pf_enabled && alf_enabled {
            Some("pf+alf".into())
        } else if pf_enabled {
            Some("pf".into())
        } else if alf_enabled {
            Some("alf".into())
        } else {
            None
        };

        (active, pf_rules, backend)
    }

    #[cfg(not(target_os = "macos"))]
    async fn collect_firewall_info() -> (bool, u32, Option<String>) {
        // Try nftables first, then iptables
        if let Some(nft) = run_cmd("nft", &["list", "ruleset"]).await {
            let rules = nft
                .lines()
                .filter(|l| l.trim().starts_with("rule") || l.contains("accept") || l.contains("drop"))
                .count() as u32;
            return (rules > 0, rules, Some("nftables".into()));
        }

        if let Some(ipt) = run_cmd("iptables", &["-L", "-n", "--line-numbers"]).await {
            let rules = ipt
                .lines()
                .filter(|l| {
                    let trimmed = l.trim();
                    !trimmed.is_empty()
                        && !trimmed.starts_with("Chain")
                        && !trimmed.starts_with("num")
                        && !trimmed.starts_with("target")
                })
                .count() as u32;
            return (rules > 0, rules, Some("iptables".into()));
        }

        (false, 0, None)
    }

    async fn collect_sshd_info() -> (bool, bool, bool) {
        // Check if sshd is running
        let sshd_running = run_cmd("pgrep", &["-x", "sshd"])
            .await
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

        // Parse sshd_config for policy
        let config_paths = [
            "/etc/ssh/sshd_config",
            "/etc/ssh/sshd_config.d/",
        ];

        let mut root_login = true; // default is usually permit
        let mut password_auth = true; // default is usually yes

        for path in &config_paths {
            if let Ok(content) = tokio::fs::read_to_string(path).await {
                for line in content.lines() {
                    let line = line.trim();
                    if line.starts_with('#') || line.is_empty() {
                        continue;
                    }
                    let lower = line.to_lowercase();
                    if lower.starts_with("permitrootlogin") {
                        root_login = !lower.contains("no");
                    }
                    if lower.starts_with("passwordauthentication") {
                        password_auth = !lower.contains("no");
                    }
                }
            }
        }

        (sshd_running, root_login, password_auth)
    }
}

// ═══════════════════════════════════════════════════════════════
// Helper functions
// ═══════════════════════════════════════════════════════════════

async fn run_cmd(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        None
    }
}

fn gethostname() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

#[cfg(target_os = "macos")]
fn parse_vm_stat_field(output: &str, field: &str) -> u64 {
    output
        .lines()
        .find(|l| l.contains(field))
        .and_then(|l| {
            l.split(':')
                .nth(1)
                .and_then(|v| v.trim().trim_end_matches('.').parse().ok())
        })
        .unwrap_or(0)
}

#[cfg(not(target_os = "macos"))]
fn parse_meminfo_kb(meminfo: &str, field: &str) -> u64 {
    meminfo
        .lines()
        .find(|l| l.starts_with(field))
        .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn parse_swap_field(output: &str, field: &str) -> u64 {
    output
        .split(field)
        .nth(1)
        .and_then(|s| {
            s.split_whitespace()
                .find(|w| w.ends_with('M') || w.ends_with('G'))
                .and_then(|v| {
                    let num_str = v.trim_end_matches('M').trim_end_matches('G').trim_start_matches("= ");
                    let num: f64 = num_str.parse().ok()?;
                    if v.ends_with('G') {
                        Some((num * 1024.0 * 1024.0 * 1024.0) as u64)
                    } else {
                        Some((num * 1024.0 * 1024.0) as u64)
                    }
                })
        })
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn parse_kern_boottime(output: &str) -> Option<chrono::DateTime<Utc>> {
    let sec_str = output.split("sec = ").nth(1)?.split(',').next()?.trim();
    let sec: i64 = sec_str.parse().ok()?;
    chrono::DateTime::from_timestamp(sec, 0)
}

#[cfg(target_os = "macos")]
fn parse_vram_string(s: &str) -> Option<u64> {
    // "1536 MB" or "16 GB"
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() >= 2 {
        let num: f64 = parts[0].parse().ok()?;
        match parts[1].to_uppercase().as_str() {
            "GB" => Some((num * 1024.0 * 1024.0 * 1024.0) as u64),
            "MB" => Some((num * 1024.0 * 1024.0) as u64),
            _ => None,
        }
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn parse_macos_ifconfig(output: &str) -> Vec<InterfaceSnapshot> {
    let mut interfaces = Vec::new();
    let mut current_name = String::new();
    let mut current_addresses = Vec::new();
    let mut current_mac = None;
    let mut current_mtu = None;
    let mut current_state = "unknown".to_string();

    for line in output.lines() {
        if !line.starts_with('\t') && !line.starts_with(' ') && line.contains(':') {
            if !current_name.is_empty() {
                let iface_type = classify_macos_interface(&current_name);
                interfaces.push(InterfaceSnapshot {
                    name: current_name.clone(),
                    state: current_state.clone(),
                    addresses: current_addresses.clone(),
                    mac: current_mac.clone(),
                    mtu: current_mtu,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    speed_mbps: None,
                    interface_type: Some(iface_type),
                });
            }
            current_name = line.split(':').next().unwrap_or("").to_string();
            current_addresses = Vec::new();
            current_mac = None;
            current_mtu = None;

            current_state = if line.contains("<UP") || line.contains(",UP") {
                "up".to_string()
            } else {
                "down".to_string()
            };

            if let Some(mtu_str) = line.split("mtu ").nth(1) {
                current_mtu = mtu_str.split_whitespace().next().and_then(|s| s.parse().ok());
            }
        } else if line.contains("inet ") && !line.contains("inet6") {
            if let Some(addr) = line.split("inet ").nth(1) {
                if let Some(ip) = addr.split_whitespace().next() {
                    current_addresses.push(ip.to_string());
                }
            }
        } else if line.contains("inet6 ") {
            if let Some(addr) = line.split("inet6 ").nth(1) {
                if let Some(ip) = addr.split_whitespace().next() {
                    let clean = ip.split('%').next().unwrap_or(ip);
                    current_addresses.push(format!("ipv6:{}", clean));
                }
            }
        } else if line.contains("ether ") {
            current_mac = line
                .split("ether ")
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .map(|s| s.to_string());
        }
    }

    if !current_name.is_empty() {
        let iface_type = classify_macos_interface(&current_name);
        interfaces.push(InterfaceSnapshot {
            name: current_name,
            state: current_state,
            addresses: current_addresses,
            mac: current_mac,
            mtu: current_mtu,
            rx_bytes: 0,
            tx_bytes: 0,
            speed_mbps: None,
            interface_type: Some(iface_type),
        });
    }

    interfaces
}

#[cfg(target_os = "macos")]
fn classify_macos_interface(name: &str) -> String {
    if name.starts_with("en0") || name.starts_with("en1") {
        "ethernet/wifi".into()
    } else if name.starts_with("en") {
        "ethernet".into()
    } else if name.starts_with("lo") {
        "loopback".into()
    } else if name.starts_with("bridge") {
        "bridge".into()
    } else if name.starts_with("utun") || name.starts_with("ipsec") {
        "vpn".into()
    } else if name.starts_with("awdl") {
        "airdrop".into()
    } else if name.starts_with("llw") {
        "low-latency-wlan".into()
    } else if name.starts_with("ap") {
        "access-point".into()
    } else {
        "other".into()
    }
}

#[cfg(target_os = "macos")]
fn enrich_macos_traffic(
    mut interfaces: Vec<InterfaceSnapshot>,
    netstat_ib: &str,
) -> Vec<InterfaceSnapshot> {
    // netstat -ib output:
    // Name  Mtu   Network     Address         Ipkts   Ierrs  Ibytes    Opkts  Oerrs  Obytes
    for line in netstat_ib.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 10 {
            let name = parts[0];
            let ibytes: u64 = parts[6].parse().unwrap_or(0);
            let obytes: u64 = parts[9].parse().unwrap_or(0);

            if let Some(iface) = interfaces.iter_mut().find(|i| i.name == name) {
                // netstat -ib may show multiple rows per interface; accumulate
                iface.rx_bytes = iface.rx_bytes.max(ibytes);
                iface.tx_bytes = iface.tx_bytes.max(obytes);
            }
        }
    }
    interfaces
}

#[cfg(target_os = "macos")]
fn parse_macos_routes(output: &str) -> Vec<RouteSnapshot> {
    let mut routes = Vec::new();
    let mut in_inet = false;

    for line in output.lines() {
        // Find the "Internet:" section
        if line.starts_with("Internet:") || line.starts_with("Internet6:") {
            in_inet = true;
            continue;
        }
        if line.starts_with("Routing tables") || (in_inet && line.is_empty()) {
            // new section
        }
        if !in_inet || line.starts_with("Destination") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            routes.push(RouteSnapshot {
                destination: parts[0].to_string(),
                gateway: Some(parts[1].to_string()),
                interface: parts.last().unwrap_or(&"").to_string(),
            });
        }
    }
    routes
}

#[cfg(not(target_os = "macos"))]
fn parse_linux_ip_addr(json_str: &str) -> Vec<InterfaceSnapshot> {
    let parsed: Vec<serde_json::Value> = serde_json::from_str(json_str).unwrap_or_default();

    parsed
        .iter()
        .map(|iface| {
            let name = iface
                .get("ifname")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            let state = iface
                .get("operstate")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_lowercase();

            let addresses: Vec<String> = iface
                .get("addr_info")
                .and_then(|a| a.as_array())
                .map(|addrs| {
                    addrs
                        .iter()
                        .filter_map(|a| {
                            let local = a.get("local").and_then(|l| l.as_str())?;
                            let prefix = a.get("prefixlen").and_then(|p| p.as_u64());
                            Some(if let Some(p) = prefix {
                                format!("{}/{}", local, p)
                            } else {
                                local.to_string()
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();

            let mac = iface
                .get("address")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let mtu = iface
                .get("mtu")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32);

            let link_type = iface
                .get("link_type")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            InterfaceSnapshot {
                name,
                state,
                addresses,
                mac,
                mtu,
                rx_bytes: 0,
                tx_bytes: 0,
                speed_mbps: None,
                interface_type: link_type,
            }
        })
        .collect()
}

#[cfg(not(target_os = "macos"))]
async fn enrich_linux_traffic(mut interfaces: Vec<InterfaceSnapshot>) -> Vec<InterfaceSnapshot> {
    // /proc/net/dev has rx/tx bytes per interface
    if let Ok(content) = tokio::fs::read_to_string("/proc/net/dev").await {
        for line in content.lines().skip(2) {
            let line = line.trim();
            if let Some((name, stats)) = line.split_once(':') {
                let name = name.trim();
                let parts: Vec<&str> = stats.split_whitespace().collect();
                if parts.len() >= 9 {
                    let rx: u64 = parts[0].parse().unwrap_or(0);
                    let tx: u64 = parts[8].parse().unwrap_or(0);

                    if let Some(iface) = interfaces.iter_mut().find(|i| i.name == name) {
                        iface.rx_bytes = rx;
                        iface.tx_bytes = tx;
                    }
                }
            }
        }
    }

    // Try to get link speed from /sys/class/net/<iface>/speed
    for iface in &mut interfaces {
        if let Some(speed) = read_sys_file(&format!(
            "/sys/class/net/{}/speed",
            iface.name
        ))
        .await
        {
            if let Ok(mbps) = speed.trim().parse::<u32>() {
                if mbps > 0 && mbps < 100_000 {
                    // sanity check
                    iface.speed_mbps = Some(mbps);
                }
            }
        }
    }

    interfaces
}

#[cfg(not(target_os = "macos"))]
fn parse_linux_routes(json_str: &str) -> Vec<RouteSnapshot> {
    let parsed: Vec<serde_json::Value> = serde_json::from_str(json_str).unwrap_or_default();

    parsed
        .iter()
        .map(|route| {
            let dst = route
                .get("dst")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let gw = route
                .get("gateway")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let iface = route
                .get("dev")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            RouteSnapshot {
                destination: dst,
                gateway: gw,
                interface: iface,
            }
        })
        .collect()
}

fn parse_resolv_conf(content: &str) -> Vec<String> {
    content
        .lines()
        .filter(|l| l.starts_with("nameserver"))
        .filter_map(|l| l.split_whitespace().nth(1))
        .map(|s| s.to_string())
        .collect()
}

#[cfg(not(target_os = "macos"))]
fn parse_os_release_field(content: &str, field: &str) -> Option<String> {
    content
        .lines()
        .find(|l| l.starts_with(&format!("{}=", field)))
        .map(|l| {
            l.split('=')
                .nth(1)
                .unwrap_or("")
                .trim_matches('"')
                .to_string()
        })
}

#[cfg(not(target_os = "macos"))]
fn extract_proc_field(cpuinfo: &str, field: &str) -> Option<String> {
    cpuinfo
        .lines()
        .find(|l| l.starts_with(field))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
}

#[cfg(not(target_os = "macos"))]
async fn read_sys_file(path: &str) -> Option<String> {
    tokio::fs::read_to_string(path).await.ok()
}

#[cfg(not(target_os = "macos"))]
async fn detect_wsl() -> bool {
    tokio::fs::read_to_string("/proc/version")
        .await
        .map(|v| {
            let lower = v.to_lowercase();
            lower.contains("microsoft") || lower.contains("wsl")
        })
        .unwrap_or(false)
}

fn parse_k8s_cpu(s: &str) -> u64 {
    // "250m" → 250, "1" → 1000
    if let Some(millis) = s.strip_suffix('m') {
        millis.parse().unwrap_or(0)
    } else {
        s.parse::<u64>().unwrap_or(0) * 1000
    }
}

fn parse_k8s_memory(s: &str) -> u64 {
    if let Some(gi) = s.strip_suffix("Gi") {
        gi.parse::<u64>().unwrap_or(0) * 1024 * 1024 * 1024
    } else if let Some(mi) = s.strip_suffix("Mi") {
        mi.parse::<u64>().unwrap_or(0) * 1024 * 1024
    } else if let Some(ki) = s.strip_suffix("Ki") {
        ki.parse::<u64>().unwrap_or(0) * 1024
    } else {
        s.parse().unwrap_or(0)
    }
}

// ═══════════════════════════════════════════════════════════════
// Defaults for error fallback
// ═══════════════════════════════════════════════════════════════

fn default_hardware() -> HardwareSnapshot {
    HardwareSnapshot {
        cpu_model: "unknown".into(),
        cpu_vendor: "unknown".into(),
        cpu_architecture: "unknown".into(),
        cpu_cores: 0,
        cpu_threads: 0,
        cpu_frequency_mhz: None,
        cpu_cache_bytes: None,
        ram_total_bytes: 0,
        ram_available_bytes: 0,
        swap_total_bytes: 0,
        swap_used_bytes: 0,
        disks: Vec::new(),
        gpus: Vec::new(),
        temperatures: Vec::new(),
        power: None,
    }
}

fn default_os() -> OsSnapshot {
    OsSnapshot {
        distribution: "unknown".into(),
        version: "unknown".into(),
        kernel_version: "unknown".into(),
        architecture: "unknown".into(),
        platform_triple: "unknown".into(),
        hostname: "unknown".into(),
        product_name: None,
        build_id: None,
        systemd_version: None,
        boot_time: None,
        uptime_secs: 0,
        timezone: None,
        is_wsl: false,
        virtualization: None,
    }
}

fn default_network() -> NetworkSnapshot {
    NetworkSnapshot {
        hostname: "unknown".into(),
        interfaces: Vec::new(),
        routes: Vec::new(),
        dns_resolvers: Vec::new(),
        default_gateway: None,
        listening_ports: Vec::new(),
    }
}

fn default_nix() -> NixSnapshot {
    NixSnapshot {
        nix_version: "unknown".into(),
        store_size_bytes: 0,
        store_path_count: 0,
        gc_roots_count: 0,
        last_rebuild_timestamp: None,
        current_system_path: None,
        substituters: Vec::new(),
        system_generations: 0,
        channels: Vec::new(),
        trusted_users: Vec::new(),
        max_jobs: None,
        sandbox_enabled: false,
    }
}

fn default_health() -> HealthMetrics {
    HealthMetrics {
        load_average_1m: 0.0,
        load_average_5m: 0.0,
        load_average_15m: 0.0,
        memory_usage_percent: 0.0,
        swap_usage_percent: 0.0,
        cpu_usage_percent: 0.0,
        disk_usage: Vec::new(),
        open_file_descriptors: None,
        max_file_descriptors: None,
    }
}

fn default_security() -> SecuritySnapshot {
    SecuritySnapshot {
        ssh_keys_deployed: Vec::new(),
        tls_certificates: Vec::new(),
        firewall_active: false,
        firewall_rules_count: 0,
        firewall_backend: None,
        sshd_running: false,
        root_login_allowed: true,
        password_auth_enabled: true,
    }
}

fn default_processes() -> ProcessSnapshot {
    ProcessSnapshot {
        total_processes: 0,
        running_processes: 0,
        zombie_processes: 0,
        top_cpu: Vec::new(),
        top_memory: Vec::new(),
    }
}
