//! `kindling report` — generate and display a runtime report for this node.

use std::path::PathBuf;

use anyhow::Result;
use colored::Colorize;

use crate::client::KindlingClient;
use crate::config;
use crate::domain::node_report::StoredReport;
use crate::domain::report_collector::ReportCollector;
use crate::domain::report_store::ReportStore;

pub fn run(
    format: &str,
    push: bool,
    controller_url: Option<&str>,
    fresh: bool,
    cached: bool,
) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async { run_async(format, push, controller_url, fresh, cached).await })
}

async fn run_async(
    format: &str,
    push: bool,
    controller_url: Option<&str>,
    fresh: bool,
    cached: bool,
) -> Result<()> {
    let cfg = config::load()?;
    let report_config = cfg
        .daemon
        .as_ref()
        .map(|d| d.report.clone())
        .unwrap_or_default();
    let store = ReportStore::new(PathBuf::from(&report_config.cache_file));

    let stored = if cached {
        // --cached: read from persisted file, no collection
        store.read().await?
    } else if fresh {
        // --fresh: force live collection, write to store
        let report = ReportCollector::collect().await?;
        let stored = StoredReport::new(report);
        store.write(&stored).await?;
        stored
    } else {
        // Default: try daemon HTTP cache first, fall back to fresh collection
        match try_daemon_cache(&cfg).await {
            Ok(stored) => stored,
            Err(_) => {
                let report = ReportCollector::collect().await?;
                let stored = StoredReport::new(report);
                store.write(&stored).await?;
                stored
            }
        }
    };

    match format {
        "json" => {
            let json = serde_json::to_string_pretty(&stored)?;
            println!("{}", json);
        }
        _ => {
            print_table(&stored.report);
            println!(
                "  {} {}  {} {}",
                "Checksum:".dimmed(),
                &stored.checksum[..std::cmp::min(stored.checksum.len(), 24)],
                "Age:".dimmed(),
                format!("{}s", stored.age_secs())
            );
        }
    }

    if push {
        let url = controller_url.unwrap_or("http://localhost:9100");
        let endpoint = format!(
            "{}/api/v1/fleet/nodes/{}/report",
            url, stored.report.hostname
        );

        println!("\n{} to {}...", "Pushing report".cyan(), endpoint);

        let client = reqwest::Client::new();
        let resp = client.post(&endpoint).json(&stored).send().await?;

        if resp.status().is_success() {
            println!("{}", "Report pushed successfully".green());
        } else {
            println!(
                "{}: {} {}",
                "Push failed".red(),
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
    }

    Ok(())
}

/// Try to fetch the cached report from a running daemon.
async fn try_daemon_cache(cfg: &config::Config) -> Result<StoredReport> {
    let client = KindlingClient::from_node(None, &cfg.nodes)?;
    client.report().await
}

fn fmt_bytes(bytes: u64) -> String {
    if bytes >= 1_099_511_627_776 {
        format!("{:.1} TB", bytes as f64 / 1_099_511_627_776.0)
    } else if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn fmt_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    if days > 0 {
        format!("{}d {}h {}m", days, hours, mins)
    } else if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else {
        format!("{}m", mins)
    }
}

fn print_table(report: &crate::domain::node_report::NodeReport) {
    println!("{}", "═══ Node Report ═══".cyan().bold());
    println!("  Hostname:      {}", report.hostname.bold());
    println!("  Daemon:        {}", report.daemon_version);
    println!();

    // ── OS ──
    println!("{}", "── OS ──".yellow());
    println!("  Distribution:    {}", report.os.distribution);
    println!("  Version:         {}", report.os.version);
    println!("  Kernel:          {}", report.os.kernel_version);
    println!("  Architecture:    {}", report.os.architecture);
    println!("  Platform:        {}", report.os.platform_triple);
    if let Some(ref name) = report.os.product_name {
        println!("  Product:         {}", name);
    }
    if let Some(ref tz) = report.os.timezone {
        println!("  Timezone:        {}", tz);
    }
    println!("  Uptime:          {}", fmt_uptime(report.os.uptime_secs));
    if let Some(ref boot) = report.os.boot_time {
        println!("  Boot Time:       {}", boot.to_rfc3339());
    }
    if let Some(ref sd) = report.os.systemd_version {
        println!("  Systemd:         {}", sd);
    }
    if let Some(ref virt) = report.os.virtualization {
        println!("  Virtualization:  {}", virt);
    }
    if report.os.is_wsl {
        println!("  WSL:             {}", "yes".yellow());
    }

    // ── Hardware ──
    println!();
    println!("{}", "── Hardware ──".yellow());
    println!("  CPU Model:       {}", report.hardware.cpu_model);
    println!("  CPU Vendor:      {}", report.hardware.cpu_vendor);
    println!("  CPU Arch:        {}", report.hardware.cpu_architecture);
    println!(
        "  Cores/Threads:   {}/{}",
        report.hardware.cpu_cores, report.hardware.cpu_threads
    );
    if let Some(freq) = report.hardware.cpu_frequency_mhz {
        println!("  CPU Frequency:   {} MHz", freq);
    }
    if let Some(cache) = report.hardware.cpu_cache_bytes {
        println!("  CPU Cache:       {}", fmt_bytes(cache));
    }
    println!(
        "  RAM:             {} / {}",
        fmt_bytes(report.hardware.ram_available_bytes),
        fmt_bytes(report.hardware.ram_total_bytes)
    );
    if report.hardware.swap_total_bytes > 0 {
        println!(
            "  Swap:            {} / {}",
            fmt_bytes(report.hardware.swap_used_bytes),
            fmt_bytes(report.hardware.swap_total_bytes)
        );
    }

    if !report.hardware.disks.is_empty() {
        println!();
        println!("  {}", "Disks:".dimmed());
        for d in &report.hardware.disks {
            let pct = if d.total_bytes > 0 {
                (d.used_bytes as f64 / d.total_bytes as f64) * 100.0
            } else {
                0.0
            };
            let pct_str = if pct > 90.0 {
                format!("{:.0}%", pct).red().to_string()
            } else if pct > 75.0 {
                format!("{:.0}%", pct).yellow().to_string()
            } else {
                format!("{:.0}%", pct)
            };
            println!(
                "    {} → {} ({}) {} used of {}",
                d.device,
                d.mount_point,
                d.filesystem,
                pct_str,
                fmt_bytes(d.total_bytes)
            );
        }
    }

    if !report.hardware.gpus.is_empty() {
        println!();
        println!("  {}", "GPUs:".dimmed());
        for gpu in &report.hardware.gpus {
            let mut info = format!("    {} ({})", gpu.name, gpu.vendor);
            if let Some(vram) = gpu.vram_bytes {
                info.push_str(&format!(" — {}", fmt_bytes(vram)));
            }
            if let Some(ref metal) = gpu.metal_support {
                info.push_str(&format!(" [Metal: {}]", metal));
            }
            println!("{}", info);
        }
    }

    if !report.hardware.temperatures.is_empty() {
        println!();
        println!("  {}", "Temperatures:".dimmed());
        for t in &report.hardware.temperatures {
            let temp_str = if t.celsius > 85.0 {
                format!("{:.0}°C", t.celsius).red().to_string()
            } else if t.celsius > 70.0 {
                format!("{:.0}°C", t.celsius).yellow().to_string()
            } else {
                format!("{:.0}°C", t.celsius)
            };
            println!("    {}: {}", t.label, temp_str);
        }
    }

    if let Some(ref pwr) = report.hardware.power {
        println!();
        println!("  {}", "Power:".dimmed());
        let src = if pwr.on_battery { "Battery" } else { "AC Power" };
        print!("    Source: {}", src);
        if let Some(pct) = pwr.charge_percent {
            let charge = if pct < 20.0 {
                format!(" ({:.0}%)", pct).red().to_string()
            } else {
                format!(" ({:.0}%)", pct)
            };
            print!("{}", charge);
        }
        if pwr.charging {
            print!(" {}", "[Charging]".green());
        }
        println!();
        if let Some(mins) = pwr.time_remaining_minutes {
            println!("    Remaining: {}h {}m", mins / 60, mins % 60);
        }
    }

    // ── Health ──
    println!();
    println!("{}", "── Health ──".yellow());
    println!(
        "  Load Average:    {:.2} / {:.2} / {:.2}",
        report.health.load_average_1m,
        report.health.load_average_5m,
        report.health.load_average_15m
    );
    let cpu_str = if report.health.cpu_usage_percent > 90.0 {
        format!("{:.1}%", report.health.cpu_usage_percent).red().to_string()
    } else if report.health.cpu_usage_percent > 70.0 {
        format!("{:.1}%", report.health.cpu_usage_percent).yellow().to_string()
    } else {
        format!("{:.1}%", report.health.cpu_usage_percent)
    };
    println!("  CPU Usage:       {}", cpu_str);
    let mem_str = if report.health.memory_usage_percent > 90.0 {
        format!("{:.1}%", report.health.memory_usage_percent).red().to_string()
    } else if report.health.memory_usage_percent > 75.0 {
        format!("{:.1}%", report.health.memory_usage_percent).yellow().to_string()
    } else {
        format!("{:.1}%", report.health.memory_usage_percent)
    };
    println!("  Memory Usage:    {}", mem_str);
    if report.health.swap_usage_percent > 0.0 {
        println!("  Swap Usage:      {:.1}%", report.health.swap_usage_percent);
    }
    if let (Some(open), Some(max)) = (report.health.open_file_descriptors, report.health.max_file_descriptors) {
        println!("  File Descriptors: {} / {}", open, max);
    }
    for du in &report.health.disk_usage {
        let du_str = if du.usage_percent > 90.0 {
            format!("{:.1}%", du.usage_percent).red().to_string()
        } else if du.usage_percent > 75.0 {
            format!("{:.1}%", du.usage_percent).yellow().to_string()
        } else {
            format!("{:.1}%", du.usage_percent)
        };
        println!("  Disk {}:  {}", du.mount_point, du_str);
    }

    // ── Processes ──
    println!();
    println!("{}", "── Processes ──".yellow());
    println!(
        "  Total: {}  Running: {}  Zombie: {}",
        report.processes.total_processes,
        report.processes.running_processes,
        if report.processes.zombie_processes > 0 {
            report.processes.zombie_processes.to_string().red().to_string()
        } else {
            report.processes.zombie_processes.to_string()
        }
    );
    if !report.processes.top_cpu.is_empty() {
        println!("  {}", "Top CPU:".dimmed());
        for p in &report.processes.top_cpu {
            println!(
                "    {:>6} {:<20} CPU: {:>5.1}%  MEM: {:>5.1}%",
                p.pid, p.name, p.cpu_percent, p.memory_percent
            );
        }
    }
    if !report.processes.top_memory.is_empty() {
        println!("  {}", "Top Memory:".dimmed());
        for p in &report.processes.top_memory {
            println!(
                "    {:>6} {:<20} MEM: {:>5.1}%  CPU: {:>5.1}%",
                p.pid, p.name, p.memory_percent, p.cpu_percent
            );
        }
    }

    // ── Network ──
    println!();
    println!("{}", "── Network ──".yellow());
    if let Some(ref gw) = report.network.default_gateway {
        println!("  Default Gateway: {}", gw);
    }
    if !report.network.dns_resolvers.is_empty() {
        println!("  DNS Resolvers:   {}", report.network.dns_resolvers.join(", "));
    }
    println!();
    println!("  {}", "Interfaces:".dimmed());
    for iface in &report.network.interfaces {
        if iface.addresses.is_empty() && iface.state == "down" {
            continue;
        }
        let mut info = format!("    {} ({})", iface.name.bold(), iface.state);
        if let Some(ref itype) = iface.interface_type {
            info.push_str(&format!(" [{}]", itype));
        }
        println!("{}", info);
        if !iface.addresses.is_empty() {
            println!("      Addresses: {}", iface.addresses.join(", "));
        }
        if let Some(ref mac) = iface.mac {
            print!("      MAC: {}", mac);
        }
        if let Some(mtu) = iface.mtu {
            print!("  MTU: {}", mtu);
        }
        if let Some(speed) = iface.speed_mbps {
            print!("  Speed: {} Mbps", speed);
        }
        if iface.mac.is_some() || iface.mtu.is_some() || iface.speed_mbps.is_some() {
            println!();
        }
        if iface.rx_bytes > 0 || iface.tx_bytes > 0 {
            println!(
                "      Traffic: RX {} / TX {}",
                fmt_bytes(iface.rx_bytes),
                fmt_bytes(iface.tx_bytes)
            );
        }
    }

    if !report.network.listening_ports.is_empty() {
        println!();
        println!("  {}", "Listening Ports:".dimmed());
        for lp in &report.network.listening_ports {
            let addr = lp.address.as_deref().unwrap_or("*");
            let proc = lp.process.as_deref().unwrap_or("-");
            println!(
                "    {}:{} ({}) — {}",
                addr, lp.port, lp.protocol, proc
            );
        }
    }

    // ── Nix ──
    println!();
    println!("{}", "── Nix ──".yellow());
    println!("  Version:         {}", report.nix.nix_version);
    println!(
        "  Store Size:      {}",
        fmt_bytes(report.nix.store_size_bytes)
    );
    println!("  Store Paths:     {}", report.nix.store_path_count);
    println!("  GC Roots:        {}", report.nix.gc_roots_count);
    println!("  Generations:     {}", report.nix.system_generations);
    println!(
        "  Sandbox:         {}",
        if report.nix.sandbox_enabled {
            "enabled".green().to_string()
        } else {
            "disabled".yellow().to_string()
        }
    );
    if let Some(ref jobs) = report.nix.max_jobs {
        println!("  Max Jobs:        {}", jobs);
    }
    if !report.nix.substituters.is_empty() {
        println!("  Substituters:    {}", report.nix.substituters.join(", "));
    }
    if !report.nix.trusted_users.is_empty() {
        println!("  Trusted Users:   {}", report.nix.trusted_users.join(", "));
    }
    if !report.nix.channels.is_empty() {
        println!("  Channels:        {}", report.nix.channels.join(", "));
    }
    if let Some(ref path) = report.nix.current_system_path {
        println!("  System Path:     {}", path);
    }
    if let Some(ref ts) = report.nix.last_rebuild_timestamp {
        println!("  Last Rebuild:    {}", ts.to_rfc3339());
    }

    // ── Kubernetes ──
    if let Some(k8s) = &report.kubernetes {
        println!();
        println!("{}", "── Kubernetes ──".yellow());
        if let Some(v) = &k8s.k3s_version {
            println!("  K3s Version:     {}", v);
        }
        println!(
            "  Node Ready:      {}",
            if k8s.node_ready {
                "yes".green().to_string()
            } else {
                "no".red().to_string()
            }
        );
        println!("  Pods:            {}", k8s.pod_count);
        println!("  Namespaces:      {}", k8s.namespace_count);

        if k8s.cpu_requests_millis > 0 || k8s.memory_requests_bytes > 0 {
            println!(
                "  CPU Requests:    {}m / Limits: {}m",
                k8s.cpu_requests_millis, k8s.cpu_limits_millis
            );
            println!(
                "  Mem Requests:    {} / Limits: {}",
                fmt_bytes(k8s.memory_requests_bytes),
                fmt_bytes(k8s.memory_limits_bytes)
            );
        }

        if let Some(flux) = k8s.flux_installed {
            println!(
                "  FluxCD:          {}",
                if flux {
                    "installed".green().to_string()
                } else {
                    "not installed".dimmed().to_string()
                }
            );
        }
        if let Some(hr) = k8s.helm_releases {
            println!("  Helm Releases:   {}", hr);
        }

        if !k8s.conditions.is_empty() {
            println!("  {}", "Conditions:".dimmed());
            for c in &k8s.conditions {
                let status_str = if c.status == "True" {
                    c.status.green().to_string()
                } else {
                    c.status.red().to_string()
                };
                print!("    {}: {}", c.condition_type, status_str);
                if let Some(ref msg) = c.message {
                    if !msg.is_empty() {
                        print!(" — {}", msg);
                    }
                }
                println!();
            }
        }
    }

    // ── Security ──
    println!();
    println!("{}", "── Security ──".yellow());
    println!(
        "  Firewall:        {}",
        if report.security.firewall_active {
            "active".green().to_string()
        } else {
            "inactive".red().to_string()
        }
    );
    if let Some(ref backend) = report.security.firewall_backend {
        println!("  FW Backend:      {}", backend);
    }
    if report.security.firewall_rules_count > 0 {
        println!("  FW Rules:        {}", report.security.firewall_rules_count);
    }
    println!(
        "  SSHD Running:    {}",
        if report.security.sshd_running {
            "yes".to_string()
        } else {
            "no".dimmed().to_string()
        }
    );
    println!(
        "  Root Login:      {}",
        if report.security.root_login_allowed {
            "allowed".red().to_string()
        } else {
            "prohibited".green().to_string()
        }
    );
    println!(
        "  Password Auth:   {}",
        if report.security.password_auth_enabled {
            "enabled".yellow().to_string()
        } else {
            "disabled".green().to_string()
        }
    );
    println!("  SSH Keys:        {}", report.security.ssh_keys_deployed.len());
    if !report.security.tls_certificates.is_empty() {
        println!("  {}", "TLS Certificates:".dimmed());
        for cert in &report.security.tls_certificates {
            let mut line = format!("    {}", cert.domain);
            if let Some(days) = cert.days_until_expiry {
                let days_str = if days < 14 {
                    format!(" ({} days)", days).red().to_string()
                } else if days < 30 {
                    format!(" ({} days)", days).yellow().to_string()
                } else {
                    format!(" ({} days)", days)
                };
                line.push_str(&days_str);
            }
            if let Some(ref issuer) = cert.issuer {
                line.push_str(&format!(" — {}", issuer));
            }
            println!("{}", line);
        }
    }

    println!();
    println!(
        "{} {}",
        "Report generated at:".dimmed(),
        report.timestamp.to_rfc3339()
    );
}
