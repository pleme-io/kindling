mod api;
mod client;
mod commands;
mod config;
mod direnv_setup;
mod domain;
mod harden;
#[cfg(feature = "grpc")]
mod grpc;
mod nix;
mod node_identity;
mod platform;
mod server;
mod telemetry;
mod tend_setup;
mod tools;
mod vpn;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "kindling", version, about = "Cross-platform unattended Nix installer and daemon")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Download and run the Nix installer
    Install {
        /// Installer backend to use
        #[arg(long, default_value = "upstream")]
        backend: String,

        /// Skip confirmation prompts
        #[arg(long)]
        no_confirm: bool,
    },

    /// Uninstall Nix using the install receipt
    Uninstall,

    /// Check Nix installation status
    Check,

    /// Ensure Nix is installed (direnv integration point)
    Ensure {
        /// Required Nix version (semver range, e.g. ">=2.24")
        #[arg(long)]
        version: Option<String>,
    },

    /// Bootstrap a bare machine: nix → direnv → tend → profile → apply
    Bootstrap {
        /// Skip direnv setup
        #[arg(long)]
        skip_direnv: bool,

        /// Skip tend setup
        #[arg(long)]
        skip_tend: bool,

        /// GitHub org for tend workspace config
        #[arg(long)]
        org: Option<String>,

        /// Skip confirmation prompts
        #[arg(long)]
        no_confirm: bool,

        /// Machine profile from kindling-profiles
        #[arg(long)]
        profile: Option<String>,

        /// Hostname for this machine
        #[arg(long)]
        hostname: Option<String>,

        /// Username
        #[arg(long)]
        user: Option<String>,

        /// Path to age key file for SOPS secrets
        #[arg(long)]
        age_key_file: Option<String>,

        /// Path to existing node.yaml (skip interactive setup)
        #[arg(long)]
        node_config: Option<String>,
    },

    /// Run the kindling daemon (REST + GraphQL + telemetry)
    Daemon {
        /// HTTP listen address (overrides config)
        #[arg(long)]
        http_addr: Option<String>,

        /// gRPC listen address (overrides config, requires grpc feature)
        #[arg(long)]
        grpc_addr: Option<String>,

        /// Log level (overrides config)
        #[arg(long)]
        log_level: Option<String>,

        /// Path to config file (default: ~/.config/kindling/config.toml)
        #[arg(long)]
        config: Option<String>,
    },

    /// Manage machine profiles
    Profile {
        #[command(subcommand)]
        command: ProfileCommands,
    },

    /// Read node.yaml, regenerate Nix config, and rebuild the system
    Apply {
        /// Show what would change without applying
        #[arg(long)]
        diff: bool,
    },

    /// Fleet management — deploy to remote nodes
    Fleet {
        #[command(subcommand)]
        command: FleetCommands,
    },

    /// Generate a runtime report for this node
    Report {
        /// Output format (table or json)
        #[arg(long, default_value = "table")]
        format: String,

        /// Push report to fleet controller
        #[arg(long)]
        push: bool,

        /// Fleet controller URL (used with --push)
        #[arg(long)]
        controller_url: Option<String>,

        /// Force live collection (bypass cache), write result to disk store
        #[arg(long)]
        fresh: bool,

        /// Read from persisted file on disk (no daemon needed, no collection)
        #[arg(long)]
        cached: bool,
    },

    /// Server mode — K3s cluster bootstrap and monitoring
    Server {
        #[command(subcommand)]
        command: ServerCommands,
    },

    /// VPN key management and validation
    Vpn {
        #[command(subcommand)]
        command: VpnCommands,
    },

    /// Deterministic k3s PKI: mint cluster CA roots + admin cert, or
    /// seed them from sops-nix into /var/lib/rancher/k3s/server/tls/
    /// before k3s.service starts (kasou-VM counterpart to the EC2
    /// userdata path in `kindling init`).
    Pki {
        #[command(subcommand)]
        command: PkiCommands,
    },

    /// Apply one or more hardening profiles to this host
    Harden(commands::harden::HardenArgs),

    /// Build a NixOS AMI: nixos-rebuild + clean K3s state + validate + cleanup
    AmiBuild(commands::ami_build::AmiBuildArgs),

    /// Validate a NixOS AMI before Packer snapshots it
    AmiTest(commands::ami_test::AmiTestArgs),

    /// Validate full boot orchestration (VPN + K3s + kubectl) on a test instance
    AmiIntegrationTest(commands::ami_integration_test::AmiIntegrationTestArgs),

    /// Read cloud userdata, extract cluster config, and bootstrap the node
    Init(commands::init::InitArgs),

    /// Query a kindling daemon's REST API
    Query {
        /// Target node name (from config nodes map; defaults to localhost)
        #[arg(long, global = true)]
        node: Option<String>,

        /// Output format (table or json)
        #[arg(long, global = true, default_value = "table")]
        format: String,

        #[command(subcommand)]
        command: commands::query::QueryCommands,
    },
}

#[derive(Subcommand)]
enum ProfileCommands {
    /// List available profiles
    List,
    /// Show details for a specific profile
    Show {
        /// Profile name
        name: String,
    },
}

#[derive(Subcommand)]
enum ServerCommands {
    /// Run the server bootstrap sequence (config → identity → rebuild → K3s → FluxCD)
    Bootstrap {
        /// Path to cluster-config.json (default: /etc/pangea/cluster-config.json)
        #[arg(long, default_value = "/etc/pangea/cluster-config.json")]
        config: String,
    },
    /// Show current server bootstrap status and health
    Status,
}

#[derive(Subcommand)]
enum VpnCommands {
    /// Generate WireGuard keys for a new VPN link
    Keygen {
        /// Link name (e.g., ryn-k3s)
        #[arg(long)]
        link: String,

        /// Side A node name (initiator, typically macOS host)
        #[arg(long)]
        side_a: String,

        /// Side B node name (responder, typically VM/server)
        #[arg(long)]
        side_b: String,

        /// VPN profile (k8s-control-plane, k8s-full, site-to-site, mesh)
        #[arg(long, default_value = "k8s-control-plane")]
        profile: String,

        /// Output format (text or json)
        #[arg(long, default_value = "text")]
        output: String,
    },
    /// List available VPN profiles and their firewall configurations
    Profiles,
    /// Validate VPN configuration from a cluster-config.json
    Validate {
        /// Path to cluster-config.json
        #[arg(long, default_value = "/etc/pangea/cluster-config.json")]
        config: String,

        /// Also check key files exist on disk with correct permissions
        #[arg(long)]
        check_files: bool,
    },
    /// Generate WireGuard key material for a portao JIT VPN concentrator —
    /// hub keypair, per-spoke keypairs + PSKs, hub-side peers.json,
    /// SSM put-parameter commands, and SOPS path hints. Pure Rust, no
    /// shell-out to `wg`.
    PortaoBootstrap {
        /// Logical environment name (akeyless-dev, akeyless-saas, …).
        /// Used as the link name in vpn-links.nix and the SSM scope.
        #[arg(long)]
        env_name: String,

        /// First three octets of the WG /24 (e.g. `10.100.30`). Hub
        /// goes at .254, spokes at .1, .2, .3, …
        #[arg(long, default_value = "10.100.30")]
        subnet_base: String,

        /// Spoke node names (one per workstation that should reach
        /// the env). Repeatable: `--spoke ryn --spoke cid --spoke rio`.
        #[arg(long = "spoke", value_name = "NODE")]
        spokes: Vec<String>,

        /// Optional spoke-side WG interface suffix override (default
        /// is the env's last hyphen-segment, truncated to 3 chars).
        #[arg(long)]
        interface_suffix: Option<String>,

        /// AWS region for the SSM put-parameter command hints.
        #[arg(long, default_value = "us-east-1")]
        region: String,

        /// AWS profile for the SSM put-parameter command hints.
        #[arg(long, default_value = "akeyless-development")]
        aws_profile: String,

        /// Output format: text (default), yaml, or json.
        #[arg(long, default_value = "text")]
        output: String,
    },
    /// Bootstrap an entire portao fleet from a single YAML manifest.
    /// One invocation generates key material for every portao in the
    /// manifest (multi-account, multi-region) and emits one consolidated
    /// output the operator merges into SOPS once.
    PortaoFleet {
        /// Path to the fleet manifest YAML (see
        /// `kindling/docs/portao-fleet.example.yaml`).
        #[arg(long)]
        config: String,

        /// Output format: text (default), yaml, or json.
        #[arg(long, default_value = "text")]
        output: String,
    },
}

#[derive(Subcommand)]
enum PkiCommands {
    /// Generate the full k3s PKI bag (server-CA, client-CA,
    /// request-header-CA, service.key, admin client cert/key) for a
    /// cluster. Emits a sops-mergeable YAML block on stdout for the
    /// operator to paste into nix/secrets.yaml under
    /// `clusters.<name>.tls.*`. Runs ONCE per cluster ever.
    Mint {
        /// Cluster name (becomes the sops path prefix + the CN suffix).
        #[arg(long)]
        cluster: String,

        /// Common Name for the admin client cert. Default is the k3s
        /// convention `system:admin`; only change if you know why.
        #[arg(long, default_value = "system:admin")]
        admin_cn: String,

        /// Validity period in days. Default ~10 years matches k3s'
        /// own self-generated CA lifetime.
        #[arg(long, default_value_t = 3650)]
        validity_days: u32,
    },
    /// Read-first, idempotent provisioning of a cluster's TLS bag in
    /// an existing sops-encrypted file. Generates the 9-PEM bag if
    /// the cluster has none; no-op if everything is already present;
    /// `--rotate` forces regeneration (invalidates kubeconfigs).
    /// Atomic re-encrypt with backup-and-recover semantics.
    Provision {
        /// Cluster name (the sops path prefix under `clusters/<name>/tls/`).
        #[arg(long)]
        cluster: String,

        /// Path to the sops-encrypted secrets file (typically
        /// `~/code/github/pleme-io/nix/secrets.yaml`).
        #[arg(long)]
        secrets_file: std::path::PathBuf,

        /// Common Name for the admin client cert. Default
        /// `system:admin` matches k3s' convention.
        #[arg(long, default_value = "system:admin")]
        admin_cn: String,

        /// Validity period in days. Default ~10 years.
        #[arg(long, default_value_t = 3650)]
        validity_days: u32,

        /// Force regeneration even if the bag is already complete.
        /// Use only when rotating compromised material — every
        /// dependent kubeconfig becomes invalid.
        #[arg(long)]
        rotate: bool,
    },
    /// Copy decrypted PKI files into `/var/lib/rancher/k3s/server/tls/`.
    /// Run as a `Before=k3s.service` oneshot. Cleanly skips if no
    /// matching sops-nix secrets are present (k3s falls back to
    /// auto-generation, matching pre-fix behaviour).
    Seed {
        /// Source backend. Currently only `sops-nix` is supported —
        /// reads from `/run/secrets/clusters/<cluster>/tls/`.
        #[arg(long, default_value = "sops-nix")]
        source: String,

        /// Cluster name (the sops path prefix used by `mint`).
        #[arg(long)]
        cluster: String,
    },
}

#[derive(Subcommand)]
enum FleetCommands {
    /// Check connectivity to all fleet peers
    Status,
    /// Deploy configuration to a remote node
    Apply {
        /// Node name (must be in fleet.peers)
        node: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Install {
            backend,
            no_confirm,
        } => {
            let backend = backend.parse()?;
            commands::install::run(backend, no_confirm)
        }
        Commands::Uninstall => commands::uninstall::run(),
        Commands::Check => commands::check::run(),
        Commands::Ensure { version } => {
            let version_req = version
                .map(|v| v.parse::<semver::VersionReq>())
                .transpose()?;
            commands::ensure::run(version_req)
        }
        Commands::Bootstrap {
            skip_direnv,
            skip_tend,
            org,
            no_confirm,
            profile,
            hostname,
            user,
            age_key_file,
            node_config,
        } => commands::bootstrap::run(
            skip_direnv,
            skip_tend,
            org,
            no_confirm,
            profile,
            hostname,
            user,
            age_key_file,
            node_config,
        ),
        Commands::Daemon {
            http_addr,
            grpc_addr,
            log_level,
            config,
        } => commands::daemon::run(http_addr, grpc_addr, log_level, config),
        Commands::Profile { command } => match command {
            ProfileCommands::List => commands::profile::list(),
            ProfileCommands::Show { name } => commands::profile::show(&name),
        },
        Commands::Apply { diff } => commands::apply::run(diff),
        Commands::Fleet { command } => match command {
            FleetCommands::Status => commands::fleet::status(),
            FleetCommands::Apply { node } => commands::fleet::apply(&node),
        },
        Commands::Vpn { command } => match command {
            VpnCommands::Profiles => commands::vpn::run_profiles(),
            VpnCommands::Keygen {
                link,
                side_a,
                side_b,
                profile,
                output,
            } => commands::vpn::run_keygen(&link, &side_a, &side_b, &profile, &output),
            VpnCommands::Validate {
                config,
                check_files,
            } => commands::vpn::run_validate(&config, check_files),
            VpnCommands::PortaoBootstrap {
                env_name,
                subnet_base,
                spokes,
                interface_suffix,
                region,
                aws_profile,
                output,
            } => commands::vpn::run_portao_bootstrap(
                &env_name,
                &subnet_base,
                &spokes,
                interface_suffix.as_deref(),
                &region,
                &aws_profile,
                &output,
            ),
            VpnCommands::PortaoFleet { config, output } => {
                commands::vpn::run_portao_fleet(&config, &output)
            }
        },
        Commands::Server { command } => match command {
            ServerCommands::Bootstrap { config } => commands::server::run_bootstrap(&config),
            ServerCommands::Status => commands::server::run_status(),
        },
        Commands::Pki { command } => match command {
            PkiCommands::Mint {
                cluster,
                admin_cn,
                validity_days,
            } => commands::pki::run_mint(&cluster, &admin_cn, validity_days),
            PkiCommands::Provision {
                cluster,
                secrets_file,
                admin_cn,
                validity_days,
                rotate,
            } => commands::pki::run_provision(
                &cluster,
                &secrets_file,
                &admin_cn,
                validity_days,
                rotate,
            ),
            PkiCommands::Seed { source, cluster } => {
                commands::pki::run_seed(&source, &cluster)
            }
        },
        Commands::Harden(args) => commands::harden::run_cmd(args),
        Commands::AmiBuild(args) => commands::ami_build::run(args),
        Commands::AmiTest(args) => commands::ami_test::run(args),
        Commands::AmiIntegrationTest(args) => commands::ami_integration_test::run(args),
        Commands::Init(args) => commands::init::run(args),
        Commands::Report {
            format,
            push,
            controller_url,
            fresh,
            cached,
        } => commands::report::run(&format, push, controller_url.as_deref(), fresh, cached),
        Commands::Query {
            node,
            format,
            command,
        } => commands::query::run(node.as_deref(), &format, &command),
    }
}
