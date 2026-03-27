mod api;
mod client;
mod commands;
mod config;
mod direnv_setup;
mod domain;
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

    /// Validate a NixOS AMI before Packer snapshots it
    AmiTest(commands::ami_test::AmiTestArgs),

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
        },
        Commands::Server { command } => match command {
            ServerCommands::Bootstrap { config } => commands::server::run_bootstrap(&config),
            ServerCommands::Status => commands::server::run_status(),
        },
        Commands::AmiTest(args) => commands::ami_test::run(args),
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
