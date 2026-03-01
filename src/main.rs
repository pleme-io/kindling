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
