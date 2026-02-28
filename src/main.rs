mod commands;
mod config;
mod direnv_setup;
mod nix;
mod platform;
mod tend_setup;
mod tools;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "kindling", version, about = "Cross-platform unattended Nix installer")]
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

    /// Bootstrap a bare machine: nix → direnv → tend → workspace repos
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
        } => commands::bootstrap::run(skip_direnv, skip_tend, org, no_confirm),
    }
}
