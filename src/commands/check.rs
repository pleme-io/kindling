use colored::Colorize;

use crate::nix;
use crate::platform;

pub fn run() -> anyhow::Result<()> {
    let status = nix::detect();
    let platform = platform::detect()?;

    println!("{}", "kindling check".bold());
    println!(
        "  platform: {} {} {}",
        format!("{:?}", platform.os).to_lowercase(),
        format!("{:?}", platform.arch).to_lowercase(),
        if platform.is_wsl { "(WSL)" } else { "" }
    );

    if status.installed {
        println!("  nix:      {}", "installed".green());
        if let Some(ver) = &status.version {
            println!("  version:  {}", ver);
        }
        if let Some(path) = &status.nix_path {
            println!("  path:     {}", path.display());
        }
        std::process::exit(0);
    } else {
        println!("  nix:      {}", "not installed".red());
        println!("  hint:     run `kindling install` to install Nix");
        std::process::exit(1);
    }
}
