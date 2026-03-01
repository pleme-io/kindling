//! `kindling query` — query a kindling daemon via its REST API.

use anyhow::Result;
use clap::Subcommand;

use crate::client::KindlingClient;
use crate::config;

#[derive(Subcommand)]
pub enum QueryCommands {
    /// Daemon health check
    Health,
    /// Nix installation status
    Status,
    /// Platform information
    Platform,
    /// Nix store information
    Store,
    /// Nix configuration
    NixConfig,
    /// Garbage collection status
    GcStatus,
    /// Trigger garbage collection
    GcRun,
    /// Optimise the Nix store
    Optimise,
    /// Binary cache reachability
    Caches,
    /// Node identity (from node.yaml)
    Identity,
    /// Cached runtime report
    Report,
    /// Force-refresh the runtime report
    RefreshReport,
}

pub fn run(node: Option<&str>, format: &str, command: &QueryCommands) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async(node, format, command))
}

async fn run_async(node: Option<&str>, format: &str, command: &QueryCommands) -> Result<()> {
    let cfg = config::load()?;
    let client = KindlingClient::from_node(node, &cfg.nodes)?;

    match command {
        QueryCommands::Health => {
            let data = client.health().await?;
            print_output(format, &data)
        }
        QueryCommands::Status => {
            let data = client.status().await?;
            print_output(format, &data)
        }
        QueryCommands::Platform => {
            let data = client.platform().await?;
            print_output(format, &data)
        }
        QueryCommands::Store => {
            let data = client.store().await?;
            print_output(format, &data)
        }
        QueryCommands::NixConfig => {
            let data = client.nix_config().await?;
            print_output(format, &data)
        }
        QueryCommands::GcStatus => {
            let data = client.gc_status().await?;
            print_output(format, &data)
        }
        QueryCommands::GcRun => {
            let data = client.gc_run().await?;
            print_output(format, &data)
        }
        QueryCommands::Optimise => {
            let data = client.optimise().await?;
            print_output(format, &data)
        }
        QueryCommands::Caches => {
            let data = client.caches().await?;
            print_output(format, &data)
        }
        QueryCommands::Identity => {
            let data = client.identity().await?;
            print_output(format, &data)
        }
        QueryCommands::Report => {
            let data = client.report().await?;
            print_output(format, &data)
        }
        QueryCommands::RefreshReport => {
            let data = client.refresh_report().await?;
            print_output(format, &data)
        }
    }
}

fn print_output<T: serde::Serialize>(format: &str, data: &T) -> Result<()> {
    match format {
        "json" => {
            let json = serde_json::to_string_pretty(data)?;
            println!("{}", json);
        }
        _ => {
            // Table format: recursive key-value from serde_json::Value
            let value = serde_json::to_value(data)?;
            print_value(&value, 0);
        }
    }
    Ok(())
}

fn print_value(value: &serde_json::Value, indent: usize) {
    let pad = "  ".repeat(indent);
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                match val {
                    serde_json::Value::Object(_) => {
                        println!("{}{}:", pad, key);
                        print_value(val, indent + 1);
                    }
                    serde_json::Value::Array(arr) => {
                        if arr.is_empty() {
                            println!("{}{}: []", pad, key);
                        } else if arr.iter().all(|v| !v.is_object() && !v.is_array()) {
                            // Simple array: print inline
                            let items: Vec<String> =
                                arr.iter().map(|v| format_scalar(v)).collect();
                            println!("{}{}: {}", pad, key, items.join(", "));
                        } else {
                            println!("{}{}:", pad, key);
                            for (i, item) in arr.iter().enumerate() {
                                if item.is_object() {
                                    println!("{}  [{}]:", pad, i);
                                    print_value(item, indent + 2);
                                } else {
                                    println!("{}  - {}", pad, format_scalar(item));
                                }
                            }
                        }
                    }
                    _ => {
                        println!("{}{}: {}", pad, key, format_scalar(val));
                    }
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, item) in arr.iter().enumerate() {
                if item.is_object() {
                    println!("{}[{}]:", pad, i);
                    print_value(item, indent + 1);
                } else {
                    println!("{}- {}", pad, format_scalar(item));
                }
            }
        }
        _ => {
            println!("{}{}", pad, format_scalar(value));
        }
    }
}

fn format_scalar(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}
