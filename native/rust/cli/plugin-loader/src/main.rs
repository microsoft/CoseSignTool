// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CoseSignTool Plugin Loader — trusted bridge between host and compiled-in providers.

use anyhow::{Context, Result};
use cosesigntool_plugin_api::server;
use cosesigntool_plugin_api::traits::PluginProvider;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    if let Err(err) = run() {
        eprintln!("[plugin-loader] fatal: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let plugin_name =
        find_arg(&args, "--plugin").context("--plugin is required (e.g., aas, akv)")?;
    let plugin = create_provider(plugin_name.as_str())?;
    server::run(plugin)?;
    Ok(())
}

/// Select a compiled-in provider by name.
fn create_provider(name: &str) -> Result<Box<dyn PluginProvider>> {
    match name {
        // First-party providers compiled in via feature flags.
        // No dynamic loading, no C ABI, no unsafe.
        //
        // To add a new provider:
        // 1. Add a feature flag in Cargo.toml
        // 2. Add a match arm here behind #[cfg(feature = "...")]
        // 3. Implement PluginProvider for your provider struct
        _ => anyhow::bail!(
            "Unknown plugin '{}'. Available: {}",
            name,
            available_plugins().join(", ")
        ),
    }
}

/// List available compiled-in plugins.
fn available_plugins() -> Vec<&'static str> {
    Vec::new()
}

fn find_arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|argument| argument == name)
        .and_then(|index| args.get(index + 1))
        .cloned()
}
