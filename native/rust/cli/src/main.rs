// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod commands;
mod output;
mod plugin_host;
mod providers;
mod spawn;

fn main() {
    // Initialize logging (respects --verbosity / -vv / -vvv)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::WARN.into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let mut plugin_registry = plugin_host::PluginRegistry::new();
    if let Err(err) = plugin_registry.discover() {
        tracing::warn!("Failed to discover plugins: {err:#}");
    }

    let cli = match commands::parse(&plugin_registry) {
        Ok(cli) => cli,
        Err(err) => {
            err.print().expect("failed to print clap error");
            std::process::exit(if err.use_stderr() { 2 } else { 0 });
        }
    };

    // Print banner unless quiet
    if !cli.quiet() {
        output::print_banner();
    }

    let result = commands::dispatch(cli, &plugin_registry);

    match result {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("\n[ERROR] {err:#}");
            std::process::exit(1);
        }
    }
}
