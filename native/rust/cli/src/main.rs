// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use clap::Parser;

mod commands;
mod output;
mod plugin_host;
mod providers;

use commands::Cli;

fn main() {
    // Initialize logging (respects --verbosity / -vv / -vvv)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::WARN.into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    // Print banner unless quiet
    if !cli.quiet() {
        output::print_banner();
    }

    let result = commands::dispatch(cli);

    match result {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("\n[ERROR] {err:#}");
            std::process::exit(1);
        }
    }
}
