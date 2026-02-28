// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CoseSignTool CLI — sign, verify, and inspect COSE_Sign1 messages.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

mod commands;
mod providers;

use clap::{Parser, Subcommand};
use std::process;

#[derive(Parser)]
#[command(name = "CoseSignTool")]
#[command(about = "Sign, verify, and inspect COSE_Sign1 messages")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Commands {
    /// Sign a payload and produce a COSE_Sign1 message
    Sign(commands::sign::SignArgs),
    /// Verify a COSE_Sign1 message
    Verify(commands::verify::VerifyArgs),
    /// Inspect a COSE_Sign1 message (parse and display structure)
    Inspect(commands::inspect::InspectArgs),
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn main() {
    let cli = Cli::parse();

    // Initialize tracing
    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .with_target(false)
        .init();

    let exit_code = match cli.command {
        Commands::Sign(args) => commands::sign::run(args),
        Commands::Verify(args) => commands::verify::run(args),
        Commands::Inspect(args) => commands::inspect::run(args),
    };

    process::exit(exit_code);
}