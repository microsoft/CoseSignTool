// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CLI command definitions using clap derive, mirroring V2 .NET CoseSignTool syntax.

pub mod inspect;
pub mod sign;
pub mod verify;

use crate::output::OutputFormat;
use clap::{Parser, Subcommand};

/// Modern CLI tool for COSE Sign1 signing and verification.
#[derive(Parser, Debug)]
#[command(name = "CoseSignTool", version, about = "Sign, verify, and inspect COSE_Sign1 messages")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Output format for command results.
    #[arg(short = 'f', long = "output-format", default_value = "text", global = true)]
    pub output_format: OutputFormat,

    /// Set logging verbosity (0=quiet, 1=normal, 2=verbose, 3=debug, 4=trace).
    #[arg(long, default_value = "1", global = true)]
    pub verbosity: u8,

    /// Enable debug logging (equivalent to --verbosity 3).
    #[arg(long = "vv", global = true)]
    pub debug: bool,

    /// Enable trace logging (equivalent to --verbosity 4).
    #[arg(long = "vvv", global = true)]
    pub trace: bool,
}

impl Cli {
    /// Returns true if output should be suppressed.
    pub fn quiet(&self) -> bool {
        self.verbosity == 0 || matches!(self.output_format, OutputFormat::Quiet)
    }
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Sign a payload and produce a COSE_Sign1 message.
    Sign {
        #[command(subcommand)]
        method: sign::SignMethod,
    },
    /// Verify a COSE_Sign1 message.
    Verify {
        #[command(subcommand)]
        method: verify::VerifyMethod,
    },
    /// Inspect a COSE_Sign1 message (parse and display structure).
    Inspect(inspect::InspectArgs),
}

/// Dispatch the parsed CLI command to the appropriate handler.
pub fn dispatch(cli: Cli) -> anyhow::Result<i32> {
    match cli.command {
        Command::Sign { method } => sign::execute(method, cli.output_format),
        Command::Verify { method } => verify::execute(method, cli.output_format),
        Command::Inspect(args) => inspect::execute(args, cli.output_format),
    }
}
