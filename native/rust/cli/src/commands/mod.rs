// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CLI command definitions using clap derive, mirroring V2 .NET CoseSignTool syntax.

pub mod inspect;
pub mod sign;
pub mod verify;

use crate::output::OutputFormat;
use crate::plugin_host::PluginRegistry;
use clap::{
    value_parser, Arg, ArgAction, Command as ClapCommand, FromArgMatches, Parser, Subcommand,
};
use cosesigntool_plugin_api::traits::PluginInfo;

/// Modern CLI tool for COSE Sign1 signing and verification.
#[derive(Parser, Debug)]
#[command(
    name = "CoseSignTool",
    version,
    about = "Sign, verify, and inspect COSE_Sign1 messages"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Output format for command results.
    #[arg(
        short = 'f',
        long = "output-format",
        default_value = "text",
        global = true
    )]
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

#[derive(Debug)]
pub struct PluginCli {
    pub output_format: OutputFormat,
    pub verbosity: u8,
    pub invocation: sign::PluginSignInvocation,
}

#[derive(Debug)]
pub enum ParsedCli {
    BuiltIn(Cli),
    Plugin(PluginCli),
}

impl ParsedCli {
    pub fn quiet(&self) -> bool {
        match self {
            Self::BuiltIn(cli) => cli.quiet(),
            Self::Plugin(cli) => {
                cli.verbosity == 0 || matches!(cli.output_format, OutputFormat::Quiet)
            }
        }
    }
}

pub fn build_command(plugin_infos: &[PluginInfo]) -> ClapCommand {
    ClapCommand::new("CoseSignTool")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Sign, verify, and inspect COSE_Sign1 messages")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("output_format")
                .short('f')
                .long("output-format")
                .default_value("text")
                .global(true)
                .help("Output format for command results.")
                .value_parser(value_parser!(OutputFormat)),
        )
        .arg(
            Arg::new("verbosity")
                .long("verbosity")
                .default_value("1")
                .global(true)
                .help("Set logging verbosity (0=quiet, 1=normal, 2=verbose, 3=debug, 4=trace).")
                .value_parser(value_parser!(u8)),
        )
        .arg(
            Arg::new("debug")
                .long("vv")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Enable debug logging (equivalent to --verbosity 3)."),
        )
        .arg(
            Arg::new("trace")
                .long("vvv")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Enable trace logging (equivalent to --verbosity 4)."),
        )
        .subcommand(sign::build_sign_command(plugin_infos))
        .subcommand(verify::build_verify_command())
        .subcommand(inspect::build_inspect_command())
}

pub fn parse(registry: &PluginRegistry) -> Result<ParsedCli, clap::Error> {
    let plugin_infos = registry.list();
    parse_from(std::env::args_os(), plugin_infos.as_slice())
}

pub fn parse_from<I, T>(args: I, plugin_infos: &[PluginInfo]) -> Result<ParsedCli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let command = build_command(plugin_infos);
    let matches = command.try_get_matches_from(args)?;

    if let Some(invocation) = sign::try_parse_plugin_invocation(plugin_infos, &matches)
        .map_err(|error| clap::Error::raw(clap::error::ErrorKind::InvalidValue, error))?
    {
        return Ok(ParsedCli::Plugin(PluginCli {
            output_format: matches
                .get_one::<OutputFormat>("output_format")
                .copied()
                .unwrap_or_default(),
            verbosity: matches.get_one::<u8>("verbosity").copied().unwrap_or(1),
            invocation,
        }));
    }

    let mut cli = Cli::from_arg_matches(&matches)?;
    if let Some(("sign", sign_matches)) = matches.subcommand() {
        if let Some(("x509", x509_matches)) = sign_matches.subcommand() {
            if let Some((provider_name, provider_matches)) = x509_matches.subcommand() {
                if sign::is_builtin_provider_name(provider_name) {
                    let transparency_options =
                        sign::transparency_option_values_from_matches(provider_matches, plugin_infos);
                    if let Command::Sign { method } = &mut cli.command {
                        sign::set_builtin_transparency_options(method, transparency_options);
                    }
                }
            }
        }
    }

    Ok(ParsedCli::BuiltIn(cli))
}

/// Dispatch the parsed CLI command to the appropriate handler.
pub fn dispatch(cli: ParsedCli, registry: &PluginRegistry) -> anyhow::Result<i32> {
    match cli {
        ParsedCli::BuiltIn(cli) => match cli.command {
            Command::Sign { method } => sign::execute(method, cli.output_format),
            Command::Verify { method } => verify::execute(method, cli.output_format),
            Command::Inspect(args) => inspect::execute(args, cli.output_format),
        },
        ParsedCli::Plugin(cli) => sign::execute_plugin(cli.invocation, cli.output_format, registry),
    }
}
