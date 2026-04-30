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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_quiet_when_verbosity_zero() {
        let cli = Cli {
            command: Command::Inspect(inspect::InspectArgs {
                signature: "sig.cose".into(),
                extract_payload: None,
            }),
            output_format: OutputFormat::Text,
            verbosity: 0,
            debug: false,
            trace: false,
        };
        assert!(cli.quiet());
    }

    #[test]
    fn cli_quiet_when_output_format_quiet() {
        let cli = Cli {
            command: Command::Inspect(inspect::InspectArgs {
                signature: "sig.cose".into(),
                extract_payload: None,
            }),
            output_format: OutputFormat::Quiet,
            verbosity: 1,
            debug: false,
            trace: false,
        };
        assert!(cli.quiet());
    }

    #[test]
    fn cli_not_quiet_with_normal_verbosity() {
        let cli = Cli {
            command: Command::Inspect(inspect::InspectArgs {
                signature: "sig.cose".into(),
                extract_payload: None,
            }),
            output_format: OutputFormat::Text,
            verbosity: 1,
            debug: false,
            trace: false,
        };
        assert!(!cli.quiet());
    }

    #[test]
    fn parsed_cli_quiet_builtin_delegates_to_cli() {
        let cli = ParsedCli::BuiltIn(Cli {
            command: Command::Inspect(inspect::InspectArgs {
                signature: "sig.cose".into(),
                extract_payload: None,
            }),
            output_format: OutputFormat::Text,
            verbosity: 0,
            debug: false,
            trace: false,
        });
        assert!(cli.quiet());
    }

    #[test]
    fn parsed_cli_quiet_plugin_with_verbosity_zero() {
        let cli = ParsedCli::Plugin(PluginCli {
            output_format: OutputFormat::Text,
            verbosity: 0,
            invocation: sign::PluginSignInvocation {
                command_name: "test".into(),
                common: sign::CommonSignArgs {
                    payload: String::new(),
                    output: String::new(),
                    content_type: String::new(),
                    format: sign::SignatureFormat::Indirect,
                    detached: false,
                    embed: false,
                    issuer: None,
                    cwt_subject: None,
                    scitt_subject: None,
                    enable_scitt: false,
                    no_scitt: false,
                    scitt_type: None,
                    #[cfg(feature = "mst")]
                    mst_endpoints: Vec::new(),
                    transparency_options: std::collections::HashMap::new(),
                },
                provider_options: std::collections::HashMap::new(),
            },
        });
        assert!(cli.quiet());
    }

    #[test]
    fn parsed_cli_quiet_plugin_with_quiet_format() {
        let cli = ParsedCli::Plugin(PluginCli {
            output_format: OutputFormat::Quiet,
            verbosity: 1,
            invocation: sign::PluginSignInvocation {
                command_name: "test".into(),
                common: sign::CommonSignArgs {
                    payload: String::new(),
                    output: String::new(),
                    content_type: String::new(),
                    format: sign::SignatureFormat::Indirect,
                    detached: false,
                    embed: false,
                    issuer: None,
                    cwt_subject: None,
                    scitt_subject: None,
                    enable_scitt: false,
                    no_scitt: false,
                    scitt_type: None,
                    #[cfg(feature = "mst")]
                    mst_endpoints: Vec::new(),
                    transparency_options: std::collections::HashMap::new(),
                },
                provider_options: std::collections::HashMap::new(),
            },
        });
        assert!(cli.quiet());
    }

    #[test]
    fn parse_from_verify_x509_subcommand() {
        let result = parse_from(
            [
                "CoseSignTool",
                "verify",
                "x509",
                "signature.cose",
            ],
            &[],
        );
        let cli = result.expect("verify x509 should parse");
        assert!(!cli.quiet());
        match cli {
            ParsedCli::BuiltIn(cli) => {
                assert!(matches!(cli.command, Command::Verify { .. }));
            }
            _ => panic!("expected builtin CLI"),
        }
    }

    #[test]
    fn parse_from_inspect_subcommand() {
        let result = parse_from(
            ["CoseSignTool", "inspect", "signature.cose"],
            &[],
        );
        let cli = result.expect("inspect should parse");
        match cli {
            ParsedCli::BuiltIn(cli) => {
                assert!(matches!(cli.command, Command::Inspect(_)));
            }
            _ => panic!("expected builtin CLI"),
        }
    }

    #[test]
    fn parse_from_with_output_format_json() {
        let result = parse_from(
            [
                "CoseSignTool",
                "--output-format",
                "json",
                "inspect",
                "signature.cose",
            ],
            &[],
        );
        let cli = result.expect("inspect with json format should parse");
        match cli {
            ParsedCli::BuiltIn(cli) => {
                assert!(matches!(cli.output_format, OutputFormat::Json));
            }
            _ => panic!("expected builtin CLI"),
        }
    }

    #[test]
    fn parse_from_with_output_format_quiet() {
        let result = parse_from(
            [
                "CoseSignTool",
                "-f",
                "quiet",
                "inspect",
                "signature.cose",
            ],
            &[],
        );
        let cli = result.expect("inspect with quiet format should parse");
        match cli {
            ParsedCli::BuiltIn(cli) => {
                assert!(matches!(cli.output_format, OutputFormat::Quiet));
            }
            _ => panic!("expected builtin CLI"),
        }
    }

    #[test]
    fn build_command_includes_all_subcommands() {
        let cmd = build_command(&[]);
        let subcommands: Vec<&str> = cmd
            .get_subcommands()
            .map(|sub| sub.get_name())
            .collect();
        assert!(subcommands.contains(&"sign"));
        assert!(subcommands.contains(&"verify"));
        assert!(subcommands.contains(&"inspect"));
    }

    #[test]
    fn parse_from_missing_subcommand_returns_error() {
        let result = parse_from(["CoseSignTool"].iter().copied(), &[]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_from_plugin_sign_command_recognized() {
        use cosesigntool_plugin_api::traits::*;
        let plugin = PluginInfo {
            id: "test-plugin".into(),
            name: "Test Plugin".into(),
            version: "1.0".into(),
            description: "A test plugin".into(),
            capabilities: vec![PluginCapability::Signing],
            commands: vec![PluginCommandDef {
                name: "test-provider".into(),
                description: "Test provider".into(),
                options: vec![PluginOptionDef {
                    name: "test-key".into(),
                    value_name: "KEY".into(),
                    description: "A test key".into(),
                    required: true,
                    default_value: None,
                    short: None,
                    is_flag: false,
                }],
                capability: PluginCapability::Signing,
            }],
            transparency_options: vec![],
        };
        let result = parse_from(
            [
                "CoseSignTool",
                "sign",
                "x509",
                "test-provider",
                "payload.bin",
                "--output",
                "out.cose",
                "--test-key",
                "my-value",
            ],
            &[plugin],
        );
        let cli = result.expect("plugin sign should parse");
        match cli {
            ParsedCli::Plugin(plugin_cli) => {
                assert_eq!(plugin_cli.invocation.command_name, "test-provider");
                assert_eq!(
                    plugin_cli.invocation.provider_options.get("test-key"),
                    Some(&"my-value".to_string())
                );
            }
            _ => panic!("expected plugin CLI"),
        }
    }
}
