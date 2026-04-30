// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use clap::error::ErrorKind;
use cose_sign1_cli::commands::{self, ParsedCli};
use cosesigntool_plugin_api::traits::{
    PluginCapability, PluginCommandDef, PluginInfo, PluginOptionDef,
};

#[cfg(feature = "ats")]
#[test]
fn ats_help_includes_exact_v2_option_strings() {
    let help = help_text(
        commands::build_command(&[]),
        ["CoseSignTool", "sign", "x509", "ats", "--help"],
    );

    assert!(help.contains("--ats-endpoint <ats-endpoint>"));
    assert!(help.contains("Azure Artifact Signing endpoint URL (e.g., https://xxx.codesigning.azure.net)"));
    assert!(help.contains("--ats-account-name <ats-account-name>"));
    assert!(help.contains("Azure Artifact Signing account name"));
    assert!(help.contains("--ats-cert-profile-name <ats-cert-profile-name>"));
    assert!(help.contains("Certificate profile name in Azure Artifact Signing"));
}

#[test]
fn pfx_help_includes_exact_v2_option_strings() {
    let help = help_text(
        commands::build_command(&[]),
        ["CoseSignTool", "sign", "x509", "pfx", "--help"],
    );

    assert!(help.contains("--pfx <pfx>"));
    assert!(help.contains("Path to PFX/PKCS#12 file containing the signing certificate and private key"));
    assert!(help.contains("--pfx-password-file <pfx-password-file>"));
    assert!(help.contains("Path to a file containing the PFX password (more secure than command line)"));
    assert!(help.contains("--pfx-password-env <pfx-password-env>"));
    assert!(help.contains("Name of environment variable containing the PFX password"));
    assert!(help.contains("-o, --output <output>"));
    assert!(help.contains("--content-type <content-type>"));
    assert!(help.contains("--format <format>"));
    assert!(help.contains("--detached"));
    assert!(help.contains("--embed"));
    assert!(help.contains("--issuer <issuer>"));
    assert!(help.contains("--cwt-subject <cwt-subject>"));
}

#[test]
fn pem_help_includes_exact_v2_option_strings() {
    let help = help_text(
        commands::build_command(&[]),
        ["CoseSignTool", "sign", "x509", "pem", "--help"],
    );

    assert!(help.contains("--cert-file <cert-file>"));
    assert!(help.contains("Path to the certificate file (.pem, .crt)"));
    assert!(help.contains("--key-file <key-file>"));
    assert!(help.contains("Path to the private key file (.key, .pem)"));
}

#[cfg(feature = "akv")]
#[test]
fn akv_cert_help_includes_exact_v2_option_strings() {
    let help = help_text(
        commands::build_command(&[]),
        ["CoseSignTool", "sign", "x509", "akv-cert", "--help"],
    );

    assert!(help.contains("--akv-vault <akv-vault>"));
    assert!(help.contains("Azure Key Vault URL (e.g., https://my-vault.vault.azure.net)"));
    assert!(help.contains("--akv-cert-name <akv-cert-name>"));
    assert!(help.contains("Name of the certificate in Azure Key Vault"));
    assert!(help.contains("--akv-cert-version <akv-cert-version>"));
    assert!(help.contains("Specific version of the certificate (optional - uses latest)"));
}

#[test]
fn verify_help_includes_v2_parity_options() {
    let help = help_text(
        commands::build_command(&[]),
        ["CoseSignTool", "verify", "x509", "--help"],
    );

    assert!(help.contains("-p, --payload <payload>"));
    assert!(help.contains("--signature-only"));
    assert!(help.contains("Verify only cryptographic signature, skip payload validation"));
    assert!(help.contains("--trust-system-roots"));
    assert!(help.contains("Use system trust roots (default: true)"));
    assert!(help.contains("--allow-untrusted"));
    assert!(help.contains("Allow untrusted roots (skip chain trust requirement)"));
    assert!(help.contains("--allow-thumbprint <thumbprint>"));
    assert!(help.contains("Allow specific signing certificate thumbprint (SHA-256 hex)"));
}

#[test]
fn inspect_help_includes_extract_payload_option() {
    let help = help_text(
        commands::build_command(&[]),
        ["CoseSignTool", "inspect", "--help"],
    );

    assert!(help.contains("--extract-payload <path>"));
    assert!(help.contains("Extract embedded payload to file"));
}

#[test]
fn dynamic_plugin_help_and_parse_include_declared_options() {
    let plugin_info = sample_plugin_info();
    let help = help_text(
        commands::build_command(&[plugin_info.clone()]),
        ["CoseSignTool", "sign", "x509", "plugin-provider", "--help"],
    );

    assert!(help.contains("--plugin-endpoint <plugin-endpoint>"));
    assert!(help.contains("Plugin endpoint URL"));
    assert!(help.contains("--use-managed-identity"));
    assert!(help.contains("Use managed identity"));
    assert!(help.contains("-o, --output <output>"));
    assert!(help.contains("--content-type <content-type>"));

    let parsed = commands::parse_from(
        [
            "CoseSignTool",
            "sign",
            "x509",
            "plugin-provider",
            "payload.bin",
            "-o",
            "signature.cose",
            "--plugin-endpoint",
            "https://example.test",
            "--use-managed-identity",
        ],
        &[plugin_info],
    )
    .expect("plugin command should parse");

    match parsed {
        ParsedCli::Plugin(cli) => {
            assert_eq!(cli.invocation.command_name, "plugin-provider");
            assert_eq!(cli.invocation.common.payload, "payload.bin");
            assert_eq!(cli.invocation.common.output, "signature.cose");
            assert_eq!(
                cli.invocation.provider_options.get("plugin-endpoint"),
                Some(&"https://example.test".to_string())
            );
            assert_eq!(
                cli.invocation.provider_options.get("use-managed-identity"),
                Some(&"true".to_string())
            );
        }
        other => panic!("expected plugin parse result, got {other:?}"),
    }
}

fn help_text<const N: usize>(mut command: clap::Command, args: [&str; N]) -> String {
    match command.try_get_matches_from_mut(args) {
        Ok(_) => panic!("expected clap to return help output"),
        Err(error) => {
            assert_eq!(error.kind(), ErrorKind::DisplayHelp);
            error.to_string()
        }
    }
}

fn sample_plugin_info() -> PluginInfo {
    PluginInfo {
        id: "plugin-provider".to_string(),
        name: "Plugin Provider".to_string(),
        version: "1.0.0".to_string(),
        description: "Dynamic plugin provider".to_string(),
        capabilities: vec![PluginCapability::Signing],
        commands: vec![PluginCommandDef {
            name: "plugin-provider".to_string(),
            description: "Plugin-backed X.509 provider".to_string(),
            options: vec![
                PluginOptionDef {
                    name: "plugin-endpoint".to_string(),
                    value_name: "plugin-endpoint".to_string(),
                    description: "Plugin endpoint URL".to_string(),
                    required: true,
                    default_value: None,
                    short: None,
                    is_flag: false,
                },
                PluginOptionDef {
                    name: "use-managed-identity".to_string(),
                    value_name: "use-managed-identity".to_string(),
                    description: "Use managed identity".to_string(),
                    required: false,
                    default_value: None,
                    short: None,
                    is_flag: true,
                },
            ],
            capability: PluginCapability::Signing,
        }],
    }
}