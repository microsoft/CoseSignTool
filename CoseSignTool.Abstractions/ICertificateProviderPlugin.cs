// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

using CoseSign1.Abstractions.Interfaces;
using Microsoft.Extensions.Configuration;

/// <summary>
/// Defines the interface for certificate provider plugins that supply signing key providers
/// for COSE signing operations. Certificate provider plugins allow third-party extensions
/// to integrate custom certificate sources (e.g., cloud HSMs, hardware tokens, remote signing services)
/// into CoseSignTool's Sign and indirect-sign commands.
/// </summary>
/// <remarks>
/// <para>
/// Certificate provider plugins are discovered automatically from the plugins directory and
/// integrated into the Sign and indirect-sign commands. Each plugin declares its own command-line
/// parameters and creates an <see cref="ICoseSigningKeyProvider"/> instance when its provider
/// is selected via the --cert-provider parameter.
/// </para>
/// <para>
/// Security Note: Plugins should NEVER accept raw tokens or secrets directly on the command line.
/// Instead, use secure credential mechanisms like DefaultAzureCredential, environment variables,
/// or credential stores.
/// </para>
/// </remarks>
public interface ICertificateProviderPlugin
{
    /// <summary>
    /// Gets the unique identifier for this certificate provider.
    /// This name is used with the --cert-provider command-line parameter to select this provider.
    /// </summary>
    /// <remarks>
    /// The provider name should be lowercase, use hyphens for multiple words (e.g., "azure-trusted-signing"),
    /// and be unique across all certificate provider plugins.
    /// </remarks>
    /// <example>
    /// "local", "azure-trusted-signing", "aws-kms", "yubikey"
    /// </example>
    string ProviderName { get; }

    /// <summary>
    /// Gets a human-readable description of this certificate provider for help output.
    /// </summary>
    string Description { get; }

    /// <summary>
    /// Gets the command-line options supported by this certificate provider.
    /// The dictionary maps command-line switches (with -- or - prefixes) to configuration keys.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These options are merged into the Sign and indirect-sign commands when this provider is selected.
    /// Keys should be prefixed with a provider-specific identifier to avoid conflicts
    /// (e.g., "--ats-endpoint" for Azure Trusted Signing).
    /// </para>
    /// <para>
    /// Security: Do NOT include options for raw tokens or secrets. Use credential mechanisms instead.
    /// </para>
    /// </remarks>
    /// <returns>
    /// A dictionary mapping command-line switches to configuration keys.
    /// Example: { "--ats-endpoint": "ats-endpoint", "--ats-account-name": "ats-account-name" }
    /// </returns>
    IDictionary<string, string> GetProviderOptions();

    /// <summary>
    /// Determines whether this provider can create a signing key provider with the given configuration.
    /// </summary>
    /// <param name="configuration">The command-line configuration containing parsed arguments.</param>
    /// <returns>
    /// True if this provider has all required parameters to create a signing key provider;
    /// otherwise, false.
    /// </returns>
    /// <remarks>
    /// This method should check for the presence of required configuration values but should NOT
    /// perform expensive operations like credential acquisition or network calls.
    /// </remarks>
    bool CanCreateProvider(IConfiguration configuration);

    /// <summary>
    /// Creates an <see cref="ICoseSigningKeyProvider"/> instance from the provided configuration.
    /// </summary>
    /// <param name="configuration">The command-line configuration containing parsed arguments.</param>
    /// <param name="logger">Optional logger for diagnostic output during provider creation.</param>
    /// <returns>
    /// An <see cref="ICoseSigningKeyProvider"/> instance configured with the parameters from configuration.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// Thrown when required configuration parameters are missing or invalid.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the provider cannot be created due to environmental or service issues
    /// (e.g., authentication failure, service unavailable).
    /// </exception>
    /// <remarks>
    /// <para>
    /// This method performs the actual initialization of the certificate provider, which may include:
    /// - Acquiring credentials (using secure mechanisms like DefaultAzureCredential)
    /// - Establishing connections to remote services
    /// - Validating certificates and keys
    /// </para>
    /// <para>
    /// Security: This method should use secure credential acquisition mechanisms and NEVER accept
    /// raw tokens or secrets from command-line parameters. Use DefaultAzureCredential, environment
    /// variables, or other secure credential stores.
    /// </para>
    /// </remarks>
    ICoseSigningKeyProvider CreateProvider(IConfiguration configuration, IPluginLogger? logger = null);

    /// <summary>
    /// Gets usage documentation for this certificate provider, including parameter descriptions
    /// and examples.
    /// </summary>
    /// <returns>
    /// A formatted string containing usage instructions, parameter descriptions, and examples
    /// for using this certificate provider.
    /// </returns>
    string GetUsageDocumentation();
}
