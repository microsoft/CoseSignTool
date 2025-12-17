// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using CoseSignTool.Abstractions;

namespace CoseSignTool.AzureKeyVault.Plugin;

/// <summary>
/// Azure Key Vault plugin for COSE Sign1 operations.
/// Provides two signing modes:
/// <list type="bullet">
///   <item><description>Certificate-based signing with auto-refresh support</description></item>
///   <item><description>Key-only signing with RFC 9052 kid headers</description></item>
/// </list>
/// </summary>
public class AzureKeyVaultPlugin : IPlugin
{
    /// <inheritdoc/>
    public string Name => "Azure Key Vault";

    /// <inheritdoc/>
    public string Version => "1.0.0";

    /// <inheritdoc/>
    public string Description => "Sign with Azure Key Vault certificates or keys";

    /// <inheritdoc/>
    public Task InitializeAsync(IDictionary<string, string>? configuration = null) => Task.CompletedTask;

    /// <inheritdoc/>
    public PluginExtensions GetExtensions() => new(
        signingCommandProviders:
        [
            new AzureKeyVaultCertificateCommandProvider(),
            new AzureKeyVaultKeyCommandProvider()
        ],
        verificationProviders:
        [
            new AzureKeyVaultVerificationProvider()
        ],
        transparencyProviders: []);

    /// <inheritdoc/>
    public void RegisterCommands(Command rootCommand)
    {
        // No additional commands - signing handled through extensions
    }
}
