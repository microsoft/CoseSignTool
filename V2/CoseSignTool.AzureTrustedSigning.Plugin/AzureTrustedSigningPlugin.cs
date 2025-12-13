// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using CoseSignTool.Abstractions;

namespace CoseSignTool.AzureTrustedSigning.Plugin;

/// <summary>
/// Azure Trusted Signing service plugin for COSE Sign1 operations.
/// Provides cloud-based signing using Microsoft's Azure Trusted Signing service
/// with FIPS 140-2 Level 3 HSM-backed keys.
/// </summary>
public class AzureTrustedSigningPlugin : IPlugin
{
    /// <inheritdoc/>
    public string Name => "Azure Trusted Signing";

    /// <inheritdoc/>
    public string Version => "1.0.0";

    /// <inheritdoc/>
    public string Description => "Sign with Microsoft Azure Trusted Signing cloud service";

    /// <inheritdoc/>
    public Task InitializeAsync(IDictionary<string, string>? configuration = null) => Task.CompletedTask;

    /// <inheritdoc/>
    public PluginExtensions GetExtensions() => new(
        signingCommandProviders: [new AzureTrustedSigningCommandProvider()],
        verificationProviders: [],
        transparencyProviders: []);

    /// <inheritdoc/>
    public void RegisterCommands(Command rootCommand)
    {
        // No additional commands - signing handled through extensions
    }
}