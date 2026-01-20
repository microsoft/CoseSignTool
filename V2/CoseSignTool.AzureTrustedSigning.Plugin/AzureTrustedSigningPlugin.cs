// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.AzureTrustedSigning.Plugin;

using System.CommandLine;
using System.Diagnostics.CodeAnalysis;
using CoseSignTool.Abstractions;

/// <summary>
/// Azure Trusted Signing service plugin for COSE Sign1 operations.
/// Provides cloud-based signing using Microsoft's Azure Trusted Signing service
/// with FIPS 140-2 Level 3 HSM-backed keys.
/// </summary>
public class AzureTrustedSigningPlugin : IPlugin
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string Name = "Azure Trusted Signing";
        public const string Version = "1.0.0";
        public const string Description = "Sign with Microsoft Azure Trusted Signing cloud service";
    }

    /// <inheritdoc/>
    public string Name => ClassStrings.Name;

    /// <inheritdoc/>
    public string Version => ClassStrings.Version;

    /// <inheritdoc/>
    public string Description => ClassStrings.Description;

    /// <inheritdoc/>
    public Task InitializeAsync(IDictionary<string, string>? configuration = null) => Task.CompletedTask;

    /// <inheritdoc/>
    public PluginExtensions GetExtensions() => new(
        signingCommandProviders: [new AzureTrustedSigningCommandProvider()],
        verificationProviders: [],
        transparencyProviders: [],
        signingRootProviders: [],
        signingMaterialProviders: [],
        certificateSigningMaterialProviders: [new AtsCertificateSigningMaterialProvider()]);

    /// <inheritdoc/>
    public void RegisterCommands(Command rootCommand)
    {
        // No additional commands - signing handled through extensions
    }
}

[ExcludeFromCodeCoverage]
internal sealed class AtsCertificateSigningMaterialProvider : ICertificateSigningMaterialProvider
{
    internal static class ClassStrings
    {
        public const string ProviderId = "ats";
        public const string ProviderDisplayName = "Azure Trusted Signing";
        public const string ProviderHelpSummary = "Microsoft Azure Trusted Signing cloud service";
    }

    public string ProviderId => ClassStrings.ProviderId;

    public string ProviderDisplayName => ClassStrings.ProviderDisplayName;

    public string ProviderHelpSummary => ClassStrings.ProviderHelpSummary;

    public string CommandName => AzureTrustedSigningCommandProvider.ClassStrings.CommandNameValue;

    public int Priority => 50;

    public IReadOnlyList<string> Aliases => [];
}