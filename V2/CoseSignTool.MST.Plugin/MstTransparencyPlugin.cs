// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.Diagnostics.CodeAnalysis;
using CoseSignTool.Abstractions;

namespace CoseSignTool.MST.Plugin;

/// <summary>
/// Plugin for Microsoft Signing Transparency (MST) verification.
/// Provides verification providers and transparency contributors for MST proofs in COSE signatures.
/// </summary>
/// <remarks>
/// This plugin extends CoseSignTool with MST capabilities:
/// - Verification: Use 'verify' command with --require-receipt and --mst-endpoint options
/// - Transparency: Automatically contributes MST transparency provider for signing
/// 
/// All I/O is handled by the main executable; this plugin only provides validators and providers.
/// </remarks>
public class MstTransparencyPlugin : IPlugin
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string Name = "Microsoft Signing Transparency";
        public const string Version = "1.0.0";
        public const string Description = "Verify signatures against Microsoft Signing Transparency service";
    }

    /// <inheritdoc/>
    public string Name => ClassStrings.Name;

    /// <inheritdoc/>
    public string Version => ClassStrings.Version;

    /// <inheritdoc/>
    public string Description => ClassStrings.Description;

    /// <inheritdoc/>
    public Task InitializeAsync(IDictionary<string, string>? options = null) => Task.CompletedTask;

    /// <inheritdoc/>
    public PluginExtensions GetExtensions() => new(
        signingCommandProviders: [],
        verificationProviders: [new MstVerificationProvider()],
        transparencyProviders: [new MstTransparencyProviderContributor()]);

    /// <inheritdoc/>
    public void RegisterCommands(Command rootCommand)
    {
        // No additional commands - verification/transparency handled through extensions
    }
}