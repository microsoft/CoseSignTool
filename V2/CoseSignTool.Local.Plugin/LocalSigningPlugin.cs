// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Local.Plugin;

using System.CommandLine;
using System.Diagnostics.CodeAnalysis;
using CoseSignTool.Abstractions;

/// <summary>
/// Local signing plugin for COSE Sign1 operations with local certificates.
/// Provides signing with PFX files, PEM files, and certificate stores.
/// All I/O and formatting is handled by the main executable.
/// </summary>
public class LocalSigningPlugin : IPlugin
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string PluginName = "Local Certificate Signing";
        public static readonly string PluginVersion = "1.0.0";
        public static readonly string PluginDescription = "Sign with local certificates (PFX, PEM, certificate stores)";
    }

    /// <inheritdoc/>
    public string Name => ClassStrings.PluginName;

    /// <inheritdoc/>
    public string Version => ClassStrings.PluginVersion;

    /// <inheritdoc/>
    public string Description => ClassStrings.PluginDescription;

    /// <inheritdoc/>
    public Task InitializeAsync(IDictionary<string, string>? configuration = null) => Task.CompletedTask;

    /// <inheritdoc/>
    public PluginExtensions GetExtensions() => new(
        signingCommandProviders: GetSigningCommandProviders(),
        verificationProviders: [new X509VerificationProvider()],
        transparencyProviders: []);

    /// <inheritdoc/>
    public void RegisterCommands(Command rootCommand)
    {
        // No additional commands - signing/verification handled through extensions
    }

    private static IEnumerable<ISigningCommandProvider> GetSigningCommandProviders()
    {
        yield return new PfxSigningCommandProvider();
        yield return new PemSigningCommandProvider();
        yield return new EphemeralSigningCommandProvider();

        // Platform-specific certificate store providers
        if (OperatingSystem.IsWindows())
        {
            yield return new WindowsCertStoreSigningCommandProvider();
        }
        else if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            yield return new LinuxCertStoreSigningCommandProvider();
        }
    }
}