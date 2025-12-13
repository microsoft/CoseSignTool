// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using CoseSignTool.Abstractions;

namespace CoseSignTool.Local.Plugin;

/// <summary>
/// Local signing plugin for COSE Sign1 operations with local certificates.
/// Provides signing with PFX files, PEM files, and certificate stores.
/// All I/O and formatting is handled by the main executable.
/// </summary>
public class LocalSigningPlugin : IPlugin
{
    /// <inheritdoc/>
    public string Name => "Local Certificate Signing";

    /// <inheritdoc/>
    public string Version => "1.0.0";

    /// <inheritdoc/>
    public string Description => "Sign with local certificates (PFX, PEM, certificate stores)";

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