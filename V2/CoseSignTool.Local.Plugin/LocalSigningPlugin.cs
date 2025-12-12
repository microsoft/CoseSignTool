// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using CoseSignTool.Plugins;

namespace CoseSignTool.Local.Plugin;

/// <summary>
/// Local signing plugin for COSE Sign1 operations with local certificates.
/// Provides signing with PFX files and certificate stores.
/// All I/O and formatting is handled by the main executable.
/// </summary>
public class LocalSigningPlugin : IPlugin
{
    /// <inheritdoc/>
    public string Name => "Local Certificate Signing";

    /// <inheritdoc/>
    public string Version => "1.0.0";

    /// <inheritdoc/>
    public string Description => "Sign with local certificates (PFX files, certificate stores)";

    /// <inheritdoc/>
    public Task InitializeAsync(IDictionary<string, string>? configuration = null)
    {
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public IEnumerable<ISigningCommandProvider> GetSigningCommandProviders()
    {
        var providers = new List<ISigningCommandProvider>
        {
            // PFX signing is cross-platform
            new PfxSigningCommandProvider()
        };

        // Platform-specific certificate store providers
        if (OperatingSystem.IsWindows())
        {
            providers.Add(new WindowsCertStoreSigningCommandProvider());
        }
        else if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS() || OperatingSystem.IsFreeBSD())
        {
            providers.Add(new PemSigningCommandProvider());
            providers.Add(new LinuxCertStoreSigningCommandProvider());
        }

        return providers;
    }

    /// <inheritdoc/>
    public IEnumerable<ITransparencyProviderContributor> GetTransparencyProviderContributors()
    {
        // Local plugin doesn't provide transparency services
        return Enumerable.Empty<ITransparencyProviderContributor>();
    }

    /// <inheritdoc/>
    public void RegisterCommands(Command rootCommand)
    {
        // No additional commands to register
        // All signing commands are handled via GetSigningCommandProviders()
    }
}
