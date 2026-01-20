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

        public static readonly string ProviderIdPfx = "pfx";
        public static readonly string ProviderDisplayNamePfx = "PFX";
        public static readonly string ProviderHelpSummaryPfx = "Local PFX/PKCS#12 certificate";

        public static readonly string ProviderIdPem = "pem";
        public static readonly string ProviderDisplayNamePem = "PEM";
        public static readonly string ProviderHelpSummaryPem = "Local PEM certificate and key";

        public static readonly string ProviderIdCertStore = "certstore";
        public static readonly string ProviderDisplayNameCertStore = "Cert Store";
        public static readonly string ProviderHelpSummaryCertStore = "OS certificate store";

        public static readonly string ProviderIdEphemeral = "ephemeral";
        public static readonly string ProviderDisplayNameEphemeral = "Ephemeral";
        public static readonly string ProviderHelpSummaryEphemeral = "Ephemeral in-memory certificate (testing)";
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
        transparencyProviders: [],
        signingRootProviders: [new X509SigningRootProvider()],
        signingMaterialProviders: [],
        certificateSigningMaterialProviders: GetCertificateSigningMaterialProviders());

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

    private static IEnumerable<ICertificateSigningMaterialProvider> GetCertificateSigningMaterialProviders()
    {
        yield return new CertificateSigningMaterialProvider(
            providerId: ClassStrings.ProviderIdPfx,
            providerDisplayName: ClassStrings.ProviderDisplayNamePfx,
            providerHelpSummary: ClassStrings.ProviderHelpSummaryPfx,
            commandName: PfxSigningCommandProvider.ClassStrings.CommandNameValue,
            priority: 10);

        yield return new CertificateSigningMaterialProvider(
            providerId: ClassStrings.ProviderIdPem,
            providerDisplayName: ClassStrings.ProviderDisplayNamePem,
            providerHelpSummary: ClassStrings.ProviderHelpSummaryPem,
            commandName: PemSigningCommandProvider.ClassStrings.CommandNameValue,
            priority: 20);

        yield return new CertificateSigningMaterialProvider(
            providerId: ClassStrings.ProviderIdCertStore,
            providerDisplayName: ClassStrings.ProviderDisplayNameCertStore,
            providerHelpSummary: ClassStrings.ProviderHelpSummaryCertStore,
            commandName: WindowsCertStoreSigningCommandProvider.ClassStrings.CommandNameValue,
            priority: 30);

        yield return new CertificateSigningMaterialProvider(
            providerId: ClassStrings.ProviderIdEphemeral,
            providerDisplayName: ClassStrings.ProviderDisplayNameEphemeral,
            providerHelpSummary: ClassStrings.ProviderHelpSummaryEphemeral,
            commandName: EphemeralSigningCommandProvider.ClassStrings.CommandNameValue,
            priority: 40);
    }
}

[ExcludeFromCodeCoverage]
internal sealed class X509SigningRootProvider : ISigningRootProvider
{
    internal static class ClassStrings
    {
        public const string RootId = "x509";
        public const string RootDisplayName = "X509";
        public const string RootHelpSummary = "Sign using X.509 certificates";
        public const string RootSelector = "--x509";
    }

    public string RootId => ClassStrings.RootId;

    public string RootDisplayName => ClassStrings.RootDisplayName;

    public string RootHelpSummary => ClassStrings.RootHelpSummary;

    public string RootSelector => ClassStrings.RootSelector;
}

[ExcludeFromCodeCoverage]
internal sealed class CertificateSigningMaterialProvider : ICertificateSigningMaterialProvider
{
    public CertificateSigningMaterialProvider(
        string providerId,
        string providerDisplayName,
        string providerHelpSummary,
        string commandName,
        int priority,
        IReadOnlyList<string>? aliases = null)
    {
        ProviderId = providerId ?? throw new ArgumentNullException(nameof(providerId));
        ProviderDisplayName = providerDisplayName ?? throw new ArgumentNullException(nameof(providerDisplayName));
        ProviderHelpSummary = providerHelpSummary ?? throw new ArgumentNullException(nameof(providerHelpSummary));
        CommandName = commandName ?? throw new ArgumentNullException(nameof(commandName));
        Priority = priority;
        Aliases = aliases ?? Array.Empty<string>();
    }

    public string ProviderId { get; }

    public string ProviderDisplayName { get; }

    public string ProviderHelpSummary { get; }

    public string CommandName { get; }

    public int Priority { get; }

    public IReadOnlyList<string> Aliases { get; }
}