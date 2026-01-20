// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.AzureKeyVault.Plugin;

using System.CommandLine;
using System.Diagnostics.CodeAnalysis;
using CoseSignTool.Abstractions;

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
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string Name = "Azure Key Vault";
        public const string Version = "1.0.0";
        public const string Description = "Sign with Azure Key Vault certificates or keys";

        public const string ProviderIdAkvCert = "akv-cert";
        public const string ProviderDisplayNameAkvCert = "AKV Certificate";
        public const string ProviderHelpSummaryAkvCert = "Azure Key Vault certificate";

        public const string MaterialAliasAkv = "akv";

        public const string ProviderIdAkvKey = "akv-key";
        public const string ProviderDisplayNameAkvKey = "AKV Key";
        public const string ProviderHelpSummaryAkvKey = "Azure Key Vault key-only signing (no X.509 chain)";

        public const string MaterialAliasKey = "key";
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
        signingCommandProviders:
        [
            new AzureKeyVaultCertificateCommandProvider(),
            new AzureKeyVaultKeyCommandProvider()
        ],
        verificationProviders:
        [
            new AzureKeyVaultVerificationProvider()
        ],
        transparencyProviders: [],
        signingRootProviders: [new AkvSigningRootProvider()],
        signingMaterialProviders: GetSigningMaterialProviders(),
        certificateSigningMaterialProviders: GetCertificateSigningMaterialProviders());

    /// <inheritdoc/>
    public void RegisterCommands(Command rootCommand)
    {
        // No additional commands - signing handled through extensions
    }

    private static IEnumerable<ISigningMaterialProvider> GetSigningMaterialProviders()
    {
        // AKV key-only root.
            yield return new AkvSigningMaterialProvider(
                providerId: ClassStrings.ProviderIdAkvKey,
                rootId: AkvSigningRootProvider.ClassStrings.RootId,
                providerDisplayName: ClassStrings.ProviderDisplayNameAkvKey,
                providerHelpSummary: ClassStrings.ProviderHelpSummaryAkvKey,
                commandName: AzureKeyVaultKeyCommandProvider.ClassStrings.CommandNameValue,
                priority: 10,
                aliases: [ClassStrings.MaterialAliasKey]);
    }

    private static IEnumerable<ICertificateSigningMaterialProvider> GetCertificateSigningMaterialProviders()
    {
        // Extends X.509 signing by sourcing certificates/chains from AKV.
        yield return new AkvCertificateSigningMaterialProvider(
            providerId: ClassStrings.ProviderIdAkvCert,
            providerDisplayName: ClassStrings.ProviderDisplayNameAkvCert,
            providerHelpSummary: ClassStrings.ProviderHelpSummaryAkvCert,
            commandName: AzureKeyVaultCertificateCommandProvider.ClassStrings.CommandNameValue,
            priority: 15,
            aliases: [ClassStrings.MaterialAliasAkv]);
    }
}

[ExcludeFromCodeCoverage]
internal sealed class AkvCertificateSigningMaterialProvider : ICertificateSigningMaterialProvider
{
    public AkvCertificateSigningMaterialProvider(
        string providerId,
        string providerDisplayName,
        string providerHelpSummary,
        string commandName,
        int priority,
        IEnumerable<string>? aliases = null)
    {
        ProviderId = providerId;
        ProviderDisplayName = providerDisplayName;
        ProviderHelpSummary = providerHelpSummary;
        CommandName = commandName;
        Priority = priority;
        Aliases = aliases?.ToList() ?? [];
    }

    public string ProviderId { get; }

    public string ProviderDisplayName { get; }

    public string ProviderHelpSummary { get; }

    public string CommandName { get; }

    public int Priority { get; }

    public IReadOnlyList<string> Aliases { get; }
}

[ExcludeFromCodeCoverage]
internal sealed class AkvSigningRootProvider : ISigningRootProvider
{
    internal static class ClassStrings
    {
        public const string RootId = "akv";
        public const string RootDisplayName = "AKV";
        public const string RootHelpSummary = "Sign using Azure Key Vault keys (no certificate chain)";
        public const string RootSelector = "--akv";
    }

    public string RootId => ClassStrings.RootId;

    public string RootDisplayName => ClassStrings.RootDisplayName;

    public string RootHelpSummary => ClassStrings.RootHelpSummary;

    public string RootSelector => ClassStrings.RootSelector;
}

[ExcludeFromCodeCoverage]
internal sealed class AkvSigningMaterialProvider : ISigningMaterialProviderWithAliases
{
    public AkvSigningMaterialProvider(
        string providerId,
        string rootId,
        string providerDisplayName,
        string providerHelpSummary,
        string commandName,
        int priority,
        IReadOnlyList<string>? aliases = null)
    {
        ProviderId = providerId ?? throw new ArgumentNullException(nameof(providerId));
        RootId = rootId ?? throw new ArgumentNullException(nameof(rootId));
        ProviderDisplayName = providerDisplayName ?? throw new ArgumentNullException(nameof(providerDisplayName));
        ProviderHelpSummary = providerHelpSummary ?? throw new ArgumentNullException(nameof(providerHelpSummary));
        CommandName = commandName ?? throw new ArgumentNullException(nameof(commandName));
        Priority = priority;
        Aliases = aliases ?? Array.Empty<string>();
    }

    public string ProviderId { get; }

    public string RootId { get; }

    public string ProviderDisplayName { get; }

    public string ProviderHelpSummary { get; }

    public string CommandName { get; }

    public int Priority { get; }

    public IReadOnlyList<string> Aliases { get; }
}
