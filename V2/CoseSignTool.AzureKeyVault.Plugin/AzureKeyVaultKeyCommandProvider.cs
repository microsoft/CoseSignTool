// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.AzureKeyVault.Plugin;

using System.CommandLine;
using System.Diagnostics.CodeAnalysis;
using Azure.Core;
using Azure.Identity;
using CoseSign1.Abstractions;
using CoseSign1.AzureKeyVault;
using CoseSignTool.Abstractions;

/// <summary>
/// Command provider for signing with Azure Key Vault keys (non-certificate).
/// Uses <see cref="AzureKeyVaultSigningService"/> with RFC 9052 kid headers.
/// </summary>
public class AzureKeyVaultKeyCommandProvider : ISigningCommandProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string CommandNameValue = "akv-key";
        public static readonly string CommandDescriptionValue = "Sign a payload using a key from Azure Key Vault (adds kid header per RFC 9052)";
        public static readonly string ExampleUsageValue = "--akv-vault https://my-vault.vault.azure.net --akv-key-name my-key";

        public static readonly string OptionNameVault = "--akv-vault";
        public static readonly string OptionNameKeyName = "--akv-key-name";
        public static readonly string OptionNameKeyVersion = "--akv-key-version";
        public static readonly string OptionNameRefreshInterval = "--akv-refresh-interval";

        public static readonly string OptionKeyVault = "akv-vault";
        public static readonly string OptionKeyKeyName = "akv-key-name";
        public static readonly string OptionKeyKeyVersion = "akv-key-version";
        public static readonly string OptionKeyRefreshInterval = "akv-refresh-interval";

        public static readonly string OptionDescriptionVault = "Azure Key Vault URL (e.g., https://my-vault.vault.azure.net)";
        public static readonly string OptionDescriptionKeyName = "Name of the key in Azure Key Vault";
        public static readonly string OptionDescriptionKeyVersion = "Specific version of the key (optional - uses latest if not specified)";
        public static readonly string OptionDescriptionRefreshInterval = "Auto-refresh interval in minutes for checking new key versions (default: 15, 0 to disable)";

        public static readonly string ErrorVaultUrlRequired = "Azure Key Vault URL is required";
        public static readonly string ErrorKeyNameRequired = "Key name is required";
        public static readonly string ErrorFormatInvalidVaultUrl = "Invalid Azure Key Vault URL: {0}";

        public static readonly string MetadataKeySource = "Key Source";
        public static readonly string MetadataKeyVaultUrl = "Vault URL";
        public static readonly string MetadataKeyName = "Key Name";
        public static readonly string MetadataKeyVersion = "Key Version";
        public static readonly string MetadataKeyKid = "Key ID (kid)";
        public static readonly string MetadataKeyPinnedVersion = "Pinned Version";
        public static readonly string MetadataKeyKeyType = "Key Type";
        public static readonly string MetadataKeyAutoRefreshInterval = "Auto-Refresh Interval";

        public static readonly string MetadataValueSource = "Azure Key Vault";
        public static readonly string MetadataValueUnknown = "Unknown";
        public static readonly string MetadataValueLatest = "Latest";
        public static readonly string SuffixMinutes = " minutes";
    }

    private AzureKeyVaultSigningService? SigningService;
    private string? VaultUrl;
    private string? KeyName;
    private string? KeyVersion;

    /// <inheritdoc/>
    public string CommandName => ClassStrings.CommandNameValue;

    /// <inheritdoc/>
    public string CommandDescription => ClassStrings.CommandDescriptionValue;

    /// <inheritdoc/>
    public string ExampleUsage => ClassStrings.ExampleUsageValue;

    /// <inheritdoc/>
    public void AddCommandOptions(Command command)
    {
        var vaultOption = new Option<string>(
            name: ClassStrings.OptionNameVault,
            description: ClassStrings.OptionDescriptionVault)
        {
            IsRequired = true
        };

        var keyNameOption = new Option<string>(
            name: ClassStrings.OptionNameKeyName,
            description: ClassStrings.OptionDescriptionKeyName)
        {
            IsRequired = true
        };

        var keyVersionOption = new Option<string?>(
            name: ClassStrings.OptionNameKeyVersion,
            description: ClassStrings.OptionDescriptionKeyVersion)
        {
            IsRequired = false
        };

        var refreshIntervalOption = new Option<int>(
            name: ClassStrings.OptionNameRefreshInterval,
            description: ClassStrings.OptionDescriptionRefreshInterval)
        {
            IsRequired = false
        };
        refreshIntervalOption.SetDefaultValue(15);

        command.AddOption(vaultOption);
        command.AddOption(keyNameOption);
        command.AddOption(keyVersionOption);
        command.AddOption(refreshIntervalOption);
    }

    /// <summary>
    /// Creates the Azure credential used to authenticate with Azure Key Vault.
    /// </summary>
    /// <returns>A credential instance for authenticating with Azure.</returns>
    protected virtual TokenCredential CreateCredential()
    {
        // Non-interactive by default to avoid prompting when used in CI or headless environments.
        return new DefaultAzureCredential(new DefaultAzureCredentialOptions
        {
            ExcludeInteractiveBrowserCredential = true
        });
    }

    /// <summary>
    /// Creates an <see cref="AzureKeyVaultSigningService"/> for the specified vault and key.
    /// </summary>
    /// <param name="vaultUri">The Key Vault URI.</param>
    /// <param name="keyName">The key name.</param>
    /// <param name="credential">The credential used to authenticate.</param>
    /// <param name="keyVersion">Optional key version; if null, uses the latest.</param>
    /// <param name="autoRefreshInterval">Optional refresh interval for non-pinned keys.</param>
    /// <returns>A task that completes with the created signing service.</returns>
    protected virtual Task<AzureKeyVaultSigningService> CreateAzureKeyVaultSigningServiceAsync(
        Uri vaultUri,
        string keyName,
        TokenCredential credential,
        string? keyVersion,
        TimeSpan? autoRefreshInterval)
    {
        return AzureKeyVaultSigningService.CreateAsync(
            vaultUri,
            keyName,
            credential,
            keyVersion,
            autoRefreshInterval);
    }

    /// <inheritdoc/>
    /// <exception cref="InvalidOperationException">Required options are missing.</exception>
    /// <exception cref="ArgumentException">The provided Key Vault URL is not valid.</exception>
    public async Task<ISigningService<SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options)
    {
        VaultUrl = options[ClassStrings.OptionKeyVault] as string
            ?? throw new InvalidOperationException(ClassStrings.ErrorVaultUrlRequired);
        KeyName = options[ClassStrings.OptionKeyKeyName] as string
            ?? throw new InvalidOperationException(ClassStrings.ErrorKeyNameRequired);
        KeyVersion = options.TryGetValue(ClassStrings.OptionKeyKeyVersion, out var version) ? version as string : null;

        var refreshIntervalMinutes = 15;
        if (options.TryGetValue(ClassStrings.OptionKeyRefreshInterval, out var intervalObj) && intervalObj is int interval)
        {
            refreshIntervalMinutes = interval;
        }

        // Parse vault URI
        if (!Uri.TryCreate(VaultUrl, UriKind.Absolute, out var vaultUri))
        {
            throw new ArgumentException(string.Format(ClassStrings.ErrorFormatInvalidVaultUrl, VaultUrl));
        }

        var credential = CreateCredential();

        // Create signing service with appropriate mode
        TimeSpan? autoRefreshInterval = refreshIntervalMinutes > 0
            ? TimeSpan.FromMinutes(refreshIntervalMinutes)
            : null;

        SigningService = await CreateAzureKeyVaultSigningServiceAsync(
            vaultUri,
            KeyName,
            credential,
            KeyVersion,
            autoRefreshInterval).ConfigureAwait(false);

        return SigningService;
    }

    /// <inheritdoc/>
    public IDictionary<string, string> GetSigningMetadata()
    {
        var metadata = new Dictionary<string, string>
        {
            [ClassStrings.MetadataKeySource] = ClassStrings.MetadataValueSource,
            [ClassStrings.MetadataKeyVaultUrl] = VaultUrl ?? ClassStrings.MetadataValueUnknown,
            [ClassStrings.MetadataKeyName] = KeyName ?? ClassStrings.MetadataValueUnknown
        };

        if (SigningService != null)
        {
            metadata[ClassStrings.MetadataKeyVersion] = SigningService.Version ?? ClassStrings.MetadataValueLatest;
            metadata[ClassStrings.MetadataKeyKid] = SigningService.KeyId;
            metadata[ClassStrings.MetadataKeyPinnedVersion] = SigningService.IsPinnedVersion.ToString();
            metadata[ClassStrings.MetadataKeyKeyType] = SigningService.KeyType;

            if (!SigningService.IsPinnedVersion && SigningService.AutoRefreshInterval.HasValue)
            {
                metadata[ClassStrings.MetadataKeyAutoRefreshInterval] = SigningService.AutoRefreshInterval.Value.TotalMinutes + ClassStrings.SuffixMinutes;
            }
        }

        return metadata;
    }
}
