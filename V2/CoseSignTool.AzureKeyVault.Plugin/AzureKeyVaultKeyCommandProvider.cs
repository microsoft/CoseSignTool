// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.Diagnostics.CodeAnalysis;
using Azure.Core;
using Azure.Identity;
using CoseSign1.Abstractions;
using CoseSign1.AzureKeyVault;
using CoseSignTool.Abstractions;

namespace CoseSignTool.AzureKeyVault.Plugin;

/// <summary>
/// Command provider for signing with Azure Key Vault keys (non-certificate).
/// Uses <see cref="AzureKeyVaultSigningService"/> with RFC 9052 kid headers.
/// </summary>
public class AzureKeyVaultKeyCommandProvider : ISigningCommandProvider
{
    private AzureKeyVaultSigningService? SigningService;
    private string? VaultUrl;
    private string? KeyName;
    private string? KeyVersion;

    /// <inheritdoc/>
    public string CommandName => "sign-akv-key";

    /// <inheritdoc/>
    public string CommandDescription => "Sign a payload using a key from Azure Key Vault (adds kid header per RFC 9052)";

    /// <inheritdoc/>
    public string ExampleUsage => "--akv-vault https://my-vault.vault.azure.net --akv-key-name my-key";

    /// <inheritdoc/>
    public void AddCommandOptions(Command command)
    {
        var vaultOption = new Option<string>(
            name: "--akv-vault",
            description: "Azure Key Vault URL (e.g., https://my-vault.vault.azure.net)")
        {
            IsRequired = true
        };

        var keyNameOption = new Option<string>(
            name: "--akv-key-name",
            description: "Name of the key in Azure Key Vault")
        {
            IsRequired = true
        };

        var keyVersionOption = new Option<string?>(
            name: "--akv-key-version",
            description: "Specific version of the key (optional - uses latest if not specified)")
        {
            IsRequired = false
        };

        var refreshIntervalOption = new Option<int>(
            name: "--akv-refresh-interval",
            description: "Auto-refresh interval in minutes for checking new key versions (default: 15, 0 to disable)")
        {
            IsRequired = false
        };
        refreshIntervalOption.SetDefaultValue(15);

        command.AddOption(vaultOption);
        command.AddOption(keyNameOption);
        command.AddOption(keyVersionOption);
        command.AddOption(refreshIntervalOption);
    }

    protected virtual TokenCredential CreateCredential()
    {
        // Non-interactive by default to avoid prompting when used in CI or headless environments.
        return new DefaultAzureCredential(new DefaultAzureCredentialOptions
        {
            ExcludeInteractiveBrowserCredential = true
        });
    }

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
    public async Task<ISigningService<SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options)
    {
        VaultUrl = options["akv-vault"] as string
            ?? throw new InvalidOperationException("Azure Key Vault URL is required");
        KeyName = options["akv-key-name"] as string
            ?? throw new InvalidOperationException("Key name is required");
        KeyVersion = options.TryGetValue("akv-key-version", out var version) ? version as string : null;

        var refreshIntervalMinutes = 15;
        if (options.TryGetValue("akv-refresh-interval", out var intervalObj) && intervalObj is int interval)
        {
            refreshIntervalMinutes = interval;
        }

        // Parse vault URI
        if (!Uri.TryCreate(VaultUrl, UriKind.Absolute, out var vaultUri))
        {
            throw new ArgumentException($"Invalid Azure Key Vault URL: {VaultUrl}");
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
            ["Key Source"] = "Azure Key Vault",
            ["Vault URL"] = VaultUrl ?? "Unknown",
            ["Key Name"] = KeyName ?? "Unknown"
        };

        if (SigningService != null)
        {
            metadata["Key Version"] = SigningService.Version ?? "Latest";
            metadata["Key ID (kid)"] = SigningService.KeyId;
            metadata["Pinned Version"] = SigningService.IsPinnedVersion.ToString();
            metadata["Key Type"] = SigningService.KeyType;

            if (!SigningService.IsPinnedVersion && SigningService.AutoRefreshInterval.HasValue)
            {
                metadata["Auto-Refresh Interval"] = SigningService.AutoRefreshInterval.Value.TotalMinutes + " minutes";
            }
        }

        return metadata;
    }
}
