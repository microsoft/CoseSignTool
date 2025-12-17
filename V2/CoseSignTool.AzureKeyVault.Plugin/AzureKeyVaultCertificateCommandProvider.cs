// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.Diagnostics.CodeAnalysis;
using Azure.Core;
using Azure.Identity;
using CoseSign1.AzureKeyVault.Common;
using CoseSign1.Abstractions;
using CoseSign1.Certificates;
using CoseSign1.Certificates.AzureKeyVault;
using CoseSign1.Certificates.Remote;
using CoseSignTool.Abstractions;

namespace CoseSignTool.AzureKeyVault.Plugin;

/// <summary>
/// Command provider for signing with Azure Key Vault certificates.
/// Uses <see cref="AzureKeyVaultCertificateSource"/> with optional auto-refresh.
/// </summary>
public class AzureKeyVaultCertificateCommandProvider : ISigningCommandProvider
{
    private ISigningService<SigningOptions>? SigningService;
    private AzureKeyVaultCertificateSource? CertificateSource;
    private string? VaultUrl;
    private string? CertificateName;
    private string? CertificateVersion;

    /// <inheritdoc/>
    public string CommandName => "sign-akv-cert";

    /// <inheritdoc/>
    public string CommandDescription => "Sign a payload using a certificate from Azure Key Vault";

    /// <inheritdoc/>
    public string ExampleUsage => "--akv-vault https://my-vault.vault.azure.net --akv-cert-name my-cert";

    /// <inheritdoc/>
    public void AddCommandOptions(Command command)
    {
        var vaultOption = new Option<string>(
            name: "--akv-vault",
            description: "Azure Key Vault URL (e.g., https://my-vault.vault.azure.net)")
        {
            IsRequired = true
        };

        var certNameOption = new Option<string>(
            name: "--akv-cert-name",
            description: "Name of the certificate in Azure Key Vault")
        {
            IsRequired = true
        };

        var certVersionOption = new Option<string?>(
            name: "--akv-cert-version",
            description: "Specific version of the certificate (optional - uses latest if not specified)")
        {
            IsRequired = false
        };

        var refreshIntervalOption = new Option<int>(
            name: "--akv-refresh-interval",
            description: "Auto-refresh interval in minutes for checking new certificate versions (default: 15, 0 to disable)")
        {
            IsRequired = false
        };
        refreshIntervalOption.SetDefaultValue(15);

        command.AddOption(vaultOption);
        command.AddOption(certNameOption);
        command.AddOption(certVersionOption);
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

    protected virtual IKeyVaultClientFactory CreateClientFactory(Uri vaultUri, TokenCredential credential)
    {
        return new KeyVaultClientFactory(vaultUri, credential);
    }

    /// <inheritdoc/>
    public async Task<ISigningService<SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options)
    {
        VaultUrl = options["akv-vault"] as string
            ?? throw new InvalidOperationException("Azure Key Vault URL is required");
        CertificateName = options["akv-cert-name"] as string
            ?? throw new InvalidOperationException("Certificate name is required");
        CertificateVersion = options.TryGetValue("akv-cert-version", out var version) ? version as string : null;

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

        // Create certificate source with appropriate mode
        TimeSpan? autoRefreshInterval = refreshIntervalMinutes > 0
            ? TimeSpan.FromMinutes(refreshIntervalMinutes)
            : null;

        var factory = CreateClientFactory(vaultUri, credential);
        CertificateSource = new AzureKeyVaultCertificateSource(
            factory,
            CertificateName,
            CertificateVersion,
            autoRefreshInterval);
        await CertificateSource.InitializeAsync().ConfigureAwait(false);

        // Create signing service
        SigningService = CertificateSigningService.Create(CertificateSource);

        return SigningService;
    }

    /// <inheritdoc/>
    public IDictionary<string, string> GetSigningMetadata()
    {
        var metadata = new Dictionary<string, string>
        {
            ["Certificate Source"] = "Azure Key Vault",
            ["Vault URL"] = VaultUrl ?? "Unknown",
            ["Certificate Name"] = CertificateName ?? "Unknown"
        };

        if (CertificateSource != null)
        {
            metadata["Certificate Version"] = CertificateSource.Version ?? "Latest";
            metadata["Pinned Version"] = CertificateSource.IsPinnedVersion.ToString();
            metadata["Key Mode"] = CertificateSource.KeyMode.ToString();
            metadata["Requires Remote Signing"] = CertificateSource.RequiresRemoteSigning.ToString();

            var signingCert = CertificateSource.GetSigningCertificate();
            if (signingCert != null)
            {
                metadata["Certificate Subject"] = signingCert.Subject;
                metadata["Certificate Thumbprint"] = signingCert.Thumbprint;
            }

            if (!CertificateSource.IsPinnedVersion && CertificateSource.AutoRefreshInterval.HasValue)
            {
                metadata["Auto-Refresh Interval"] = CertificateSource.AutoRefreshInterval.Value.TotalMinutes + " minutes";
            }
        }

        return metadata;
    }
}
