// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.AzureKeyVault.Plugin;

using System.CommandLine;
using System.Diagnostics.CodeAnalysis;
using Azure.Core;
using Azure.Identity;
using CoseSign1.AzureKeyVault.Common;
using CoseSign1.Abstractions;
using CoseSign1.Certificates;
using CoseSign1.Certificates.AzureKeyVault;
using CoseSignTool.Abstractions;

/// <summary>
/// Command provider for signing with Azure Key Vault certificates.
/// Uses <see cref="AzureKeyVaultCertificateSource"/> with optional auto-refresh.
/// </summary>
public class AzureKeyVaultCertificateCommandProvider : ISigningCommandProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string CommandNameValue = "x509-akv-cert";
        public static readonly string CommandDescriptionValue = "Sign a payload using a certificate from Azure Key Vault";
        public static readonly string ExampleUsageValue = "--akv-vault https://my-vault.vault.azure.net --akv-cert-name my-cert";

        public static readonly string OptionNameVault = "--akv-vault";
        public static readonly string OptionNameCertName = "--akv-cert-name";
        public static readonly string OptionNameCertVersion = "--akv-cert-version";
        public static readonly string OptionNameRefreshInterval = "--akv-refresh-interval";

        public static readonly string OptionKeyVault = "akv-vault";
        public static readonly string OptionKeyCertName = "akv-cert-name";
        public static readonly string OptionKeyCertVersion = "akv-cert-version";
        public static readonly string OptionKeyRefreshInterval = "akv-refresh-interval";

        public static readonly string OptionDescriptionVault = "Azure Key Vault URL (e.g., https://my-vault.vault.azure.net)";
        public static readonly string OptionDescriptionCertName = "Name of the certificate in Azure Key Vault";
        public static readonly string OptionDescriptionCertVersion = "Specific version of the certificate (optional - uses latest if not specified)";
        public static readonly string OptionDescriptionRefreshInterval = "Auto-refresh interval in minutes for checking new certificate versions (default: 15, 0 to disable)";

        public static readonly string ErrorVaultUrlRequired = "Azure Key Vault URL is required";
        public static readonly string ErrorCertNameRequired = "Certificate name is required";
        public static readonly string ErrorFormatInvalidVaultUrl = "Invalid Azure Key Vault URL: {0}";

        public static readonly string MetadataKeyCertificateSource = "Certificate Source";
        public static readonly string MetadataKeyVaultUrl = "Vault URL";
        public static readonly string MetadataKeyCertificateName = "Certificate Name";
        public static readonly string MetadataKeyCertificateVersion = "Certificate Version";
        public static readonly string MetadataKeyPinnedVersion = "Pinned Version";
        public static readonly string MetadataKeyKeyMode = "Key Mode";
        public static readonly string MetadataKeyRequiresRemoteSigning = "Requires Remote Signing";
        public static readonly string MetadataKeyCertificateSubject = "Certificate Subject";
        public static readonly string MetadataKeyCertificateThumbprint = "Certificate Thumbprint";
        public static readonly string MetadataKeyAutoRefreshInterval = "Auto-Refresh Interval";

        public static readonly string MetadataValueCertificateSource = "Azure Key Vault";
        public static readonly string MetadataValueUnknown = "Unknown";
        public static readonly string MetadataValueLatest = "Latest";
        public static readonly string SuffixMinutes = " minutes";
    }

    private ISigningService<SigningOptions>? SigningService;
    private AzureKeyVaultCertificateSource? CertificateSource;
    private string? VaultUrl;
    private string? CertificateName;
    private string? CertificateVersion;

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

        var certNameOption = new Option<string>(
            name: ClassStrings.OptionNameCertName,
            description: ClassStrings.OptionDescriptionCertName)
        {
            IsRequired = true
        };

        var certVersionOption = new Option<string?>(
            name: ClassStrings.OptionNameCertVersion,
            description: ClassStrings.OptionDescriptionCertVersion)
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
        command.AddOption(certNameOption);
        command.AddOption(certVersionOption);
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
    /// Creates the client factory used to access Azure Key Vault.
    /// </summary>
    /// <param name="vaultUri">The Key Vault URI.</param>
    /// <param name="credential">The credential used to authenticate.</param>
    /// <returns>A client factory instance.</returns>
    protected virtual IKeyVaultClientFactory CreateClientFactory(Uri vaultUri, TokenCredential credential)
    {
        return new KeyVaultClientFactory(vaultUri, credential);
    }

    /// <inheritdoc/>
    /// <exception cref="InvalidOperationException">Required options are missing.</exception>
    /// <exception cref="ArgumentException">The provided Key Vault URL is not valid.</exception>
    public async Task<ISigningService<SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options)
    {
        VaultUrl = options[ClassStrings.OptionKeyVault] as string
            ?? throw new InvalidOperationException(ClassStrings.ErrorVaultUrlRequired);
        CertificateName = options[ClassStrings.OptionKeyCertName] as string
            ?? throw new InvalidOperationException(ClassStrings.ErrorCertNameRequired);
        CertificateVersion = options.TryGetValue(ClassStrings.OptionKeyCertVersion, out var version) ? version as string : null;

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
            [ClassStrings.MetadataKeyCertificateSource] = ClassStrings.MetadataValueCertificateSource,
            [ClassStrings.MetadataKeyVaultUrl] = VaultUrl ?? ClassStrings.MetadataValueUnknown,
            [ClassStrings.MetadataKeyCertificateName] = CertificateName ?? ClassStrings.MetadataValueUnknown
        };

        if (CertificateSource != null)
        {
            metadata[ClassStrings.MetadataKeyCertificateVersion] = CertificateSource.Version ?? ClassStrings.MetadataValueLatest;
            metadata[ClassStrings.MetadataKeyPinnedVersion] = CertificateSource.IsPinnedVersion.ToString();
            metadata[ClassStrings.MetadataKeyKeyMode] = CertificateSource.KeyMode.ToString();
            metadata[ClassStrings.MetadataKeyRequiresRemoteSigning] = CertificateSource.RequiresRemoteSigning.ToString();

            var signingCert = CertificateSource.GetSigningCertificate();
            if (signingCert != null)
            {
                metadata[ClassStrings.MetadataKeyCertificateSubject] = signingCert.Subject;
                metadata[ClassStrings.MetadataKeyCertificateThumbprint] = signingCert.Thumbprint;
            }

            if (!CertificateSource.IsPinnedVersion && CertificateSource.AutoRefreshInterval.HasValue)
            {
                metadata[ClassStrings.MetadataKeyAutoRefreshInterval] = CertificateSource.AutoRefreshInterval.Value.TotalMinutes + ClassStrings.SuffixMinutes;
            }
        }

        return metadata;
    }
}
