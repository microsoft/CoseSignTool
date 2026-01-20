// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.AzureTrustedSigning.Plugin;

using System.CommandLine;
using System.Diagnostics.CodeAnalysis;
using Azure.Developer.TrustedSigning.CryptoProvider;
using Azure.Identity;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.AzureTrustedSigning;
using CoseSignTool.Abstractions;

/// <summary>
/// Command provider for signing with Azure Trusted Signing service.
/// </summary>
public class AzureTrustedSigningCommandProvider : ISigningCommandProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string CommandNameValue = "x509-ats";
        public static readonly string CommandDescriptionValue = "Sign a payload using Azure Trusted Signing service";
        public static readonly string ExampleUsageValue = "--ats-endpoint https://... --ats-account-name <account> --ats-cert-profile-name <profile>";

        public static readonly string OptionNameAtsEndpoint = "--ats-endpoint";
        public static readonly string OptionNameAtsAccountName = "--ats-account-name";
        public static readonly string OptionNameAtsCertProfileName = "--ats-cert-profile-name";

        public static readonly string OptionKeyAtsEndpoint = "ats-endpoint";
        public static readonly string OptionKeyAtsAccountName = "ats-account-name";
        public static readonly string OptionKeyAtsCertProfileName = "ats-cert-profile-name";

        public static readonly string OptionDescriptionAtsEndpoint = "Azure Trusted Signing endpoint URL (e.g., https://xxx.codesigning.azure.net)";
        public static readonly string OptionDescriptionAtsAccountName = "Azure Trusted Signing account name";
        public static readonly string OptionDescriptionAtsCertProfileName = "Certificate profile name in Azure Trusted Signing";

        public static readonly string ErrorAtsEndpointRequired = "Azure Trusted Signing endpoint is required";
        public static readonly string ErrorAtsAccountNameRequired = "Azure Trusted Signing account name is required";
        public static readonly string ErrorAtsCertProfileRequired = "Certificate profile name is required";
        public static readonly string ErrorFormatInvalidEndpointUrl = "Invalid Azure Trusted Signing endpoint URL: {0}";

        public static readonly string MetadataKeyCertificateSource = "Certificate Source";
        public static readonly string MetadataKeyAccountName = "Account Name";
        public static readonly string MetadataKeyCertificateProfile = "Certificate Profile";
        public static readonly string MetadataKeyCertificateSubject = "Certificate Subject";
        public static readonly string MetadataValueCertificateSource = "Azure Trusted Signing";
        public static readonly string MetadataValueUnknown = "Unknown";

        public static readonly string DefaultCertificateSubject = "Azure Trusted Signing Certificate";
    }

    private ISigningService<CoseSign1.Abstractions.SigningOptions>? SigningService;
    private string? CertificateSubject;
    private string? AccountName;
    private string? CertificateProfileName;

    /// <inheritdoc/>
    public string CommandName => ClassStrings.CommandNameValue;

    /// <inheritdoc/>
    public string CommandDescription => ClassStrings.CommandDescriptionValue;

    /// <inheritdoc/>
    public string ExampleUsage => ClassStrings.ExampleUsageValue;

    /// <inheritdoc/>
    public void AddCommandOptions(Command command)
    {
        var endpointOption = new Option<string>(
            name: ClassStrings.OptionNameAtsEndpoint,
            description: ClassStrings.OptionDescriptionAtsEndpoint)
        {
            IsRequired = true
        };

        var accountNameOption = new Option<string>(
            name: ClassStrings.OptionNameAtsAccountName,
            description: ClassStrings.OptionDescriptionAtsAccountName)
        {
            IsRequired = true
        };

        var certProfileOption = new Option<string>(
            name: ClassStrings.OptionNameAtsCertProfileName,
            description: ClassStrings.OptionDescriptionAtsCertProfileName)
        {
            IsRequired = true
        };

        command.AddOption(endpointOption);
        command.AddOption(accountNameOption);
        command.AddOption(certProfileOption);
    }

    /// <inheritdoc/>
    /// <exception cref="InvalidOperationException">Required options are missing.</exception>
    /// <exception cref="ArgumentException">The provided endpoint URL is not valid.</exception>
    public async Task<ISigningService<CoseSign1.Abstractions.SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options)
    {
        var endpoint = options[ClassStrings.OptionKeyAtsEndpoint] as string
            ?? throw new InvalidOperationException(ClassStrings.ErrorAtsEndpointRequired);
        AccountName = options[ClassStrings.OptionKeyAtsAccountName] as string
            ?? throw new InvalidOperationException(ClassStrings.ErrorAtsAccountNameRequired);
        CertificateProfileName = options[ClassStrings.OptionKeyAtsCertProfileName] as string
            ?? throw new InvalidOperationException(ClassStrings.ErrorAtsCertProfileRequired);

        // Create Azure credential with non-interactive authentication
        var credential = new DefaultAzureCredential(new DefaultAzureCredentialOptions
        {
            ExcludeInteractiveBrowserCredential = true
        });

        // Parse endpoint URI
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var endpointUri))
        {
            throw new ArgumentException(string.Format(ClassStrings.ErrorFormatInvalidEndpointUrl, endpoint));
        }

        // Create certificate profile client
        var certificateProfileClient = new Azure.CodeSigning.CertificateProfileClient(credential, endpointUri);

        // Create signing context
        var signContext = new AzSignContext(endpoint, AccountName, certificateProfileClient);

        // Create Azure Trusted Signing service
        SigningService = new AzureTrustedSigningService(signContext);

        // Get certificate info for metadata
        // Note: API has changed - commented out for now
        /*
        try
        {
            var certificates = await certificateProfileClient.GetCertificatesAsync(_certificateProfileName);
            if (certificates?.Value?.Certificates?.Count > 0)
            {
                _certificateSubject = certificates.Value.Certificates[0].SubjectName;
            }
        }
        catch
        {
            // Certificate metadata retrieval is best-effort
        }
        */
        CertificateSubject = ClassStrings.DefaultCertificateSubject;

        return SigningService;
    }

    /// <inheritdoc/>
    public IDictionary<string, string> GetSigningMetadata()
    {
        return new Dictionary<string, string>
        {
            [ClassStrings.MetadataKeyCertificateSource] = ClassStrings.MetadataValueCertificateSource,
            [ClassStrings.MetadataKeyAccountName] = AccountName ?? ClassStrings.MetadataValueUnknown,
            [ClassStrings.MetadataKeyCertificateProfile] = CertificateProfileName ?? ClassStrings.MetadataValueUnknown,
            [ClassStrings.MetadataKeyCertificateSubject] = CertificateSubject ?? ClassStrings.MetadataValueUnknown
        };
    }
}