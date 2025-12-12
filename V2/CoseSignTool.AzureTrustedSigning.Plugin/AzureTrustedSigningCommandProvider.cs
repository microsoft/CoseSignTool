// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using Azure.Developer.TrustedSigning.CryptoProvider;
using Azure.Identity;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.AzureTrustedSigning;
using CoseSignTool.Plugins;

namespace CoseSignTool.AzureTrustedSigning.Plugin;

/// <summary>
/// Command provider for signing with Azure Trusted Signing service.
/// </summary>
public class AzureTrustedSigningCommandProvider : ISigningCommandProvider
{
    private ISigningService<CoseSign1.Abstractions.SigningOptions>? _signingService;
    private string? _certificateSubject;
    private string? _accountName;
    private string? _certificateProfileName;

    public string CommandName => "sign-azure";

    public string CommandDescription => "Sign a payload using Azure Trusted Signing service";

    public void AddCommandOptions(Command command)
    {
        var endpointOption = new Option<string>(
            name: "--ats-endpoint",
            description: "Azure Trusted Signing endpoint URL (e.g., https://xxx.codesigning.azure.net)")
        {
            IsRequired = true
        };

        var accountNameOption = new Option<string>(
            name: "--ats-account-name",
            description: "Azure Trusted Signing account name")
        {
            IsRequired = true
        };

        var certProfileOption = new Option<string>(
            name: "--ats-cert-profile-name",
            description: "Certificate profile name in Azure Trusted Signing")
        {
            IsRequired = true
        };

        command.AddOption(endpointOption);
        command.AddOption(accountNameOption);
        command.AddOption(certProfileOption);
    }

    public async Task<ISigningService<CoseSign1.Abstractions.SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options)
    {
        var endpoint = options["ats-endpoint"] as string
            ?? throw new InvalidOperationException("Azure Trusted Signing endpoint is required");
        _accountName = options["ats-account-name"] as string
            ?? throw new InvalidOperationException("Azure Trusted Signing account name is required");
        _certificateProfileName = options["ats-cert-profile-name"] as string
            ?? throw new InvalidOperationException("Certificate profile name is required");

        // Create Azure credential with non-interactive authentication
        var credential = new DefaultAzureCredential(new DefaultAzureCredentialOptions
        {
            ExcludeInteractiveBrowserCredential = true
        });

        // Parse endpoint URI
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var endpointUri))
        {
            throw new ArgumentException($"Invalid Azure Trusted Signing endpoint URL: {endpoint}");
        }

        // Create certificate profile client
        var certificateProfileClient = new Azure.CodeSigning.CertificateProfileClient(credential, endpointUri);

        // Create signing context
        var signContext = new AzSignContext(endpoint, _accountName, certificateProfileClient);

        // Create Azure Trusted Signing service
        _signingService = new AzureTrustedSigningService(signContext);

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
        _certificateSubject = "Azure Trusted Signing Certificate";

        return _signingService;
    }

    public IDictionary<string, string> GetSigningMetadata()
    {
        return new Dictionary<string, string>
        {
            ["Certificate Source"] = "Azure Trusted Signing",
            ["Account Name"] = _accountName ?? "Unknown",
            ["Certificate Profile"] = _certificateProfileName ?? "Unknown",
            ["Certificate Subject"] = _certificateSubject ?? "Unknown"
        };
    }
}
