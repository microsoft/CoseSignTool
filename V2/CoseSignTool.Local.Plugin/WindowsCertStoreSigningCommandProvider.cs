// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Local;
using CoseSignTool.Plugins;
using Microsoft.Extensions.Logging;

namespace CoseSignTool.Local.Plugin;

/// <summary>
/// Command provider for signing with Windows certificate store.
/// </summary>
public class WindowsCertStoreSigningCommandProvider : ISigningCommandProvider
{
    private ISigningService<CoseSign1.Abstractions.SigningOptions>? SigningService;
    private string? CertificateSubject;
    private string? CertificateThumbprint;

    public string CommandName => "sign-certstore";

    public string CommandDescription => "Sign a payload with a certificate from Windows certificate store";

    public string ExampleUsage => "--thumbprint ABC123";

    public void AddCommandOptions(Command command)
    {
        var thumbprintOption = new Option<string>(
            name: "--thumbprint",
            description: "Certificate thumbprint (hex string) to find in the certificate store")
        {
            IsRequired = true
        };

        var storeLocationOption = new Option<string>(
            name: "--store-location",
            getDefaultValue: () => "CurrentUser",
            description: "Certificate store location (CurrentUser or LocalMachine)");

        var storeNameOption = new Option<string>(
            name: "--store-name",
            getDefaultValue: () => "My",
            description: "Certificate store name (My, Root, CA, etc.)");

        command.AddOption(thumbprintOption);
        command.AddOption(storeLocationOption);
        command.AddOption(storeNameOption);
    }

    public async Task<ISigningService<CoseSign1.Abstractions.SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options)
    {
        var thumbprint = options["thumbprint"] as string
            ?? throw new InvalidOperationException("Thumbprint is required");
        var storeLocation = options.TryGetValue("store-location", out var loc) ? loc as string ?? "CurrentUser" : "CurrentUser";
        var storeName = options.TryGetValue("store-name", out var name) ? name as string ?? "My" : "My";

        // Get logger factory if provided
        var loggerFactory = options.TryGetValue("__loggerFactory", out var lf) ? lf as ILoggerFactory : null;
        var logger = loggerFactory?.CreateLogger<WindowsCertificateStoreCertificateSource>();

        // Parse store location and name
        var storeLocationEnum = Enum.Parse<StoreLocation>(storeLocation, ignoreCase: true);
        var storeNameEnum = Enum.Parse<StoreName>(storeName, ignoreCase: true);

        // Create certificate source with logging
        var certSource = new WindowsCertificateStoreCertificateSource(
            thumbprint,
            storeNameEnum,
            storeLocationEnum,
            logger: logger);

        var signingCert = certSource.GetSigningCertificate();
        var chainBuilder = certSource.GetChainBuilder();

        // Store metadata
        CertificateSubject = signingCert.Subject;
        CertificateThumbprint = signingCert.Thumbprint;

        // Create logger for signing service
        var signingServiceLogger = loggerFactory?.CreateLogger<LocalCertificateSigningService>();

        // Create signing service
        SigningService = new LocalCertificateSigningService(signingCert, chainBuilder, signingServiceLogger);

        return await Task.FromResult(SigningService);
    }

    public IDictionary<string, string> GetSigningMetadata()
    {
        return new Dictionary<string, string>
        {
            ["Certificate Source"] = "Windows certificate store",
            ["Certificate Subject"] = CertificateSubject ?? "Unknown",
            ["Certificate Thumbprint"] = CertificateThumbprint ?? "Unknown"
        };
    }
}