// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Local;
using CoseSignTool.Abstractions;

namespace CoseSignTool.Local.Plugin;

/// <summary>
/// Command provider for signing by searching Linux/macOS certificate store paths by thumbprint.
/// </summary>
public class LinuxCertStoreSigningCommandProvider : ISigningCommandProvider
{
    private ISigningService<CoseSign1.Abstractions.SigningOptions>? SigningService;
    private string? CertificateSubject;
    private string? CertificateThumbprint;

    public string CommandName => "sign-certstore";

    public string CommandDescription => "Sign a payload by searching system certificate store paths by thumbprint";

    public string ExampleUsage => "--thumbprint ABC123";

    public void AddCommandOptions(Command command)
    {
        var thumbprintOption = new Option<string>(
            name: "--thumbprint",
            description: "Certificate thumbprint (hex string) to search in system certificate paths")
        {
            IsRequired = true
        };

        var storePathsOption = new Option<string[]?>(
            name: "--store-paths",
            description: "Custom certificate store search paths. Defaults: /etc/ssl/certs, /etc/pki/tls/certs, ~/.certs");

        command.AddOption(thumbprintOption);
        command.AddOption(storePathsOption);
    }

    public async Task<ISigningService<CoseSign1.Abstractions.SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options)
    {
        var thumbprint = options["thumbprint"] as string
            ?? throw new InvalidOperationException("Thumbprint is required");

        var storePaths = options.TryGetValue("store-paths", out var paths) ? paths as string[] : null;
        var searchPaths = storePaths?.AsEnumerable() ?? LinuxCertificateStoreCertificateSource.DefaultCertificateStorePaths;

        // Create certificate source by searching system paths
        var certSource = new LinuxCertificateStoreCertificateSource(thumbprint, searchPaths);
        var signingCert = certSource.GetSigningCertificate();
        var chainBuilder = certSource.GetChainBuilder();

        // Store metadata
        CertificateSubject = signingCert.Subject;
        CertificateThumbprint = signingCert.Thumbprint;

        // Create signing service
        SigningService = new LocalCertificateSigningService(signingCert, chainBuilder);

        return await Task.FromResult(SigningService);
    }

    public IDictionary<string, string> GetSigningMetadata()
    {
        return new Dictionary<string, string>
        {
            ["Certificate Source"] = "Linux certificate store",
            ["Certificate Subject"] = CertificateSubject ?? "Unknown",
            ["Certificate Thumbprint"] = CertificateThumbprint ?? "Unknown"
        };
    }
}