// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Local;
using CoseSignTool.Plugins;

namespace CoseSignTool.Local.Plugin;

/// <summary>
/// Command provider for signing with PEM certificate and key files on Linux/macOS.
/// </summary>
public class PemSigningCommandProvider : ISigningCommandProvider
{
    private ISigningService<CoseSign1.Abstractions.SigningOptions>? SigningService;
    private string? CertificateSubject;
    private string? CertificateThumbprint;

    public string CommandName => "sign-pem";

    public string CommandDescription => "Sign a payload with PEM certificate and private key files";

    public string ExampleUsage => "--cert-file cert.pem --key-file key.pem";

    public void AddCommandOptions(Command command)
    {
        var certFileOption = new Option<FileInfo>(
            name: "--cert-file",
            description: "Path to the certificate file (.pem, .crt)")
        {
            IsRequired = true
        };

        var keyFileOption = new Option<FileInfo>(
            name: "--key-file",
            description: "Path to the private key file (.key, .pem)")
        {
            IsRequired = true
        };

        command.AddOption(certFileOption);
        command.AddOption(keyFileOption);
    }

    public async Task<ISigningService<CoseSign1.Abstractions.SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options)
    {
        var certFile = options["cert-file"] as FileInfo
            ?? throw new InvalidOperationException("Certificate file is required");
        var keyFile = options["key-file"] as FileInfo
            ?? throw new InvalidOperationException("Private key file is required");

        if (!certFile.Exists)
        {
            throw new FileNotFoundException($"Certificate file not found: {certFile.FullName}");
        }

        if (!keyFile.Exists)
        {
            throw new FileNotFoundException($"Private key file not found: {keyFile.FullName}");
        }

        // Create certificate source from PEM files
        var certSource = new LinuxCertificateStoreCertificateSource(
            certFile.FullName,
            keyFile.FullName);

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
            ["Certificate Source"] = "PEM files",
            ["Certificate Subject"] = CertificateSubject ?? "Unknown",
            ["Certificate Thumbprint"] = CertificateThumbprint ?? "Unknown"
        };
    }
}