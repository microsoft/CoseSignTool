// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Local;
using CoseSignTool.Plugins;
using Microsoft.Extensions.Logging;

namespace CoseSignTool.Local.Plugin;

/// <summary>
/// Command provider for signing with PFX/PKCS#12 certificate files.
/// </summary>
public class PfxSigningCommandProvider : ISigningCommandProvider
{
    private ISigningService<CoseSign1.Abstractions.SigningOptions>? SigningService;
    private string? CertificateSubject;
    private string? CertificateThumbprint;

    public string CommandName => "sign-pfx";

    public string CommandDescription => "Sign a payload with a PFX/PKCS#12 certificate file";

    public string ExampleUsage => "--pfx cert.pfx";

    public void AddCommandOptions(Command command)
    {
        var pfxOption = new Option<FileInfo>(
            name: "--pfx",
            description: "Path to PFX/PKCS#12 file containing the signing certificate")
        {
            IsRequired = true
        };

        var pfxPasswordOption = new Option<string?>(
            name: "--pfx-password",
            description: "Password for the PFX file (if not provided, assumes unprotected)");

        command.AddOption(pfxOption);
        command.AddOption(pfxPasswordOption);
    }

    public async Task<ISigningService<CoseSign1.Abstractions.SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options)
    {
        var pfxFile = options["pfx"] as FileInfo
            ?? throw new InvalidOperationException("PFX file is required");
        var pfxPassword = options.TryGetValue("pfx-password", out var pwd) ? pwd as string : null;

        // Get logger factory if provided
        var loggerFactory = options.TryGetValue("__loggerFactory", out var lf) ? lf as ILoggerFactory : null;
        var logger = loggerFactory?.CreateLogger<PfxCertificateSource>();

        if (!pfxFile.Exists)
        {
            throw new FileNotFoundException($"PFX file not found: {pfxFile.FullName}");
        }

        // Create certificate source with logging
        var certSource = new PfxCertificateSource(pfxFile.FullName, pfxPassword, logger: logger);
        var signingCert = certSource.GetSigningCertificate();
        var chainBuilder = certSource.GetChainBuilder();

        // Store metadata for later display
        CertificateSubject = signingCert.Subject;
        CertificateThumbprint = signingCert.Thumbprint;

        // Create logger for signing service
        var signingServiceLogger = loggerFactory?.CreateLogger<LocalCertificateSigningService>();

        // Create and return signing service
        SigningService = new LocalCertificateSigningService(signingCert, chainBuilder, signingServiceLogger);

        return await Task.FromResult(SigningService);
    }

    public IDictionary<string, string> GetSigningMetadata()
    {
        return new Dictionary<string, string>
        {
            ["Certificate Source"] = "PFX file",
            ["Certificate Subject"] = CertificateSubject ?? "Unknown",
            ["Certificate Thumbprint"] = CertificateThumbprint ?? "Unknown"
        };
    }
}