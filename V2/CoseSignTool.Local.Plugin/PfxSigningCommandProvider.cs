// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Local;
using CoseSignTool.Plugins;

namespace CoseSignTool.Local.Plugin;

/// <summary>
/// Command provider for signing with PFX/PKCS#12 certificate files.
/// </summary>
public class PfxSigningCommandProvider : ISigningCommandProvider
{
    private ISigningService<CoseSign1.Abstractions.SigningOptions>? _signingService;
    private string? _certificateSubject;
    private string? _certificateThumbprint;

    public string CommandName => "sign-pfx";

    public string CommandDescription => "Sign a payload with a PFX/PKCS#12 certificate file";

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

        if (!pfxFile.Exists)
        {
            throw new FileNotFoundException($"PFX file not found: {pfxFile.FullName}");
        }

        // Create certificate source
        var certSource = new PfxCertificateSource(pfxFile.FullName, pfxPassword);
        var signingCert = certSource.GetSigningCertificate();
        var chainBuilder = certSource.GetChainBuilder();

        // Store metadata for later display
        _certificateSubject = signingCert.Subject;
        _certificateThumbprint = signingCert.Thumbprint;

        // Create and return signing service
        _signingService = new LocalCertificateSigningService(signingCert, chainBuilder);
        
        return await Task.FromResult(_signingService);
    }

    public IDictionary<string, string> GetSigningMetadata()
    {
        return new Dictionary<string, string>
        {
            ["Certificate Source"] = "PFX file",
            ["Certificate Subject"] = _certificateSubject ?? "Unknown",
            ["Certificate Thumbprint"] = _certificateThumbprint ?? "Unknown"
        };
    }
}
