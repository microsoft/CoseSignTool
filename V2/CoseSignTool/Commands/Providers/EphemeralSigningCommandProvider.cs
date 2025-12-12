// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Local;
using CoseSignTool.Plugins;

namespace CoseSignTool.Commands.Providers;

/// <summary>
/// Built-in command provider for ephemeral test certificate signing.
/// </summary>
public class EphemeralSigningCommandProvider : ISigningCommandProvider
{
    public string CommandName => "sign-ephemeral";

    public string CommandDescription => "Sign a payload with COSE Sign1 (ephemeral test certificate - not for production)";

    public void AddCommandOptions(Command command)
    {
        // Ephemeral signing has no additional options - uses generated certificate
    }

    public IDictionary<string, string> GetSigningMetadata()
    {
        return new Dictionary<string, string>
        {
            ["Provider"] = "Ephemeral",
            ["CertificateType"] = "Self-Signed Test Certificate",
            ["Warning"] = "Not for production use"
        };
    }

    public async Task<ISigningService<CoseSign1.Abstractions.SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options)
    {
        // Generate ephemeral certificate for testing
        var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest(
            "CN=CoseSignTool Ephemeral Test Certificate",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        certReq.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature,
                critical: true));

        var cert = certReq.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddHours(1));

        // Create signing service with ephemeral certificate
        var chainBuilder = new X509ChainBuilder();
        var signingService = new LocalCertificateSigningService(cert, chainBuilder);
        
        return await Task.FromResult(signingService);
    }
}
