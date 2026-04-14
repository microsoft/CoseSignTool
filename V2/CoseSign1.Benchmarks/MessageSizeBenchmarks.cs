// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Benchmarks;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using CoseSign1.Certificates;
using CoseSign1.Certificates.Local;
using CoseSign1.Factories.Direct;
using CoseSign1.Factories.Indirect;

/// <summary>
/// Reports COSE_Sign1 message sizes across all algorithms.
/// The benchmark itself is a no-op; sizes are printed during GlobalSetup.
/// </summary>
[MemoryDiagnoser]
public class MessageSizeBenchmarks
{
    private Dictionary<string, int> sizes = new();

    [GlobalSetup]
    public void Setup()
    {
        byte[] payload = new byte[1024];
        Random.Shared.NextBytes(payload);

        DateTimeOffset notBefore = DateTimeOffset.Now.AddDays(-1);
        DateTimeOffset notAfter = DateTimeOffset.Now.AddHours(2);
        string contentType = "application/octet-stream";

        // ECDSA P-256
        using ECDsa ecdsaP256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest ecdsaP256Req = new("CN=Size-P256", ecdsaP256, HashAlgorithmName.SHA256);
        using X509Certificate2 ecdsaP256Cert = ecdsaP256Req.CreateSelfSigned(notBefore, notAfter);
        CertificateSigningService ecdsaP256Service = CertificateSigningService.Create(ecdsaP256Cert, new[] { ecdsaP256Cert });
        using DirectSignatureFactory ecdsaP256Factory = new(ecdsaP256Service);
        this.sizes["ECDSA P-256"] = ecdsaP256Factory.CreateCoseSign1MessageBytes(payload, contentType).Length;

        // ECDSA P-384
        using ECDsa ecdsaP384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        CertificateRequest ecdsaP384Req = new("CN=Size-P384", ecdsaP384, HashAlgorithmName.SHA384);
        using X509Certificate2 ecdsaP384Cert = ecdsaP384Req.CreateSelfSigned(notBefore, notAfter);
        CertificateSigningService ecdsaP384Service = CertificateSigningService.Create(ecdsaP384Cert, new[] { ecdsaP384Cert });
        using DirectSignatureFactory ecdsaP384Factory = new(ecdsaP384Service);
        this.sizes["ECDSA P-384"] = ecdsaP384Factory.CreateCoseSign1MessageBytes(payload, contentType).Length;

        // RSA-PSS 2048
        using RSA rsa = RSA.Create(2048);
        CertificateRequest rsaReq = new("CN=Size-RSA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        using X509Certificate2 rsaCert = rsaReq.CreateSelfSigned(notBefore, notAfter);
        CertificateSigningService rsaService = CertificateSigningService.Create(rsaCert, new[] { rsaCert });
        using DirectSignatureFactory rsaFactory = new(rsaService);
        this.sizes["RSA-PSS 2048"] = rsaFactory.CreateCoseSign1MessageBytes(payload, contentType).Length;

#pragma warning disable SYSLIB5006 // ML-DSA is preview in .NET 10
        // ML-DSA-65
        EphemeralCertificateFactory certFactory = new();
        using X509Certificate2 mldsaCert = certFactory.CreateCertificate(opts =>
        {
            opts.SubjectName = "CN=Size-MLDSA65";
            opts.KeyAlgorithm = KeyAlgorithm.MLDSA;
            opts.KeySize = 65;
        });
        CertificateSigningService mldsaService = CertificateSigningService.Create(mldsaCert, new[] { mldsaCert });
        using DirectSignatureFactory mldsaFactory = new(mldsaService);
        this.sizes["ML-DSA-65"] = mldsaFactory.CreateCoseSign1MessageBytes(payload, contentType).Length;
#pragma warning restore SYSLIB5006

        // Indirect ECDSA P-256 (hash-then-sign)
        using IndirectSignatureFactory indirectP256Factory = new(ecdsaP256Factory);
        this.sizes["ES256 Indirect SHA-256"] = indirectP256Factory.CreateCoseSign1MessageBytes(payload, contentType).Length;

        // EdDSA / Ed25519: N/A — System.Security.Cryptography.EdDsa does not exist in .NET 10

        // Print table
        Console.WriteLine();
        Console.WriteLine("=== COSE_Sign1 Message Sizes (1 KB payload) ===");
        Console.WriteLine($"{"Algorithm",-25} {"Size",10} {"Overhead",10} {"Overhead%",10}");
        foreach (KeyValuePair<string, int> entry in this.sizes)
        {
            int overhead = entry.Value - 1024;
            double pct = overhead * 100.0 / 1024;
            Console.WriteLine($"{entry.Key,-25} {entry.Value,10:N0} {overhead,10:N0} {pct,9:F1}%");
        }

        Console.WriteLine();
    }

    [Benchmark(Description = "Message size reference (no-op)")]
    public int Reference() => this.sizes.Count;
}