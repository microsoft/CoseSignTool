// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Benchmarks;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using CoseSign1.Certificates;
using CoseSign1.Certificates.Local;
using CoseSign1.Factories.Direct;

/// <summary>
/// Benchmarks for COSE Sign1 direct signature creation using certificate-based signing.
/// Measures signing throughput for different payload sizes and key algorithms.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(warmupCount: 3, iterationCount: 20)]
public class SigningBenchmarks : IDisposable
{
    private DirectSignatureFactory ecdsaP256Factory = null!;
    private DirectSignatureFactory ecdsaP384Factory = null!;
    private DirectSignatureFactory rsaFactory = null!;
    private DirectSignatureFactory mldsaFactory = null!;
    private X509Certificate2 ecdsaP256Cert = null!;
    private X509Certificate2 ecdsaP384Cert = null!;
    private X509Certificate2 rsaCert = null!;
    private X509Certificate2 mldsaCert = null!;
    private byte[] payload1KB = null!;
    private byte[] payload100KB = null!;
    private byte[] payload1MB = null!;

    [GlobalSetup]
    public void Setup()
    {
        DateTimeOffset notBefore = DateTimeOffset.Now.AddDays(-1);
        DateTimeOffset notAfter = DateTimeOffset.Now.AddHours(2);

        // ECDSA P-256
        using ECDsa ecdsaP256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest ecdsaP256Req = new("CN=Benchmark-ECDSA-P256", ecdsaP256, HashAlgorithmName.SHA256);
        this.ecdsaP256Cert = ecdsaP256Req.CreateSelfSigned(notBefore, notAfter);

        CertificateSigningService ecdsaP256Service = CertificateSigningService.Create(
            this.ecdsaP256Cert,
            new X509Certificate2[] { this.ecdsaP256Cert });
        this.ecdsaP256Factory = new DirectSignatureFactory(ecdsaP256Service);

        // ECDSA P-384
        using ECDsa ecdsaP384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        CertificateRequest ecdsaP384Req = new("CN=Benchmark-ECDSA-P384", ecdsaP384, HashAlgorithmName.SHA384);
        this.ecdsaP384Cert = ecdsaP384Req.CreateSelfSigned(notBefore, notAfter);

        CertificateSigningService ecdsaP384Service = CertificateSigningService.Create(
            this.ecdsaP384Cert,
            new X509Certificate2[] { this.ecdsaP384Cert });
        this.ecdsaP384Factory = new DirectSignatureFactory(ecdsaP384Service);

        // RSA-2048
        using RSA rsa = RSA.Create(2048);
        CertificateRequest rsaReq = new("CN=Benchmark-RSA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        this.rsaCert = rsaReq.CreateSelfSigned(notBefore, notAfter);

        CertificateSigningService rsaService = CertificateSigningService.Create(
            this.rsaCert,
            new X509Certificate2[] { this.rsaCert });
        this.rsaFactory = new DirectSignatureFactory(rsaService);

#pragma warning disable SYSLIB5006 // ML-DSA is preview in .NET 10
        // ML-DSA-65 (Post-Quantum)
        EphemeralCertificateFactory certFactory = new();
        this.mldsaCert = certFactory.CreateCertificate(opts =>
        {
            opts.SubjectName = "CN=Benchmark-MLDSA65";
            opts.KeyAlgorithm = KeyAlgorithm.MLDSA;
            opts.KeySize = 65;
        });

        CertificateSigningService mldsaService = CertificateSigningService.Create(
            this.mldsaCert,
            new X509Certificate2[] { this.mldsaCert });
        this.mldsaFactory = new DirectSignatureFactory(mldsaService);
#pragma warning restore SYSLIB5006

        // Generate payloads
        this.payload1KB = new byte[1024];
        this.payload100KB = new byte[100 * 1024];
        this.payload1MB = new byte[1024 * 1024];
        Random.Shared.NextBytes(this.payload1KB);
        Random.Shared.NextBytes(this.payload100KB);
        Random.Shared.NextBytes(this.payload1MB);
    }

    [GlobalCleanup]
    public void Cleanup() => this.Dispose();

    public void Dispose()
    {
        this.ecdsaP256Factory?.Dispose();
        this.ecdsaP384Factory?.Dispose();
        this.rsaFactory?.Dispose();
        this.mldsaFactory?.Dispose();
        this.ecdsaP256Cert?.Dispose();
        this.ecdsaP384Cert?.Dispose();
        this.rsaCert?.Dispose();
        this.mldsaCert?.Dispose();
        GC.SuppressFinalize(this);
    }

    // --- ECDSA P-256 ---

    [Benchmark(Description = "Sign ECDSA P-256 1 KB")]
    public byte[] Sign_ECDSA_P256_1KB() =>
        this.ecdsaP256Factory.CreateCoseSign1MessageBytes(this.payload1KB, "application/octet-stream");

    [Benchmark(Description = "Sign ECDSA P-256 100 KB")]
    public byte[] Sign_ECDSA_P256_100KB() =>
        this.ecdsaP256Factory.CreateCoseSign1MessageBytes(this.payload100KB, "application/octet-stream");

    [Benchmark(Description = "Sign ECDSA P-256 1 MB")]
    public byte[] Sign_ECDSA_P256_1MB() =>
        this.ecdsaP256Factory.CreateCoseSign1MessageBytes(this.payload1MB, "application/octet-stream");

    // --- ECDSA P-384 ---

    [Benchmark(Description = "Sign ECDSA P-384 1 KB")]
    public byte[] Sign_ECDSA_P384_1KB() =>
        this.ecdsaP384Factory.CreateCoseSign1MessageBytes(this.payload1KB, "application/octet-stream");

    [Benchmark(Description = "Sign ECDSA P-384 100 KB")]
    public byte[] Sign_ECDSA_P384_100KB() =>
        this.ecdsaP384Factory.CreateCoseSign1MessageBytes(this.payload100KB, "application/octet-stream");

    [Benchmark(Description = "Sign ECDSA P-384 1 MB")]
    public byte[] Sign_ECDSA_P384_1MB() =>
        this.ecdsaP384Factory.CreateCoseSign1MessageBytes(this.payload1MB, "application/octet-stream");

    // --- RSA-2048 ---

    [Benchmark(Description = "Sign RSA-2048 1 KB")]
    public byte[] Sign_RSA2048_1KB() =>
        this.rsaFactory.CreateCoseSign1MessageBytes(this.payload1KB, "application/octet-stream");

    [Benchmark(Description = "Sign RSA-2048 100 KB")]
    public byte[] Sign_RSA2048_100KB() =>
        this.rsaFactory.CreateCoseSign1MessageBytes(this.payload100KB, "application/octet-stream");

    [Benchmark(Description = "Sign RSA-2048 1 MB")]
    public byte[] Sign_RSA2048_1MB() =>
        this.rsaFactory.CreateCoseSign1MessageBytes(this.payload1MB, "application/octet-stream");

    // --- ML-DSA-65 (Post-Quantum) ---

    [Benchmark(Description = "Sign ML-DSA-65 1 KB")]
    public byte[] Sign_MLDSA65_1KB() =>
        this.mldsaFactory.CreateCoseSign1MessageBytes(this.payload1KB, "application/octet-stream");

    [Benchmark(Description = "Sign ML-DSA-65 100 KB")]
    public byte[] Sign_MLDSA65_100KB() =>
        this.mldsaFactory.CreateCoseSign1MessageBytes(this.payload100KB, "application/octet-stream");

    [Benchmark(Description = "Sign ML-DSA-65 1 MB")]
    public byte[] Sign_MLDSA65_1MB() =>
        this.mldsaFactory.CreateCoseSign1MessageBytes(this.payload1MB, "application/octet-stream");
}
