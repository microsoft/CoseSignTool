// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Benchmarks;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using CoseSign1.Certificates;
using CoseSign1.Factories.Direct;

/// <summary>
/// Benchmarks for COSE Sign1 direct signature creation using certificate-based signing.
/// Measures signing throughput for different payload sizes and key algorithms.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(warmupCount: 3, iterationCount: 20)]
public class SigningBenchmarks : IDisposable
{
    private DirectSignatureFactory ecdsaFactory = null!;
    private DirectSignatureFactory rsaFactory = null!;
    private X509Certificate2 ecdsaCert = null!;
    private X509Certificate2 rsaCert = null!;
    private byte[] payload1KB = null!;
    private byte[] payload100KB = null!;
    private byte[] payload1MB = null!;

    [GlobalSetup]
    public void Setup()
    {
        // Create self-signed ECDSA P-256 cert
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest ecdsaReq = new("CN=Benchmark-ECDSA", ecdsa, HashAlgorithmName.SHA256);
        this.ecdsaCert = ecdsaReq.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddHours(2));

        CertificateSigningService ecdsaService = CertificateSigningService.Create(
            this.ecdsaCert,
            new X509Certificate2[] { this.ecdsaCert });
        this.ecdsaFactory = new DirectSignatureFactory(ecdsaService);

        // Create self-signed RSA 2048 cert
        using RSA rsa = RSA.Create(2048);
        CertificateRequest rsaReq = new("CN=Benchmark-RSA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        this.rsaCert = rsaReq.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddHours(2));

        CertificateSigningService rsaService = CertificateSigningService.Create(
            this.rsaCert,
            new X509Certificate2[] { this.rsaCert });
        this.rsaFactory = new DirectSignatureFactory(rsaService);

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
        this.ecdsaFactory?.Dispose();
        this.rsaFactory?.Dispose();
        this.ecdsaCert?.Dispose();
        this.rsaCert?.Dispose();
        GC.SuppressFinalize(this);
    }

    [Benchmark(Description = "Sign ECDSA P-256 1 KB")]
    public byte[] Sign_ECDSA_P256_1KB() =>
        this.ecdsaFactory.CreateCoseSign1MessageBytes(this.payload1KB, "application/octet-stream");

    [Benchmark(Description = "Sign ECDSA P-256 100 KB")]
    public byte[] Sign_ECDSA_P256_100KB() =>
        this.ecdsaFactory.CreateCoseSign1MessageBytes(this.payload100KB, "application/octet-stream");

    [Benchmark(Description = "Sign ECDSA P-256 1 MB")]
    public byte[] Sign_ECDSA_P256_1MB() =>
        this.ecdsaFactory.CreateCoseSign1MessageBytes(this.payload1MB, "application/octet-stream");

    [Benchmark(Description = "Sign RSA-2048 1 KB")]
    public byte[] Sign_RSA2048_1KB() =>
        this.rsaFactory.CreateCoseSign1MessageBytes(this.payload1KB, "application/octet-stream");

    [Benchmark(Description = "Sign RSA-2048 100 KB")]
    public byte[] Sign_RSA2048_100KB() =>
        this.rsaFactory.CreateCoseSign1MessageBytes(this.payload100KB, "application/octet-stream");
}
