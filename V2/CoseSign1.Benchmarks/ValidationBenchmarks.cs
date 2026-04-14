// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Benchmarks;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using CoseSign1.Certificates;
using CoseSign1.Factories.Direct;

/// <summary>
/// Benchmarks for COSE Sign1 message parsing and signature verification.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(warmupCount: 3, iterationCount: 20)]
public class ValidationBenchmarks : IDisposable
{
    private byte[] signedBytes1KB = null!;
    private byte[] signedBytes100KB = null!;
    private CoseSign1Message parsedMessage = null!;
    private ECDsa verificationKey = null!;
    private X509Certificate2 cert = null!;
    private DirectSignatureFactory factory = null!;

    [GlobalSetup]
    public void Setup()
    {
        // Create self-signed ECDSA P-256 cert
        this.verificationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest req = new("CN=Benchmark-Validation", this.verificationKey, HashAlgorithmName.SHA256);
        this.cert = req.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddHours(2));

        CertificateSigningService service = CertificateSigningService.Create(
            this.cert,
            new X509Certificate2[] { this.cert });
        this.factory = new DirectSignatureFactory(service);

        byte[] payload1KB = new byte[1024];
        byte[] payload100KB = new byte[100 * 1024];
        Random.Shared.NextBytes(payload1KB);
        Random.Shared.NextBytes(payload100KB);

        this.signedBytes1KB = this.factory.CreateCoseSign1MessageBytes(payload1KB, "application/octet-stream");
        this.signedBytes100KB = this.factory.CreateCoseSign1MessageBytes(payload100KB, "application/octet-stream");
        this.parsedMessage = CoseMessage.DecodeSign1(this.signedBytes1KB);
    }

    [GlobalCleanup]
    public void Cleanup() => this.Dispose();

    public void Dispose()
    {
        this.factory?.Dispose();
        this.cert?.Dispose();
        this.verificationKey?.Dispose();
        GC.SuppressFinalize(this);
    }

    [Benchmark(Description = "Parse CoseSign1 1 KB payload")]
    public CoseSign1Message Parse_1KB() =>
        CoseMessage.DecodeSign1(this.signedBytes1KB);

    [Benchmark(Description = "Parse CoseSign1 100 KB payload")]
    public CoseSign1Message Parse_100KB() =>
        CoseMessage.DecodeSign1(this.signedBytes100KB);

    [Benchmark(Description = "Verify embedded ECDSA signature")]
    public void Verify_Embedded_ECDSA()
    {
        // Re-parse to get a fresh message for verification
        CoseSign1Message message = CoseMessage.DecodeSign1(this.signedBytes1KB);
        message.VerifyEmbedded(this.verificationKey);
    }

    [Benchmark(Description = "Full parse + verify roundtrip 1 KB")]
    public void ParseAndVerify_1KB()
    {
        CoseSign1Message message = CoseMessage.DecodeSign1(this.signedBytes1KB);
        message.VerifyEmbedded(this.verificationKey);
    }
}
