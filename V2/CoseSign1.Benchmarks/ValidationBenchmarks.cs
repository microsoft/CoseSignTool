// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Benchmarks;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using CoseSign1.Certificates;
using CoseSign1.Certificates.Local;
using CoseSign1.Factories.Direct;

/// <summary>
/// Benchmarks for COSE Sign1 message parsing and signature verification
/// across all supported key algorithms, using production-realistic 3-tier
/// certificate chains (Root CA → Intermediate CA → Leaf).
/// </summary>
[MemoryDiagnoser]
[SimpleJob(warmupCount: 3, iterationCount: 20)]
public class ValidationBenchmarks : IDisposable
{
    // ECDSA P-256
    private byte[] ecdsaP256SignedBytes1KB = null!;
    private byte[] ecdsaP256SignedBytes100KB = null!;
    private ECDsa ecdsaP256VerificationKey = null!;
    private DirectSignatureFactory ecdsaP256Factory = null!;
    private X509Certificate2Collection ecdsaP256Chain = null!;

    // ECDSA P-384
    private byte[] ecdsaP384SignedBytes1KB = null!;
    private ECDsa ecdsaP384VerificationKey = null!;
    private DirectSignatureFactory ecdsaP384Factory = null!;
    private X509Certificate2Collection ecdsaP384Chain = null!;

    // RSA-2048
    private byte[] rsaSignedBytes1KB = null!;
    private RSA rsaVerificationKey = null!;
    private DirectSignatureFactory rsaFactory = null!;
    private X509Certificate2Collection rsaChain = null!;

    // ML-DSA-65
    private byte[] mldsaSignedBytes1KB = null!;
    private DirectSignatureFactory mldsaFactory = null!;
    private X509Certificate2Collection mldsaChain = null!;
    private CoseKey mldsaCoseKey = null!;

    [GlobalSetup]
    public void Setup()
    {
        CertificateChainFactory chainFactory = new();
        byte[] payload1KB = new byte[1024];
        byte[] payload100KB = new byte[100 * 1024];
        Random.Shared.NextBytes(payload1KB);
        Random.Shared.NextBytes(payload100KB);

        // --- ECDSA P-256 (3-tier chain: Root CA → Intermediate CA → Leaf) ---
        this.ecdsaP256Chain = chainFactory.CreateChain(opts =>
        {
            opts.KeyAlgorithm = KeyAlgorithm.ECDSA;
            opts.KeySize = 256;
            opts.LeafFirst = true;
        });
        this.ecdsaP256VerificationKey = this.ecdsaP256Chain[0].GetECDsaPublicKey()!;

        CertificateSigningService ecdsaP256Service = CertificateSigningService.Create(
            this.ecdsaP256Chain[0], this.ecdsaP256Chain.ToArray());
        this.ecdsaP256Factory = new DirectSignatureFactory(ecdsaP256Service);
        this.ecdsaP256SignedBytes1KB = this.ecdsaP256Factory.CreateCoseSign1MessageBytes(payload1KB, "application/octet-stream");
        this.ecdsaP256SignedBytes100KB = this.ecdsaP256Factory.CreateCoseSign1MessageBytes(payload100KB, "application/octet-stream");

        // --- ECDSA P-384 (3-tier chain: Root CA → Intermediate CA → Leaf) ---
        this.ecdsaP384Chain = chainFactory.CreateChain(opts =>
        {
            opts.KeyAlgorithm = KeyAlgorithm.ECDSA;
            opts.KeySize = 384;
            opts.LeafFirst = true;
        });
        this.ecdsaP384VerificationKey = this.ecdsaP384Chain[0].GetECDsaPublicKey()!;

        CertificateSigningService ecdsaP384Service = CertificateSigningService.Create(
            this.ecdsaP384Chain[0], this.ecdsaP384Chain.ToArray());
        this.ecdsaP384Factory = new DirectSignatureFactory(ecdsaP384Service);
        this.ecdsaP384SignedBytes1KB = this.ecdsaP384Factory.CreateCoseSign1MessageBytes(payload1KB, "application/octet-stream");

        // --- RSA-2048 (3-tier chain: Root CA → Intermediate CA → Leaf) ---
        this.rsaChain = chainFactory.CreateChain(opts =>
        {
            opts.KeyAlgorithm = KeyAlgorithm.RSA;
            opts.KeySize = 2048;
            opts.LeafFirst = true;
        });
        this.rsaVerificationKey = this.rsaChain[0].GetRSAPublicKey()!;

        CertificateSigningService rsaService = CertificateSigningService.Create(
            this.rsaChain[0], this.rsaChain.ToArray());
        this.rsaFactory = new DirectSignatureFactory(rsaService);
        this.rsaSignedBytes1KB = this.rsaFactory.CreateCoseSign1MessageBytes(payload1KB, "application/octet-stream");

#pragma warning disable SYSLIB5006 // ML-DSA is preview in .NET 10
        // --- ML-DSA-65 (3-tier chain: Root CA → Intermediate CA → Leaf) ---
        this.mldsaChain = chainFactory.CreateChain(opts =>
        {
            opts.KeyAlgorithm = KeyAlgorithm.MLDSA;
            opts.KeySize = 65;
            opts.LeafFirst = true;
        });

        CertificateSigningService mldsaService = CertificateSigningService.Create(
            this.mldsaChain[0], this.mldsaChain.ToArray());
        this.mldsaFactory = new DirectSignatureFactory(mldsaService);
        this.mldsaSignedBytes1KB = this.mldsaFactory.CreateCoseSign1MessageBytes(payload1KB, "application/octet-stream");
        this.mldsaCoseKey = X509CertificateCoseKeyFactory.CreateFromPublicKey(this.mldsaChain[0]);
#pragma warning restore SYSLIB5006
    }

    [GlobalCleanup]
    public void Cleanup() => this.Dispose();

    public void Dispose()
    {
        this.ecdsaP256Factory?.Dispose();
        this.ecdsaP384Factory?.Dispose();
        this.rsaFactory?.Dispose();
        this.mldsaFactory?.Dispose();
        DisposeCertificateChain(this.ecdsaP256Chain);
        DisposeCertificateChain(this.ecdsaP384Chain);
        DisposeCertificateChain(this.rsaChain);
        DisposeCertificateChain(this.mldsaChain);
        this.ecdsaP256VerificationKey?.Dispose();
        this.ecdsaP384VerificationKey?.Dispose();
        this.rsaVerificationKey?.Dispose();
        GC.SuppressFinalize(this);
    }

    private static void DisposeCertificateChain(X509Certificate2Collection? chain)
    {
        if (chain is null)
        {
            return;
        }

        foreach (X509Certificate2 cert in chain)
        {
            cert.Dispose();
        }
    }

    // --- Parse benchmarks ---

    [Benchmark(Description = "Parse CoseSign1 1 KB payload")]
    public CoseSign1Message Parse_1KB() =>
        CoseMessage.DecodeSign1(this.ecdsaP256SignedBytes1KB);

    [Benchmark(Description = "Parse CoseSign1 100 KB payload")]
    public CoseSign1Message Parse_100KB() =>
        CoseMessage.DecodeSign1(this.ecdsaP256SignedBytes100KB);

    // --- Verify ECDSA P-256 ---

    [Benchmark(Description = "Verify embedded ECDSA P-256 1 KB")]
    public void Verify_ECDSA_P256_1KB()
    {
        CoseSign1Message message = CoseMessage.DecodeSign1(this.ecdsaP256SignedBytes1KB);
        message.VerifyEmbedded(this.ecdsaP256VerificationKey);
    }

    [Benchmark(Description = "Verify embedded ECDSA P-256 100 KB")]
    public void Verify_ECDSA_P256_100KB()
    {
        CoseSign1Message message = CoseMessage.DecodeSign1(this.ecdsaP256SignedBytes100KB);
        message.VerifyEmbedded(this.ecdsaP256VerificationKey);
    }

    // --- Verify ECDSA P-384 ---

    [Benchmark(Description = "Verify embedded ECDSA P-384 1 KB")]
    public void Verify_ECDSA_P384_1KB()
    {
        CoseSign1Message message = CoseMessage.DecodeSign1(this.ecdsaP384SignedBytes1KB);
        message.VerifyEmbedded(this.ecdsaP384VerificationKey);
    }

    // --- Verify RSA-2048 ---

    [Benchmark(Description = "Verify embedded RSA-2048 1 KB")]
    public void Verify_RSA2048_1KB()
    {
        CoseSign1Message message = CoseMessage.DecodeSign1(this.rsaSignedBytes1KB);
        message.VerifyEmbedded(this.rsaVerificationKey);
    }

    // --- Verify ML-DSA-65 ---

    [Benchmark(Description = "Verify embedded ML-DSA-65 1 KB")]
    public void Verify_MLDSA65_1KB()
    {
        CoseSign1Message message = CoseMessage.DecodeSign1(this.mldsaSignedBytes1KB);
        message.VerifyEmbedded(this.mldsaCoseKey);
    }

    // --- Full parse + verify roundtrips ---

    [Benchmark(Description = "Full roundtrip ECDSA P-256 1 KB")]
    public void ParseAndVerify_ECDSA_P256_1KB()
    {
        CoseSign1Message message = CoseMessage.DecodeSign1(this.ecdsaP256SignedBytes1KB);
        message.VerifyEmbedded(this.ecdsaP256VerificationKey);
    }

    [Benchmark(Description = "Full roundtrip RSA-2048 1 KB")]
    public void ParseAndVerify_RSA2048_1KB()
    {
        CoseSign1Message message = CoseMessage.DecodeSign1(this.rsaSignedBytes1KB);
        message.VerifyEmbedded(this.rsaVerificationKey);
    }

    [Benchmark(Description = "Full roundtrip ML-DSA-65 1 KB")]
    public void ParseAndVerify_MLDSA65_1KB()
    {
        CoseSign1Message message = CoseMessage.DecodeSign1(this.mldsaSignedBytes1KB);
        message.VerifyEmbedded(this.mldsaCoseKey);
    }
}
