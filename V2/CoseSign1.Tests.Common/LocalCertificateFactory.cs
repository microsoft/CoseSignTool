// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Local;

namespace CoseSign1.Tests.Common;

/// <summary>
/// Provides convenient access to the <see cref="EphemeralCertificateFactory"/> 
/// and <see cref="CertificateChainFactory"/> for test scenarios.
/// </summary>
/// <remarks>
/// <para>
/// This class wraps the <see cref="CoseSign1.Certificates.Local"/> library to provide
/// a simplified API for creating test certificates with RSA, ECDSA, and ML-DSA algorithms.
/// </para>
/// <para>
/// Unlike <see cref="TestCertificateUtils"/>, this class uses the production-ready
/// certificate factory that properly handles ML-DSA certificate chains.
/// </para>
/// </remarks>
public static class LocalCertificateFactory
{
    private static readonly EphemeralCertificateFactory CertFactory = new();
    private static readonly CertificateChainFactory ChainFactory = new(CertFactory);

    /// <summary>
    /// Creates a self-signed RSA certificate.
    /// </summary>
    /// <param name="subjectName">The subject name (will be prefixed with CN=).</param>
    /// <param name="keySize">The RSA key size (default 2048).</param>
    /// <param name="duration">Certificate validity duration (default 1 year).</param>
    /// <returns>A self-signed RSA certificate with private key.</returns>
    public static X509Certificate2 CreateRsaCertificate(
        [CallerMemberName] string subjectName = "Test",
        int keySize = 2048,
        TimeSpan? duration = null)
    {
        return CertFactory.CreateCertificate(o => o
            .WithSubjectName($"CN={subjectName}")
            .WithKeyAlgorithm(KeyAlgorithm.RSA)
            .WithKeySize(keySize)
            .WithValidity(duration ?? TimeSpan.FromDays(365)));
    }

    /// <summary>
    /// Creates a self-signed ECDSA certificate.
    /// </summary>
    /// <param name="subjectName">The subject name (will be prefixed with CN=).</param>
    /// <param name="keySize">The ECDSA key size (256, 384, or 521; default 256).</param>
    /// <param name="duration">Certificate validity duration (default 1 year).</param>
    /// <returns>A self-signed ECDSA certificate with private key.</returns>
    public static X509Certificate2 CreateEcdsaCertificate(
        [CallerMemberName] string subjectName = "Test",
        int keySize = 256,
        TimeSpan? duration = null)
    {
        return CertFactory.CreateCertificate(o => o
            .WithSubjectName($"CN={subjectName}")
            .WithKeyAlgorithm(KeyAlgorithm.ECDSA)
            .WithKeySize(keySize)
            .WithValidity(duration ?? TimeSpan.FromDays(365)));
    }

    /// <summary>
    /// Creates a self-signed ML-DSA (Post-Quantum) certificate.
    /// </summary>
    /// <param name="subjectName">The subject name (will be prefixed with CN=).</param>
    /// <param name="parameterSet">The ML-DSA parameter set (44, 65, or 87; default 65).</param>
    /// <param name="duration">Certificate validity duration (default 1 year).</param>
    /// <returns>A self-signed ML-DSA certificate with private key.</returns>
    public static X509Certificate2 CreateMlDsaCertificate(
        [CallerMemberName] string subjectName = "Test",
        int parameterSet = 65,
        TimeSpan? duration = null)
    {
        return CertFactory.CreateCertificate(o => o
            .WithSubjectName($"CN={subjectName}")
            .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
            .WithKeySize(parameterSet)
            .WithValidity(duration ?? TimeSpan.FromDays(365)));
    }

    /// <summary>
    /// Creates a certificate chain with RSA certificates.
    /// </summary>
    /// <param name="testName">Test name for certificate naming.</param>
    /// <param name="keySize">RSA key size (default 2048).</param>
    /// <param name="leafFirst">If true, returns leaf first; otherwise root first.</param>
    /// <param name="includeIntermediate">If true, includes an intermediate CA.</param>
    /// <returns>Certificate collection with root, optionally intermediate, and leaf certificates.</returns>
    public static X509Certificate2Collection CreateRsaChain(
        [CallerMemberName] string? testName = "Test",
        int keySize = 2048,
        bool leafFirst = false,
        bool includeIntermediate = true)
    {
        return ChainFactory.CreateChain(o =>
        {
            o.WithRootName($"CN=Root: {testName}")
             .WithIntermediateName(includeIntermediate ? $"CN=Intermediate: {testName}" : null)
             .WithLeafName($"CN=Leaf: {testName}")
             .WithKeyAlgorithm(KeyAlgorithm.RSA)
             .WithKeySize(keySize);
            if (leafFirst)
            {
                o.LeafFirstOrder();
            }
        });
    }

    /// <summary>
    /// Creates a certificate chain with ECDSA certificates.
    /// </summary>
    /// <param name="testName">Test name for certificate naming.</param>
    /// <param name="keySize">ECDSA key size (256, 384, or 521; default 256).</param>
    /// <param name="leafFirst">If true, returns leaf first; otherwise root first.</param>
    /// <param name="includeIntermediate">If true, includes an intermediate CA.</param>
    /// <returns>Certificate collection with root, optionally intermediate, and leaf certificates.</returns>
    public static X509Certificate2Collection CreateEcdsaChain(
        [CallerMemberName] string? testName = "Test",
        int keySize = 256,
        bool leafFirst = false,
        bool includeIntermediate = true)
    {
        return ChainFactory.CreateChain(o =>
        {
            o.WithRootName($"CN=Root: {testName}")
             .WithIntermediateName(includeIntermediate ? $"CN=Intermediate: {testName}" : null)
             .WithLeafName($"CN=Leaf: {testName}")
             .WithKeyAlgorithm(KeyAlgorithm.ECDSA)
             .WithKeySize(keySize);
            if (leafFirst)
            {
                o.LeafFirstOrder();
            }
        });
    }

    /// <summary>
    /// Creates a certificate chain with ML-DSA (Post-Quantum) certificates.
    /// </summary>
    /// <param name="testName">Test name for certificate naming.</param>
    /// <param name="parameterSet">ML-DSA parameter set (44, 65, or 87; default 65).</param>
    /// <param name="leafFirst">If true, returns leaf first; otherwise root first.</param>
    /// <param name="includeIntermediate">If true, includes an intermediate CA.</param>
    /// <returns>Certificate collection with root, optionally intermediate, and leaf certificates.</returns>
    public static X509Certificate2Collection CreateMlDsaChain(
        [CallerMemberName] string? testName = "Test",
        int parameterSet = 65,
        bool leafFirst = false,
        bool includeIntermediate = true)
    {
        return ChainFactory.CreateChain(o =>
        {
            o.WithRootName($"CN=Root: {testName}")
             .WithIntermediateName(includeIntermediate ? $"CN=Intermediate: {testName}" : null)
             .WithLeafName($"CN=Leaf: {testName}")
             .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
             .WithKeySize(parameterSet);
            if (leafFirst)
            {
                o.LeafFirstOrder();
            }
        });
    }

    /// <summary>
    /// Gets the underlying certificate factory for advanced scenarios.
    /// </summary>
    public static EphemeralCertificateFactory Factory => CertFactory;

    /// <summary>
    /// Gets the underlying chain factory for advanced scenarios.
    /// </summary>
    public static CertificateChainFactory Chain => ChainFactory;

    /// <summary>
    /// Gets the generated key for a certificate created by this factory.
    /// </summary>
    /// <param name="certificate">The certificate to look up.</param>
    /// <returns>The generated key if found, null otherwise.</returns>
    /// <remarks>
    /// This is useful for getting the <see cref="X509SignatureGenerator"/> for
    /// certificates that need to sign other certificates in a chain.
    /// </remarks>
    public static IGeneratedKey? GetGeneratedKey(X509Certificate2 certificate)
    {
        return CertFactory.GetGeneratedKey(certificate);
    }
}