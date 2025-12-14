// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Tests.Common;

using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Local;

/// <summary>
/// Class used to create in-memory certificates and certificate chains used for UnitTesting.
/// </summary>
/// <remarks>
/// This class delegates to <see cref="EphemeralCertificateFactory"/> and <see cref="CertificateChainFactory"/>
/// from the CoseSign1.Certificates.Local library for certificate creation.
/// </remarks>
public static class TestCertificateUtils
{
    private static readonly EphemeralCertificateFactory CertFactory = new();
    private static readonly CertificateChainFactory ChainFactory = new(CertFactory);

    /// <summary>
    /// Gets the ML-DSA private key associated with a certificate, if one exists.
    /// </summary>
    /// <param name="certificate">The certificate to look up.</param>
    /// <returns>The ML-DSA key if found, null otherwise.</returns>
    internal static MLDsa? GetMLDsaKey(X509Certificate2 certificate)
    {
        if (certificate == null)
        {
            return null;
        }

        IGeneratedKey? key = CertFactory.GetGeneratedKey(certificate);
        return key?.GetMLDsa();
    }

    /// <summary>
    /// Creates a certificate with a given subject name, optionally signed by an issuing certificate.
    /// </summary>
    /// <param name="subjectName">The subject name of the certificate.</param>
    /// <param name="issuingCa">(Optional) The issuing CA if present to sign this certificate, self-signed otherwise.</param>
    /// <param name="useEcc">(Optional) True for ECC certificates, false (default) for RSA certificates.</param>
    /// <param name="keySize">(Optional) The optional key size for the cert being created.</param>
    /// <param name="duration">(Optional) How long the certificate should be valid for after it is created. Default value is one year.</param>
    /// <param name="addLifetimeEku">(Optional) If true, adds the lifetime signing EKU.</param>
    /// <param name="customEkus">(Optional) Custom EKU OIDs to add instead of the default TLS EKUs. If provided, default EKUs are not added.</param>
    /// <param name="customSans">(Optional) Custom SAN entries as tuples of (type, value) where type is "dns", "email", or "uri". If provided, default DNS SAN is not added.</param>
    /// <returns>An <see cref="X509Certificate2"/> object for use in testing.</returns>
    /// <exception cref="ArgumentOutOfRangeException"></exception>
    public static X509Certificate2 CreateCertificate(
        [CallerMemberName] string subjectName = "none",
        X509Certificate2? issuingCa = null,
        bool useEcc = false,
        int? keySize = null,
        TimeSpan? duration = null,
        bool addLifetimeEku = false,
        string[]? customEkus = null,
        (string type, string value)[]? customSans = null)
    {
        // Default duration matches original TestCertificateUtils behavior
        var effectiveDuration = duration ?? TimeSpan.FromDays(365);

        return CertFactory.CreateCertificate(o =>
        {
            o.WithSubjectName($"CN={subjectName}")
             .WithKeyAlgorithm(useEcc ? KeyAlgorithm.ECDSA : KeyAlgorithm.RSA)
             .WithKeySize(keySize ?? (useEcc ? 256 : 2048))
             .WithNotBeforeOffset(TimeSpan.FromDays(-1))
             .WithValidity(effectiveDuration + TimeSpan.FromDays(1))
             .AsCertificateAuthority(pathLengthConstraint: 12);

            // Handle EKUs
            if (customEkus != null && customEkus.Length > 0)
            {
                o.WithEnhancedKeyUsages(customEkus);
            }
            else
            {
                o.ForTlsAuthentication();
                if (addLifetimeEku)
                {
                    o.WithLifetimeSigning();
                }
            }

            // Handle SANs
            if (customSans != null && customSans.Length > 0)
            {
                o.WithSubjectAlternativeNames(customSans);
            }

            // Handle issuer
            if (issuingCa != null)
            {
                o.SignedBy(issuingCa);
            }
        });
    }

    /// <summary>
    /// Creates a certificate without private key from an existing certificate.
    /// </summary>
    /// <param name="certificate">The certificate to extract public key from.</param>
    /// <returns>A certificate with only the public key.</returns>
    public static X509Certificate2 CreateCertificateWithoutPrivateKey(X509Certificate2 certificate)
    {
        return ICertificateFactory.CreatePublicOnlyCertificate(certificate);
    }

    /// <summary>
    /// Creates a 3-tiered certificate structure in memory for use in unit tests.
    /// </summary>
    /// <param name="testName">The test name for cert name uniqueness.  They all start with Test.</param>
    /// <param name="useEcc">True for ecc certs, false (default) for RSA certs.</param>
    /// <param name="keySize">The optional key size to request for the certificate, defaults to 256 for ECC and 2048 for RSA.</param>
    /// <param name="leafFirst">If true, returns collection with leaf first; if false, root first.</param>
    /// <param name="rootDuration">Optional duration for the root certificate validity.</param>
    /// <returns>An <see cref="X509Certificate2Collection"/> containing a root, intermediate, and leaf node certificate.</returns>
    public static X509Certificate2Collection CreateTestChain(
        [CallerMemberName] string? testName = "none",
        bool useEcc = false,
        int? keySize = null,
        bool leafFirst = false,
        TimeSpan? rootDuration = null)
    {
        return ChainFactory.CreateChain(o =>
        {
            o.WithRootName($"CN=Test Root: {testName}")
             .WithIntermediateName($"CN=Test Issuer: {testName}")
             .WithLeafName($"CN=Test Leaf: {testName}")
             .WithKeyAlgorithm(useEcc ? KeyAlgorithm.ECDSA : KeyAlgorithm.RSA)
             .WithKeySize(keySize ?? (useEcc ? 256 : 2048));

            if (rootDuration.HasValue)
            {
                o.RootValidity = rootDuration.Value;
            }

            if (leafFirst)
            {
                o.LeafFirstOrder();
            }
        });
    }

    /// <summary>
    /// Creates a 3-tiered certificate structure for PFX testing where only the leaf certificate has a private key.
    /// Root and intermediate certificates will only contain public keys.
    /// </summary>
    /// <param name="testName">The test name for cert name uniqueness.</param>
    /// <param name="useEcc">True for ecc certs, false (default) for RSA certs.</param>
    /// <param name="keySize">The optional key size to request for the certificate, defaults to 256 for ECC and 2048 for RSA.</param>
    /// <param name="rootDuration">Optional duration for the root certificate validity.</param>
    /// <returns>An <see cref="X509Certificate2Collection"/> containing root (public only), intermediate (public only), and leaf (with private key) certificates.</returns>
    public static X509Certificate2Collection CreateTestChainForPfx(
        [CallerMemberName] string? testName = "none",
        bool useEcc = false,
        int? keySize = null,
        TimeSpan? rootDuration = null)
    {
        return ChainFactory.CreateChain(o =>
        {
            o.WithRootName($"CN=Test Root: {testName}")
             .WithIntermediateName($"CN=Test Issuer: {testName}")
             .WithLeafName($"CN=Test Leaf: {testName}")
             .WithKeyAlgorithm(useEcc ? KeyAlgorithm.ECDSA : KeyAlgorithm.RSA)
             .WithKeySize(keySize ?? (useEcc ? 256 : 2048))
             .ForPfxExport();

            if (rootDuration.HasValue)
            {
                o.RootValidity = rootDuration.Value;
            }
        });
    }

    /// <summary>
    /// Creates an ECDSA certificate for testing.
    /// </summary>
    /// <param name="subjectName">The subject name of the certificate.</param>
    /// <param name="keySize">The key size (default 256).</param>
    /// <returns>An ECDSA certificate with private key.</returns>
    public static X509Certificate2 CreateECDsaCertificate(
        [CallerMemberName] string subjectName = "ECDSATest",
        int keySize = 256)
    {
        return CreateCertificate(subjectName, useEcc: true, keySize: keySize);
    }

    /// <summary>
    /// Creates a certificate with custom validity dates.
    /// </summary>
    /// <param name="subjectName">The subject name of the certificate.</param>
    /// <param name="notBefore">Start of validity period.</param>
    /// <param name="notAfter">End of validity period.</param>
    /// <returns>A certificate with specified validity dates.</returns>
    public static X509Certificate2 CreateCertificate(
        string subjectName,
        DateTime notBefore,
        DateTime notAfter)
    {
        var duration = notAfter - DateTime.UtcNow;
        return CreateCertificate(subjectName, duration: duration);
    }

    /// <summary>
    /// Creates an ML-DSA Post-Quantum Cryptography certificate for testing.
    /// </summary>
    /// <param name="subjectName">The subject name of the certificate.</param>
    /// <param name="issuingCa">(Optional) The issuing CA if present to sign this certificate, self-signed otherwise.</param>
    /// <param name="mlDsaParameterSet">The ML-DSA parameter set to use (44, 65, or 87). Default is 65.</param>
    /// <param name="duration">(Optional) How long the certificate should be valid for after it is created. Default value is one year.</param>
    /// <returns>An <see cref="X509Certificate2"/> object for use in PQC testing.</returns>
    /// <remarks>
    /// <para>
    /// This method creates real ML-DSA certificates using the .NET 10 MLDsa class and CertificateRequest API.
    /// The certificates can be used for actual PQC signing operations and testing.
    /// </para>
    /// <para>
    /// ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is a NIST-standardized post-quantum signature algorithm.
    /// Parameter sets: ML-DSA-44 (2560 bits), ML-DSA-65 (4032 bits), ML-DSA-87 (4896 bits).
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when mlDsaParameterSet is not 44, 65, or 87.</exception>
    public static X509Certificate2 CreateMLDsaCertificate(
        [CallerMemberName] string subjectName = "none",
        X509Certificate2? issuingCa = null,
        int mlDsaParameterSet = 65,
        TimeSpan? duration = null)
    {
        return CertFactory.CreateCertificate(o =>
        {
            o.WithSubjectName($"CN={subjectName}")
             .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
             .WithKeySize(mlDsaParameterSet)
             .WithValidity(duration ?? TimeSpan.FromDays(365))
             .AsCertificateAuthority(pathLengthConstraint: 12)
             .ForTlsAuthentication();

            if (issuingCa != null)
            {
                o.SignedBy(issuingCa);
            }
        });
    }

    /// <summary>
    /// Determines if a certificate uses the ML-DSA algorithm.
    /// </summary>
    /// <param name="certificate">The certificate to check.</param>
    /// <returns>True if the certificate uses ML-DSA algorithm, false otherwise.</returns>
    /// <remarks>
    /// Checks the certificate's public key algorithm OID to determine if it's ML-DSA.
    /// ML-DSA OIDs: 2.16.840.1.101.3.4.3.17 (ML-DSA-44), 2.16.840.1.101.3.4.3.18 (ML-DSA-65), 2.16.840.1.101.3.4.3.19 (ML-DSA-87)
    /// </remarks>
    public static bool IsMLDsaCertificate(X509Certificate2 certificate)
    {
        return MLDsaCertificateUtils.IsMLDsaCertificate(certificate);
    }

    /// <summary>
    /// Extracts the ML-DSA parameter set from an ML-DSA certificate.
    /// </summary>
    /// <param name="certificate">The ML-DSA certificate.</param>
    /// <returns>The parameter set (44, 65, or 87) or null if not an ML-DSA certificate.</returns>
    /// <remarks>
    /// Parses the certificate's public key algorithm OID to determine the parameter set.
    /// </remarks>
    public static int? GetMLDsaParameterSet(X509Certificate2 certificate)
    {
        return MLDsaCertificateUtils.GetParameterSet(certificate);
    }

    /// <summary>
    /// Gets the underlying certificate factory for advanced scenarios.
    /// </summary>
    public static EphemeralCertificateFactory Factory => CertFactory;

    /// <summary>
    /// Gets the underlying chain factory for advanced scenarios.
    /// </summary>
    public static CertificateChainFactory Chain => ChainFactory;
}