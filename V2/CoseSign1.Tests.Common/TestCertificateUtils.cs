// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.


namespace CoseSign1.Tests.Common;

using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Class used to create in-memory certificates and certificate chains used for UnitTesting.
/// </summary>
public static class TestCertificateUtils
{
    // Thread-safe dictionary to store ML-DSA private keys associated with certificates
    // Key: certificate thumbprint, Value: ML-DSA private key
    private static readonly ConcurrentDictionary<string, MLDsa> MldsaKeys = new();

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

        MldsaKeys.TryGetValue(certificate.Thumbprint, out MLDsa? key);
        return key;
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
        using AsymmetricAlgorithm algo = useEcc ? ECDsa.Create() : RSA.Create();
        algo.KeySize = keySize ?? (useEcc ? 256 : 2048);

        CertificateRequest request = useEcc
            ? new CertificateRequest(
                $"CN={subjectName}",
                (ECDsa)algo,
                HashAlgorithmName.SHA256) :
             new CertificateRequest(
                $"CN={subjectName}",
                (RSA)algo,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

        // Set basic certificate contraints
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, true, 12, true));

        // Key usage: Digital Signature and Key Cert Sign (for both CA and leaf certs)
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature,
                true));

        if (issuingCa != null)
        {
            // Set the AuthorityKeyIdentifier. There is no built-in
            // support, so it needs to be copied from the Subject Key
            // Identifier of the signing certificate and massaged slightly.
            // AuthorityKeyIdentifier is "KeyID=<subject key identifier>"
            // byte[] issuerSubjectKey = issuingCa.Extensions?["Subject Key Identifier"]?.RawData ?? throw new ArgumentOutOfRangeException(nameof(issuingCa), @"Issuing CA did not a ""Subject Key Identifier"" extension present");
            byte[] issuerSubjectKey = issuingCa.Extensions.First(x => x is X509SubjectKeyIdentifierExtension)?.RawData ?? throw new ArgumentOutOfRangeException(nameof(issuingCa), @"Issuing CA did not a ""Subject Key Identifier"" extension present");
            ArraySegment<byte> segment = new(issuerSubjectKey, 2, issuerSubjectKey.Length - 2);
            byte[] authorityKeyIdentifier = new byte[segment.Count + 4];
            // these bytes define the "KeyID" part of the AuthorityKeyIdentifer
            authorityKeyIdentifier[0] = 0x30;
            authorityKeyIdentifier[1] = 0x16;
            authorityKeyIdentifier[2] = 0x80;
            authorityKeyIdentifier[3] = 0x14;
            segment.CopyTo(authorityKeyIdentifier, 4);
            request.CertificateExtensions.Add(new X509Extension("2.5.29.35", authorityKeyIdentifier, false));
        }

        // Subject Alternative Names
        SubjectAlternativeNameBuilder sanBuilder = new();
        if (customSans != null && customSans.Length > 0)
        {
            // Use custom SANs provided by caller
            foreach (var (type, value) in customSans)
            {
                switch (type.ToLowerInvariant())
                {
                    case "dns":
                        sanBuilder.AddDnsName(value);
                        break;
                    case "email":
                        sanBuilder.AddEmailAddress(value);
                        break;
                    case "uri":
                        sanBuilder.AddUri(new Uri(value));
                        break;
                    default:
                        throw new ArgumentException($"Unsupported SAN type: {type}", nameof(customSans));
                }
            }
        }
        else
        {
            // Use default DNS SAN based on subject name
            string dnsName = subjectName.Replace(":", "").Replace(" ", "");
            if (dnsName.Length > 40)
            {
                dnsName = dnsName[..39];
            }
            sanBuilder.AddDnsName(dnsName);
        }
        X509Extension sanExtension = sanBuilder.Build();
        request.CertificateExtensions.Add(sanExtension);

        // Enhanced key usages
        OidCollection oids;

        if (customEkus != null && customEkus.Length > 0)
        {
            // Use custom EKUs provided by caller
            oids = new OidCollection();
            foreach (string ekuOid in customEkus)
            {
                oids.Add(new Oid(ekuOid));
            }
        }
        else
        {
            // Use default EKUs
            oids =
            [
                new Oid("1.3.6.1.5.5.7.3.2"), // TLS Client auth
                new Oid("1.3.6.1.5.5.7.3.1")  // TLS Server auth
            ];

            if (addLifetimeEku)
            {
                oids.Add(new("1.3.6.1.4.1.311.10.3.13"));  // Lifetime EKU
            }
        }

        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(oids, false));

        // add this subject key identifier
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        // Certificate expiry: Valid from Yesterday to Now+365 days
        // Unless the signing cert's validity is less. It's not possible
        // to create a cert with longer validity than the signing cert.
        DateTimeOffset notbefore = DateTimeOffset.UtcNow.AddDays(-1);
        if (issuingCa != null && notbefore < issuingCa.NotBefore)
        {
            notbefore = new DateTimeOffset(issuingCa.NotBefore);
        }
        DateTimeOffset notafter =
            duration is not null ? DateTimeOffset.UtcNow.Add(duration.Value) :
            DateTimeOffset.UtcNow.AddDays(365);
        if (issuingCa != null && notafter > issuingCa.NotAfter)
        {
            notafter = new DateTimeOffset(issuingCa.NotAfter);
        }

        // cert serial is the epoch/unix timestamp
        DateTime epoch = new(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        long unixTime = Convert.ToInt64((DateTime.UtcNow - epoch).TotalSeconds);
        byte[] serial = BitConverter.GetBytes(unixTime);

        X509Certificate2? generatedCertificate = null;
        if (issuingCa != null)
        {
            using (var certWithoutKey = request.Create(issuingCa, notbefore, notafter, serial))
            {
                generatedCertificate = useEcc
                    ? certWithoutKey.CopyWithPrivateKey((ECDsa)algo)
                    : certWithoutKey.CopyWithPrivateKey((RSA)algo);
            }
            return generatedCertificate;
        }
        else
        {
            generatedCertificate = request.CreateSelfSigned(notbefore, notafter);
            return generatedCertificate;
        }
    }

    /// <summary>
    /// Creates a certificate without private key from an existing certificate.
    /// </summary>
    /// <param name="certificate">The certificate to extract public key from.</param>
    /// <returns>A certificate with only the public key.</returns>
    public static X509Certificate2 CreateCertificateWithoutPrivateKey(X509Certificate2 certificate)
    {
        return X509CertificateLoader.LoadCertificate(certificate.Export(X509ContentType.Cert));
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
        X509Certificate2 testRoot = CreateCertificate($"Test Root: {testName}", useEcc: useEcc, keySize: keySize, duration: rootDuration);
        X509Certificate2 issuer = CreateCertificate($"Test Issuer: {testName}", testRoot, useEcc: useEcc, keySize: keySize);
        X509Certificate2 leaf = CreateCertificate($"Test Leaf: {testName}", issuer, useEcc: useEcc, keySize: keySize);

        X509Certificate2Collection returnValue =
        [
            leafFirst ? leaf : testRoot,
            issuer,
            leafFirst ? testRoot : leaf
        ];
        return returnValue;
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
        // Create certificates with private keys for signing purposes
        X509Certificate2 testRootWithPrivateKey = CreateCertificate($"Test Root: {testName}", useEcc: useEcc, keySize: keySize, duration: rootDuration);
        X509Certificate2 issuerWithPrivateKey = CreateCertificate($"Test Issuer: {testName}", testRootWithPrivateKey, useEcc: useEcc, keySize: keySize);
        X509Certificate2 leafWithPrivateKey = CreateCertificate($"Test Leaf: {testName}", issuerWithPrivateKey, useEcc: useEcc, keySize: keySize);

        // Create public-only versions of root and intermediate certificates
        X509Certificate2 testRootPublicOnly = CreateCertificateWithoutPrivateKey(testRootWithPrivateKey);
        X509Certificate2 issuerPublicOnly = CreateCertificateWithoutPrivateKey(issuerWithPrivateKey);

        // Return collection with public-only root and intermediate, but private key leaf
        X509Certificate2Collection returnValue =
        [
            testRootPublicOnly,    // Root with public key only
            issuerPublicOnly,      // Intermediate with public key only  
            leafWithPrivateKey     // Leaf with private key
        ];

        // Dispose the private key versions we don't need
        testRootWithPrivateKey.Dispose();
        issuerWithPrivateKey.Dispose();

        return returnValue;
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
        // Validate ML-DSA parameter set and get the algorithm
        MLDsaAlgorithm algorithm = mlDsaParameterSet switch
        {
            44 => MLDsaAlgorithm.MLDsa44,
            65 => MLDsaAlgorithm.MLDsa65,
            87 => MLDsaAlgorithm.MLDsa87,
            _ => throw new ArgumentOutOfRangeException(nameof(mlDsaParameterSet),
                "ML-DSA parameter set must be 44, 65, or 87")
        };

        // Generate ML-DSA key pair
        MLDsa mldsaKey = MLDsa.GenerateKey(algorithm);

        // Create certificate request with ML-DSA key
        CertificateRequest request = new($"CN={subjectName}", mldsaKey);

        // Set basic certificate constraints
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, true, 12, true));

        // Key usage: Digital Signature
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature,
                true));

        if (issuingCa != null)
        {
            // Set the AuthorityKeyIdentifier
            byte[] issuerSubjectKey = issuingCa.Extensions.First(x => x is X509SubjectKeyIdentifierExtension)?.RawData
                ?? throw new ArgumentOutOfRangeException(nameof(issuingCa), @"Issuing CA did not have a ""Subject Key Identifier"" extension present");
            ArraySegment<byte> segment = new(issuerSubjectKey, 2, issuerSubjectKey.Length - 2);
            byte[] authorityKeyIdentifier = new byte[segment.Count + 4];
            authorityKeyIdentifier[0] = 0x30;
            authorityKeyIdentifier[1] = 0x16;
            authorityKeyIdentifier[2] = 0x80;
            authorityKeyIdentifier[3] = 0x14;
            segment.CopyTo(authorityKeyIdentifier, 4);
            request.CertificateExtensions.Add(new X509Extension("2.5.29.35", authorityKeyIdentifier, false));
        }

        // Add SAN
        SubjectAlternativeNameBuilder sanBuilder = new();
        string dnsName = subjectName.Replace(":", "").Replace(" ", "");
        if (dnsName.Length > 40)
        {
            dnsName = dnsName[..39];
        }
        sanBuilder.AddDnsName(dnsName);
        X509Extension sanExtension = sanBuilder.Build();
        request.CertificateExtensions.Add(sanExtension);

        // Enhanced key usages
        OidCollection oids =
        [
            new Oid("1.3.6.1.5.5.7.3.2"), // TLS Client auth
            new Oid("1.3.6.1.5.5.7.3.1")  // TLS Server auth
        ];
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(oids, false));

        // Add subject key identifier
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        // Certificate expiry
        DateTimeOffset notbefore = DateTimeOffset.UtcNow.AddDays(-1);
        if (issuingCa != null && notbefore < issuingCa.NotBefore)
        {
            notbefore = new DateTimeOffset(issuingCa.NotBefore);
        }
        DateTimeOffset notafter =
            duration is not null ? DateTimeOffset.UtcNow.Add(duration.Value) :
            DateTimeOffset.UtcNow.AddDays(365);
        if (issuingCa != null && notafter > issuingCa.NotAfter)
        {
            notafter = new DateTimeOffset(issuingCa.NotAfter);
        }

        // cert serial is the epoch/unix timestamp
        DateTime epoch = new(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        long unixTime = Convert.ToInt64((DateTime.UtcNow - epoch).TotalSeconds);
        byte[] serial = BitConverter.GetBytes(unixTime);

        X509Certificate2 generatedCertificate;
        if (issuingCa != null)
        {
            // Get the issuer's ML-DSA key
            MLDsa? issuerKey = GetMLDsaKey(issuingCa);
            if (issuerKey == null)
            {
                throw new InvalidOperationException(
                    $"Cannot sign with ML-DSA issuer certificate: private key not found for certificate with thumbprint {issuingCa.Thumbprint}");
            }

            // Use custom signature generator for ML-DSA signing
            MLDsaX509SignatureGenerator generator = new(issuerKey);
            generatedCertificate = request.Create(issuingCa.SubjectName, generator, notbefore, notafter, serial);
        }
        else
        {
            generatedCertificate = request.CreateSelfSigned(notbefore, notafter);
        }

        // Store the ML-DSA key for this certificate so it can be used as an issuer later
        MldsaKeys[generatedCertificate.Thumbprint] = mldsaKey;

        return generatedCertificate;
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
        string? oid = certificate.PublicKey.Oid?.Value;
        return oid != null && (
            oid == "2.16.840.1.101.3.4.3.17" ||
            oid == "2.16.840.1.101.3.4.3.18" ||
            oid == "2.16.840.1.101.3.4.3.19");
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
        string? oid = certificate.PublicKey.Oid?.Value;
        return oid switch
        {
            "2.16.840.1.101.3.4.3.17" => 44,
            "2.16.840.1.101.3.4.3.18" => 65,
            "2.16.840.1.101.3.4.3.19" => 87,
            _ => null
        };
    }

}