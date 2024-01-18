// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.


namespace CoseSign1.Tests.Common;

/// <summary>
/// Class used to create in-memory certificates and certificate chains used for UnitTesting.
/// </summary>
public static class TestCertificateUtils
{
    /// <summary>
    /// Creates a certificate with a given subject name, optionally signed by an issuing certificate.
    /// </summary>
    /// <param name="subjectName">The subject name of the certificate.</param>
    /// <param name="issuingCa">(Optional) The issuing CA if present to sign this certificate, self-signed otherwise.</param>
    /// <param name="useEcc">(Optional) True for ECC certificates, false (default) for RSA certificates.</param>
    /// <param name="keySize">(Optional) The optional key size for the cert being created.</param>
    /// <returns>An <see cref="X509Certificate2"/> object for use in testing.</returns>
    /// <exception cref="ArgumentOutOfRangeException"></exception>
    public static X509Certificate2 CreateCertificate(
        string subjectName,
        X509Certificate2? issuingCa = null,
        bool useEcc = false,
        int? keySize = null)
    {
        using AsymmetricAlgorithm? algo = useEcc ? ECDsa.Create() : RSA.Create();
        if (algo == null)
        {
            throw new ArgumentOutOfRangeException(nameof(algo), "algo was null after creation");
        }
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

        // Key usage: Digital Signature and Key Encipherment
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign,
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
        // DPS samples create certs with the device name as a SAN name
        // in addition to the subject name
        SubjectAlternativeNameBuilder sanBuilder = new();
        string dnsName = subjectName.Replace(":", "").Replace(" ", "");
        if (dnsName.Length > 40)
        {
            dnsName = dnsName.Substring(0, 39);
        }
        sanBuilder.AddDnsName(dnsName);
        X509Extension sanExtension = sanBuilder.Build();
        request.CertificateExtensions.Add(sanExtension);

        // Enhanced key usages
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection {
                        new Oid("1.3.6.1.5.5.7.3.2"), // TLS Client auth
                        new Oid("1.3.6.1.5.5.7.3.1")  // TLS Server auth
                },
                false));

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
        DateTimeOffset notafter = DateTimeOffset.UtcNow.AddDays(365);
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
            generatedCertificate = request.Create(issuingCa, notbefore, notafter, serial);
            return useEcc
                ? generatedCertificate.CopyWithPrivateKey((ECDsa)algo)
                : generatedCertificate.CopyWithPrivateKey((RSA)algo);
        }
        else
        {
            generatedCertificate = request.CreateSelfSigned(notbefore, notafter);
            return generatedCertificate;
        }
    }

    /// <summary>
    /// Creates a 3-tiered certificate structure in memory for use in unit tests.
    /// </summary>
    /// <param name="testName">The test name for cert name uniqueness.  They all start with Test.</param>
    /// <param name="useEcc">True for ecc certs, false (default) for RSA certs.</param>
    /// <param name="keySize">The optional key size to request for the certificate, defaults to 256 for ECC and 2048 for RSA.</param>
    /// <returns>An <see cref="X509Certificate2Collection"/> containing a root, intermediate, and leaf node certificate.</returns>
    public static X509Certificate2Collection CreateTestChain(
        string? testName = "none",
        bool useEcc = false,
        int? keySize = null,
        bool leafFirst = false)
    {
        X509Certificate2 testRoot = CreateCertificate($"Test Root: {testName}", useEcc: useEcc, keySize: keySize);
        X509Certificate2 issuer = CreateCertificate($"Test Issuer: {testName}", testRoot, useEcc: useEcc, keySize: keySize);
        X509Certificate2 leaf = CreateCertificate($"Test Leaf: {testName}", issuer, useEcc: useEcc, keySize: keySize);

        X509Certificate2Collection returnValue = new()
        {
            leafFirst ? leaf : testRoot,
            issuer,
            leafFirst ? testRoot : leaf
        };
        return returnValue;
    }

}

