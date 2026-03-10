// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Tests;

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Tests.Common;
using NUnit.Framework;

#pragma warning disable SYSLIB5006 // ML-DSA APIs are marked as preview

/// <summary>
/// Test parameter for certificate algorithm types.
/// </summary>
public enum CertAlgorithm
{
    RSA,
    ECDSA,
    MLDsa
}

/// <summary>
/// Base class for DIDx509 tests providing common certificate creation utilities.
/// </summary>
public abstract class DIDx509TestBase
{
    /// <summary>
    /// Creates a test certificate with the specified algorithm and subject.
    /// </summary>
    /// <param name="subject">The certificate subject name.</param>
    /// <param name="algorithm">The algorithm type for the certificate.</param>
    /// <param name="customEkus">Optional custom EKU OIDs to add instead of default EKUs.</param>
    /// <param name="customSans">Optional custom SAN entries as tuples of (type, value).</param>
    protected static X509Certificate2 CreateTestCertificate(string subject, CertAlgorithm algorithm = CertAlgorithm.RSA, string[]? customEkus = null, (string type, string value)[]? customSans = null)
    {
        return algorithm switch
        {
            CertAlgorithm.RSA => TestCertificateUtils.CreateCertificate(subject, useEcc: false, customEkus: customEkus, customSans: customSans),
            CertAlgorithm.ECDSA => TestCertificateUtils.CreateCertificate(subject, useEcc: true, customEkus: customEkus, customSans: customSans),
            CertAlgorithm.MLDsa => TestCertificateUtils.CreateMLDsaCertificate(subject),
            _ => throw new System.NotSupportedException($"Unsupported algorithm: {algorithm}")
        };
    }

    /// <summary>
    /// Creates a self-signed root certificate with the specified algorithm.
    /// </summary>
    protected static X509Certificate2 CreateSelfSignedCertificate(string subject, CertAlgorithm algorithm = CertAlgorithm.RSA)
    {
        return CreateTestCertificate(subject, algorithm);
    }

    /// <summary>
    /// Creates a certificate chain with the specified algorithm.
    /// </summary>
    protected static X509Certificate2[] CreateTestChain(CertAlgorithm algorithm = CertAlgorithm.RSA)
    {
        bool useEcc = algorithm == CertAlgorithm.ECDSA;

        if (algorithm == CertAlgorithm.MLDsa)
        {
            // Create ML-DSA chain manually
            X509Certificate2 root = TestCertificateUtils.CreateMLDsaCertificate("Test Root");
            X509Certificate2 intermediate = TestCertificateUtils.CreateMLDsaCertificate("Test Intermediate", root);
            X509Certificate2 leaf = TestCertificateUtils.CreateMLDsaCertificate("Test Leaf", intermediate);
            return [leaf, intermediate, root];
        }

        var collection = TestCertificateUtils.CreateTestChain(useEcc: useEcc, leafFirst: true);
        return [collection[0], collection[1], collection[2]];
    }

    /// <summary>
    /// Provides test cases for all supported algorithms.
    /// </summary>
    public static CertAlgorithm[] AllAlgorithms => PlatformHelper.IsMLDsaSupported
        ? [CertAlgorithm.RSA, CertAlgorithm.ECDSA, CertAlgorithm.MLDsa]
        : [CertAlgorithm.RSA, CertAlgorithm.ECDSA];

    /// <summary>
    /// Gets the base64url-encoded certificate hash.
    /// </summary>
    protected static string GetCertHashBase64Url(X509Certificate2 cert, string hashAlgorithm = "sha256")
    {
        byte[] hash = hashAlgorithm.ToLowerInvariant() switch
        {
            "sha256" => System.Security.Cryptography.SHA256.HashData(cert.RawData),
            "sha384" => System.Security.Cryptography.SHA384.HashData(cert.RawData),
            "sha512" => System.Security.Cryptography.SHA512.HashData(cert.RawData),
            _ => throw new System.ArgumentException($"Unsupported hash algorithm: {hashAlgorithm}")
        };

        return System.Convert.ToBase64String(hash)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    /// <summary>
    /// Verifies that a DID contains the expected certificate hash.
    /// </summary>
    protected static void AssertDidContainsCertHash(string did, X509Certificate2 cert, string hashAlgorithm = "sha256")
    {
        string expectedHash = GetCertHashBase64Url(cert, hashAlgorithm);
        Assert.That(did, Does.Contain(expectedHash),
            $"DID should contain the Base64URL-encoded {hashAlgorithm} hash of the certificate");
    }

    /// <summary>
    /// Verifies the complete structure of a DID string.
    /// </summary>
    protected static void AssertDidStructure(
        string did,
        string expectedHashAlgorithm,
        X509Certificate2 caCert,
        string? expectedPolicy = null,
        string? expectedPolicyValue = null)
    {
        // Verify prefix
        Assert.That(did, Does.StartWith($"did:x509:0:{expectedHashAlgorithm}:"));

        // Verify CA cert hash
        AssertDidContainsCertHash(did, caCert, expectedHashAlgorithm);

        // Verify policy separator
        Assert.That(did, Does.Contain("::"));

        // If policy is specified, verify it
        if (expectedPolicy != null)
        {
            Assert.That(did, Does.Contain($"::{expectedPolicy}:"));

            if (expectedPolicyValue != null)
            {
                Assert.That(did, Does.Contain(expectedPolicyValue));
            }
        }
    }
}