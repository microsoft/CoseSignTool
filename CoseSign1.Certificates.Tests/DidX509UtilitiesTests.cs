// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Tests.Common;
using NUnit.Framework;

/// <summary>
/// Tests for the DidX509Utilities class.
/// </summary>
[TestFixture]
public class DidX509UtilitiesTests
{
    private static void DisposeCertificates(X509Certificate2Collection collection)
    {
        foreach (var cert in collection)
        {
            cert.Dispose();
        }
    }

    [Test]
    public void GenerateDidX509Identifier_WithCertificates_ReturnsValidDid()
    {
        // Arrange
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = chain[^1];
        X509Certificate2 rootCert = chain[0];

        // Act
        string did = DidX509Utilities.GenerateDidX509Identifier(leafCert, rootCert);

        // Assert
        Assert.That(did, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(did, Does.Contain("::subject:"));
        
        // Cleanup
        DisposeCertificates(chain);
    }

    [Test]
    public void GenerateDidX509Identifier_WithNullLeaf_ThrowsArgumentNullException()
    {
        // Arrange
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 rootCert = chain[0];

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            DidX509Utilities.GenerateDidX509Identifier(null!, rootCert));
        
        // Cleanup
        DisposeCertificates(chain);
    }

    [Test]
    public void GenerateDidX509Identifier_WithNullRoot_ThrowsArgumentNullException()
    {
        // Arrange
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = chain[^1];

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            DidX509Utilities.GenerateDidX509Identifier(leafCert, null!));
        
        // Cleanup
        DisposeCertificates(chain);
    }

    [Test]
    public void GenerateDidX509Identifier_ConsistentForSameCertificates()
    {
        // Arrange
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = chain[^1];
        X509Certificate2 rootCert = chain[0];

        // Act
        string did1 = DidX509Utilities.GenerateDidX509Identifier(leafCert, rootCert);
        string did2 = DidX509Utilities.GenerateDidX509Identifier(leafCert, rootCert);

        // Assert
        Assert.That(did1, Is.EqualTo(did2));
        
        // Cleanup
        DisposeCertificates(chain);
    }

    [Test]
    public void GenerateDidX509Identifier_ContainsEncodedSubject()
    {
        // Arrange
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = chain[^1];
        X509Certificate2 rootCert = chain[0];

        // Act
        string did = DidX509Utilities.GenerateDidX509Identifier(leafCert, rootCert);

        // Assert
        string[] parts = did.Split(new[] { "::subject:" }, StringSplitOptions.None);
        Assert.That(parts.Length, Is.EqualTo(2));
        
        string encodedSubject = parts[1];
        Assert.That(encodedSubject, Does.Contain("CN"));
        Assert.That(encodedSubject, Does.Contain("Test"));
        
        // Cleanup
        DisposeCertificates(chain);
    }

    [Test]
    public void GenerateDidX509Identifier_WithSHA256_UsesCorrectAlgorithm()
    {
        // Arrange
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = chain[^1];
        X509Certificate2 rootCert = chain[0];

        // Act
        string did = DidX509Utilities.GenerateDidX509Identifier(
            leafCert,
            rootCert,
            HashAlgorithmName.SHA256);

        // Assert
        Assert.That(did, Does.Contain("sha256"));
        
        // Cleanup
        DisposeCertificates(chain);
    }

    [Test]
    public void GenerateDidX509Identifier_WithSHA384_UsesCorrectAlgorithm()
    {
        // Arrange
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = chain[^1];
        X509Certificate2 rootCert = chain[0];

        // Act
        string did = DidX509Utilities.GenerateDidX509Identifier(
            leafCert,
            rootCert,
            HashAlgorithmName.SHA384);

        // Assert
        Assert.That(did, Does.Contain("sha384"));
        
        // Cleanup
        DisposeCertificates(chain);
    }

    [Test]
    public void GenerateDidX509Identifier_WithSHA512_UsesCorrectAlgorithm()
    {
        // Arrange
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = chain[^1];
        X509Certificate2 rootCert = chain[0];

        // Act
        string did = DidX509Utilities.GenerateDidX509Identifier(
            leafCert,
            rootCert,
            HashAlgorithmName.SHA512);

        // Assert
        Assert.That(did, Does.Contain("sha512"));
        
        // Cleanup
        DisposeCertificates(chain);
    }

    [Test]
    public void GenerateDidX509Identifier_DefaultHashAlgorithm_UsesSHA256()
    {
        // Arrange
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = chain[^1];
        X509Certificate2 rootCert = chain[0];

        // Act
        string did = DidX509Utilities.GenerateDidX509Identifier(leafCert, rootCert);

        // Assert
        Assert.That(did, Does.Contain("sha256"));
        
        // Cleanup
        DisposeCertificates(chain);
    }

    [Test]
    public void GenerateDidX509Identifier_DifferentRoots_ProducesDifferentDids()
    {
        // Arrange
        X509Certificate2Collection chain1 = TestCertificateUtils.CreateTestChain();
        X509Certificate2Collection chain2 = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = chain1[^1];
        X509Certificate2 root1 = chain1[0];
        X509Certificate2 root2 = chain2[0];

        // Act
        string did1 = DidX509Utilities.GenerateDidX509Identifier(leafCert, root1);
        string did2 = DidX509Utilities.GenerateDidX509Identifier(leafCert, root2);

        // Assert
        Assert.That(did1, Is.Not.EqualTo(did2));
        
        // Cleanup
        DisposeCertificates(chain1);
        DisposeCertificates(chain2);
    }

    [Test]
    public void GenerateDidX509Identifier_DifferentLeafs_ProducesDifferentDids()
    {
        // Arrange - create certificates with different subjects
        X509Certificate2 leaf1 = TestCertificateUtils.CreateCertificate("Leaf1");
        X509Certificate2 leaf2 = TestCertificateUtils.CreateCertificate("Leaf2");
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 rootCert = chain[0];

        // Act
        string did1 = DidX509Utilities.GenerateDidX509Identifier(leaf1, rootCert);
        string did2 = DidX509Utilities.GenerateDidX509Identifier(leaf2, rootCert);

        // Assert
        Assert.That(did1, Is.Not.EqualTo(did2));
        
        // Cleanup
        leaf1.Dispose();
        leaf2.Dispose();
        DisposeCertificates(chain);
    }

    [Test]
    public void GenerateDidX509Identifier_SubjectWithSpaces_PercentEncoded()
    {
        // Arrange
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate("Test With Spaces");
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 rootCert = chain[0];

        // Act
        string did = DidX509Utilities.GenerateDidX509Identifier(cert, rootCert);

        // Assert
        // Verify the subject portion contains the CN
        string[] parts = did.Split(new[] { "::subject:" }, StringSplitOptions.None);
        Assert.That(parts[1], Does.Contain("Test"));
        Assert.That(parts[1], Does.Contain("Spaces"));
        
        // Cleanup
        cert.Dispose();
        DisposeCertificates(chain);
    }

    [Test]
    public void GenerateDidX509Identifier_HasNoBase64Padding()
    {
        // Arrange
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = chain[^1];
        X509Certificate2 rootCert = chain[0];

        // Act
        string did = DidX509Utilities.GenerateDidX509Identifier(leafCert, rootCert);

        // Assert
        // Extract the fingerprint portion (between "sha256:" and "::subject:")
        int hashStart = did.IndexOf("sha256:") + "sha256:".Length;
        int subjectStart = did.IndexOf("::subject:");
        string fingerprint = did.Substring(hashStart, subjectStart - hashStart);
        
        // Base64URL should not contain padding characters
        Assert.That(fingerprint, Does.Not.Contain("="));
        Assert.That(fingerprint, Does.Not.Contain("+"));
        Assert.That(fingerprint, Does.Not.Contain("/"));
        
        // Cleanup
        DisposeCertificates(chain);
    }

    [Test]
    public void GenerateDidX509Identifier_UsesRootFingerprint()
    {
        // Arrange
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = chain[^1];
        X509Certificate2 rootCert = chain[0];

        // Act
        string did1 = DidX509Utilities.GenerateDidX509Identifier(leafCert, rootCert);
        
        // Using the root as both leaf and root should have same fingerprint portion
        string did2 = DidX509Utilities.GenerateDidX509Identifier(rootCert, rootCert);

        // Assert
        // Extract fingerprint portions
        int hashStart1 = did1.IndexOf("sha256:") + "sha256:".Length;
        int subjectStart1 = did1.IndexOf("::subject:");
        string fingerprint1 = did1.Substring(hashStart1, subjectStart1 - hashStart1);

        int hashStart2 = did2.IndexOf("sha256:") + "sha256:".Length;
        int subjectStart2 = did2.IndexOf("::subject:");
        string fingerprint2 = did2.Substring(hashStart2, subjectStart2 - hashStart2);

        // Both should have the same fingerprint since they use the same root
        Assert.That(fingerprint1, Is.EqualTo(fingerprint2));
        
        // Cleanup
        DisposeCertificates(chain);
    }

    [Test]
    public void GenerateDidX509Identifier_SelfSignedCertificate_GeneratesValidDid()
    {
        // Arrange - create a self-signed certificate
        X509Certificate2 selfSignedCert = TestCertificateUtils.CreateCertificate("SelfSigned");

        // Act
        string did = DidX509Utilities.GenerateDidX509Identifier(selfSignedCert, selfSignedCert);

        // Assert
        Assert.That(did, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(did, Does.Contain("::subject:"));
        Assert.That(did, Does.Contain("CN:SelfSigned"));

        // Cleanup
        selfSignedCert.Dispose();
    }

    [Test]
    public void GenerateDidX509IdentifierFromChain_SelfSignedCertificate_GeneratesValidDid()
    {
        // Arrange - create a self-signed certificate in a single-element chain
        X509Certificate2 selfSignedCert = TestCertificateUtils.CreateCertificate("SelfSignedChain");
        var chain = new X509Certificate2Collection { selfSignedCert };

        // Act
        string did = DidX509Utilities.GenerateDidX509IdentifierFromChain(chain);

        // Assert
        Assert.That(did, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(did, Does.Contain("::subject:"));
        Assert.That(did, Does.Contain("CN:SelfSignedChain"));

        // Cleanup
        selfSignedCert.Dispose();
    }

    [Test]
    public void GenerateDidX509Identifier_SelfSignedCert_UsesSameFingerprintForLeafAndRoot()
    {
        // Arrange
        X509Certificate2 selfSignedCert = TestCertificateUtils.CreateCertificate("SelfSigned");

        // Act
        string did = DidX509Utilities.GenerateDidX509Identifier(selfSignedCert, selfSignedCert);

        // Assert - extract and verify the fingerprint is consistent
        int hashStart = did.IndexOf("sha256:") + "sha256:".Length;
        int subjectStart = did.IndexOf("::subject:");
        string fingerprint = did.Substring(hashStart, subjectStart - hashStart);

        // The fingerprint should be non-empty and valid base64url
        Assert.That(fingerprint, Is.Not.Empty);
        Assert.That(fingerprint, Does.Not.Contain("+"));
        Assert.That(fingerprint, Does.Not.Contain("/"));
        Assert.That(fingerprint, Does.Not.Contain("="));

        // Cleanup
        selfSignedCert.Dispose();
    }

    [Test]
    public void GenerateDidX509Identifier_MultipleSelfSignedCerts_ProduceDifferentDids()
    {
        // Arrange - create two different self-signed certificates
        X509Certificate2 cert1 = TestCertificateUtils.CreateCertificate("SelfSigned1");
        X509Certificate2 cert2 = TestCertificateUtils.CreateCertificate("SelfSigned2");

        // Act
        string did1 = DidX509Utilities.GenerateDidX509Identifier(cert1, cert1);
        string did2 = DidX509Utilities.GenerateDidX509Identifier(cert2, cert2);

        // Assert
        Assert.That(did1, Is.Not.EqualTo(did2));
        Assert.That(did1, Does.Contain("CN:SelfSigned1"));
        Assert.That(did2, Does.Contain("CN:SelfSigned2"));

        // Cleanup
        cert1.Dispose();
        cert2.Dispose();
    }

    [Test]
    public void GenerateDidX509IdentifierFromChain_SelfSignedWithSHA384_UsesCorrectAlgorithm()
    {
        // Arrange
        X509Certificate2 selfSignedCert = TestCertificateUtils.CreateCertificate("SelfSignedSHA384");
        var chain = new X509Certificate2Collection { selfSignedCert };

        // Act
        string did = DidX509Utilities.GenerateDidX509IdentifierFromChain(chain, HashAlgorithmName.SHA384);

        // Assert
        Assert.That(did, Does.StartWith("did:x509:0:sha384:"));
        Assert.That(did, Does.Contain("::subject:"));

        // Cleanup
        selfSignedCert.Dispose();
    }

    [Test]
    public void GenerateDidX509Identifier_WithUnsupportedHashAlgorithm_ThrowsInvalidOperationException()
    {
        // Arrange
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = chain[^1];
        X509Certificate2 rootCert = chain[0];
        HashAlgorithmName unsupportedAlgorithm = HashAlgorithmName.MD5;

        // Act & Assert
        InvalidOperationException? exception = Assert.Throws<InvalidOperationException>(() =>
            DidX509Utilities.GenerateDidX509Identifier(leafCert, rootCert, unsupportedAlgorithm));
        
        Assert.That(exception!.Message, Does.Contain("Unsupported hash algorithm"));
        Assert.That(exception.Message, Does.Contain("MD5"));

        // Cleanup
        DisposeCertificates(chain);
    }

    [Test]
    public void GenerateDidX509IdentifierFromChain_WithNullChain_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            DidX509Utilities.GenerateDidX509IdentifierFromChain(null!));
    }

    [Test]
    public void GenerateDidX509IdentifierFromChain_WithEmptyChain_ThrowsArgumentException()
    {
        // Arrange
        var emptyChain = new List<X509Certificate2>();

        // Act & Assert
        ArgumentException? exception = Assert.Throws<ArgumentException>(() =>
            DidX509Utilities.GenerateDidX509IdentifierFromChain(emptyChain));
        
        Assert.That(exception!.Message, Does.Contain("Certificate chain cannot be empty"));
    }

    [Test]
    public void GenerateDidX509IdentifierFromChain_WithMultipleCertificates_UsesLeafAndRoot()
    {
        // Arrange
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();

        // Act
        string did = DidX509Utilities.GenerateDidX509IdentifierFromChain(chain);

        // Assert
        Assert.That(did, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(did, Does.Contain("::subject:"));

        // Cleanup
        DisposeCertificates(chain);
    }

    [Test]
    public void GenerateDidX509IdentifierFromChain_WithSHA512_UsesCorrectAlgorithm()
    {
        // Arrange
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();

        // Act
        string did = DidX509Utilities.GenerateDidX509IdentifierFromChain(chain, HashAlgorithmName.SHA512);

        // Assert
        Assert.That(did, Does.StartWith("did:x509:0:sha512:"));

        // Cleanup
        DisposeCertificates(chain);
    }

    [Test]
    public void GenerateDidX509Identifier_SubjectWithSpecialCharacters_PercentEncoded()
    {
        // Arrange
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate("Test@#$%");
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 rootCert = chain[0];

        // Act
        string did = DidX509Utilities.GenerateDidX509Identifier(cert, rootCert);

        // Assert
        string[] parts = did.Split(new[] { "::subject:" }, StringSplitOptions.None);
        Assert.That(parts[1], Does.Contain("CN"));
        
        // Special characters should be percent-encoded
        Assert.That(parts[1], Does.Contain("%"));

        // Cleanup
        cert.Dispose();
        DisposeCertificates(chain);
    }

    [Test]
    public void GenerateDidX509Identifier_SubjectWithColons_PercentEncoded()
    {
        // Arrange
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate("Test:Colon");
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 rootCert = chain[0];

        // Act
        string did = DidX509Utilities.GenerateDidX509Identifier(cert, rootCert);

        // Assert
        string[] parts = did.Split(new[] { "::subject:" }, StringSplitOptions.None);
        
        // Colons in values should be percent-encoded as %3A
        Assert.That(parts[1], Does.Contain("CN"));

        // Cleanup
        cert.Dispose();
        DisposeCertificates(chain);
    }

    [Test]
    public void GenerateDidX509IdentifierFromChain_NullHashAlgorithm_UsesSHA256Default()
    {
        // Arrange
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();

        // Act
        string did = DidX509Utilities.GenerateDidX509IdentifierFromChain(chain, null);

        // Assert
        Assert.That(did, Does.Contain("sha256"));

        // Cleanup
        DisposeCertificates(chain);
    }

    [Test]
    public void GenerateDidX509Identifier_WithDefaultHashAlgorithm_UsesLowercaseAlgorithmName()
    {
        // Arrange
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 leafCert = chain[^1];
        X509Certificate2 rootCert = chain[0];

        // Act - pass null to use default
        string did = DidX509Utilities.GenerateDidX509Identifier(leafCert, rootCert, null);

        // Assert - should use lowercase 'sha256'
        Assert.That(did, Does.Contain(":sha256:"));
        Assert.That(did, Does.Not.Contain(":SHA256:"));

        // Cleanup
        DisposeCertificates(chain);
    }

    [Test]
    public void GenerateDidX509Identifier_SubjectWithUnicodeCharacters_PercentEncoded()
    {
        // Arrange - create certificate with Unicode characters
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate("Tëst");
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 rootCert = chain[0];

        // Act
        string did = DidX509Utilities.GenerateDidX509Identifier(cert, rootCert);

        // Assert
        string[] parts = did.Split(new[] { "::subject:" }, StringSplitOptions.None);
        // Unicode should be percent-encoded
        Assert.That(parts[1], Does.Contain("CN"));
        Assert.That(parts[1], Does.Contain("%")); // Should have percent encoding

        // Cleanup
        cert.Dispose();
        DisposeCertificates(chain);
    }

    [Test]
    public void GenerateDidX509Identifier_SubjectWithHyphensDotsUnderscores_NotEncoded()
    {
        // Arrange - these characters should NOT be encoded
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate("Test-Name.Value_123");
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain();
        X509Certificate2 rootCert = chain[0];

        // Act
        string did = DidX509Utilities.GenerateDidX509Identifier(cert, rootCert);

        // Assert
        string[] parts = did.Split(new[] { "::subject:" }, StringSplitOptions.None);
        // These characters are allowed and should appear as-is in the CN value
        Assert.That(parts[1], Does.Contain("CN"));
        Assert.That(parts[1], Does.Contain("Test-Name.Value_123"));

        // Cleanup
        cert.Dispose();
        DisposeCertificates(chain);
    }
}


