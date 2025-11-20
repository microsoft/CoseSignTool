// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.AzureTrustedSigning.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using CoseSign1.Certificates.AzureTrustedSigning;
using CoseSign1.Tests.Common;
using NUnit.Framework;

/// <summary>
/// Unit tests for the <see cref="AzureTrustedSigningDidX509Generator"/> class.
/// Tests Azure Trusted Signing specific DID generation with Microsoft EKU support.
/// </summary>
[TestFixture]
public class AzureTrustedSigningDidX509GeneratorTests
{
    private AzureTrustedSigningDidX509Generator _generator = null!;

    [SetUp]
    public void SetUp()
    {
        _generator = new AzureTrustedSigningDidX509Generator();
    }

    #region GenerateFromChain Tests

    [Test]
    public void GenerateFromChain_WithNullCertificates_ThrowsArgumentNullException()
    {
        // Act & Assert
        ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => _generator.GenerateFromChain(null!));
        Assert.That(ex.ParamName, Is.EqualTo("certificates"));
    }

    [Test]
    public void GenerateFromChain_WithEmptyChain_ThrowsArgumentException()
    {
        // Arrange
        X509Certificate2[] emptyChain = Array.Empty<X509Certificate2>();

        // Act & Assert
        ArgumentException ex = Assert.Throws<ArgumentException>(() => _generator.GenerateFromChain(emptyChain));
        Assert.That(ex.Message, Does.Contain("cannot be empty"));
        Assert.That(ex.ParamName, Is.EqualTo("certificates"));
    }

    [Test]
    public void GenerateFromChain_WithOnlyStandardEkus_UsesSuperClassImplementation()
    {
        // Arrange - Standard EKUs (no Microsoft EKUs)
        using X509Certificate2 leafCert = CreateCertificateWithStandardEkus("CN=Leaf");
        using X509Certificate2 rootCert = CreateSelfSignedCertificate("CN=Root");
        X509Certificate2[] chain = new[] { leafCert, rootCert };

        // Act
        string did = _generator.GenerateFromChain(chain);

        // Assert - Should use subject-based format (no Microsoft EKUs present)
        Assert.That(did, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(did, Does.Contain("::subject:"));
        Assert.That(did, Does.Not.Contain("::eku:"));
    }

    [Test]
    public void GenerateFromChain_WithNoEkus_UsesSuperClassImplementation()
    {
        // Arrange - Certificate without any EKUs
        using X509Certificate2 leafCert = CreateCertificateWithoutEku("CN=Leaf");
        using X509Certificate2 rootCert = CreateSelfSignedCertificate("CN=Root");
        X509Certificate2[] chain = new[] { leafCert, rootCert };

        // Act
        string did = _generator.GenerateFromChain(chain);

        // Assert - Should use subject-based format (no Microsoft EKUs present)
        Assert.That(did, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(did, Does.Contain("::subject:"));
        Assert.That(did, Does.Not.Contain("::eku:"));
    }

    [Test]
    public void GenerateFromChain_WithMicrosoftEku_UsesEkuBasedFormat()
    {
        // Arrange - Azure Trusted Signing certificate with Microsoft EKU
        string microsoftEku = "1.3.6.1.4.1.311.20.30.40.50";
        using X509Certificate2 leafCert = CreateCertificateWithCustomEku("CN=Leaf", microsoftEku);
        using X509Certificate2 rootCert = CreateSelfSignedCertificate("CN=Root");
        X509Certificate2[] chain = new[] { leafCert, rootCert };

        // Act
        string did = _generator.GenerateFromChain(chain);

        // Assert - Should use EKU-based format (Azure Trusted Signing specific)
        Assert.That(did, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(did, Does.Contain($"::eku:{microsoftEku}"));
        Assert.That(did, Does.Not.Contain("::subject:"));
    }

    [Test]
    public void GenerateFromChain_WithMixedEkus_SelectsDeepestMicrosoftEku()
    {
        // Arrange - Mix of standard and Microsoft EKUs
        List<string> ekus = new()
        {
            "1.3.6.1.5.5.7.3.1", // Standard TLS Server Auth (not Microsoft)
            "1.3.6.1.4.1.311.20.30.40.50", // Microsoft EKU (9 segments)
            "1.3.6.1.4.1.311.99.88.77.66.55" // Microsoft EKU (11 segments - deepest)
        };
        using X509Certificate2 leafCert = CreateCertificateWithMultipleEkus("CN=Leaf", ekus);
        using X509Certificate2 rootCert = CreateSelfSignedCertificate("CN=Root");
        X509Certificate2[] chain = new[] { leafCert, rootCert };

        // Act
        string did = _generator.GenerateFromChain(chain);

        // Assert - Should select the deepest Microsoft EKU
        Assert.That(did, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(did, Does.Contain("::eku:1.3.6.1.4.1.311.99.88.77.66.55"));
    }

    [Test]
    public void GenerateFromChain_WithMultipleMicrosoftEkusOfSameDepth_SelectsGreatestLastSegment()
    {
        // Arrange - Multiple Microsoft EKUs with same depth
        List<string> ekus = new()
        {
            "1.3.6.1.4.1.311.20.5",   // Last segment: 5
            "1.3.6.1.4.1.311.20.99",  // Last segment: 99 (greatest)
            "1.3.6.1.4.1.311.20.50"   // Last segment: 50
        };
        using X509Certificate2 leafCert = CreateCertificateWithMultipleEkus("CN=Leaf", ekus);
        using X509Certificate2 rootCert = CreateSelfSignedCertificate("CN=Root");
        X509Certificate2[] chain = new[] { leafCert, rootCert };

        // Act
        string did = _generator.GenerateFromChain(chain);

        // Assert - Should select Microsoft EKU with greatest last segment value
        Assert.That(did, Does.Contain("::eku:1.3.6.1.4.1.311.20.99"));
    }

    [Test]
    public void GenerateFromChain_WithSingleMicrosoftEku_SelectsThatEku()
    {
        // Arrange - Single Microsoft EKU
        string microsoftEku = "1.3.6.1.4.1.311.99.88.77";
        using X509Certificate2 leafCert = CreateCertificateWithCustomEku("CN=Leaf", microsoftEku);
        using X509Certificate2 rootCert = CreateSelfSignedCertificate("CN=Root");
        X509Certificate2[] chain = new[] { leafCert, rootCert };

        // Act
        string did = _generator.GenerateFromChain(chain);

        // Assert
        Assert.That(did, Does.Contain($"::eku:{microsoftEku}"));
    }

    [Test]
    public void GenerateFromChain_IncludesCorrectRootHash()
    {
        // Arrange
        string customEku = "1.3.6.1.4.1.311.88.77.66";
        using X509Certificate2 leafCert = CreateCertificateWithCustomEku("CN=Leaf", customEku);
        using X509Certificate2 rootCert = CreateSelfSignedCertificate("CN=Root");
        X509Certificate2[] chain = new[] { leafCert, rootCert };

        // Act
        string did = _generator.GenerateFromChain(chain);

        // Assert - Extract hash from DID and verify it's correct format
        Assert.That(did, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(Regex.IsMatch(did, @"did:x509:0:sha256:[a-f0-9]{64}::eku:1\.3\.6\.1\.4\.1\.311\.\d+\.\d+\.\d+"), Is.True);
        
        // The hash should be from the root cert (self-signed one)
        string hashPart = did.Substring("did:x509:0:sha256:".Length, 64);
        Assert.That(hashPart, Has.Length.EqualTo(64));
        Assert.That(Regex.IsMatch(hashPart, "^[a-f0-9]{64}$"), Is.True);
    }

    [Test]
    public void GenerateFromChain_WithChainContainingSelfSignedCertificate_UsesItAsRoot()
    {
        // Arrange
        string customEku = "1.3.6.1.4.1.311.77.88";
        using X509Certificate2 leafCert = CreateCertificateWithCustomEku("CN=Leaf", customEku);
        using X509Certificate2 intermediateCert = CreateCertificateWithoutEku("CN=Intermediate");
        using X509Certificate2 rootCert = CreateSelfSignedCertificate("CN=Root");
        X509Certificate2[] chain = new[] { leafCert, intermediateCert, rootCert };

        // Act
        string did = _generator.GenerateFromChain(chain);

        // Assert - Should use valid format with EKU
        Assert.That(did, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(did, Does.Contain("::eku:"));
        
        // The hash should be from a root cert in the chain
        string hashPart = did.Substring("did:x509:0:sha256:".Length, 64);
        Assert.That(hashPart, Has.Length.EqualTo(64));
        Assert.That(Regex.IsMatch(hashPart, "^[a-f0-9]{64}$"), Is.True);
    }

    [Test]
    public void GenerateFromChain_WithNonMicrosoftEku_UsesSuperClassImplementation()
    {
        // Arrange - Non-Microsoft EKU (not Azure Trusted Signing)
        string nonMicrosoftEku = "1.2.3.4.5.6.7.8.9";
        using X509Certificate2 leafCert = CreateCertificateWithCustomEku("CN=Leaf", nonMicrosoftEku);
        using X509Certificate2 rootCert = CreateSelfSignedCertificate("CN=Root");
        X509Certificate2[] chain = new[] { leafCert, rootCert };

        // Act
        string did = _generator.GenerateFromChain(chain);

        // Assert - Should use subject-based format (no Microsoft EKUs)
        Assert.That(did, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(did, Does.Contain("::subject:"));
        Assert.That(did, Does.Not.Contain("::eku:"));
    }

    [Test]
    public void GenerateFromChain_WithMixOfMicrosoftAndNonMicrosoftEkus_UsesOnlyMicrosoftEkus()
    {
        // Arrange - Mix of Microsoft and non-Microsoft EKUs
        List<string> ekus = new()
        {
            "1.2.3.4.5.6.7.8.9.10.11.12", // Non-Microsoft (12 segments but ignored)
            "1.3.6.1.4.1.311.20.30", // Microsoft EKU (9 segments)
            "1.3.6.1.4.1.311.40.50.60" // Microsoft EKU (10 segments - selected)
        };
        using X509Certificate2 leafCert = CreateCertificateWithMultipleEkus("CN=Leaf", ekus);
        using X509Certificate2 rootCert = CreateSelfSignedCertificate("CN=Root");
        X509Certificate2[] chain = new[] { leafCert, rootCert };

        // Act
        string did = _generator.GenerateFromChain(chain);

        // Assert - Should select the deepest Microsoft EKU only
        Assert.That(did, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(did, Does.Contain("::eku:1.3.6.1.4.1.311.40.50.60"));
        Assert.That(did, Does.Not.Contain("1.2.3.4.5"));
    }

    #endregion

    #region ExtractEkus Tests

    [Test]
    public void ExtractEkus_WithNoEkuExtension_ReturnsEmptyList()
    {
        // Arrange
        using X509Certificate2 cert = CreateCertificateWithoutEku("CN=Test");

        // Act
        List<string> ekus = InvokeProtectedMethod<List<string>>("ExtractEkus", cert);

        // Assert
        Assert.That(ekus, Is.Empty);
    }

    [Test]
    public void ExtractEkus_WithSingleEku_ReturnsSingleEku()
    {
        // Arrange
        string expectedEku = "1.2.3.4.5";
        using X509Certificate2 cert = CreateCertificateWithCustomEku("CN=Test", expectedEku);

        // Act
        List<string> ekus = InvokeProtectedMethod<List<string>>("ExtractEkus", cert);

        // Assert
        Assert.That(ekus, Has.Count.EqualTo(1));
        Assert.That(ekus[0], Is.EqualTo(expectedEku));
    }

    [Test]
    public void ExtractEkus_WithMultipleEkus_ReturnsAllEkus()
    {
        // Arrange - Use valid OID format
        List<string> expectedEkus = new() { "1.2.3.4.5", "1.2.3.4.6", "1.2.3.4.7" };
        using X509Certificate2 cert = CreateCertificateWithMultipleEkus("CN=Test", expectedEkus);

        // Act
        List<string> ekus = InvokeProtectedMethod<List<string>>("ExtractEkus", cert);

        // Assert
        Assert.That(ekus, Is.EquivalentTo(expectedEkus));
    }

    [Test]
    public void ExtractEkus_WithStandardEkus_ReturnsStandardEkus()
    {
        // Arrange
        using X509Certificate2 cert = CreateCertificateWithStandardEkus("CN=Test");

        // Act
        List<string> ekus = InvokeProtectedMethod<List<string>>("ExtractEkus", cert);

        // Assert
        Assert.That(ekus, Is.Not.Empty);
        Assert.That(ekus.Any(eku => eku == "1.3.6.1.5.5.7.3.1" || eku == "1.3.6.1.5.5.7.3.2"), Is.True);
    }

    #endregion

    #region SelectDeepestGreatestEku Tests

    [Test]
    public void SelectDeepestGreatestEku_WithEmptyList_ThrowsArgumentException()
    {
        // Arrange
        List<string> emptyList = new();

        // Act & Assert - Unwrap TargetInvocationException
        var ex = Assert.Throws<System.Reflection.TargetInvocationException>(() => 
            InvokeProtectedMethod<string>("SelectDeepestGreatestEku", emptyList));
        
        Assert.That(ex.InnerException, Is.TypeOf<ArgumentException>());
        ArgumentException argEx = (ArgumentException)ex.InnerException!;
        Assert.That(argEx.Message, Does.Contain("cannot be empty"));
        Assert.That(argEx.ParamName, Is.EqualTo("ekus"));
    }

    [Test]
    public void SelectDeepestGreatestEku_WithSingleEku_ReturnsThatEku()
    {
        // Arrange
        List<string> ekus = new() { "1.3.6.1.4.1.311.20.30" };

        // Act
        string result = InvokeProtectedMethod<string>("SelectDeepestGreatestEku", ekus);

        // Assert
        Assert.That(result, Is.EqualTo("1.3.6.1.4.1.311.20.30"));
    }

    [Test]
    public void SelectDeepestGreatestEku_WithDifferentDepths_ReturnsDeepest()
    {
        // Arrange
        List<string> ekus = new()
        {
            "1.3.6.1.4.1.311",           // 7 segments
            "1.3.6.1.4.1.311.20.30.40.50.60.70",  // 13 segments (deepest)
            "1.3.6.1.4.1.311.88"          // 8 segments
        };

        // Act
        string result = InvokeProtectedMethod<string>("SelectDeepestGreatestEku", ekus);

        // Assert
        Assert.That(result, Is.EqualTo("1.3.6.1.4.1.311.20.30.40.50.60.70"));
    }

    [Test]
    public void SelectDeepestGreatestEku_WithSameDepth_ReturnsGreatestLastSegment()
    {
        // Arrange
        List<string> ekus = new()
        {
            "1.3.6.1.4.1.311.20.5",    // Last segment: 5
            "1.3.6.1.4.1.311.20.100",  // Last segment: 100 (greatest)
            "1.3.6.1.4.1.311.20.42"    // Last segment: 42
        };

        // Act
        string result = InvokeProtectedMethod<string>("SelectDeepestGreatestEku", ekus);

        // Assert
        Assert.That(result, Is.EqualTo("1.3.6.1.4.1.311.20.100"));
    }

    [Test]
    public void SelectDeepestGreatestEku_WithSameDepthAndLastSegment_ReturnsFirst()
    {
        // Arrange - When depth and last segment are identical, first wins
        List<string> ekus = new()
        {
            "1.3.6.1.4.1.311.20.5",
            "1.3.6.1.4.1.311.88.5",  // Same depth and last segment
            "1.3.6.1.4.1.311.99.5"   // Same depth and last segment
        };

        // Act
        string result = InvokeProtectedMethod<string>("SelectDeepestGreatestEku", ekus);

        // Assert
        Assert.That(result, Is.EqualTo("1.3.6.1.4.1.311.20.5"));
    }

    [Test]
    public void SelectDeepestGreatestEku_PrioritizesDepthOverLastSegment()
    {
        // Arrange
        List<string> ekus = new()
        {
            "1.3.6.1.4.1.311.999",         // 8 segments, huge last segment
            "1.3.6.1.4.1.311.20.30.40.50.1"      // 11 segments, small last segment (should win due to depth)
        };

        // Act
        string result = InvokeProtectedMethod<string>("SelectDeepestGreatestEku", ekus);

        // Assert
        Assert.That(result, Is.EqualTo("1.3.6.1.4.1.311.20.30.40.50.1"));
    }

    #endregion

    #region CountSegments Tests

    [Test]
    public void CountSegments_WithValidOid_ReturnsCorrectCount()
    {
        // Arrange & Act & Assert
        Assert.That(InvokeProtectedMethod<int>("CountSegments", "1.2.3.4.5"), Is.EqualTo(5));
        Assert.That(InvokeProtectedMethod<int>("CountSegments", "1.2"), Is.EqualTo(2));
        Assert.That(InvokeProtectedMethod<int>("CountSegments", "1"), Is.EqualTo(1));
        Assert.That(InvokeProtectedMethod<int>("CountSegments", "1.2.3.4.5.6.7.8.9.10"), Is.EqualTo(10));
    }

    [Test]
    public void CountSegments_WithEmptyString_ReturnsZero()
    {
        // Act
        int result = InvokeProtectedMethod<int>("CountSegments", string.Empty);

        // Assert
        Assert.That(result, Is.EqualTo(0));
    }

    [Test]
    public void CountSegments_WithNull_ReturnsZero()
    {
        // Act
        int result = InvokeProtectedMethod<int>("CountSegments", new object[] { null! });

        // Assert
        Assert.That(result, Is.EqualTo(0));
    }

    #endregion

    #region GetLastSegmentValue Tests

    [Test]
    public void GetLastSegmentValue_WithValidOid_ReturnsLastSegmentValue()
    {
        // Arrange & Act & Assert
        Assert.That(InvokeProtectedMethod<long>("GetLastSegmentValue", "1.2.3.4.5"), Is.EqualTo(5));
        Assert.That(InvokeProtectedMethod<long>("GetLastSegmentValue", "1.2.3.4.999"), Is.EqualTo(999));
        Assert.That(InvokeProtectedMethod<long>("GetLastSegmentValue", "1.2.3.4.0"), Is.EqualTo(0));
    }

    [Test]
    public void GetLastSegmentValue_WithSingleSegment_ReturnsValue()
    {
        // Act
        long result = InvokeProtectedMethod<long>("GetLastSegmentValue", "42");

        // Assert
        Assert.That(result, Is.EqualTo(42));
    }

    [Test]
    public void GetLastSegmentValue_WithEmptyString_ReturnsZero()
    {
        // Act
        long result = InvokeProtectedMethod<long>("GetLastSegmentValue", string.Empty);

        // Assert
        Assert.That(result, Is.EqualTo(0));
    }

    [Test]
    public void GetLastSegmentValue_WithNull_ReturnsZero()
    {
        // Act
        long result = InvokeProtectedMethod<long>("GetLastSegmentValue", new object[] { null! });

        // Assert
        Assert.That(result, Is.EqualTo(0));
    }

    [Test]
    public void GetLastSegmentValue_WithNonNumericLastSegment_ReturnsZero()
    {
        // Act - If the last segment isn't numeric, should return 0
        long result = InvokeProtectedMethod<long>("GetLastSegmentValue", "1.2.3.4.abc");

        // Assert
        Assert.That(result, Is.EqualTo(0));
    }

    [Test]
    public void GetLastSegmentValue_WithLargeNumber_ReturnsCorrectValue()
    {
        // Arrange
        long expectedValue = 9223372036854775807; // long.MaxValue

        // Act
        long result = InvokeProtectedMethod<long>("GetLastSegmentValue", $"1.2.3.4.{expectedValue}");

        // Assert
        Assert.That(result, Is.EqualTo(expectedValue));
    }

    #endregion

    #region Standard EKU Coverage Tests

    [Test]
    public void GenerateFromChain_WithOnlyNonMicrosoftStandardEkus_UsesSuperClass()
    {
        // Arrange - Only non-Microsoft standard EKUs
        List<string> standardEkus = new()
        {
            "1.3.6.1.5.5.7.3.1",  // TLS Server Authentication
            "1.3.6.1.5.5.7.3.2",  // TLS Client Authentication
            "1.3.6.1.5.5.7.3.3",  // Code Signing
            "1.3.6.1.5.5.7.3.4",  // Email Protection
            "1.3.6.1.5.5.7.3.8"   // Time Stamping
        };

        using X509Certificate2 leafCert = CreateCertificateWithMultipleEkus("CN=Leaf", standardEkus);
        using X509Certificate2 rootCert = CreateSelfSignedCertificate("CN=Root");
        X509Certificate2[] chain = new[] { leafCert, rootCert };

        // Act
        string did = _generator.GenerateFromChain(chain);

        // Assert - Should use subject format (no Microsoft EKUs)
        Assert.That(did, Does.Contain("::subject:"));
        Assert.That(did, Does.Not.Contain("::eku:"));
    }

    [Test]
    public void GenerateFromChain_WithMicrosoftLifetimeSigningEku_UsesEkuFormat()
    {
        // Arrange - Lifetime Signing is a Microsoft EKU that triggers Azure Trusted Signing format
        List<string> ekus = new()
        {
            "1.3.6.1.5.5.7.3.3",      // Code Signing (standard, non-Microsoft)
            "1.3.6.1.4.1.311.10.3.13" // Lifetime Signing (Microsoft EKU)
        };

        using X509Certificate2 leafCert = CreateCertificateWithMultipleEkus("CN=Leaf", ekus);
        using X509Certificate2 rootCert = CreateSelfSignedCertificate("CN=Root");
        X509Certificate2[] chain = new[] { leafCert, rootCert };

        // Act
        string did = _generator.GenerateFromChain(chain);

        // Assert - Should use EKU format (Microsoft EKU present)
        Assert.That(did, Does.Contain("::eku:1.3.6.1.4.1.311.10.3.13"));
        Assert.That(did, Does.Not.Contain("::subject:"));
    }

    #endregion

    #region Helper Methods

    private T InvokeProtectedMethod<T>(string methodName, params object[] args)
    {
        var method = typeof(AzureTrustedSigningDidX509Generator)
            .GetMethod(methodName, System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        
        if (method == null)
        {
            throw new InvalidOperationException($"Method {methodName} not found");
        }

        return (T)method.Invoke(_generator, args)!;
    }

    private X509Certificate2 CreateCertificateWithoutEku(string subject)
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        
        // Add basic constraints but no EKU
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));

        return request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
    }

    private X509Certificate2 CreateCertificateWithStandardEkus(string subject)
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        OidCollection oids = new()
        {
            new Oid("1.3.6.1.5.5.7.3.1"),  // TLS Server auth
            new Oid("1.3.6.1.5.5.7.3.2")   // TLS Client auth
        };

        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(oids, false));

        return request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
    }

    private X509Certificate2 CreateCertificateWithCustomEku(string subject, string ekuOid)
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        OidCollection oids = new() { new Oid(ekuOid) };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(oids, false));

        return request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
    }

    private X509Certificate2 CreateCertificateWithMultipleEkus(string subject, List<string> ekuOids)
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        OidCollection oids = new();
        foreach (string oid in ekuOids)
        {
            oids.Add(new Oid(oid));
        }

        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(oids, false));

        return request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
    }

    private X509Certificate2 CreateSelfSignedCertificate(string subject)
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Mark as CA
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));

        return request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
    }

    #endregion
}
