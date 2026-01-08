// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Tests;

using DIDx509.Builder;
using NUnit.Framework;

/// <summary>
/// Tests for DID:X509 generation with multiple policies combined.
/// Validates that policies can be properly stacked and that the resulting DIDs
/// contain all expected policy components with correct structure and formatting.
/// </summary>
[TestFixture]
public class MultiplePolicyTests : DIDx509TestBase
{
    #region Subject + EKU Tests

    [Test]
    public void GetDidWithRootAndEku_WithSubjectAndEku_ContainsBothPolicies()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=TestUser, O=TestOrg");
        using var root = CreateSelfSignedCertificate("CN=Root CA");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRootAndEku(chain);

        // Assert
        Assert.That(did, Is.Not.Null);
        Assert.That(did, Does.StartWith("did:x509:0:sha256:"));

        // Verify root certificate hash
        AssertDidContainsCertHash(did, root, "sha256");

        // Verify subject policy is present
        Assert.That(did, Does.Contain("::subject:"));

        // Verify EKU policy is present (TestCertificateUtils adds default EKU)
        Assert.That(did, Does.Contain("::eku:"));
    }

    [Test]
    public void Builder_WithSubjectAndEku_ContainsBothPoliciesInCorrectOrder()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Alice");
        using var root = CreateSelfSignedCertificate("CN=Root");

        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate()
            .WithEkuPolicy("1.3.6.1.5.5.7.3.1");

        // Act
        string did = builder.Build();

        // Assert
        Assert.That(did, Is.Not.Null);
        AssertDidContainsCertHash(did, root, "sha256");

        // Subject should appear before EKU in the DID
        int subjectPos = did.IndexOf("::subject:");
        int ekuPos = did.IndexOf("::eku:");
        Assert.That(subjectPos, Is.GreaterThan(0), "Subject policy should be present");
        Assert.That(ekuPos, Is.GreaterThan(0), "EKU policy should be present");
        Assert.That(subjectPos, Is.LessThan(ekuPos), "Subject should appear before EKU");

        // Verify specific values (CN value is URL-encoded and may be quoted by X500DN formatting)
        Assert.That(did, Does.Contain("CN:"));
        Assert.That(did, Does.Contain("::eku:1.3.6.1.5.5.7.3.1"));
    }

    [Test]
    public void GetDidWithRootAndEku_WithMultipleEkus_SelectsMostSpecific()
    {
        // Arrange
        string[] ekuOids = new[]
        {
            "1.3.6.1.5.5.7.3.1", // Server auth (8 segments)
            "1.3.6.1.4.1.311.10.3.12" // Document signing (10 segments, more specific)
        };
        using var leaf = CreateTestCertificate("CN=Multi EKU", customEkus: ekuOids);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act - Use MostSpecific preference
        string did = leaf.GetDidWithRootAndEku(chain, EkuPreference.MostSpecific);

        // Assert
        Assert.That(did, Is.Not.Null);
        Assert.That(did, Does.Contain("::subject:"));
        Assert.That(did, Does.Contain("::eku:1.3.6.1.4.1.311.10.3.12"),
            "Should select the more specific EKU (more segments)");
        Assert.That(did, Does.Not.Contain("::eku:1.3.6.1.5.5.7.3.1"));
        AssertDidContainsCertHash(did, root, "sha256");
    }

    [Test]
    public void GetDidWithRootAndEku_WithSubjectAndFilteredEku_ContainsOnlyFilteredEku()
    {
        // Arrange
        string[] ekuOids = new[]
        {
            "1.3.6.1.5.5.7.3.1", // Server auth
            "1.3.6.1.4.1.311.10.3.12" // Microsoft document signing
        };
        using var leaf = CreateTestCertificate("CN=Filtered", customEkus: ekuOids);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act - Filter to Microsoft enterprise OIDs only
        string did = leaf.GetDidWithRootAndEku(chain, EkuPreference.First, "1.3.6.1.4.1.311");

        // Assert
        Assert.That(did, Is.Not.Null);
        Assert.That(did, Does.Contain("::subject:"));
        Assert.That(did, Does.Contain("::eku:1.3.6.1.4.1.311.10.3.12"));
        Assert.That(did, Does.Not.Contain("::eku:1.3.6.1.5.5.7.3.1"),
            "Should exclude non-filtered EKU");
        AssertDidContainsCertHash(did, root, "sha256");
    }

    #endregion

    #region Subject + SAN Tests

    [Test]
    public void Builder_WithSubjectAndSan_ContainsBothPolicies()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Web Server");
        var chain = new[] { leaf }; // Self-signed

        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(leaf)
            .WithSubjectFromCertificate()
            .WithSanPolicy("dns", "www.example.com");

        // Act
        string did = builder.Build();

        // Assert
        Assert.That(did, Is.Not.Null);
        AssertDidContainsCertHash(did, leaf, "sha256");

        // Verify both policies
        Assert.That(did, Does.Contain("::subject:"));
        Assert.That(did, Does.Contain("CN:%22CN%3DWeb%20Server%22"));
        Assert.That(did, Does.Contain("::san:dns:www.example.com"));

        // Verify order
        int subjectPos = did.IndexOf("::subject:");
        int sanPos = did.IndexOf("::san:");
        Assert.That(subjectPos, Is.LessThan(sanPos), "Subject should appear before SAN");
    }

    [Test]
    public void GetDidWithRootAndSan_WithSubjectIncluded_ContainsBothPolicies()
    {
        // Arrange
        using var cert = CreateTestCertificate("CN=Email User, O=Contoso");
        var chain = new[] { cert }; // Self-signed

        // Act - GetDidWithRootAndSan doesn't include subject by default, use builder
        string did = new DidX509Builder()
            .WithLeafCertificate(cert)
            .WithCaCertificate(cert)
            .WithSubjectFromCertificate()
            .WithSanPolicy("email", "user@contoso.com")
            .Build();

        // Assert
        Assert.That(did, Is.Not.Null);
        Assert.That(did, Does.Contain("::subject:"));
        Assert.That(did, Does.Contain("CN:%22CN%3DEmail%20User%22"));
        Assert.That(did, Does.Contain("O:Contoso"));
        Assert.That(did, Does.Contain("::san:email:user%40contoso.com"));
        AssertDidContainsCertHash(did, cert, "sha256");
    }

    [Test]
    public void Builder_WithSubjectAndMultipleSans_ContainsAllSans()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Multi SAN");

        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(leaf)
            .WithSubjectFromCertificate()
            .WithSanPolicy("dns", "example.com")
            .WithSanPolicy("dns", "www.example.com")
            .WithSanPolicy("email", "admin@example.com");

        // Act
        string did = builder.Build();

        // Assert
        Assert.That(did, Is.Not.Null);
        Assert.That(did, Does.Contain("::subject:"));
        Assert.That(did, Does.Contain("::san:dns:example.com"));
        Assert.That(did, Does.Contain("::san:dns:www.example.com"));
        Assert.That(did, Does.Contain("::san:email:admin%40example.com"));
        AssertDidContainsCertHash(did, leaf, "sha256");
    }

    #endregion

    #region EKU + SAN Tests

    [Test]
    public void Builder_WithEkuAndSan_ContainsBothPolicies()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Service");

        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(leaf)
            .WithEkuPolicy("1.3.6.1.5.5.7.3.1")
            .WithSanPolicy("dns", "api.service.com");

        // Act
        string did = builder.Build();

        // Assert
        Assert.That(did, Is.Not.Null);
        AssertDidContainsCertHash(did, leaf, "sha256");

        // Verify both policies present
        Assert.That(did, Does.Contain("::eku:1.3.6.1.5.5.7.3.1"));
        Assert.That(did, Does.Contain("::san:dns:api.service.com"));

        // Verify order (EKU before SAN)
        int ekuPos = did.IndexOf("::eku:");
        int sanPos = did.IndexOf("::san:");
        Assert.That(ekuPos, Is.LessThan(sanPos), "EKU should appear before SAN");
    }

    [Test]
    public void Builder_WithEkuAndMultipleSans_ContainsAllPolicies()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Multi Service");

        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(leaf)
            .WithEkuPolicy("1.3.6.1.5.5.7.3.2") // Client auth
            .WithSanPolicy("uri", "https://service.example.com")
            .WithSanPolicy("dns", "service.example.com");

        // Act
        string did = builder.Build();

        // Assert
        Assert.That(did, Is.Not.Null);
        Assert.That(did, Does.Contain("::eku:1.3.6.1.5.5.7.3.2"));
        Assert.That(did, Does.Contain("::san:uri:https%3A%2F%2Fservice.example.com"));
        Assert.That(did, Does.Contain("::san:dns:service.example.com"));
        AssertDidContainsCertHash(did, leaf, "sha256");
    }

    #endregion

    #region Subject + EKU + SAN Tests (All Three)

    [Test]
    public void Builder_WithSubjectEkuAndSan_ContainsAllThreePolicies()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Full Policy, O=Example Corp");
        using var root = CreateSelfSignedCertificate("CN=Root CA");

        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate()
            .WithEkuPolicy("1.3.6.1.5.5.7.3.1")
            .WithSanPolicy("dns", "full.example.com");

        // Act
        string did = builder.Build();

        // Assert
        Assert.That(did, Is.Not.Null);
        AssertDidContainsCertHash(did, root, "sha256");

        // Verify all three policies
        Assert.That(did, Does.Contain("::subject:"));
        Assert.That(did, Does.Contain("CN:%22CN%3DFull%20Policy%22"));
        Assert.That(did, Does.Contain("O:Example%20Corp"));
        Assert.That(did, Does.Contain("::eku:1.3.6.1.5.5.7.3.1"));
        Assert.That(did, Does.Contain("::san:dns:full.example.com"));

        // Verify order: subject, then eku, then san
        int subjectPos = did.IndexOf("::subject:");
        int ekuPos = did.IndexOf("::eku:");
        int sanPos = did.IndexOf("::san:");
        Assert.That(subjectPos, Is.LessThan(ekuPos), "Subject should appear before EKU");
        Assert.That(ekuPos, Is.LessThan(sanPos), "EKU should appear before SAN");
    }

    [Test]
    public void Builder_WithAllPoliciesAndMultipleValues_ContainsAllComponents()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Complex, O=Org, OU=Unit");
        using var root = CreateSelfSignedCertificate("CN=Root");

        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate()
            .WithEkuPolicy("1.3.6.1.4.1.311.10.3.12")
            .WithSanPolicy("email", "admin@example.com")
            .WithSanPolicy("dns", "mail.example.com")
            .WithSanPolicy("uri", "https://example.com");

        // Act
        string did = builder.Build();

        // Assert
        Assert.That(did, Is.Not.Null);

        // Verify root hash
        AssertDidContainsCertHash(did, root, "sha256");

        // Verify subject components
        Assert.That(did, Does.Contain("::subject:"));
        Assert.That(did, Does.Contain("CN:%22CN%3DComplex%22"));
        Assert.That(did, Does.Contain("O:Org"));
        Assert.That(did, Does.Contain("OU:Unit"));

        // Verify EKU
        Assert.That(did, Does.Contain("::eku:1.3.6.1.4.1.311.10.3.12"));

        // Verify multiple SANs
        Assert.That(did, Does.Contain("::san:email:admin%40example.com"));
        Assert.That(did, Does.Contain("::san:dns:mail.example.com"));
        Assert.That(did, Does.Contain("::san:uri:https%3A%2F%2Fexample.com"));
    }

    [Test]
    public void Builder_WithAllPoliciesAndSHA384_GeneratesCorrectDid()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=SHA384 Test");
        using var root = CreateSelfSignedCertificate("CN=Root CA");

        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithHashAlgorithm("sha384")
            .WithSubjectFromCertificate()
            .WithEkuPolicy("1.3.6.1.5.5.7.3.2")
            .WithSanPolicy("dns", "sha384.example.com");

        // Act
        string did = builder.Build();

        // Assert
        Assert.That(did, Is.Not.Null);
        Assert.That(did, Does.StartWith("did:x509:0:sha384:"));

        // Verify root hash with SHA-384
        AssertDidContainsCertHash(did, root, "sha384");

        // Verify all policies
        Assert.That(did, Does.Contain("::subject:"));
        Assert.That(did, Does.Contain("::eku:1.3.6.1.5.5.7.3.2"));
        Assert.That(did, Does.Contain("::san:dns:sha384.example.com"));
    }

    [Test]
    public void Builder_WithAllPoliciesAndSHA512_GeneratesCorrectDid()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=SHA512 Test, O=Security");
        using var root = CreateSelfSignedCertificate("CN=Root");

        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithHashAlgorithm("sha512")
            .WithSubjectFromCertificate()
            .WithEkuPolicy("1.3.6.1.4.1.311.10.3.4")
            .WithSanPolicy("email", "secure@example.com");

        // Act
        string did = builder.Build();

        // Assert
        Assert.That(did, Is.Not.Null);
        Assert.That(did, Does.StartWith("did:x509:0:sha512:"));

        // Verify root hash with SHA-512
        AssertDidContainsCertHash(did, root, "sha512");

        // Verify all policies
        Assert.That(did, Does.Contain("::subject:"));
        Assert.That(did, Does.Contain("CN:%22CN%3DSHA512%20Test%22"));
        Assert.That(did, Does.Contain("O:Security"));
        Assert.That(did, Does.Contain("::eku:1.3.6.1.4.1.311.10.3.4"));
        Assert.That(did, Does.Contain("::san:email:secure%40example.com"));
    }

    #endregion

    #region Chain Location with Multiple Policies

    [Test]
    public void Builder_WithIntermediateAndMultiplePolicies_PinsToCorrectCert()
    {
        // Arrange
        var testChain = CreateTestChain();
        var leaf = testChain[0];
        var intermediate = testChain[1];
        var root = testChain[2];

        using var sanLeaf = CreateTestCertificate("CN=Chained");

        var builder = new DidX509Builder()
            .WithLeafCertificate(sanLeaf)
            .WithCaCertificate(intermediate)
            .WithSubjectFromCertificate()
            .WithEkuPolicy("1.3.6.1.5.5.7.3.8")
            .WithSanPolicy("dns", "chain.example.com");

        // Act
        string did = builder.Build();

        // Assert
        Assert.That(did, Is.Not.Null);

        // Verify pinned to intermediate, not root
        AssertDidContainsCertHash(did, intermediate, "sha256");

        // Verify all policies
        Assert.That(did, Does.Contain("::subject:"));
        Assert.That(did, Does.Contain("::eku:1.3.6.1.5.5.7.3.8"));
        Assert.That(did, Does.Contain("::san:dns:chain.example.com"));
    }

    [Test]
    public void Builder_WithPcaAndAllPolicies_PinsToPolicyCA()
    {
        // Arrange
        var testChain = CreateTestChain();
        var leaf = testChain[0];
        var pca = testChain[1];

        using var sanLeaf = CreateTestCertificate("CN=PCA Test, O=PCA Org");

        var builder = new DidX509Builder()
            .WithLeafCertificate(sanLeaf)
            .WithCaCertificate(pca)
            .WithSubjectFromCertificate()
            .WithEkuPolicy("1.3.6.1.5.5.7.3.3")
            .WithSanPolicy("uri", "https://pca.example.com");

        // Act
        string did = builder.Build();

        // Assert
        Assert.That(did, Is.Not.Null);
        AssertDidContainsCertHash(did, pca, "sha256");

        // Verify all policies
        Assert.That(did, Does.Contain("::subject:"));
        Assert.That(did, Does.Contain("CN:%22CN%3DPCA%20Test%22"));
        Assert.That(did, Does.Contain("O:PCA%20Org"));
        Assert.That(did, Does.Contain("::eku:1.3.6.1.5.5.7.3.3"));
        Assert.That(did, Does.Contain("::san:uri:https%3A%2F%2Fpca.example.com"));
    }

    #endregion

    #region Policy Order and Structure Validation

    [Test]
    public void Builder_WithPoliciesAddedInDifferentOrder_MaintainsCallOrder()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=OrderTest");
        using var root = CreateSelfSignedCertificate("CN=Root");

        // Build DID with policies in one order: subject, eku, san
        var did1 = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate()
            .WithEkuPolicy("1.3.6.1.5.5.7.3.1")
            .WithSanPolicy("dns", "order.example.com")
            .Build();

        // Build DID with policies in different order: san, subject, eku
        var did2 = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSanPolicy("dns", "order.example.com")
            .WithSubjectFromCertificate()
            .WithEkuPolicy("1.3.6.1.5.5.7.3.1")
            .Build();

        // Act & Assert - DIDs should differ based on call order
        Assert.That(did1, Is.Not.EqualTo(did2),
            "DIDs should differ when builder methods are called in different order");

        // Both should contain all policies
        Assert.That(did1, Does.Contain("::subject:"));
        Assert.That(did1, Does.Contain("::eku:"));
        Assert.That(did1, Does.Contain("::san:"));
        Assert.That(did2, Does.Contain("::subject:"));
        Assert.That(did2, Does.Contain("::eku:"));
        Assert.That(did2, Does.Contain("::san:"));

        // Verify did1 has subject before san
        Assert.That(did1.IndexOf("::subject:"), Is.LessThan(did1.IndexOf("::san:")));

        // Verify did2 has san before subject
        Assert.That(did2.IndexOf("::san:"), Is.LessThan(did2.IndexOf("::subject:")));
    }

    [Test]
    public void Builder_WithMultiplePolicies_MaintainsProperDelimiters()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Delim Test, O=Test Corp");
        using var root = CreateSelfSignedCertificate("CN=Root");

        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate()
            .WithEkuPolicy("1.3.6.1.5.5.7.3.4")
            .WithSanPolicy("email", "test@example.com")
            .WithSanPolicy("dns", "test.example.com");

        // Act
        string did = builder.Build();

        // Assert
        Assert.That(did, Is.Not.Null);

        // Verify proper use of :: for policy separation
        Assert.That(did, Does.Match(@"did:x509:\d+:sha256:[A-Za-z0-9_-]+::subject:.*::eku:.*::san:.*::san:.*"));

        // Verify no triple colons or other malformed delimiters
        Assert.That(did, Does.Not.Contain(":::"));
        Assert.That(did, Does.Not.Contain("::::"));

        // Verify colons within policy values are properly encoded
        Assert.That(did, Does.Contain("CN:%22CN%3DDelim%20Test%22"));
        Assert.That(did, Does.Contain("O:Test%20Corp"));
        Assert.That(did, Does.Contain("test%40example.com")); // @ encoded as %40
    }

    [Test]
    public void Builder_WithDuplicatePolicyTypes_IncludesBothInstances()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=Duplicate Test");
        using var root = CreateSelfSignedCertificate("CN=Root");

        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithEkuPolicy("1.3.6.1.5.5.7.3.1")
            .WithEkuPolicy("1.3.6.1.5.5.7.3.2")
            .WithSanPolicy("dns", "primary.example.com")
            .WithSanPolicy("dns", "secondary.example.com");

        // Act
        string did = builder.Build();

        // Assert
        Assert.That(did, Is.Not.Null);

        // Verify both EKU policies present
        Assert.That(did, Does.Contain("::eku:1.3.6.1.5.5.7.3.1"));
        Assert.That(did, Does.Contain("::eku:1.3.6.1.5.5.7.3.2"));

        // Verify both SAN policies present
        Assert.That(did, Does.Contain("::san:dns:primary.example.com"));
        Assert.That(did, Does.Contain("::san:dns:secondary.example.com"));

        // Count occurrences
        int ekuCount = System.Text.RegularExpressions.Regex.Matches(did, "::eku:").Count;
        int sanCount = System.Text.RegularExpressions.Regex.Matches(did, "::san:").Count;
        Assert.That(ekuCount, Is.EqualTo(2), "Should have exactly 2 EKU policies");
        Assert.That(sanCount, Is.EqualTo(2), "Should have exactly 2 SAN policies");
    }

    #endregion
}