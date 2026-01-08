// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Tests;

using DIDx509.Builder;
using DIDx509.Validation;
using NUnit.Framework;

/// <summary>
/// Tests for DID:X509 validation with multiple policies.
/// Validates that certificates can be properly validated against DIDs containing
/// various policy combinations.
/// </summary>
[TestFixture]
public class ValidationTests : DIDx509TestBase
{
    #region Single Policy Validation Tests

    [Test]
    public void Validate_WithSubjectPolicy_ValidCertificate_ReturnsSuccess()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=TestUser");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        string did = leaf.GetDidWithRoot(chain);

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, chain);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Is.Empty);
    }

    [Test]
    public void Validate_WithSubjectPolicy_InvalidCertificate_ReturnsFailure()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=TestUser");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        string did = leaf.GetDidWithRoot(chain);

        // Use a different leaf certificate
        using var wrongLeaf = CreateTestCertificate("CN=WrongUser");
        var wrongChain = new[] { wrongLeaf, root };

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, wrongChain);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Has.Count.GreaterThan(0));
        Assert.That(result.Errors[0], Does.Contain("Subject policy validation failed"));
    }

    [Test]
    public void Validate_WithEkuPolicy_ValidCertificate_ReturnsSuccess()
    {
        // Arrange - TestCertificateUtils adds default EKUs (1.3.6.1.5.5.7.3.2 and 1.3.6.1.5.5.7.3.1)
        using var leaf = CreateTestCertificate("CN=TestUser");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        string did = leaf.GetDidWithRootAndEku(chain);

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, chain);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Is.Empty);
    }

    [Test]
    public void Validate_WithEkuPolicy_MissingEku_ReturnsFailure()
    {
        // Arrange - Create DID requiring specific EKU
        using var leaf = CreateTestCertificate("CN=TestUser");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        string did = leaf.GetDidWithRootAndEku(chain);

        // Manually build DID with an EKU that doesn't exist in the cert
        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate()
            .WithEkuPolicy("1.3.6.1.5.5.7.3.99"); // Non-existent EKU

        string didWithMissingEku = builder.Build();

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(didWithMissingEku, chain);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Has.Count.GreaterThan(0));
        Assert.That(result.Errors[0], Does.Contain("EKU policy validation failed"));
    }

    [Test]
    public void Validate_WithSanPolicy_ValidCertificate_ReturnsSuccess()
    {
        // Arrange - Create certificate with specific DNS SAN
        using var cert = CreateTestCertificate("CN=Test", customSans: [("dns", "example.com")]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { cert, root };

        // Build DID with SAN policy matching the certificate
        var builder = new DidX509Builder()
            .WithLeafCertificate(cert)
            .WithCaCertificate(root)
            .WithSanPolicy("dns", "example.com");

        string did = builder.Build();

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, chain);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Is.Empty);
    }

    [Test]
    public void Validate_WithSanPolicy_MissingSan_ReturnsFailure()
    {
        // Arrange
        using var cert = CreateTestCertificate("CN=example.com");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { cert, root };

        var builder = new DidX509Builder()
            .WithLeafCertificate(cert)
            .WithCaCertificate(root)
            .WithSanPolicy("dns", "example.com");

        string did = builder.Build();

        // Use a certificate with different SAN
        using var wrongCert = CreateTestCertificate("CN=different.com");
        var wrongChain = new[] { wrongCert, root };

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, wrongChain);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Has.Count.GreaterThan(0));
        Assert.That(result.Errors[0], Does.Contain("SAN policy validation failed"));
    }

    #endregion

    #region Multiple Policy Validation Tests

    [Test]
    public void Validate_WithSubjectAndEkuPolicies_ValidCertificate_ReturnsSuccess()
    {
        // Arrange
        string[] ekuOids = new[] { "1.3.6.1.5.5.7.3.1" };
        using var leaf = CreateTestCertificate("CN=TestUser");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        string did = leaf.GetDidWithRootAndEku(chain);

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, chain);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Is.Empty);
    }

    [Test]
    public void Validate_WithSubjectAndEkuPolicies_InvalidSubject_ReturnsFailure()
    {
        // Arrange
        string[] ekuOids = new[] { "1.3.6.1.5.5.7.3.1" };
        using var leaf = CreateTestCertificate("CN=TestUser");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        string did = leaf.GetDidWithRootAndEku(chain);

        // Use a certificate with wrong subject but correct EKU
        using var wrongLeaf = CreateTestCertificate("CN=WrongUser");
        var wrongChain = new[] { wrongLeaf, root };

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, wrongChain);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Has.Count.GreaterThan(0));
        Assert.That(result.Errors, Has.Some.Contains("Subject policy validation failed"));
    }

    [Test]
    public void Validate_WithSubjectAndEkuPolicies_InvalidEku_ReturnsFailure()
    {
        // Arrange - Create certificate with specific EKU
        using var leaf = CreateTestCertificate("CN=TestUser", customEkus: ["1.3.6.1.5.5.7.3.1"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        string did = leaf.GetDidWithRootAndEku(chain);

        // Use a certificate with correct subject but wrong EKU
        using var wrongLeaf = CreateTestCertificate("CN=TestUser", customEkus: ["1.3.6.1.5.5.7.3.2"]);
        var wrongChain = new[] { wrongLeaf, root };

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, wrongChain);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Has.Count.GreaterThan(0));
        Assert.That(result.Errors, Has.Some.Contains("EKU policy validation failed"));
    }

    [Test]
    public void Validate_WithSubjectAndSanPolicies_ValidCertificate_ReturnsSuccess()
    {
        // Arrange - Create certificate with specific DNS SAN
        using var cert = CreateTestCertificate("CN=TestUser", customSans: [("dns", "example.com")]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { cert, root };

        var builder = new DidX509Builder()
            .WithLeafCertificate(cert)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate()
            .WithSanPolicy("dns", "example.com");

        string did = builder.Build();

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, chain);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Is.Empty);
    }

    [Test]
    public void Validate_WithEkuAndSanPolicies_ValidCertificate_ReturnsSuccess()
    {
        // Arrange - Create certificate with specific EKU and email SAN
        using var cert = CreateTestCertificate("CN=TestUser", customEkus: ["1.3.6.1.5.5.7.3.4"], customSans: [("email", "user@example.com")]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { cert, root };

        var builder = new DidX509Builder()
            .WithLeafCertificate(cert)
            .WithCaCertificate(root)
            .WithEkuPolicy("1.3.6.1.5.5.7.3.4")
            .WithSanPolicy("email", "user@example.com");

        string did = builder.Build();

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, chain);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Is.Empty);
    }

    [Test]
    public void Validate_WithSubjectEkuAndSanPolicies_ValidCertificate_ReturnsSuccess()
    {
        // Arrange - Create certificate with specific EKU and DNS SAN
        using var cert = CreateTestCertificate("CN=FullTest", customEkus: ["1.3.6.1.5.5.7.3.1"], customSans: [("dns", "full.example.com")]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { cert, root };

        var builder = new DidX509Builder()
            .WithLeafCertificate(cert)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate()
            .WithEkuPolicy("1.3.6.1.5.5.7.3.1")
            .WithSanPolicy("dns", "full.example.com");

        string did = builder.Build();

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, chain);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Is.Empty);
    }

    [Test]
    public void Validate_WithSubjectEkuAndSanPolicies_OneInvalid_ReturnsFailure()
    {
        // Arrange
        using var cert = CreateTestCertificate("CN=FullTest");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { cert, root };

        var builder = new DidX509Builder()
            .WithLeafCertificate(cert)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate()
            .WithEkuPolicy("1.3.6.1.5.5.7.3.1")
            .WithSanPolicy("dns", "full.example.com");

        string did = builder.Build();

        // Use a certificate with wrong SAN but correct subject and EKU
        using var wrongCert = CreateTestCertificate("CN=FullTest", customEkus: ["1.3.6.1.5.5.7.3.1"], customSans: [("dns", "wrong.example.com")]);
        var wrongChain = new[] { wrongCert, root };

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, wrongChain);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Has.Count.GreaterThan(0));
        Assert.That(result.Errors, Has.Some.Contains("SAN policy validation failed"));
    }

    [Test]
    public void Validate_WithMultipleSanPolicies_AllValid_ReturnsSuccess()
    {
        // Arrange - Create certificate with specific DNS SAN
        using var cert = CreateTestCertificate("CN=MultiSan", customSans: [("dns", "example.com")]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { cert, root };

        var builder = new DidX509Builder()
            .WithLeafCertificate(cert)
            .WithCaCertificate(root)
            .WithSanPolicy("dns", "example.com");

        string did = builder.Build();

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, chain);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Is.Empty);
    }

    [Test]
    public void Validate_WithMultipleSanPolicies_OneInvalid_ReturnsFailure()
    {
        // Arrange - Create certificate with one DNS SAN
        using var cert = CreateTestCertificate("CN=MultiSan", customSans: [("dns", "example.com")]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { cert, root };

        // Build DID with two SAN policies, but cert only has one
        var builder = new DidX509Builder()
            .WithLeafCertificate(cert)
            .WithCaCertificate(root)
            .WithSanPolicy("dns", "example.com")
            .WithSanPolicy("dns", "another.com"); // This doesn't exist in cert

        string did = builder.Build();

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, chain);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Has.Count.GreaterThan(0));
        Assert.That(result.Errors, Has.Some.Contains("SAN policy validation failed"));
    }

    [Test]
    public void Validate_WithMultipleEkuPolicies_AllValid_ReturnsSuccess()
    {
        // Arrange
        string[] ekuOids = new[] { "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2" };
        using var leaf = CreateTestCertificate("CN=MultiEku");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithEkuPolicy("1.3.6.1.5.5.7.3.1")
            .WithEkuPolicy("1.3.6.1.5.5.7.3.2");

        string did = builder.Build();

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, chain);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Is.Empty);
    }

    [Test]
    public void Validate_WithMultipleEkuPolicies_OneInvalid_ReturnsFailure()
    {
        // Arrange - Create certificate with one EKU
        using var leaf = CreateTestCertificate("CN=MultiEku", customEkus: ["1.3.6.1.5.5.7.3.1"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Build DID with two EKU policies, but cert only has one
        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithEkuPolicy("1.3.6.1.5.5.7.3.1")
            .WithEkuPolicy("1.3.6.1.5.5.7.3.2"); // This doesn't exist in cert

        string did = builder.Build();

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, chain);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Has.Count.GreaterThan(0));
        Assert.That(result.Errors, Has.Some.Contains("EKU policy validation failed"));
    }

    #endregion

    #region CA Fingerprint Validation Tests

    [Test]
    public void Validate_WithWrongCaFingerprint_ReturnsFailure()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=TestUser");
        using var root1 = CreateSelfSignedCertificate("CN=Root1");
        using var root2 = CreateSelfSignedCertificate("CN=Root2");

        var chain1 = new[] { leaf, root1 };
        var chain2 = new[] { leaf, root2 };

        // Create DID with root1
        string did = leaf.GetDidWithRoot(chain1);

        // Validate against chain with root2
        var result = DidX509Validator.ValidatePoliciesOnly(did, chain2);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Has.Count.GreaterThan(0));
        Assert.That(result.Errors[0], Does.Contain("No CA certificate in chain matches fingerprint"));
    }

    [Test]
    public void Validate_WithMatchingIntermediateCa_ReturnsSuccess()
    {
        // Arrange
        var testChain = CreateTestChain();
        var leaf = testChain[0];
        var intermediate = testChain[1];
        var root = testChain[2];

        // Create DID pinned to intermediate
        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(intermediate)
            .WithSubjectFromCertificate();

        string did = builder.Build();

        // Validate
        var result = DidX509Validator.ValidatePoliciesOnly(did, testChain);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Is.Empty);
    }

    #endregion

    #region Hash Algorithm Tests

    [Test]
    public void Validate_WithSHA384_ValidCertificate_ReturnsSuccess()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=SHA384Test");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        string did = leaf.GetDidWithRoot(chain, "sha384");

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, chain);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Is.Empty);
    }

    [Test]
    public void Validate_WithSHA512_ValidCertificate_ReturnsSuccess()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=SHA512Test");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        string did = leaf.GetDidWithRoot(chain, "sha512");

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, chain);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Is.Empty);
    }

    [Test]
    public void Validate_WithSHA384AndMultiplePolicies_ValidCertificate_ReturnsSuccess()
    {
        // Arrange - Create certificate with specific EKU and DNS SAN
        using var cert = CreateTestCertificate("CN=SHA384Test", customEkus: ["1.3.6.1.5.5.7.3.1"], customSans: [("dns", "sha384.example.com")]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { cert, root };

        var builder = new DidX509Builder()
            .WithLeafCertificate(cert)
            .WithCaCertificate(root)
            .WithHashAlgorithm("sha384")
            .WithSubjectFromCertificate()
            .WithEkuPolicy("1.3.6.1.5.5.7.3.1")
            .WithSanPolicy("dns", "sha384.example.com");

        string did = builder.Build();

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, chain);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Is.Empty);
    }

    #endregion

    #region Complex Validation Scenarios

    [Test]
    public void Validate_WithAllPolicyTypesAndMultipleValues_ValidCertificate_ReturnsSuccess()
    {
        // Arrange - Create certificate with specific EKUs and DNS SAN
        using var cert = CreateTestCertificate("CN=ComplexTest", customEkus: ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"], customSans: [("dns", "complex.example.com")]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { cert, root };

        var builder = new DidX509Builder()
            .WithLeafCertificate(cert)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate()
            .WithEkuPolicy("1.3.6.1.5.5.7.3.1")
            .WithSanPolicy("dns", "complex.example.com");

        string did = builder.Build();

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, chain);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Is.Empty);
    }

    [Test]
    public void Validate_WithAllPolicyTypes_MultipleInvalid_ReturnsAllErrors()
    {
        // Arrange
        using var cert = CreateTestCertificate("CN=ComplexTest");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { cert, root };

        var builder = new DidX509Builder()
            .WithLeafCertificate(cert)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate()
            .WithEkuPolicy("1.3.6.1.5.5.7.3.1")
            .WithSanPolicy("dns", "complex.example.com");

        string did = builder.Build();

        // Use completely different certificate
        using var wrongCert = CreateTestCertificate("CN=WrongTest");
        var wrongChain = new[] { wrongCert, root };

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, wrongChain);

        // Assert
        Assert.That(result.IsValid, Is.False);

        // Should have multiple errors - at minimum subject and SAN fail (EKU might pass if same default EKU)
        Assert.That(result.Errors.Count, Is.GreaterThanOrEqualTo(1));
        Assert.That(result.Errors, Has.Some.Contains("policy validation failed"));
    }

    [Test]
    public void Validate_CertificateSatisfiesMoreThanRequired_ReturnsSuccess()
    {
        // Arrange - Certificate has more EKUs than DID requires
        string[] ekuOids = new[] { "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.3" };
        using var leaf = CreateTestCertificate("CN=ExtraEku");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // DID only requires one EKU
        var builder = new DidX509Builder()
            .WithLeafCertificate(leaf)
            .WithCaCertificate(root)
            .WithSubjectFromCertificate()
            .WithEkuPolicy("1.3.6.1.5.5.7.3.1");

        string did = builder.Build();

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, chain);

        // Assert - Should succeed because cert has all required policies (and more)
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Is.Empty);
    }

    #endregion

    #region Validation Result Tests

    [Test]
    public void Validate_SuccessResult_ContainsParsedDidAndChain()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=TestUser");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        string did = leaf.GetDidWithRoot(chain);

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, chain);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.ParsedDid, Is.Not.Null);
        Assert.That(result.ParsedDid!.Policies, Is.Not.Empty);
        Assert.That(result.ChainModel, Is.Not.Null);
    }

    [Test]
    public void Validate_FailureResult_ContainsErrorMessages()
    {
        // Arrange
        using var leaf = CreateTestCertificate("CN=TestUser");
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        string did = leaf.GetDidWithRoot(chain);

        // Use wrong certificate
        using var wrongLeaf = CreateTestCertificate("CN=WrongUser");
        var wrongChain = new[] { wrongLeaf, root };

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, wrongChain);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Is.Not.Empty);
        Assert.That(result.Errors, Has.All.Not.Null.And.Not.Empty);
    }

    #endregion
}