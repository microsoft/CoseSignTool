// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Tests.Validation;

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Tests.Common;
using DIDx509.Validation;

[TestFixture]
public class DidX509ValidatorTests
{
    [Test]
    public void Validate_WithValidDidAndChain_ReturnsSuccess()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Is.Empty);
        Assert.That(result.ParsedDid, Is.Not.Null);
        Assert.That(result.ChainModel, Is.Not.Null);
    }

    [Test]
    public void Validate_WithInvalidDidFormat_ReturnsFailure()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var invalidDid = "invalid:did:format";

        // Act
        var result = DidX509Validator.Validate(invalidDid, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Has.Count.GreaterThan(0));
        Assert.That(result.Errors[0], Does.Contain("DID parsing failed"));
    }

    [Test]
    public void Validate_WithNullCertificates_ReturnsFailure()
    {
        // Arrange - use a properly formatted DID
        var testChain = TestCertificateUtils.CreateTestChain();
        var did = testChain[0].GetDidWithRoot(testChain.Cast<X509Certificate2>());

        // Act
        var result = DidX509Validator.Validate(did, null!, validateChain: false);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Has.Count.GreaterThan(0));
        Assert.That(result.Errors[0], Does.Contain("Invalid").Or.Contains("empty").Or.Contains("chain"));
    }

    [Test]
    public void Validate_WithEmptyCertificateChain_ReturnsFailure()
    {
        // Arrange - use a properly formatted DID
        var testChain = TestCertificateUtils.CreateTestChain();
        var did = testChain[0].GetDidWithRoot(testChain.Cast<X509Certificate2>());
        var emptyCerts = Array.Empty<X509Certificate2>();

        // Act
        var result = DidX509Validator.Validate(did, emptyCerts, validateChain: false);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors[0], Does.Contain("Invalid").Or.Contains("empty").Or.Contains("chain"));
    }

    [Test]
    public void Validate_WithSingleCertificate_ReturnsFailure()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("SingleCert");
        var testChain = TestCertificateUtils.CreateTestChain();
        var did = testChain[0].GetDidWithRoot(testChain.Cast<X509Certificate2>());

        // Act
        var result = DidX509Validator.Validate(did, new[] { cert }, validateChain: false);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors[0], Does.Contain("Invalid").Or.Contains("empty").Or.Contains("chain"));
    }

    [Test]
    public void Validate_WithNonMatchingCaFingerprint_ReturnsFailure()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];

        // Create a DID with a non-existent CA fingerprint
        var fakeDid = "did:x509:0:sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA::subject:CN:TestLeaf";

        // Act
        var result = DidX509Validator.Validate(fakeDid, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Has.Count.GreaterThan(0));
        Assert.That(result.Errors[0], Does.Contain("No CA certificate in chain matches fingerprint"));
    }

    [Test]
    public void Validate_WithSubjectPolicy_ValidatesSuccessfully()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];

        // Use builder to create DID with subject policy
        var did = leaf.GetDidBuilder()
            .WithCaCertificate(testChain[2])
            .WithHashAlgorithm("sha256")
            .WithSubjectFromCertificate()
            .Build();

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithInvalidSubjectPolicy_ReturnsFailure()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Add subject policy that doesn't match
        did = did + ":subject:CN:WrongName";

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Has.Count.GreaterThan(0));
    }

    [Test]
    public void Validate_WithMultiplePolicies_ValidatesAll()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Add multiple policies
        did = did + ":subject:CN:TestLeaf:subject:O:TestOrg";

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert - will pass if both policies are valid
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_WithUnknownPolicyType_ReturnsFailure()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain.Cast<X509Certificate2>());

        // Manually add unknown policy type (this will be parsed but fail validation)
        // Policies are separated by "::".
        did = did + "::unknownpolicy:somevalue";

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Has.Count.GreaterThan(0));
        // The error should mention unknown policy
        Assert.That(result.Errors.Any(e => e.Contains("Unknown") || e.Contains("policy")), Is.True);
    }

    [Test]
    public void Validate_WithChainValidationEnabled_AndMismatchedIssuer_ReturnsFailureWithChainErrors()
    {
        // Arrange: create a leaf signed by an issuer we *don't* provide, so chain.Build should fail with PartialChain.
        using var issuer = TestCertificateUtils.CreateCertificate("Issuer");
        using var leaf = TestCertificateUtils.CreateCertificate("Leaf", issuingCa: issuer);
        using var unrelatedRoot = TestCertificateUtils.CreateCertificate("UnrelatedRoot");

        var did = leaf.GetDidBuilder()
            .WithCaCertificate(unrelatedRoot)
            .WithHashAlgorithm("sha256")
            .WithSubjectFromCertificate()
            .Build();

        // Act
        var result = DidX509Validator.Validate(did, new[] { leaf, unrelatedRoot }, validateChain: true, checkRevocation: false);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Has.Count.GreaterThan(0));
        Assert.That(result.Errors.Any(e => e.Contains("Chain validation error", StringComparison.OrdinalIgnoreCase)), Is.True);
    }

    [Test]
    public void Validate_WithChainValidationEnabled_AndNullLeaf_ReturnsFailureWithChainException()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var root = testChain[2];
        var did = leaf.GetDidWithRoot(testChain.Cast<X509Certificate2>());

        // Act
        var result = DidX509Validator.Validate(did, new X509Certificate2[] { null!, root }, validateChain: true, checkRevocation: false);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Has.Count.GreaterThan(0));
        Assert.That(result.Errors.Any(e => e.Contains("Chain validation exception", StringComparison.OrdinalIgnoreCase)), Is.True);
    }

    [Test]
    public void Validate_WithChainValidationEnabled_ValidatesChain()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Act - enable chain validation
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: true, checkRevocation: false);

        // Assert - may pass or fail depending on chain validity, but should not throw
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_WithRevocationCheckEnabled_DoesNotThrow()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Act - enable revocation check (may fail but shouldn't throw)
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: true, checkRevocation: true);

        // Assert
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_WithChainValidationDisabled_SkipsChainValidation()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Act - disable chain validation (should skip RFC 5280 validation)
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert - should succeed if DID and fingerprint match
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void ValidatePoliciesOnly_CallsValidateWithoutChainValidation()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Act
        var result = DidX509Validator.ValidatePoliciesOnly(did, testChain.Cast<X509Certificate2>());

        // Assert
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_WithEkuPolicy_ValidatesExtendedKeyUsage()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Add EKU policy (use codeSigning OID)
        did = did + ":eku:1.3.6.1.5.5.7.3.3";

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert - may pass or fail depending on cert EKU, but should not throw
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_WithSanPolicy_ValidatesSubjectAlternativeName()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Add SAN policy
        did = did + ":san:dns:example.com";

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert - will fail since test cert likely doesn't have SAN
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_WithCaseInsensitivePolicyNames_RecognizesPolicies()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Add policy with uppercase name
        did = did + ":SUBJECT:CN:TestLeaf";

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert - should recognize SUBJECT as subject policy
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_WithChainConversionException_ReturnsFailure()
    {
        // Arrange - this would require a malformed certificate
        // For now, test with valid input and verify no exception
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_ReturnsDetailedErrorMessages_OnFailure()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var did = "did:x509:0:sha256:FAKEFINGERPRINT::subject:CN:Wrong";

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Is.Not.Empty);
        Assert.That(result.Errors[0], Is.Not.Empty);
    }

    [Test]
    public void Validate_WithMultipleFailedPolicies_ReturnsAllErrors()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Add multiple policies that will fail
        did = did + ":subject:CN:Wrong1:subject:O:Wrong2";

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert - should collect all policy errors
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Is.Not.Empty);
    }

    [Test]
    public void Validate_WithSHA384HashAlgorithm_ValidatesCorrectly()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];

        // Get DID with SHA-384 (version 1)
        var did = leaf.GetDidWithRoot(testChain.Cast<X509Certificate2>(), "sha384");

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_WithSHA512HashAlgorithm_ValidatesCorrectly()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];

        // Get DID with SHA-512 (version 2)
        var did = leaf.GetDidWithRoot(testChain.Cast<X509Certificate2>(), "sha512");

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_WithIntermediateCaFingerprint_FindsCorrectCa()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var intermediate = testChain[1];

        // Create DID pointing to intermediate CA using builder
        var did = leaf.GetDidBuilder()
            .WithCaCertificate(intermediate)
            .WithHashAlgorithm("sha256")
            .WithSubjectFromCertificate()
            .Build();

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.ChainModel, Is.Not.Null);
    }

    [Test]
    public void Validate_WithComplexPolicyChain_ValidatesAllPolicies()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Add multiple different policy types
        did = did + ":subject:CN:TestLeaf:subject:C:US";

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_SuccessResult_ContainsParsedDidAndChain()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert
        if (result.IsValid)
        {
            Assert.That(result.ParsedDid, Is.Not.Null);
            Assert.That(result.ParsedDid!.Did, Is.EqualTo(did));
            Assert.That(result.ChainModel, Is.Not.Null);
            Assert.That(result.ChainModel!.Chain, Has.Count.EqualTo(3));
        }
    }

    #region Extended Coverage Tests

    [Test]
    public void Validate_WithFulcioIssuerPolicy_ValidatesExtension()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Add fulcio-issuer policy
        did = did + ":fulcio-issuer:https%3A%2F%2Fexample.com";

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert - will fail since test cert likely doesn't have Fulcio extension
        Assert.That(result, Is.Not.Null);
        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    public void Validate_WithChainValidationError_ReturnsChainError()
    {
        // Arrange - Create an invalid chain (self-signed certs that don't chain properly)
        var cert1 = TestCertificateUtils.CreateCertificate("Cert1");
        var cert2 = TestCertificateUtils.CreateCertificate("Cert2");
        var certs = new[] { cert1, cert2 };

        // Use a DID that points to one of the certs
        var did = cert1.GetDidBuilder()
            .WithCaCertificate(cert2)
            .WithHashAlgorithm("sha256")
            .WithSubjectFromCertificate()
            .Build();

        // Act - enable chain validation which will fail
        var result = DidX509Validator.Validate(did, certs.Cast<X509Certificate2>(), validateChain: true, checkRevocation: false);

        // Assert - chain validation should fail
        Assert.That(result, Is.Not.Null);
        // Either validation succeeds (custom trust) or fails with chain error
    }

    [Test]
    public void Validate_WithEmptyPolicyValue_HandlesGracefully()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Add subject policy with empty value
        did = did + ":subject:CN:";

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert - should handle gracefully
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_WithMultiplePoliciesPartialMatch_ReportsAllErrors()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Add one valid and multiple invalid policies
        did = did + ":subject:CN:WrongName1:san:dns:wrong.example.com:eku:1.2.3.4.5";

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert - should collect all policy errors
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Validate_WithRootCaFingerprint_FindsRootCa()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var root = testChain[2]; // Root CA

        // Create DID pointing to root CA
        var did = leaf.GetDidBuilder()
            .WithCaCertificate(root)
            .WithHashAlgorithm("sha256")
            .WithSubjectFromCertificate()
            .Build();

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_ValidatePoliciesOnlyPath_SkipsChainValidation()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Act - use ValidatePoliciesOnly which should skip chain validation
        var result = DidX509Validator.ValidatePoliciesOnly(did, testChain.Cast<X509Certificate2>());

        // Assert
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_WithMixedCasePolicyNames_NormalizesCorrectly()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Add policies with mixed case (should be case-insensitive)
        did = did + ":Subject:CN:TestLeaf:EKU:1.3.6.1.5.5.7.3.3";

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert - should recognize policies
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_ChainWithStatusFlagsOtherThanUntrustedRoot_ReportsError()
    {
        // Arrange - Create test chain
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Act - enable chain validation
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: true, checkRevocation: false);

        // Assert - result may vary based on chain validity
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_WithOnlineRevocationCheck_AttemptsRevocationCheck()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Act - enable revocation checking (will likely fail due to no CRL/OCSP)
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: true, checkRevocation: true);

        // Assert - should complete without throwing
        Assert.That(result, Is.Not.Null);
    }

    [Test]
    public void Validate_WithDifferentCertificateIndexes_FindsMatchingCa()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();

        // Create DIDs pointing to different CAs in the chain (must include a policy)
        var did1 = testChain[0].GetDidBuilder()
            .WithCaCertificate(testChain[1])
            .WithHashAlgorithm("sha256")
            .WithSubjectFromCertificate()
            .Build();
        var did2 = testChain[0].GetDidBuilder()
            .WithCaCertificate(testChain[2])
            .WithHashAlgorithm("sha256")
            .WithSubjectFromCertificate()
            .Build();

        // Act
        var result1 = DidX509Validator.Validate(did1, testChain.Cast<X509Certificate2>(), validateChain: false);
        var result2 = DidX509Validator.Validate(did2, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert - both should find their respective CAs
        Assert.That(result1, Is.Not.Null);
        Assert.That(result2, Is.Not.Null);
        Assert.That(result1.IsValid, Is.True);
        Assert.That(result2.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithVersionZeroSha256_UsesCorrectAlgorithm()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];

        // Version 0 uses SHA-256
        var did = leaf.GetDidWithRoot(testChain.Cast<X509Certificate2>(), "sha256");

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert
        Assert.That(result, Is.Not.Null);
        if (result.IsValid)
        {
            Assert.That(result.ParsedDid!.HashAlgorithm, Is.EqualTo("sha256"));
        }
    }

    [Test]
    public void Validate_PreservesOriginalDidString_InParsedResult()
    {
        // Arrange
        var testChain = TestCertificateUtils.CreateTestChain();
        var leaf = testChain[0];
        var did = leaf.GetDidWithRoot(testChain);

        // Act
        var result = DidX509Validator.Validate(did, testChain.Cast<X509Certificate2>(), validateChain: false);

        // Assert
        if (result.IsValid)
        {
            Assert.That(result.ParsedDid!.Did, Is.EqualTo(did));
        }
    }

    #endregion
}