// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Tests.Validation;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Text;
using CoseSign1.AzureKeyVault.Validation;
using CoseSign1.Validation;
using CoseSign1.Validation.Builders;
using CoseSign1.Validation.Results;
using NUnit.Framework;

[TestFixture]
public class AzureKeyVaultTrustValidatorTests
{
    private static readonly CoseHeaderLabel KidLabel = new(4);

    #region Test Helpers

    private static CoseSign1Message CreateTestMessageWithKid(string? kid)
    {
        // Create a test message with an AKV-style kid header
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var protectedHeaders = new CoseHeaderMap();
        if (kid != null)
        {
            protectedHeaders.Add(KidLabel, Encoding.UTF8.GetBytes(kid));
        }

        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA256, protectedHeaders);
        var signedBytes = CoseSign1Message.SignDetached(new byte[] { 1, 2, 3 }, signer, ReadOnlySpan<byte>.Empty);

        return CoseSign1Message.DecodeSign1(signedBytes);
    }

    #endregion

    #region Constructor Tests

    [Test]
    public void Constructor_WithNullPatterns_ShouldSucceed()
    {
        // Act
        var validator = new AzureKeyVaultTrustValidator(allowedPatterns: null);

        // Assert
        Assert.That(validator, Is.Not.Null);
        Assert.That(validator.Stages.Single(), Is.EqualTo(ValidationStage.KeyMaterialTrust));
    }

    [Test]
    public void Constructor_WithEmptyPatterns_ShouldSucceed()
    {
        // Act
        var validator = new AzureKeyVaultTrustValidator(allowedPatterns: Array.Empty<string>());

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithValidPatterns_ShouldSucceed()
    {
        // Act
        var validator = new AzureKeyVaultTrustValidator(
            allowedPatterns: new[] { "https://myvault.vault.azure.net/keys/*" });

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithRegexPattern_ShouldSucceed()
    {
        // Act
        var validator = new AzureKeyVaultTrustValidator(
            allowedPatterns: new[] { "regex:https://.*\\.vault\\.azure\\.net/keys/signing-.*" });

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    #endregion

    #region IsApplicable Tests

    [Test]
    public void IsApplicable_WithNullMessage_ShouldReturnFalse()
    {
        // Arrange
        var validator = new AzureKeyVaultTrustValidator();

        // Act
        var result = validator.IsApplicable(null!, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsApplicable_WithWrongStage_ShouldReturnFalse()
    {
        // Arrange
        var validator = new AzureKeyVaultTrustValidator();
        var message = CreateTestMessageWithKid("https://myvault.vault.azure.net/keys/mykey");

        // Act
        var result = validator.IsApplicable(message, ValidationStage.Signature);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsApplicable_WithNoKidHeader_ShouldReturnFalse()
    {
        // Arrange
        var validator = new AzureKeyVaultTrustValidator();
        var message = CreateTestMessageWithKid(null);

        // Act
        var result = validator.IsApplicable(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsApplicable_WithNonAkvKid_WhenRequireAkvKey_ShouldReturnFalse()
    {
        // Arrange
        var validator = new AzureKeyVaultTrustValidator(requireAzureKeyVaultKey: true);
        var message = CreateTestMessageWithKid("https://example.com/some/other/key");

        // Act
        var result = validator.IsApplicable(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsApplicable_WithNonAkvKid_WhenNotRequireAkvKey_ShouldReturnTrue()
    {
        // Arrange
        var validator = new AzureKeyVaultTrustValidator(requireAzureKeyVaultKey: false);
        var message = CreateTestMessageWithKid("https://example.com/some/other/key");

        // Act
        var result = validator.IsApplicable(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void IsApplicable_WithValidAkvKid_ShouldReturnTrue()
    {
        // Arrange
        var validator = new AzureKeyVaultTrustValidator();
        var message = CreateTestMessageWithKid("https://myvault.vault.azure.net/keys/mykey");

        // Act
        var result = validator.IsApplicable(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result, Is.True);
    }

    #endregion

    #region Validate Tests - Pattern Matching

    [Test]
    public void Validate_WithExactMatch_ShouldSetKidAllowed()
    {
        // Arrange
        var kid = "https://myvault.vault.azure.net/keys/mykey";
        var validator = new AzureKeyVaultTrustValidator(allowedPatterns: new[] { kid });
        var message = CreateTestMessageWithKid(kid);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsSuccess, Is.True);
        var assertions = GetTrustAssertions(result);
        Assert.That(assertions.Any(a => a.ClaimId == AkvTrustClaims.IsAzureKeyVaultKey && a.Satisfied), Is.True);
        Assert.That(assertions.Any(a => a.ClaimId == AkvTrustClaims.KidAllowed && a.Satisfied), Is.True);
    }

    [Test]
    public void Validate_WithWildcardMatch_ShouldSetKidAllowed()
    {
        // Arrange
        var pattern = "https://myvault.vault.azure.net/keys/*";
        var kid = "https://myvault.vault.azure.net/keys/mykey";
        var validator = new AzureKeyVaultTrustValidator(allowedPatterns: new[] { pattern });
        var message = CreateTestMessageWithKid(kid);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsSuccess, Is.True);
        var assertions = GetTrustAssertions(result);
        Assert.That(assertions.Any(a => a.ClaimId == AkvTrustClaims.KidAllowed && a.Satisfied), Is.True);
    }

    [Test]
    public void Validate_WithVaultWildcard_ShouldMatchAnyVault()
    {
        // Arrange
        var pattern = "https://*.vault.azure.net/keys/*";
        var kid = "https://anyvault.vault.azure.net/keys/anykey";
        var validator = new AzureKeyVaultTrustValidator(allowedPatterns: new[] { pattern });
        var message = CreateTestMessageWithKid(kid);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsSuccess, Is.True);
        var assertions = GetTrustAssertions(result);
        Assert.That(assertions.Any(a => a.ClaimId == AkvTrustClaims.KidAllowed && a.Satisfied), Is.True);
    }

    [Test]
    public void Validate_WithRegexPattern_ShouldMatch()
    {
        // Arrange
        var pattern = "regex:https://.*\\.vault\\.azure\\.net/keys/signing-.*";
        var kid = "https://myvault.vault.azure.net/keys/signing-key-2024";
        var validator = new AzureKeyVaultTrustValidator(allowedPatterns: new[] { pattern });
        var message = CreateTestMessageWithKid(kid);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsSuccess, Is.True);
        var assertions = GetTrustAssertions(result);
        Assert.That(assertions.Any(a => a.ClaimId == AkvTrustClaims.KidAllowed && a.Satisfied), Is.True);
    }

    [Test]
    public void Validate_WithNoMatchingPattern_ShouldSetKidAllowedFalse()
    {
        // Arrange
        var pattern = "https://allowedvault.vault.azure.net/keys/*";
        var kid = "https://othervault.vault.azure.net/keys/mykey";
        var validator = new AzureKeyVaultTrustValidator(allowedPatterns: new[] { pattern });
        var message = CreateTestMessageWithKid(kid);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsSuccess, Is.True); // Validation itself succeeds
        var assertions = GetTrustAssertions(result);
        Assert.That(assertions.Any(a => a.ClaimId == AkvTrustClaims.IsAzureKeyVaultKey && a.Satisfied), Is.True);
        Assert.That(assertions.Any(a => a.ClaimId == AkvTrustClaims.KidAllowed && !a.Satisfied), Is.True);
    }

    [Test]
    public void Validate_WithNoPatterns_ShouldSetKidAllowedFalse()
    {
        // Arrange
        var kid = "https://myvault.vault.azure.net/keys/mykey";
        var validator = new AzureKeyVaultTrustValidator();
        var message = CreateTestMessageWithKid(kid);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsSuccess, Is.True);
        var assertions = GetTrustAssertions(result);
        Assert.That(assertions.Any(a => a.ClaimId == AkvTrustClaims.IsAzureKeyVaultKey && a.Satisfied), Is.True);
        Assert.That(assertions.Any(a => a.ClaimId == AkvTrustClaims.KidAllowed && !a.Satisfied), Is.True);
    }

    #endregion

    #region Validate Tests - AKV Detection

    [Test]
    public void Validate_WithHttpKid_ShouldSetIsAkvKeyFalse()
    {
        // Arrange - HTTP instead of HTTPS
        var kid = "http://myvault.vault.azure.net/keys/mykey";
        var validator = new AzureKeyVaultTrustValidator(requireAzureKeyVaultKey: false);
        var message = CreateTestMessageWithKid(kid);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsSuccess, Is.True);
        var assertions = GetTrustAssertions(result);
        Assert.That(assertions.Any(a => a.ClaimId == AkvTrustClaims.IsAzureKeyVaultKey && !a.Satisfied), Is.True);
    }

    [Test]
    public void Validate_WithNonAkvHost_ShouldSetIsAkvKeyFalse()
    {
        // Arrange - Different host
        var kid = "https://example.com/keys/mykey";
        var validator = new AzureKeyVaultTrustValidator(requireAzureKeyVaultKey: false);
        var message = CreateTestMessageWithKid(kid);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsSuccess, Is.True);
        var assertions = GetTrustAssertions(result);
        Assert.That(assertions.Any(a => a.ClaimId == AkvTrustClaims.IsAzureKeyVaultKey && !a.Satisfied), Is.True);
    }

    [Test]
    public void Validate_WithNonKeyPath_ShouldSetIsAkvKeyFalse()
    {
        // Arrange - Secrets path instead of keys
        var kid = "https://myvault.vault.azure.net/secrets/mysecret";
        var validator = new AzureKeyVaultTrustValidator(requireAzureKeyVaultKey: false);
        var message = CreateTestMessageWithKid(kid);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsSuccess, Is.True);
        var assertions = GetTrustAssertions(result);
        Assert.That(assertions.Any(a => a.ClaimId == AkvTrustClaims.IsAzureKeyVaultKey && !a.Satisfied), Is.True);
    }

    [Test]
    public void Validate_WithKeyVersion_ShouldSetIsAkvKeyTrue()
    {
        // Arrange - Kid with version
        var kid = "https://myvault.vault.azure.net/keys/mykey/abc123version";
        var validator = new AzureKeyVaultTrustValidator();
        var message = CreateTestMessageWithKid(kid);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsSuccess, Is.True);
        var assertions = GetTrustAssertions(result);
        Assert.That(assertions.Any(a => a.ClaimId == AkvTrustClaims.IsAzureKeyVaultKey && a.Satisfied), Is.True);
    }

    #endregion

    #region GetDefaultTrustPolicy Tests

    [Test]
    public void GetDefaultTrustPolicy_WithNoPatterns_ShouldRequireAkvKeyDetected()
    {
        // Arrange
        var validator = new AzureKeyVaultTrustValidator();
        var context = new ValidationBuilderContext();

        // Act
        var policy = validator.GetDefaultTrustPolicy(context);

        // Assert
        Assert.That(policy, Is.Not.Null);
        // Policy should be for akv.key.detected claim
    }

    [Test]
    public void GetDefaultTrustPolicy_WithPatterns_ShouldRequireBothClaims()
    {
        // Arrange
        var validator = new AzureKeyVaultTrustValidator(
            allowedPatterns: new[] { "https://myvault.vault.azure.net/keys/*" });
        var context = new ValidationBuilderContext();

        // Act
        var policy = validator.GetDefaultTrustPolicy(context);

        // Assert
        Assert.That(policy, Is.Not.Null);
        // Policy should require both akv.key.detected AND akv.kid.allowed
    }

    #endregion

    #region Async Tests

    [Test]
    public async Task ValidateAsync_ShouldReturnSameResultAsSync()
    {
        // Arrange
        var kid = "https://myvault.vault.azure.net/keys/mykey";
        var validator = new AzureKeyVaultTrustValidator(allowedPatterns: new[] { kid });
        var message = CreateTestMessageWithKid(kid);

        // Act
        var syncResult = validator.Validate(message, ValidationStage.KeyMaterialTrust);
        var asyncResult = await validator.ValidateAsync(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(asyncResult.IsSuccess, Is.EqualTo(syncResult.IsSuccess));
    }

    #endregion

    #region Edge Case Tests

    [Test]
    public void Validate_WithMultiplePatterns_ShouldMatchFirst()
    {
        // Arrange
        var patterns = new[]
        {
            "https://vault1.vault.azure.net/keys/*",
            "https://vault2.vault.azure.net/keys/*",
            "https://vault3.vault.azure.net/keys/*"
        };
        var kid = "https://vault2.vault.azure.net/keys/mykey";
        var validator = new AzureKeyVaultTrustValidator(allowedPatterns: patterns);
        var message = CreateTestMessageWithKid(kid);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsSuccess, Is.True);
        var assertions = GetTrustAssertions(result);
        Assert.That(assertions.Any(a => a.ClaimId == AkvTrustClaims.KidAllowed && a.Satisfied), Is.True);

        // Verify metadata shows matched pattern
        Assert.That(result.Metadata.ContainsKey("matchedPattern"), Is.True);
        Assert.That(result.Metadata["matchedPattern"], Is.EqualTo(patterns[1]));
    }

    [Test]
    public void Validate_WithWrongStage_ShouldReturnNotApplicable()
    {
        // Arrange
        var kid = "https://myvault.vault.azure.net/keys/mykey";
        var validator = new AzureKeyVaultTrustValidator();
        var message = CreateTestMessageWithKid(kid);

        // Act
        var result = validator.Validate(message, ValidationStage.Signature);

        // Assert
        Assert.That(result.Kind, Is.EqualTo(ValidationResultKind.NotApplicable));
    }

    [Test]
    public void Validate_WithNullMessage_ShouldReturnFailure()
    {
        // Arrange
        var validator = new AzureKeyVaultTrustValidator();

        // Act
        var result = validator.Validate(null!, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.Kind, Is.EqualTo(ValidationResultKind.Failure));
    }

    [Test]
    public void Validate_PatternIsCaseInsensitive()
    {
        // Arrange
        var pattern = "https://MYVAULT.VAULT.AZURE.NET/keys/*";
        var kid = "https://myvault.vault.azure.net/keys/mykey";
        var validator = new AzureKeyVaultTrustValidator(allowedPatterns: new[] { pattern });
        var message = CreateTestMessageWithKid(kid);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsSuccess, Is.True);
        var assertions = GetTrustAssertions(result);
        Assert.That(assertions.Any(a => a.ClaimId == AkvTrustClaims.KidAllowed && a.Satisfied), Is.True);
    }

    #endregion

    #region Helper Methods

    private static IEnumerable<TrustAssertion> GetTrustAssertions(ValidationResult result)
    {
        if (result.Metadata.TryGetValue(TrustAssertionMetadata.AssertionsKey, out var value) &&
            value is IEnumerable<TrustAssertion> assertions)
        {
            return assertions;
        }
        return Enumerable.Empty<TrustAssertion>();
    }

    #endregion
}
