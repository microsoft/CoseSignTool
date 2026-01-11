// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using CoseSign1.Abstractions;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Trust;
using Moq;

/// <summary>
/// Tests for <see cref="SigningKeyResolutionResult"/>.
/// </summary>
[TestFixture]
[Category("Validation")]
public class SigningKeyResolutionResultTests
{
    [Test]
    public void Success_MinimalParameters_CreatesSuccessResult()
    {
        var mockKey = new Mock<ISigningKey>();

        var result = SigningKeyResolutionResult.Success(mockKey.Object);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.SigningKey, Is.SameAs(mockKey.Object));
            Assert.That(result.Diagnostics, Is.Empty);
            Assert.That(result.KeyId, Is.Null);
            Assert.That(result.Thumbprint, Is.Null);
        });
    }

    [Test]
    public void Success_AllParameters_CreatesSuccessResult()
    {
        var mockKey = new Mock<ISigningKey>();
        var keyId = "test-key-id";
        var thumbprint = new byte[] { 1, 2, 3, 4 };
        var diagnostics = new List<string> { "Diagnostic 1" };

        var result = SigningKeyResolutionResult.Success(mockKey.Object, keyId, thumbprint, diagnostics);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.SigningKey, Is.SameAs(mockKey.Object));
            Assert.That(result.KeyId, Is.EqualTo(keyId));
            Assert.That(result.Thumbprint, Is.EqualTo(thumbprint));
            Assert.That(result.Diagnostics, Has.Count.EqualTo(1));
        });
    }

    [Test]
    public void Failure_MinimalParameters_CreatesFailureResult()
    {
        var result = SigningKeyResolutionResult.Failure("Key not found");

        Assert.Multiple(() =>
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.SigningKey, Is.Null);
            Assert.That(result.ErrorMessage, Is.EqualTo("Key not found"));
            Assert.That(result.Diagnostics, Is.Empty);
        });
    }

    [Test]
    public void Failure_AllParameters_CreatesFailureResult()
    {
        var diagnostics = new List<string> { "Tried X", "Tried Y" };

        var result = SigningKeyResolutionResult.Failure("Key not found", "KEY_NOT_FOUND", diagnostics);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.ErrorMessage, Is.EqualTo("Key not found"));
            Assert.That(result.ErrorCode, Is.EqualTo("KEY_NOT_FOUND"));
            Assert.That(result.Diagnostics, Has.Count.EqualTo(2));
        });
    }

    [Test]
    public void CandidateKeys_CanBeSet()
    {
        var mockKey1 = new Mock<ISigningKey>().Object;
        var mockKey2 = new Mock<ISigningKey>().Object;

        var result = new SigningKeyResolutionResult
        {
            IsSuccess = false,
            CandidateKeys = new List<ISigningKey> { mockKey1, mockKey2 }
        };

        Assert.That(result.CandidateKeys, Has.Count.EqualTo(2));
    }

    [Test]
    public void Diagnostics_DefaultsToEmptyArray()
    {
        var result = new SigningKeyResolutionResult();

        Assert.That(result.Diagnostics, Is.Empty);
    }

    [Test]
    public void ErrorMessage_CanBeAccessed()
    {
        var result = SigningKeyResolutionResult.Failure("Error occurred");

        Assert.That(result.ErrorMessage, Is.EqualTo("Error occurred"));
    }

    [Test]
    public void ErrorCode_CanBeNull()
    {
        var result = SigningKeyResolutionResult.Failure("Error occurred");

        Assert.That(result.ErrorCode, Is.Null);
    }
}

/// <summary>
/// Tests for <see cref="PostSignatureValidationContext"/>.
/// </summary>
[TestFixture]
[Category("Validation")]
public class PostSignatureValidationContextTests
{
    [Test]
    public void Constructor_ValidParameters_CreatesContext()
    {
        var mockMessage = CreateMockMessage();
        var assertions = new List<ISigningKeyAssertion>();
        var trustDecision = TrustDecision.Trusted();
        var metadata = new Dictionary<string, object>();
        var options = new CoseSign1ValidationOptions();

        var context = new PostSignatureValidationContext(
            mockMessage,
            assertions,
            trustDecision,
            metadata,
            options);

        Assert.Multiple(() =>
        {
            Assert.That(context.Message, Is.SameAs(mockMessage));
            Assert.That(context.TrustAssertions, Is.SameAs(assertions));
            Assert.That(context.TrustDecision, Is.SameAs(trustDecision));
            Assert.That(context.SignatureMetadata, Is.SameAs(metadata));
            Assert.That(context.Options, Is.SameAs(options));
            Assert.That(context.ResolvedSigningKey, Is.Null);
        });
    }

    [Test]
    public void Constructor_WithSigningKey_SetsResolvedSigningKey()
    {
        var mockMessage = CreateMockMessage();
        var mockKey = new Mock<ISigningKey>().Object;
        var options = new CoseSign1ValidationOptions();

        var context = new PostSignatureValidationContext(
            mockMessage,
            Array.Empty<ISigningKeyAssertion>(),
            TrustDecision.Trusted(),
            new Dictionary<string, object>(),
            options,
            mockKey);

        Assert.That(context.ResolvedSigningKey, Is.SameAs(mockKey));
    }

    [Test]
    public void Constructor_NullMessage_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new PostSignatureValidationContext(
            null!,
            Array.Empty<ISigningKeyAssertion>(),
            TrustDecision.Trusted(),
            new Dictionary<string, object>(),
            new CoseSign1ValidationOptions()));
    }

    [Test]
    public void Constructor_NullAssertions_ThrowsArgumentNullException()
    {
        var mockMessage = CreateMockMessage();

        Assert.Throws<ArgumentNullException>(() => new PostSignatureValidationContext(
            mockMessage,
            null!,
            TrustDecision.Trusted(),
            new Dictionary<string, object>(),
            new CoseSign1ValidationOptions()));
    }

    [Test]
    public void Constructor_NullMetadata_ThrowsArgumentNullException()
    {
        var mockMessage = CreateMockMessage();

        Assert.Throws<ArgumentNullException>(() => new PostSignatureValidationContext(
            mockMessage,
            Array.Empty<ISigningKeyAssertion>(),
            TrustDecision.Trusted(),
            null!,
            new CoseSign1ValidationOptions()));
    }

    [Test]
    public void Constructor_NullOptions_ThrowsArgumentNullException()
    {
        var mockMessage = CreateMockMessage();

        Assert.Throws<ArgumentNullException>(() => new PostSignatureValidationContext(
            mockMessage,
            Array.Empty<ISigningKeyAssertion>(),
            TrustDecision.Trusted(),
            new Dictionary<string, object>(),
            null!));
    }

    [Test]
    public void TrustAssertions_ReturnsProvidedAssertions()
    {
        var mockAssertion = new Mock<ISigningKeyAssertion>();
        mockAssertion.Setup(a => a.Domain).Returns("test");
        var assertions = new List<ISigningKeyAssertion> { mockAssertion.Object };
        var mockMessage = CreateMockMessage();
        var options = new CoseSign1ValidationOptions();

        var context = new PostSignatureValidationContext(
            mockMessage,
            assertions,
            TrustDecision.Trusted(),
            new Dictionary<string, object>(),
            options);

        Assert.Multiple(() =>
        {
            Assert.That(context.TrustAssertions, Has.Count.EqualTo(1));
            Assert.That(context.TrustAssertions[0].Domain, Is.EqualTo("test"));
        });
    }

    [Test]
    public void SignatureMetadata_ReturnsProvidedMetadata()
    {
        var mockMessage = CreateMockMessage();
        var metadata = new Dictionary<string, object>
        {
            ["algorithm"] = "ES256",
            ["validated"] = true
        };
        var options = new CoseSign1ValidationOptions();

        var context = new PostSignatureValidationContext(
            mockMessage,
            Array.Empty<ISigningKeyAssertion>(),
            TrustDecision.Trusted(),
            metadata,
            options);

        Assert.Multiple(() =>
        {
            Assert.That(context.SignatureMetadata["algorithm"], Is.EqualTo("ES256"));
            Assert.That(context.SignatureMetadata["validated"], Is.True);
        });
    }

    [Test]
    public void Options_ReturnsProvidedOptions()
    {
        var mockMessage = CreateMockMessage();
        var payload = new MemoryStream("test"u8.ToArray());
        var options = new CoseSign1ValidationOptions
        {
            DetachedPayload = payload
        };

        var context = new PostSignatureValidationContext(
            mockMessage,
            Array.Empty<ISigningKeyAssertion>(),
            TrustDecision.Trusted(),
            new Dictionary<string, object>(),
            options);

        Assert.That(context.Options.DetachedPayload, Is.SameAs(payload));
    }

    private static System.Security.Cryptography.Cose.CoseSign1Message CreateMockMessage()
    {
        // Create a minimal valid COSE message
        using var cert = CoseSign1.Tests.Common.TestCertificateUtils.CreateCertificate("Test", useEcc: true);
        using var key = cert.GetECDsaPrivateKey()!;
        var signer = new System.Security.Cryptography.Cose.CoseSigner(key, System.Security.Cryptography.HashAlgorithmName.SHA256);
        var signedBytes = System.Security.Cryptography.Cose.CoseSign1Message.SignEmbedded("test"u8.ToArray(), signer);
        return System.Security.Cryptography.Cose.CoseMessage.DecodeSign1(signedBytes);
    }
}
