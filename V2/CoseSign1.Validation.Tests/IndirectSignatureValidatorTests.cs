// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Text;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.PostSignature;
using Microsoft.Extensions.Logging;
using Moq;

/// <summary>
/// Tests for <see cref="IndirectSignatureValidator"/>.
/// </summary>
[TestFixture]
[Category("Validation")]
public class IndirectSignatureValidatorTests
{
    private static readonly byte[] TestPayload = Encoding.UTF8.GetBytes("test payload for validation");

    #region Constructor Tests

    [Test]
    public void Constructor_NoLogger_CreatesInstance()
    {
        var validator = new IndirectSignatureValidator();

        Assert.That(validator.ComponentName, Is.EqualTo("IndirectSignatureValidator"));
    }

    [Test]
    public void Constructor_WithLogger_CreatesInstance()
    {
        var mockLogger = new Mock<ILogger<IndirectSignatureValidator>>();
        var validator = new IndirectSignatureValidator(mockLogger.Object);

        Assert.That(validator.ComponentName, Is.EqualTo("IndirectSignatureValidator"));
    }

    #endregion

    #region ComputeApplicability Tests (via IsApplicableTo)

    [Test]
    public void IsApplicableTo_DirectSignature_ReturnsFalse()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateDirectSignatureMessage();

        var result = validator.IsApplicableTo(message);

        Assert.That(result, Is.False);
    }

    [Test]
    public void IsApplicableTo_CoseHashEnvelopeSignature_ReturnsTrue()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateCoseHashEnvelopeMessage(TestPayload);

        var result = validator.IsApplicableTo(message);

        Assert.That(result, Is.True);
    }

    [Test]
    public void IsApplicableTo_CoseHashVSignature_ReturnsTrue()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateCoseHashVMessage(TestPayload);

        var result = validator.IsApplicableTo(message);

        Assert.That(result, Is.True);
    }

    [Test]
    public void IsApplicableTo_HashLegacySignature_ReturnsTrue()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateHashLegacyMessage(TestPayload);

        var result = validator.IsApplicableTo(message);

        Assert.That(result, Is.True);
    }

    [Test]
    public void IsApplicableTo_NullMessage_ReturnsFalse()
    {
        var validator = new IndirectSignatureValidator();

        var result = validator.IsApplicableTo(null);

        Assert.That(result, Is.False);
    }

    #endregion

    #region Validate Tests - Direct Signature

    [Test]
    public void Validate_DirectSignature_ReturnsNotApplicable()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateDirectSignatureMessage();
        var context = CreateContext(message, null);

        var result = validator.Validate(context);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsNotApplicable, Is.True);
            Assert.That(result.ValidatorName, Is.EqualTo("IndirectSignatureValidator"));
        });
    }

    #endregion

    #region Validate Tests - Null Context

    [Test]
    public void Validate_NullContext_ThrowsArgumentNullException()
    {
        var validator = new IndirectSignatureValidator();

        Assert.Throws<ArgumentNullException>(() => validator.Validate(null!));
    }

    #endregion

    #region Validate Tests - COSE Hash Envelope

    [Test]
    public void Validate_CoseHashEnvelope_NoPayload_ReturnsFailure()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateCoseHashEnvelopeMessage(TestPayload);
        var context = CreateContext(message, null);

        var result = validator.Validate(context);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Failures, Has.Some.Property("Message").Contain("requires payload"));
        });
    }

    [Test]
    public void Validate_CoseHashEnvelope_ValidHash_ReturnsSuccess()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateCoseHashEnvelopeMessage(TestPayload);
        var context = CreateContext(message, new MemoryStream(TestPayload));

        var result = validator.Validate(context);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Metadata, Contains.Key("IndirectSignatureType"));
        });
    }

    [Test]
    public void Validate_CoseHashEnvelope_InvalidHash_ReturnsFailure()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateCoseHashEnvelopeMessage(TestPayload);
        var wrongPayload = Encoding.UTF8.GetBytes("wrong payload");
        var context = CreateContext(message, new MemoryStream(wrongPayload));

        var result = validator.Validate(context);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Failures, Has.Some.Property("Message").Contain("does not match"));
        });
    }

    [Test]
    public void Validate_CoseHashEnvelope_StreamPositionResets()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateCoseHashEnvelopeMessage(TestPayload);
        var stream = new MemoryStream(TestPayload);
        stream.Position = 5; // Set position somewhere in the middle
        var context = CreateContext(message, stream);

        var result = validator.Validate(context);

        Assert.That(result.IsSuccess, Is.True);
    }

    #endregion

    #region Validate Tests - COSE Hash V

    [Test]
    public void Validate_CoseHashV_NoPayload_ReturnsFailure()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateCoseHashVMessage(TestPayload);
        var context = CreateContext(message, null);

        var result = validator.Validate(context);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Failures, Has.Some.Property("Message").Contain("requires payload"));
        });
    }

    [Test]
    public void Validate_CoseHashV_ValidHash_ReturnsSuccess()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateCoseHashVMessage(TestPayload);
        var context = CreateContext(message, new MemoryStream(TestPayload));

        var result = validator.Validate(context);

        Assert.That(result.IsSuccess, Is.True);
    }

    [Test]
    public void Validate_CoseHashV_InvalidHash_ReturnsFailure()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateCoseHashVMessage(TestPayload);
        var wrongPayload = Encoding.UTF8.GetBytes("wrong payload");
        var context = CreateContext(message, new MemoryStream(wrongPayload));

        var result = validator.Validate(context);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Failures, Has.Some.Property("Message").Contain("does not match"));
        });
    }

    #endregion

    #region Validate Tests - Hash Legacy

    [Test]
    public void Validate_HashLegacy_NoPayload_ReturnsFailure()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateHashLegacyMessage(TestPayload);
        var context = CreateContext(message, null);

        var result = validator.Validate(context);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Failures, Has.Some.Property("Message").Contain("requires payload"));
        });
    }

    [Test]
    public void Validate_HashLegacy_ValidHash_ReturnsSuccess()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateHashLegacyMessage(TestPayload);
        var context = CreateContext(message, new MemoryStream(TestPayload));

        var result = validator.Validate(context);

        Assert.That(result.IsSuccess, Is.True);
    }

    [Test]
    public void Validate_HashLegacy_InvalidHash_ReturnsFailure()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateHashLegacyMessage(TestPayload);
        var wrongPayload = Encoding.UTF8.GetBytes("wrong payload");
        var context = CreateContext(message, new MemoryStream(wrongPayload));

        var result = validator.Validate(context);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsFailure, Is.True);
            Assert.That(result.Failures, Has.Some.Property("Message").Contain("does not match"));
        });
    }

    [Test]
    public void Validate_HashLegacy_SHA384_ValidHash_ReturnsSuccess()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateHashLegacyMessage(TestPayload, "sha384");
        var context = CreateContext(message, new MemoryStream(TestPayload));

        var result = validator.Validate(context);

        Assert.That(result.IsSuccess, Is.True);
    }

    [Test]
    public void Validate_HashLegacy_SHA512_ValidHash_ReturnsSuccess()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateHashLegacyMessage(TestPayload, "sha512");
        var context = CreateContext(message, new MemoryStream(TestPayload));

        var result = validator.Validate(context);

        Assert.That(result.IsSuccess, Is.True);
    }

    [Test]
    public void Validate_HashLegacy_SHA1_ValidHash_ReturnsSuccess()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateHashLegacyMessage(TestPayload, "sha1");
        var context = CreateContext(message, new MemoryStream(TestPayload));

        var result = validator.Validate(context);

        Assert.That(result.IsSuccess, Is.True);
    }

    [Test]
    public void Validate_HashLegacy_UnsupportedAlgorithm_ReturnsFailure()
    {
        var validator = new IndirectSignatureValidator();
        // Create a message with an unsupported algorithm suffix
        var message = CreateHashLegacyMessageWithCustomAlgo(TestPayload, "md5");
        var context = CreateContext(message, new MemoryStream(TestPayload));

        var result = validator.Validate(context);

        Assert.That(result.IsFailure, Is.True);
    }

    [Test]
    public void Validate_HashLegacy_WithDashes_ExtractsOnlyAlgoBeforeDash()
    {
        var validator = new IndirectSignatureValidator();
        // Test algorithm name with dashes like "sha-256"
        // The regex \+hash-(?<algorithm>[\w_]+) will only capture "sha" before the dash
        // which is not a supported algorithm, so validation fails
        var message = CreateHashLegacyMessage(TestPayload, "sha-256");
        var context = CreateContext(message, new MemoryStream(TestPayload));

        var result = validator.Validate(context);

        // The regex only captures "sha" which is unsupported
        Assert.That(result.IsFailure, Is.True);
    }

    [Test]
    public void Validate_HashLegacy_WithUnderscores_ValidHash_ReturnsSuccess()
    {
        var validator = new IndirectSignatureValidator();
        // Test algorithm name with underscores like "sha_256"
        // Underscores ARE included in \w character class, so "sha_256" is captured
        var message = CreateHashLegacyMessage(TestPayload, "sha_256");
        var context = CreateContext(message, new MemoryStream(TestPayload));

        var result = validator.Validate(context);

        Assert.That(result.IsSuccess, Is.True);
    }

    #endregion

    #region COSE Hash Envelope Additional Algorithm Tests

    [Test]
    public void Validate_CoseHashEnvelope_SHA384_ValidHash_ReturnsSuccess()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateCoseHashEnvelopeMessage(TestPayload, -43); // SHA-384
        var context = CreateContext(message, new MemoryStream(TestPayload));

        var result = validator.Validate(context);

        Assert.That(result.IsSuccess, Is.True);
    }

    [Test]
    public void Validate_CoseHashEnvelope_SHA512_ValidHash_ReturnsSuccess()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateCoseHashEnvelopeMessage(TestPayload, -44); // SHA-512
        var context = CreateContext(message, new MemoryStream(TestPayload));

        var result = validator.Validate(context);

        Assert.That(result.IsSuccess, Is.True);
    }

    [Test]
    public void Validate_CoseHashEnvelope_UnsupportedAlgorithm_ReturnsFailure()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateCoseHashEnvelopeMessage(TestPayload, -99); // Unsupported
        var context = CreateContext(message, new MemoryStream(TestPayload));

        var result = validator.Validate(context);

        Assert.That(result.IsFailure, Is.True);
    }

    #endregion

    #region COSE Hash V Additional Algorithm Tests

    [Test]
    public void Validate_CoseHashV_SHA384_ValidHash_ReturnsSuccess()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateCoseHashVMessage(TestPayload, -43); // SHA-384
        var context = CreateContext(message, new MemoryStream(TestPayload));

        var result = validator.Validate(context);

        Assert.That(result.IsSuccess, Is.True);
    }

    [Test]
    public void Validate_CoseHashV_SHA512_ValidHash_ReturnsSuccess()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateCoseHashVMessage(TestPayload, -44); // SHA-512
        var context = CreateContext(message, new MemoryStream(TestPayload));

        var result = validator.Validate(context);

        Assert.That(result.IsSuccess, Is.True);
    }

    [Test]
    public void Validate_CoseHashV_UnsupportedAlgorithm_ReturnsFailure()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateCoseHashVMessage(TestPayload, -99); // Unsupported
        var context = CreateContext(message, new MemoryStream(TestPayload));

        var result = validator.Validate(context);

        Assert.That(result.IsFailure, Is.True);
    }

    [Test]
    public void Validate_CoseHashV_InvalidStructure_ReturnsFailure()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateCoseHashVMessageWithInvalidStructure();
        var context = CreateContext(message, new MemoryStream(TestPayload));

        var result = validator.Validate(context);

        Assert.That(result.IsFailure, Is.True);
    }

    [Test]
    public void Validate_CoseHashV_ArrayTooShort_ReturnsFailure()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateCoseHashVMessageWithShortArray();
        var context = CreateContext(message, new MemoryStream(TestPayload));

        var result = validator.Validate(context);

        Assert.That(result.IsFailure, Is.True);
    }

    [Test]
    public void Validate_HashLegacy_NoContentType_ReturnsFailure()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateMessageWithPayloadHashAlgButNoContent();
        var context = CreateContext(message, new MemoryStream(TestPayload));

        var result = validator.Validate(context);

        Assert.That(result.IsFailure, Is.True);
    }

    #endregion

    #region ValidateAsync Tests

    [Test]
    public async Task ValidateAsync_ReturnsResultFromValidate()
    {
        var validator = new IndirectSignatureValidator();
        var message = CreateCoseHashEnvelopeMessage(TestPayload);
        var context = CreateContext(message, new MemoryStream(TestPayload));

        var result = await validator.ValidateAsync(context);

        Assert.That(result.IsSuccess, Is.True);
    }

    [Test]
    public async Task ValidateAsync_NullContext_ThrowsArgumentNullException()
    {
        var validator = new IndirectSignatureValidator();

        await Task.Run(() => Assert.ThrowsAsync<ArgumentNullException>(() => validator.ValidateAsync(null!)));
    }

    #endregion

    #region Helper Methods

    private static CoseSign1Message CreateDirectSignatureMessage()
    {
        using var key = ECDsa.Create();
        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json") }
        };
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, headers);
        byte[] signedBytes = CoseSign1Message.SignEmbedded(TestPayload, signer);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    private static CoseSign1Message CreateCoseHashEnvelopeMessage(byte[] payload, int algorithm = -16)
    {
        using var key = ECDsa.Create();
        HashAlgorithm hasher = algorithm switch
        {
            -16 => SHA256.Create(),
            -43 => SHA384.Create(),
            -44 => SHA512.Create(),
            _ => SHA256.Create() // For unsupported tests, we still compute a hash
        };

        using (hasher)
        {
            var hash = hasher.ComputeHash(payload);

            var headers = new CoseHeaderMap
            {
                { IndirectSignatureHeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(algorithm) }
            };

            var signer = new CoseSigner(key, HashAlgorithmName.SHA256, headers);
            byte[] signedBytes = CoseSign1Message.SignEmbedded(hash, signer);
            return CoseMessage.DecodeSign1(signedBytes);
        }
    }

    private static CoseSign1Message CreateCoseHashVMessage(byte[] payload, long algorithm = -16)
    {
        using var key = ECDsa.Create();
        HashAlgorithm hasher = algorithm switch
        {
            -16 => SHA256.Create(),
            -43 => SHA384.Create(),
            -44 => SHA512.Create(),
            _ => SHA256.Create() // For unsupported tests
        };

        using (hasher)
        {
            var hash = hasher.ComputeHash(payload);

            // Create COSE Hash V structure: [algorithm, hash]
            var writer = new CborWriter();
            writer.WriteStartArray(2);
            writer.WriteInt64(algorithm);
            writer.WriteByteString(hash);
            writer.WriteEndArray();
            var coseHashVContent = writer.Encode();

            var headers = new CoseHeaderMap
            {
                { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json+cose-hash-v") }
            };

            var signer = new CoseSigner(key, HashAlgorithmName.SHA256, headers);
            byte[] signedBytes = CoseSign1Message.SignEmbedded(coseHashVContent, signer);
            return CoseMessage.DecodeSign1(signedBytes);
        }
    }

    private static CoseSign1Message CreateCoseHashVMessageWithInvalidStructure()
    {
        using var key = ECDsa.Create();

        // Create invalid COSE Hash V structure: just a single value instead of array
        var writer = new CborWriter();
        writer.WriteInt64(42);
        var invalidContent = writer.Encode();

        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json+cose-hash-v") }
        };

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, headers);
        byte[] signedBytes = CoseSign1Message.SignEmbedded(invalidContent, signer);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    private static CoseSign1Message CreateCoseHashVMessageWithShortArray()
    {
        using var key = ECDsa.Create();

        // Create COSE Hash V with array that's too short (only 1 element)
        var writer = new CborWriter();
        writer.WriteStartArray(1);
        writer.WriteInt64(-16); // Only algorithm, no hash
        writer.WriteEndArray();
        var invalidContent = writer.Encode();

        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json+cose-hash-v") }
        };

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, headers);
        byte[] signedBytes = CoseSign1Message.SignEmbedded(invalidContent, signer);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    private static CoseSign1Message CreateMessageWithPayloadHashAlgButNoContent()
    {
        using var key = ECDsa.Create();

        // Create message with PayloadHashAlg but use detached content (no embedded hash)
        var headers = new CoseHeaderMap
        {
            { IndirectSignatureHeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(-16) } // SHA-256
        };

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, headers);
        // Sign with detached payload - this creates a message with Content = null
        byte[] signedBytes = CoseSign1Message.SignDetached(TestPayload, signer);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    private static CoseSign1Message CreateHashLegacyMessageWithCustomAlgo(byte[] payload, string algorithm)
    {
        using var key = ECDsa.Create();
        using var sha256 = SHA256.Create();
        // Just compute SHA256 for the embedded hash regardless of algorithm name
        // The validator should fail because it doesn't recognize the algorithm
        var hash = sha256.ComputeHash(payload);

        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString($"application/json+hash-{algorithm}") }
        };

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, headers);
        byte[] signedBytes = CoseSign1Message.SignEmbedded(hash, signer);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    private static CoseSign1Message CreateHashLegacyMessage(byte[] payload, string algorithm = "sha256")
    {
        using var key = ECDsa.Create();
        byte[] hash;

        // Normalize the algorithm name for the switch
        var normalizedAlg = algorithm.ToUpperInvariant().Replace("-", "").Replace("_", "");

#pragma warning disable CA5350 // Do not use weak cryptographic algorithms - needed for testing legacy support
        using (var hasher = normalizedAlg switch
        {
            "SHA256" => SHA256.Create() as HashAlgorithm,
            "SHA384" => SHA384.Create(),
            "SHA512" => SHA512.Create(),
            "SHA1" => SHA1.Create(),
            _ => SHA256.Create()
        })
#pragma warning restore CA5350
        {
            hash = hasher.ComputeHash(payload);
        }

        var headers = new CoseHeaderMap
        {
            { CoseHeaderLabel.ContentType, CoseHeaderValue.FromString($"application/json+hash-{algorithm}") }
        };

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, headers);
        byte[] signedBytes = CoseSign1Message.SignEmbedded(hash, signer);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    private static IPostSignatureValidationContext CreateContext(CoseSign1Message message, Stream? detachedPayload)
    {
        var mockContext = new Mock<IPostSignatureValidationContext>();
        mockContext.Setup(c => c.Message).Returns(message);
        mockContext.Setup(c => c.Options).Returns(new CoseSign1ValidationOptions
        {
            DetachedPayload = detachedPayload
        });
        return mockContext.Object;
    }

    #endregion
}
