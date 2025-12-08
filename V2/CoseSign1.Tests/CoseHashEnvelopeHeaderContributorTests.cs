// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Indirect;
using Moq;
using NUnit.Framework;

namespace CoseSign1.Tests;

/// <summary>
/// Tests for CoseHashEnvelopeHeaderContributor.
/// </summary>
[TestFixture]
public class CoseHashEnvelopeHeaderContributorTests
{
    [Test]
    public void Constructor_WithValidParameters_ShouldSucceed()
    {
        // Act
        var contributor = new CoseHashEnvelopeHeaderContributor(
            HashAlgorithmName.SHA256,
            "application/json",
            "https://example.com/payload");

        // Assert
        Assert.That(contributor, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullContentType_ShouldThrowArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new CoseHashEnvelopeHeaderContributor(HashAlgorithmName.SHA256, null!, null));
    }

    [Test]
    public void Constructor_WithoutPayloadLocation_ShouldSucceed()
    {
        // Act
        var contributor = new CoseHashEnvelopeHeaderContributor(
            HashAlgorithmName.SHA256,
            "application/json",
            null);

        // Assert
        Assert.That(contributor, Is.Not.Null);
    }

    [Test]
    public void MergeStrategy_ShouldReturnReplace()
    {
        // Arrange
        var contributor = new CoseHashEnvelopeHeaderContributor(
            HashAlgorithmName.SHA256,
            "application/json");

        // Act
        var strategy = contributor.MergeStrategy;

        // Assert
        Assert.That(strategy, Is.EqualTo(HeaderMergeStrategy.Replace));
    }

    [Test]
    public void HeaderLabels_ShouldBeAccessible()
    {
        // Assert - verify the static labels are accessible
        var payloadHashAlg = CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg;
        var preimageContentType = CoseHashEnvelopeHeaderContributor.HeaderLabels.PreimageContentType;
        var payloadLocation = CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadLocation;
        
        // Verify they can be used in a header map
        var headers = new CoseHeaderMap();
        Assert.DoesNotThrow(() => headers.Add(payloadHashAlg, CoseHeaderValue.FromInt32(1)));
        Assert.DoesNotThrow(() => headers.Add(preimageContentType, CoseHeaderValue.FromString("test")));
        Assert.DoesNotThrow(() => headers.Add(payloadLocation, CoseHeaderValue.FromString("test")));
    }

    [Test]
    public void ContributeProtectedHeaders_WithSHA256_ShouldAddCorrectHeaders()
    {
        // Arrange
        var contributor = new CoseHashEnvelopeHeaderContributor(
            HashAlgorithmName.SHA256,
            "application/json",
            "https://example.com/payload");
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext("application/json");

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers.ContainsKey(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg), Is.True);
        Assert.That(headers[CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg].GetValueAsInt32(), Is.EqualTo(-16));
        
        Assert.That(headers.ContainsKey(CoseHashEnvelopeHeaderContributor.HeaderLabels.PreimageContentType), Is.True);
        Assert.That(headers[CoseHashEnvelopeHeaderContributor.HeaderLabels.PreimageContentType].GetValueAsString(), Is.EqualTo("application/json"));
        
        Assert.That(headers.ContainsKey(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadLocation), Is.True);
        Assert.That(headers[CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadLocation].GetValueAsString(), Is.EqualTo("https://example.com/payload"));
    }

    [Test]
    public void ContributeProtectedHeaders_WithSHA384_ShouldAddCorrectAlgorithmId()
    {
        // Arrange
        var contributor = new CoseHashEnvelopeHeaderContributor(
            HashAlgorithmName.SHA384,
            "application/json");
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext("application/json");

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers[CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg].GetValueAsInt32(), Is.EqualTo(-43));
    }

    [Test]
    public void ContributeProtectedHeaders_WithSHA512_ShouldAddCorrectAlgorithmId()
    {
        // Arrange
        var contributor = new CoseHashEnvelopeHeaderContributor(
            HashAlgorithmName.SHA512,
            "application/json");
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext("application/json");

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers[CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg].GetValueAsInt32(), Is.EqualTo(-44));
    }

    [Test]
    public void ContributeProtectedHeaders_WithUnsupportedHashAlgorithm_ShouldThrowNotSupportedException()
    {
        // Arrange
        var contributor = new CoseHashEnvelopeHeaderContributor(
            HashAlgorithmName.MD5,
            "application/json");
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext("application/json");

        // Act & Assert
        var ex = Assert.Throws<NotSupportedException>(() => 
            contributor.ContributeProtectedHeaders(headers, context));
        Assert.That(ex.Message, Does.Contain("MD5"));
    }

    [Test]
    public void ContributeProtectedHeaders_WithoutPayloadLocation_ShouldNotAddLocationHeader()
    {
        // Arrange
        var contributor = new CoseHashEnvelopeHeaderContributor(
            HashAlgorithmName.SHA256,
            "application/json",
            null);
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext("application/json");

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers.ContainsKey(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadLocation), Is.False);
    }

    [Test]
    public void ContributeProtectedHeaders_WithEmptyPayloadLocation_ShouldNotAddLocationHeader()
    {
        // Arrange
        var contributor = new CoseHashEnvelopeHeaderContributor(
            HashAlgorithmName.SHA256,
            "application/json",
            "");
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext("application/json");

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers.ContainsKey(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadLocation), Is.False);
    }

    [Test]
    public void ContributeProtectedHeaders_ShouldRemoveContentTypeHeader()
    {
        // Arrange
        var contributor = new CoseHashEnvelopeHeaderContributor(
            HashAlgorithmName.SHA256,
            "application/json");
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json"));
        var context = CreateHeaderContributorContext("application/json");

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers.ContainsKey(CoseHeaderLabel.ContentType), Is.False, 
            "Content-type header (label 3) must be removed per RFC 9054");
    }

    [Test]
    public void ContributeProtectedHeaders_WithExistingPayloadHashAlg_ShouldUpdateIt()
    {
        // Arrange
        var contributor = new CoseHashEnvelopeHeaderContributor(
            HashAlgorithmName.SHA512,
            "application/json");
        var headers = new CoseHeaderMap();
        headers.Add(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(-16)); // SHA256
        var context = CreateHeaderContributorContext("application/json");

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers[CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg].GetValueAsInt32(), 
            Is.EqualTo(-44), "Should update to SHA512 algorithm");
    }

    [Test]
    public void ContributeProtectedHeaders_WithExistingPreimageContentType_ShouldUpdateIt()
    {
        // Arrange
        var contributor = new CoseHashEnvelopeHeaderContributor(
            HashAlgorithmName.SHA256,
            "application/xml");
        var headers = new CoseHeaderMap();
        headers.Add(CoseHashEnvelopeHeaderContributor.HeaderLabels.PreimageContentType, 
            CoseHeaderValue.FromString("application/json"));
        var context = CreateHeaderContributorContext("application/xml");

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers[CoseHashEnvelopeHeaderContributor.HeaderLabels.PreimageContentType].GetValueAsString(), 
            Is.EqualTo("application/xml"));
    }

    [Test]
    public void ContributeProtectedHeaders_WithExistingPayloadLocation_ShouldUpdateIt()
    {
        // Arrange
        var contributor = new CoseHashEnvelopeHeaderContributor(
            HashAlgorithmName.SHA256,
            "application/json",
            "https://new.example.com/payload");
        var headers = new CoseHeaderMap();
        headers.Add(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadLocation, 
            CoseHeaderValue.FromString("https://old.example.com/payload"));
        var context = CreateHeaderContributorContext("application/json");

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers[CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadLocation].GetValueAsString(), 
            Is.EqualTo("https://new.example.com/payload"));
    }

    [Test]
    public void ContributeProtectedHeaders_WithOtherHeaders_ShouldPreserveThem()
    {
        // Arrange
        var contributor = new CoseHashEnvelopeHeaderContributor(
            HashAlgorithmName.SHA256,
            "application/json");
        var headers = new CoseHeaderMap();
        var customLabel = new CoseHeaderLabel(42);
        headers.Add(customLabel, CoseHeaderValue.FromString("custom-value"));
        var context = CreateHeaderContributorContext("application/json");

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers.ContainsKey(customLabel), Is.True);
        Assert.That(headers[customLabel].GetValueAsString(), Is.EqualTo("custom-value"));
    }

    [Test]
    public void ContributeProtectedHeaders_WithDifferentContentTypes_ShouldUseCorrectPreimageContentType()
    {
        // Arrange
        var testCases = new[]
        {
            "application/json",
            "application/octet-stream",
            "text/plain",
            "application/cbor",
            "application/vnd.custom+json"
        };

        foreach (var contentType in testCases)
        {
            var contributor = new CoseHashEnvelopeHeaderContributor(
                HashAlgorithmName.SHA256,
                contentType);
            var headers = new CoseHeaderMap();
            var context = CreateHeaderContributorContext(contentType);

            // Act
            contributor.ContributeProtectedHeaders(headers, context);

            // Assert
            Assert.That(headers[CoseHashEnvelopeHeaderContributor.HeaderLabels.PreimageContentType].GetValueAsString(), 
                Is.EqualTo(contentType), 
                $"PreimageContentType should be {contentType}");
        }
    }

    [Test]
    public void ContributeUnprotectedHeaders_ShouldRemoveContentTypeIfPresent()
    {
        // Arrange
        var contributor = new CoseHashEnvelopeHeaderContributor(
            HashAlgorithmName.SHA256,
            "application/json");
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json"));
        var context = CreateHeaderContributorContext("application/json");

        // Act
        contributor.ContributeUnprotectedHeaders(headers, context);

        // Assert
        Assert.That(headers.ContainsKey(CoseHeaderLabel.ContentType), Is.False, 
            "Content-type header must be removed from unprotected headers per RFC 9054");
    }

    [Test]
    public void ContributeUnprotectedHeaders_WithoutContentType_ShouldNotModify()
    {
        // Arrange
        var contributor = new CoseHashEnvelopeHeaderContributor(
            HashAlgorithmName.SHA256,
            "application/json");
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext("application/json");

        // Act
        contributor.ContributeUnprotectedHeaders(headers, context);

        // Assert
        Assert.That(headers.Count, Is.EqualTo(0));
    }

    [Test]
    public void ContributeUnprotectedHeaders_WithOtherHeaders_ShouldPreserveThem()
    {
        // Arrange
        var contributor = new CoseHashEnvelopeHeaderContributor(
            HashAlgorithmName.SHA256,
            "application/json");
        var headers = new CoseHeaderMap();
        var customLabel = new CoseHeaderLabel(42);
        headers.Add(customLabel, CoseHeaderValue.FromString("custom-value"));
        var context = CreateHeaderContributorContext("application/json");

        // Act
        contributor.ContributeUnprotectedHeaders(headers, context);

        // Assert
        Assert.That(headers.Count, Is.EqualTo(1));
        Assert.That(headers.ContainsKey(customLabel), Is.True);
    }

    [Test]
    public void ContributeProtectedHeaders_CalledMultipleTimes_ShouldBeIdempotent()
    {
        // Arrange
        var contributor = new CoseHashEnvelopeHeaderContributor(
            HashAlgorithmName.SHA256,
            "application/json",
            "https://example.com/payload");
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext("application/json");

        // Act
        contributor.ContributeProtectedHeaders(headers, context);
        var firstCallCount = headers.Count;
        contributor.ContributeProtectedHeaders(headers, context);
        var secondCallCount = headers.Count;

        // Assert
        Assert.That(firstCallCount, Is.EqualTo(secondCallCount), 
            "Calling ContributeProtectedHeaders multiple times should not increase header count");
        Assert.That(headers.Count, Is.EqualTo(3), "Should have PayloadHashAlg, PreimageContentType, and PayloadLocation");
    }

    [Test]
    public void HeaderLabels_ShouldBeStatic()
    {
        // Arrange & Act
        var label1 = CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg;
        var label2 = CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg;

        // Assert
        Assert.That(label1.Equals(label2), Is.True, 
            "Static header labels should be equal when accessed multiple times");
    }

    [Test]
    public void ContributeProtectedHeaders_WithComplexPayloadLocation_ShouldHandleCorrectly()
    {
        // Arrange
        var payloadLocation = "https://example.com/api/v1/payloads/12345?token=abc&format=json";
        var contributor = new CoseHashEnvelopeHeaderContributor(
            HashAlgorithmName.SHA256,
            "application/json",
            payloadLocation);
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext("application/json");

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers[CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadLocation].GetValueAsString(), 
            Is.EqualTo(payloadLocation));
    }

    [Test]
    public void ContributeProtectedHeaders_RFCCompliance_ShouldNotHaveLabel3()
    {
        // Arrange
        var contributor = new CoseHashEnvelopeHeaderContributor(
            HashAlgorithmName.SHA256,
            "application/json",
            "https://example.com/payload");
        var headers = new CoseHeaderMap();
        // Pre-populate with content-type header (as DirectSignatureFactory would)
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json"));
        var context = CreateHeaderContributorContext("application/json");

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert - Verify RFC 9054 compliance
        Assert.That(headers.ContainsKey(CoseHeaderLabel.ContentType), Is.False, 
            "RFC 9054: Label 3 (content_type) MUST NOT be present with hash envelope format");
        Assert.That(headers.ContainsKey(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg), Is.True,
            "RFC 9054: Label 258 (PayloadHashAlg) MUST be present");
        Assert.That(headers.ContainsKey(CoseHashEnvelopeHeaderContributor.HeaderLabels.PreimageContentType), Is.True,
            "RFC 9054: Label 259 (PreimageContentType) MUST be present");
    }

    private static HeaderContributorContext CreateHeaderContributorContext(string contentType)
    {
        var mockSigningKey = new Mock<ISigningKey>();
        var signingContext = new SigningContext(
            ReadOnlyMemory<byte>.Empty,
            contentType,
            null,
            null);

        return new HeaderContributorContext(signingContext, mockSigningKey.Object);
    }
}
