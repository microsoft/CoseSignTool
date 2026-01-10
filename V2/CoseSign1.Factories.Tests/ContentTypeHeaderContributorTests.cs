// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Factories.Tests;

using System.Security.Cryptography.Cose;
using CoseSign1.Factories.Direct;
using Moq;

/// <summary>
/// Tests for ContentTypeHeaderContributor.
/// </summary>
[TestFixture]
public class ContentTypeHeaderContributorTests
{
    [Test]
    public void MergeStrategy_ShouldReturnReplace()
    {
        // Arrange
        var contributor = new ContentTypeHeaderContributor();

        // Act
        var strategy = contributor.MergeStrategy;

        // Assert
        Assert.That(strategy, Is.EqualTo(HeaderMergeStrategy.Replace));
    }

    [Test]
    public void ContributeProtectedHeaders_ShouldAddContentTypeHeader()
    {
        // Arrange
        var contributor = new ContentTypeHeaderContributor();
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext("application/json");

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers.ContainsKey(CoseHeaderLabel.ContentType), Is.True);
        var headerValue = headers[CoseHeaderLabel.ContentType];
        Assert.That(headerValue.GetValueAsString(), Is.EqualTo("application/json"));
    }

    [Test]
    public void ContributeProtectedHeaders_WithDifferentContentTypes_ShouldAddCorrectValues()
    {
        // Arrange
        var contributor = new ContentTypeHeaderContributor();
        var testCases = new[]
        {
            "application/json",
            "application/octet-stream",
            "text/plain",
            "application/xml",
            "application/cbor"
        };

        foreach (var contentType in testCases)
        {
            var headers = new CoseHeaderMap();
            var context = CreateHeaderContributorContext(contentType);

            // Act
            contributor.ContributeProtectedHeaders(headers, context);

            // Assert
            Assert.That(headers.ContainsKey(CoseHeaderLabel.ContentType), Is.True,
                $"Content-type header should be present for {contentType}");
            Assert.That(headers[CoseHeaderLabel.ContentType].GetValueAsString(), Is.EqualTo(contentType),
                $"Content-type value should be {contentType}");
        }
    }

    [Test]
    public void ContributeProtectedHeaders_WhenHeaderAlreadyExists_ShouldReplaceIt()
    {
        // Arrange
        var contributor = new ContentTypeHeaderContributor();
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/old"));
        var context = CreateHeaderContributorContext("application/new");

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers.ContainsKey(CoseHeaderLabel.ContentType), Is.True);
        Assert.That(headers[CoseHeaderLabel.ContentType].GetValueAsString(), Is.EqualTo("application/new"));
        Assert.That(headers.Count, Is.EqualTo(1), "Should only have one content-type header");
    }

    [Test]
    public void ContributeProtectedHeaders_WithEmptyHeaderMap_ShouldAddContentType()
    {
        // Arrange
        var contributor = new ContentTypeHeaderContributor();
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext("application/json");

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers.Count, Is.EqualTo(1));
        Assert.That(headers.ContainsKey(CoseHeaderLabel.ContentType), Is.True);
    }

    [Test]
    public void ContributeProtectedHeaders_WithOtherHeaders_ShouldPreserveThemAndAddContentType()
    {
        // Arrange
        var contributor = new ContentTypeHeaderContributor();
        var headers = new CoseHeaderMap();
        var customLabel = new CoseHeaderLabel(42);
        headers.Add(customLabel, CoseHeaderValue.FromString("custom-value"));
        var context = CreateHeaderContributorContext("application/json");

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers.Count, Is.EqualTo(2));
        Assert.That(headers.ContainsKey(CoseHeaderLabel.ContentType), Is.True);
        Assert.That(headers.ContainsKey(customLabel), Is.True);
        Assert.That(headers[customLabel].GetValueAsString(), Is.EqualTo("custom-value"));
    }

    [Test]
    public void ContributeUnprotectedHeaders_ShouldNotAddAnyHeaders()
    {
        // Arrange
        var contributor = new ContentTypeHeaderContributor();
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext("application/json");

        // Act
        contributor.ContributeUnprotectedHeaders(headers, context);

        // Assert
        Assert.That(headers.Count, Is.EqualTo(0), "No headers should be added to unprotected headers");
    }

    [Test]
    public void ContributeUnprotectedHeaders_WithExistingHeaders_ShouldNotModifyThem()
    {
        // Arrange
        var contributor = new ContentTypeHeaderContributor();
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
    public void ContributeProtectedHeaders_CalledMultipleTimes_ShouldUpdateToLatestValue()
    {
        // Arrange
        var contributor = new ContentTypeHeaderContributor();
        var headers = new CoseHeaderMap();

        // Act - first call
        var context1 = CreateHeaderContributorContext("application/json");
        contributor.ContributeProtectedHeaders(headers, context1);
        var firstValue = headers[CoseHeaderLabel.ContentType].GetValueAsString();

        // Act - second call with different content type
        var context2 = CreateHeaderContributorContext("application/xml");
        contributor.ContributeProtectedHeaders(headers, context2);
        var secondValue = headers[CoseHeaderLabel.ContentType].GetValueAsString();

        // Assert
        Assert.That(firstValue, Is.EqualTo("application/json"));
        Assert.That(secondValue, Is.EqualTo("application/xml"));
        Assert.That(headers.Count, Is.EqualTo(1));
    }

    [Test]
    public void ContributeProtectedHeaders_WithNullContext_ShouldThrowArgumentNullException()
    {
        // Arrange
        var contributor = new ContentTypeHeaderContributor();
        var headers = new CoseHeaderMap();

        // Act & Assert
        Assert.Throws<NullReferenceException>(() => contributor.ContributeProtectedHeaders(headers, null!));
    }

    [Test]
    public void ContributeProtectedHeaders_WithSpecialCharactersInContentType_ShouldHandleCorrectly()
    {
        // Arrange
        var contributor = new ContentTypeHeaderContributor();
        var headers = new CoseHeaderMap();
        var contentType = "application/vnd.api+json; charset=utf-8";
        var context = CreateHeaderContributorContext(contentType);

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers[CoseHeaderLabel.ContentType].GetValueAsString(), Is.EqualTo(contentType));
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
