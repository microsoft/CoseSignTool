// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.Cose;
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST.Validation;
using Moq;

namespace CoseSign1.Transparent.MST.Tests;

[TestFixture]
public class MstReceiptValidatorTests
{
    private Mock<CodeTransparencyClient> _mockClient = null!;
    private Mock<MstTransparencyProvider> _mockProvider = null!;

    [SetUp]
    public void Setup()
    {
        _mockClient = new Mock<CodeTransparencyClient>();
        _mockProvider = new Mock<MstTransparencyProvider>(_mockClient.Object);
    }

    [Test]
    public void Constructor_WithClient_CreatesValidator()
    {
        // Arrange & Act
        var validator = new MstReceiptValidator(_mockClient.Object);

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullClient_ThrowsArgumentNullException()
    {
        // Arrange, Act & Assert
        Assert.Throws<ArgumentNullException>(() => new MstReceiptValidator((CodeTransparencyClient)null!));
    }

    [Test]
    public void Constructor_WithProvider_CreatesValidator()
    {
        // Arrange & Act
        var validator = new MstReceiptValidator(_mockProvider.Object);

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullProvider_ThrowsArgumentNullException()
    {
        // Arrange, Act & Assert
        Assert.Throws<ArgumentNullException>(() => new MstReceiptValidator((MstTransparencyProvider)null!));
    }

    [Test]
    public async Task ValidateAsync_WithNullMessage_ReturnsFailure()
    {
        // Arrange
        var validator = new MstReceiptValidator(_mockClient.Object);

        // Act
        var result = await validator.ValidateAsync(null!);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("MST_NULL_INPUT"));
    }

    [Test]
    public void Validate_WithNullMessage_ReturnsFailure()
    {
        // Arrange
        var validator = new MstReceiptValidator(_mockClient.Object);

        // Act
        var result = validator.Validate(null!);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("MST_NULL_INPUT"));
    }
}
