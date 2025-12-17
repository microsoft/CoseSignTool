// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.Cose;
using System.Threading;
using System.Threading.Tasks;
using CoseSign1.Abstractions.Transparency;
using CoseSign1.Certificates.Local;
using CoseSign1.Tests.Common;
using Moq;
using NUnit.Framework;

namespace CoseSign1.Abstractions.Tests.Transparency;

[TestFixture]
public class TransparencyValidationResultTests
{
    [Test]
    public void Success_WithProviderName_CreatesValidResult()
    {
        // Act
        var result = TransparencyValidationResult.Success("TestProvider");

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.ProviderName, Is.EqualTo("TestProvider"));
        Assert.That(result.Errors, Is.Empty);
        Assert.That(result.Metadata, Is.Null);
    }

    [Test]
    public void Success_WithProviderNameAndMetadata_CreatesValidResult()
    {
        // Arrange
        var metadata = new Dictionary<string, object>
        {
            ["logId"] = "12345",
            ["timestamp"] = 1234567890
        };

        // Act
        var result = TransparencyValidationResult.Success("TestProvider", metadata);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.ProviderName, Is.EqualTo("TestProvider"));
        Assert.That(result.Errors, Is.Empty);
        Assert.That(result.Metadata, Is.Not.Null);
        Assert.That(result.Metadata!["logId"], Is.EqualTo("12345"));
        Assert.That(result.Metadata["timestamp"], Is.EqualTo(1234567890));
    }

    [Test]
    public void Failure_WithProviderNameAndSingleError_CreatesInvalidResult()
    {
        // Act
        var result = TransparencyValidationResult.Failure("TestProvider", "Error message");

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.ProviderName, Is.EqualTo("TestProvider"));
        Assert.That(result.Errors, Has.Count.EqualTo(1));
        Assert.That(result.Errors[0], Is.EqualTo("Error message"));
        Assert.That(result.Metadata, Is.Null);
    }

    [Test]
    public void Failure_WithProviderNameAndMultipleErrors_CreatesInvalidResult()
    {
        // Act
        var result = TransparencyValidationResult.Failure("TestProvider", "Error 1", "Error 2", "Error 3");

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.ProviderName, Is.EqualTo("TestProvider"));
        Assert.That(result.Errors, Has.Count.EqualTo(3));
        Assert.That(result.Errors[0], Is.EqualTo("Error 1"));
        Assert.That(result.Errors[1], Is.EqualTo("Error 2"));
        Assert.That(result.Errors[2], Is.EqualTo("Error 3"));
    }

    [Test]
    public void Failure_WithProviderNameAndErrorCollection_CreatesInvalidResult()
    {
        // Arrange
        var errors = new List<string> { "Error A", "Error B" };

        // Act
        var result = TransparencyValidationResult.Failure("TestProvider", errors);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.ProviderName, Is.EqualTo("TestProvider"));
        Assert.That(result.Errors, Has.Count.EqualTo(2));
        Assert.That(result.Errors[0], Is.EqualTo("Error A"));
        Assert.That(result.Errors[1], Is.EqualTo("Error B"));
    }

    [Test]
    public void Success_IsSealed()
    {
        // Verify that TransparencyValidationResult is a sealed class
        Assert.That(typeof(TransparencyValidationResult).IsSealed, Is.True);
    }
}

[TestFixture]
public class TransparencyExtensionsTests
{
    private Mock<ITransparencyProvider> MockProvider = null!;
    private CoseSign1Message Message = null!;

    [SetUp]
#pragma warning disable CA2252 // Preview features
    public void SetUp()
    {
        MockProvider = new Mock<ITransparencyProvider>();

        // Create a COSE Sign1 message using the factory with TestCertificateUtils
        var cert = TestCertificateUtils.CreateCertificate("CN=Test");
        var chainBuilder = new CoseSign1.Certificates.ChainBuilders.X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        var factory = new Direct.DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3 };

        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        Message = CoseSign1Message.DecodeSign1(messageBytes);
    }
#pragma warning restore CA2252

    [Test]
    public async Task VerifyTransparencyAsync_WithValidMessage_CallsProvider()
    {
        // Arrange
        var expectedResult = TransparencyValidationResult.Success("TestProvider");
        MockProvider
            .Setup(p => p.VerifyTransparencyProofAsync(Message, It.IsAny<CancellationToken>()))
            .ReturnsAsync(expectedResult);

        // Act
        var result = await Message.VerifyTransparencyAsync(MockProvider.Object);

        // Assert
        Assert.That(result, Is.SameAs(expectedResult));
        MockProvider.Verify(p => p.VerifyTransparencyProofAsync(Message, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void VerifyTransparencyAsync_WithNullMessage_ThrowsArgumentNullException()
    {
        // Arrange
        CoseSign1Message? nullMessage = null;

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await nullMessage!.VerifyTransparencyAsync(MockProvider.Object));
    }

    [Test]
    public void VerifyTransparencyAsync_WithNullProvider_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await Message.VerifyTransparencyAsync((ITransparencyProvider)null!));
    }

    [Test]
    public async Task VerifyTransparencyAsync_WithCancellationToken_PassesTokenToProvider()
    {
        // Arrange
        var cts = new CancellationTokenSource();
        var expectedResult = TransparencyValidationResult.Success("TestProvider");
        MockProvider
            .Setup(p => p.VerifyTransparencyProofAsync(Message, cts.Token))
            .ReturnsAsync(expectedResult);

        // Act
        var result = await Message.VerifyTransparencyAsync(MockProvider.Object, cts.Token);

        // Assert
        Assert.That(result, Is.SameAs(expectedResult));
        MockProvider.Verify(p => p.VerifyTransparencyProofAsync(Message, cts.Token), Times.Once);
    }

    [Test]
    public async Task VerifyTransparencyAsync_MultipleProviders_CallsAllProviders()
    {
        // Arrange
        var provider1 = new Mock<ITransparencyProvider>();
        var provider2 = new Mock<ITransparencyProvider>();
        var result1 = TransparencyValidationResult.Success("Provider1");
        var result2 = TransparencyValidationResult.Success("Provider2");

        provider1
            .Setup(p => p.VerifyTransparencyProofAsync(Message, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result1);
        provider2
            .Setup(p => p.VerifyTransparencyProofAsync(Message, It.IsAny<CancellationToken>()))
            .ReturnsAsync(result2);

        var providers = new List<ITransparencyProvider> { provider1.Object, provider2.Object };

        // Act
        var results = await Message.VerifyTransparencyAsync(providers);

        // Assert
        Assert.That(results, Has.Count.EqualTo(2));
        Assert.That(results[0], Is.SameAs(result1));
        Assert.That(results[1], Is.SameAs(result2));
        provider1.Verify(p => p.VerifyTransparencyProofAsync(Message, It.IsAny<CancellationToken>()), Times.Once);
        provider2.Verify(p => p.VerifyTransparencyProofAsync(Message, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void VerifyTransparencyAsync_MultipleProviders_WithNullMessage_ThrowsArgumentNullException()
    {
        // Arrange
        CoseSign1Message? nullMessage = null;
        var providers = new List<ITransparencyProvider> { MockProvider.Object };

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await nullMessage!.VerifyTransparencyAsync(providers));
    }

    [Test]
    public void VerifyTransparencyAsync_MultipleProviders_WithNullProviders_ThrowsArgumentNullException()
    {
        // Arrange
        IReadOnlyList<ITransparencyProvider>? nullProviders = null;

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await Message.VerifyTransparencyAsync(nullProviders!));
    }

    [Test]
    public async Task VerifyTransparencyAsync_MultipleProviders_WithMixedResults_ReturnsAllResults()
    {
        // Arrange
        var provider1 = new Mock<ITransparencyProvider>();
        var provider2 = new Mock<ITransparencyProvider>();
        var successResult = TransparencyValidationResult.Success("Provider1");
        var failureResult = TransparencyValidationResult.Failure("Provider2", "Verification failed");

        provider1
            .Setup(p => p.VerifyTransparencyProofAsync(Message, It.IsAny<CancellationToken>()))
            .ReturnsAsync(successResult);
        provider2
            .Setup(p => p.VerifyTransparencyProofAsync(Message, It.IsAny<CancellationToken>()))
            .ReturnsAsync(failureResult);

        var providers = new List<ITransparencyProvider> { provider1.Object, provider2.Object };

        // Act
        var results = await Message.VerifyTransparencyAsync(providers);

        // Assert
        Assert.That(results, Has.Count.EqualTo(2));
        Assert.That(results[0].IsValid, Is.True);
        Assert.That(results[1].IsValid, Is.False);
    }

    [Test]
    public async Task VerifyTransparencyAsync_MultipleProviders_WithEmptyList_ReturnsEmptyResults()
    {
        // Arrange
        var providers = new List<ITransparencyProvider>();

        // Act
        var results = await Message.VerifyTransparencyAsync(providers);

        // Assert
        Assert.That(results, Is.Empty);
    }
}