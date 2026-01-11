// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Tests.Validation;

using CoseSign1.AzureKeyVault.Validation;
using CoseSign1.Validation.Abstractions;
using CoseSign1.Validation.Interfaces;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;

/// <summary>
/// Tests for AkvDefaultComponentProvider.
/// </summary>
[TestFixture]
[Category("Validation")]
public class AkvDefaultComponentProviderTests
{
    [Test]
    public void Priority_Returns150()
    {
        // Arrange
        var provider = new AkvDefaultComponentProvider();

        // Assert
        Assert.That(provider.Priority, Is.EqualTo(150));
    }

    [Test]
    public void GetDefaultComponents_WithNullLoggerFactory_ReturnsOneComponent()
    {
        // Arrange
        var provider = new AkvDefaultComponentProvider();

        // Act
        var components = provider.GetDefaultComponents(null).ToList();

        // Assert
        Assert.That(components, Has.Count.EqualTo(1));
    }

    [Test]
    public void GetDefaultComponents_ReturnsAzureKeyVaultAssertionProvider()
    {
        // Arrange
        var provider = new AkvDefaultComponentProvider();

        // Act
        var components = provider.GetDefaultComponents(null).ToList();

        // Assert
        Assert.That(components[0], Is.InstanceOf<AzureKeyVaultAssertionProvider>());
        Assert.That(components[0], Is.InstanceOf<ISigningKeyAssertionProvider>());
    }

    [Test]
    public void GetDefaultComponents_WithLoggerFactory_ReturnsComponent()
    {
        // Arrange
        var provider = new AkvDefaultComponentProvider();
        var mockLoggerFactory = new Mock<ILoggerFactory>();

        // Act
        var components = provider.GetDefaultComponents(mockLoggerFactory.Object).ToList();

        // Assert
        Assert.That(components, Has.Count.EqualTo(1));
        Assert.That(components[0], Is.InstanceOf<AzureKeyVaultAssertionProvider>());
    }

    [Test]
    public void Provider_ImplementsIDefaultValidationComponentProvider()
    {
        // Arrange
        var provider = new AkvDefaultComponentProvider();

        // Assert
        Assert.That(provider, Is.InstanceOf<IDefaultValidationComponentProvider>());
    }
}
