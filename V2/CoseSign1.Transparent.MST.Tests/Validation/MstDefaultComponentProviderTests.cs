// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests.Validation;

using CoseSign1.Transparent.MST.Validation;
using CoseSign1.Validation.Abstractions;
using CoseSign1.Validation.Interfaces;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;

/// <summary>
/// Tests for MstDefaultComponentProvider.
/// </summary>
[TestFixture]
[Category("Validation")]
public class MstDefaultComponentProviderTests
{
    [Test]
    public void Priority_Returns200()
    {
        // Arrange
        var provider = new MstDefaultComponentProvider();

        // Assert
        Assert.That(provider.Priority, Is.EqualTo(200));
    }

    [Test]
    public void GetDefaultComponents_WithNullLoggerFactory_ReturnsOneComponent()
    {
        // Arrange
        var provider = new MstDefaultComponentProvider();

        // Act
        var components = provider.GetDefaultComponents(null).ToList();

        // Assert
        Assert.That(components, Has.Count.EqualTo(1));
    }

    [Test]
    public void GetDefaultComponents_ReturnsMstReceiptPresenceAssertionProvider()
    {
        // Arrange
        var provider = new MstDefaultComponentProvider();

        // Act
        var components = provider.GetDefaultComponents(null).ToList();

        // Assert
        Assert.That(components[0], Is.InstanceOf<MstReceiptPresenceAssertionProvider>());
        Assert.That(components[0], Is.InstanceOf<ISigningKeyAssertionProvider>());
    }

    [Test]
    public void GetDefaultComponents_WithLoggerFactory_ReturnsComponent()
    {
        // Arrange
        var provider = new MstDefaultComponentProvider();
        var mockLoggerFactory = new Mock<ILoggerFactory>();

        // Act
        var components = provider.GetDefaultComponents(mockLoggerFactory.Object).ToList();

        // Assert
        Assert.That(components, Has.Count.EqualTo(1));
        Assert.That(components[0], Is.InstanceOf<MstReceiptPresenceAssertionProvider>());
    }

    [Test]
    public void Provider_ImplementsIDefaultValidationComponentProvider()
    {
        // Arrange
        var provider = new MstDefaultComponentProvider();

        // Assert
        Assert.That(provider, Is.InstanceOf<IDefaultValidationComponentProvider>());
    }
}
