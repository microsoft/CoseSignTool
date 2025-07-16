// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.CTS;
using CoseSign1.Transparent.CTS.Extensions;
using CoseSign1.Transparent.Interfaces;
using Moq;
using NUnit.Framework;

namespace CoseSign1.Transparent.CTS.Tests;

/// <summary>
/// Unit tests for the <see cref="AzureCtsTransparencyServiceExtensions"/> class.
/// </summary>
[TestFixture]
public class AzureCtsTransparencyServiceExtensionsTests
{
    /// <summary>
    /// Tests the <see cref="AzureCtsTransparencyServiceExtensions.ToCoseSign1TransparencyService"/> method
    /// to ensure it throws an <see cref="ArgumentNullException"/> when the input client is null.
    /// </summary>
    [Test]
    public void ToCoseSign1TransparencyService_ThrowsArgumentNullException_WhenClientIsNull()
    {
        // Arrange
        CodeTransparencyClient client = null;

        // Act & Assert
        Assert.That(
            () => client.ToCoseSign1TransparencyService(),
            Throws.TypeOf<ArgumentNullException>().With.Property("ParamName").EqualTo("client"));
    }

    /// <summary>
    /// Tests the <see cref="AzureCtsTransparencyServiceExtensions.ToCoseSign1TransparencyService"/> method
    /// to ensure it returns a valid <see cref="ITransparencyService"/> instance when the input client is valid.
    /// </summary>
    [Test]
    public void ToCoseSign1TransparencyService_ReturnsTransparencyService_WhenClientIsValid()
    {
        // Arrange
        Mock<CodeTransparencyClient> mockClient = new Mock<CodeTransparencyClient>();

        // Act
        ITransparencyService result = mockClient.Object.ToCoseSign1TransparencyService();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.InstanceOf<AzureCtsTransparencyService>());
    }
}
