// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent;
using CoseSign1.Transparent.MST;
using CoseSign1.Transparent.MST.Extensions;
using Moq;
using NUnit.Framework;

namespace CoseSign1.Transparent.MST.Tests;

/// <summary>
/// Unit tests for the <see cref="MstTransparencyServiceExtensions"/> class.
/// </summary>
[TestFixture]
public class MstTransparencyServiceExtensionsTests
{
    /// <summary>
    /// Tests the <see cref="MstTransparencyServiceExtensions.ToCoseSign1TransparencyService"/> method
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
    /// Tests the <see cref="MstTransparencyServiceExtensions.ToCoseSign1TransparencyService"/> method
    /// to ensure it returns a valid <see cref="TransparencyService"/> instance when the input client is valid.
    /// </summary>
    [Test]
    public void ToCoseSign1TransparencyService_ReturnsTransparencyService_WhenClientIsValid()
    {
        // Arrange
        Mock<CodeTransparencyClient> mockClient = new Mock<CodeTransparencyClient>();

        // Act
        TransparencyService result = mockClient.Object.ToCoseSign1TransparencyService();

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.InstanceOf<MstTransparencyService>());
    }
}

