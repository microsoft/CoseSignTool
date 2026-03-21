// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Cose.Abstractions.Tests;

using System.Security.Cryptography.Cose;
using Cose.Abstractions;
using Moq;

/// <summary>
/// Tests for <see cref="ICoseHeaderContributor"/> interface.
/// </summary>
[TestFixture]
public class ICoseHeaderContributorTests
{
    [Test]
    public void MockContributor_ContributeProtectedHeaders_CanBeCalled()
    {
        // Arrange
        Mock<ICoseHeaderContributor> mock = new();
        CoseHeaderMap headers = new();
        mock.Setup(c => c.MergeStrategy).Returns(HeaderMergeStrategy.Fail);

        // Act
        mock.Object.ContributeProtectedHeaders(headers);

        // Assert
        mock.Verify(c => c.ContributeProtectedHeaders(headers), Times.Once);
    }

    [Test]
    public void MockContributor_ContributeUnprotectedHeaders_CanBeCalled()
    {
        // Arrange
        Mock<ICoseHeaderContributor> mock = new();
        CoseHeaderMap headers = new();

        // Act
        mock.Object.ContributeUnprotectedHeaders(headers);

        // Assert
        mock.Verify(c => c.ContributeUnprotectedHeaders(headers), Times.Once);
    }

    [Test]
    public void MockContributor_MergeStrategy_ReturnsConfiguredValue()
    {
        // Arrange
        Mock<ICoseHeaderContributor> mock = new();
        mock.Setup(c => c.MergeStrategy).Returns(HeaderMergeStrategy.Replace);

        // Act & Assert
        Assert.That(mock.Object.MergeStrategy, Is.EqualTo(HeaderMergeStrategy.Replace));
    }
}