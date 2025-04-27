// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.AzureTrustedSigning.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Developer.TrustedSigning.CryptoProvider;
using CoseSign1.Certificates.AzureTrustedSigning;
using CoseSign1.Certificates.Local;
using CoseSign1.Tests.Common;
using Moq;
using NUnit.Framework;

/// <summary>
/// Unit tests for the <see cref="AzureTrustedSigningCoseSigningKeyProvider"/> class.
/// </summary>
[TestFixture]
public class AzureTrustedSigningCoseSigningKeyProviderTests
{
    /// <summary>
    /// Tests the constructor to ensure it throws an <see cref="ArgumentNullException"/> when the sign context is null.
    /// </summary>
    [Test]
    public void Constructor_ThrowsArgumentNullException_WhenSignContextIsNull()
    {
        // Act & Assert
        Assert.That(
            () => new AzureTrustedSigningCoseSigningKeyProvider(null),
            Throws.TypeOf<ArgumentNullException>().With.Property("ParamName").EqualTo("signContext"));
    }

    /// <summary>
    /// Tests the <see cref="AzureTrustedSigningCoseSigningKeyProvider.GetCertificateChain"/> method
    /// to ensure it throws an <see cref="InvalidOperationException"/> when the certificate chain is not available.
    /// </summary>
    [Test]
    public void GetCertificateChain_ThrowsInvalidOperationException_WhenCertificateChainIsUnavailable()
    {
        // Arrange
        Mock<AzSignContext> mockSignContext = new Mock<AzSignContext>();
        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>())).Returns((IReadOnlyList<X509Certificate2>)null);
        AzureTrustedSigningCoseSigningKeyProvider provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act & Assert
        Assert.That(
            () => InvokeProtectedWithReflection<IEnumerable<X509Certificate2>>(provider, "GetCertificateChain", X509ChainSortOrder.LeafFirst).ToList(),
            Throws.TypeOf<InvalidOperationException>().With.Message.Contains("Certificate chain is not available"));
    }

    /// <summary>
    /// Tests the <see cref="AzureTrustedSigningCoseSigningKeyProvider.GetCertificateChain"/> method
    /// to ensure it throws an <see cref="InvalidOperationException"/> when the certificate chain is empty.
    /// </summary>
    [Test]
    public void GetCertificateChain_ThrowsInvalidOperationException_WhenCertificateChainIsEmpty()
    {
        // Arrange
        Mock<AzSignContext> mockSignContext = new Mock<AzSignContext>();
        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>())).Returns(new List<X509Certificate2>());
        AzureTrustedSigningCoseSigningKeyProvider provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act & Assert
        Assert.That(
            () => InvokeProtectedWithReflection<IEnumerable<X509Certificate2>>(provider, "GetCertificateChain", X509ChainSortOrder.LeafFirst).ToList(),
            Throws.TypeOf<InvalidOperationException>().With.Message.Contains("Certificate chain is empty"));
    }

    /// <summary>
    /// Tests the <see cref="AzureTrustedSigningCoseSigningKeyProvider.GetCertificateChain"/> method
    /// to ensure it returns the certificate chain in the correct order.
    /// </summary>
    /// <param name="sortOrder">The desired sort order of the certificate chain.</param>
    /// <param name="expectedOrder">The expected order of the certificate chain.</param>
    [Test]
    [TestCase(X509ChainSortOrder.LeafFirst, false, TestName = "GetCertificateChain_ReturnsChainInLeafFirstOrder")]
    [TestCase(X509ChainSortOrder.RootFirst, true, TestName = "GetCertificateChain_ReturnsChainInRootFirstOrder")]
    public void GetCertificateChain_ReturnsChainInCorrectOrder(X509ChainSortOrder sortOrder, bool reverseOrder)
    {
        // Arrange
        Mock<AzSignContext> mockSignContext = new Mock<AzSignContext>();
        List<X509Certificate2> mockChain = CreateMockCertificateChain();
        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>())).Returns(mockChain);
        AzureTrustedSigningCoseSigningKeyProvider provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        List<X509Certificate2> result = InvokeProtectedWithReflection<IEnumerable<X509Certificate2>>(provider, "GetCertificateChain", sortOrder).ToList();

        // Assert
        List<X509Certificate2> expectedOrder = reverseOrder ? mockChain.AsEnumerable().Reverse().ToList() : mockChain;
        Assert.That(result, Is.EqualTo(expectedOrder));
    }

    /// <summary>
    /// Tests the <see cref="AzureTrustedSigningCoseSigningKeyProvider.GetSigningCertificate"/> method
    /// to ensure it throws an <see cref="InvalidOperationException"/> when the signing certificate is not available.
    /// </summary>
    [Test]
    public void GetSigningCertificate_ThrowsInvalidOperationException_WhenSigningCertificateIsUnavailable()
    {
        // Arrange
        Mock<AzSignContext> mockSignContext = new Mock<AzSignContext>();
        mockSignContext.Setup(context => context.GetSigningCertificate(It.IsAny<CancellationToken>())).Returns((X509Certificate2)null);
        AzureTrustedSigningCoseSigningKeyProvider provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act & Assert
        Assert.That(
            () => InvokeProtectedWithReflection<X509Certificate2>(provider,"GetSigningCertificate"),
            Throws.TypeOf<InvalidOperationException>().With.Message.Contains("Signing certificate is not available"));
    }

    /// <summary>
    /// Tests the <see cref="AzureTrustedSigningCoseSigningKeyProvider.GetSigningCertificate"/> method
    /// to ensure it returns the signing certificate.
    /// </summary>
    [Test]
    public void GetSigningCertificate_ReturnsSigningCertificate()
    {
        // Arrange
        Mock<AzSignContext> mockSignContext = new Mock<AzSignContext>();
        X509Certificate2 mockCertificate = TestCertificateUtils.CreateCertificate(nameof(GetSigningCertificate_ReturnsSigningCertificate));
        mockSignContext.Setup(context => context.GetSigningCertificate(It.IsAny<CancellationToken>())).Returns(mockCertificate);
        AzureTrustedSigningCoseSigningKeyProvider provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        X509Certificate2 result = InvokeProtectedWithReflection<X509Certificate2>(provider, "GetSigningCertificate");

        // Assert
        Assert.That(result, Is.EqualTo(mockCertificate));
    }

    /// <summary>
    /// Tests the <see cref="AzureTrustedSigningCoseSigningKeyProvider.ProvideECDsaKey"/> method
    /// to ensure it throws a <see cref="NotSupportedException"/>.
    /// </summary>
    [Test]
    public void ProvideECDsaKey_ThrowsNotSupportedException()
    {
        // Arrange
        Mock<AzSignContext> mockSignContext = new Mock<AzSignContext>();
        AzureTrustedSigningCoseSigningKeyProvider provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act & Assert
        Assert.That(
            () => InvokeProtectedWithReflection<ECDsa?>(provider, "ProvideECDsaKey"),
            Throws.TypeOf<NotSupportedException>().With.Message.Contains("ECDsa is not supported"));
    }

    /// <summary>
    /// Tests the <see cref="AzureTrustedSigningCoseSigningKeyProvider.ProvideRSAKey"/> method
    /// to ensure it returns an <see cref="RSA"/> instance.
    /// </summary>
    [Test]
    public void ProvideRSAKey_ReturnsRSAInstance()
    {
        // Arrange
        Mock<AzSignContext> mockSignContext = new Mock<AzSignContext>();
        AzureTrustedSigningCoseSigningKeyProvider provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        RSA result = InvokeProtectedWithReflection<RSA?>(provider, "ProvideRSAKey");

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.InstanceOf<RSAAzSign>());
    }

    /// <summary>
    /// Helper method to create a mock certificate chain.
    /// </summary>
    /// <returns>A list of mock <see cref="X509Certificate2"/> objects.</returns>
    private static List<X509Certificate2> CreateMockCertificateChain([CallerMemberName]string testCallerName = "")
    {
        return TestCertificateUtils.CreateTestChain(testCallerName).Cast<X509Certificate2>().ToList();
    }
    /// <summary>
    /// Helper method to invoke the protected GetCertificateChain method on the AzureTrustedSigningCoseSigningKeyProvider instance.
    /// </summary>
    /// <param name="provider">The instance of <see cref="AzureTrustedSigningCoseSigningKeyProvider"/>.</param>
    /// <param name="sortOrder">The desired sort order of the certificate chain.</param>
    /// <returns>The certificate chain as an <see cref="IEnumerable{X509Certificate2}"/>.</returns>
    private static T InvokeProtectedWithReflection<T>(
        AzureTrustedSigningCoseSigningKeyProvider provider,
        string methodName,
        params object[] arguments)
    {
        // Use reflection to access the protected method
        MethodInfo method = typeof(AzureTrustedSigningCoseSigningKeyProvider)
            .GetMethod(methodName, System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

        if (method == null)
        {
            throw new InvalidOperationException($"The protected method '{methodName}' could not be found.");
        }

        return (T)method.Invoke(provider, arguments);
    }
}
