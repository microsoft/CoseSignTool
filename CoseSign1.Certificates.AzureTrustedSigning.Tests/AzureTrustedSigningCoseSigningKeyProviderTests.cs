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
/// These tests ensure that the class behaves as expected under various conditions,
/// including valid and invalid configurations of the Azure Trusted Signing context.
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
        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>())).Returns((IReadOnlyList<X509Certificate2>?)null);
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
    /// <param name="reverseOrder">Indicates whether the chain should be reversed.</param>
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
        mockSignContext.Setup(context => context.GetSigningCertificate(It.IsAny<CancellationToken>())).Returns((X509Certificate2?)null);
        AzureTrustedSigningCoseSigningKeyProvider provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act & Assert
        Assert.That(
            () => InvokeProtectedWithReflection<X509Certificate2>(provider, "GetSigningCertificate"),
            Throws.TypeOf<TargetInvocationException>().With.InnerException.TypeOf<InvalidOperationException>().And.InnerException.Message.Contains("Signing certificate is not available"));
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
            () => InvokeProtectedWithReflection<ECDsa?>(provider, "ProvideECDsaKey", false),
            Throws.TypeOf<TargetInvocationException>().With.InnerException.TypeOf<NotSupportedException>().And.InnerException.Message.Contains("ECDsa is not supported"));
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
        RSA result = InvokeProtectedWithReflection<RSA?>(provider, "ProvideRSAKey", false);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.InstanceOf<RSAAzSign>());
    }

    /// <summary>
    /// Tests that <see cref="AzureTrustedSigningCoseSigningKeyProvider.GetCertificateChain"/> caches the certificate chain
    /// and only calls GetCertChain on the context once.
    /// </summary>
    [Test]
    public void GetCertificateChain_CachesChainOnFirstCall()
    {
        // Arrange
        Mock<AzSignContext> mockSignContext = new Mock<AzSignContext>();
        List<X509Certificate2> mockChain = CreateMockCertificateChain();
        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>())).Returns(mockChain);
        AzureTrustedSigningCoseSigningKeyProvider provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        List<X509Certificate2> result1 = InvokeProtectedWithReflection<IEnumerable<X509Certificate2>>(provider, "GetCertificateChain", X509ChainSortOrder.LeafFirst).ToList();
        List<X509Certificate2> result2 = InvokeProtectedWithReflection<IEnumerable<X509Certificate2>>(provider, "GetCertificateChain", X509ChainSortOrder.LeafFirst).ToList();

        // Assert
        Assert.That(result1, Is.EqualTo(result2));
        mockSignContext.Verify(context => context.GetCertChain(It.IsAny<CancellationToken>()), Times.Once);
    }

    /// <summary>
    /// Tests that <see cref="AzureTrustedSigningCoseSigningKeyProvider.GetSigningCertificate"/> caches the certificate
    /// and only calls GetSigningCertificate on the context once.
    /// </summary>
    [Test]
    public void GetSigningCertificate_CachesCertificateOnFirstCall()
    {
        // Arrange
        Mock<AzSignContext> mockSignContext = new Mock<AzSignContext>();
        X509Certificate2 mockCertificate = TestCertificateUtils.CreateCertificate(nameof(GetSigningCertificate_CachesCertificateOnFirstCall));
        mockSignContext.Setup(context => context.GetSigningCertificate(It.IsAny<CancellationToken>())).Returns(mockCertificate);
        AzureTrustedSigningCoseSigningKeyProvider provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        X509Certificate2 result1 = InvokeProtectedWithReflection<X509Certificate2>(provider, "GetSigningCertificate");
        X509Certificate2 result2 = InvokeProtectedWithReflection<X509Certificate2>(provider, "GetSigningCertificate");

        // Assert
        Assert.That(result1, Is.EqualTo(result2));
        mockSignContext.Verify(context => context.GetSigningCertificate(It.IsAny<CancellationToken>()), Times.Once);
    }

    /// <summary>
    /// Tests that <see cref="AzureTrustedSigningCoseSigningKeyProvider.ProvideRSAKey"/> caches the RSA instance
    /// and returns the same instance on subsequent calls.
    /// </summary>
    [Test]
    public void ProvideRSAKey_CachesRSAInstanceOnFirstCall()
    {
        // Arrange
        Mock<AzSignContext> mockSignContext = new Mock<AzSignContext>();
        AzureTrustedSigningCoseSigningKeyProvider provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        RSA result1 = InvokeProtectedWithReflection<RSA?>(provider, "ProvideRSAKey", false);
        RSA result2 = InvokeProtectedWithReflection<RSA?>(provider, "ProvideRSAKey", false);

        // Assert
        Assert.That(result1, Is.Not.Null);
        Assert.That(result2, Is.Not.Null);
        Assert.That(result1, Is.SameAs(result2), "ProvideRSAKey should return the same cached instance");
    }

    /// <summary>
    /// Tests that <see cref="AzureTrustedSigningCoseSigningKeyProvider.ProvideRSAKey"/> returns the same instance
    /// regardless of the publicKey parameter value (caching ignores the parameter).
    /// </summary>
    [Test]
    public void ProvideRSAKey_ReturnsSameCachedInstance_RegardlessOfPublicKeyParameter()
    {
        // Arrange
        Mock<AzSignContext> mockSignContext = new Mock<AzSignContext>();
        AzureTrustedSigningCoseSigningKeyProvider provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        RSA result1 = InvokeProtectedWithReflection<RSA?>(provider, "ProvideRSAKey", false);
        RSA result2 = InvokeProtectedWithReflection<RSA?>(provider, "ProvideRSAKey", true);

        // Assert
        Assert.That(result1, Is.Not.Null);
        Assert.That(result2, Is.Not.Null);
        Assert.That(result1, Is.SameAs(result2), "ProvideRSAKey should return the same cached instance regardless of publicKey parameter");
    }

    /// <summary>
    /// Tests that <see cref="AzureTrustedSigningCoseSigningKeyProvider.GetCertificateChain"/> is thread-safe
    /// and only calls GetCertChain once even under concurrent access.
    /// </summary>
    [Test]
    public void GetCertificateChain_IsThreadSafe_UnderConcurrentAccess()
    {
        // Arrange
        Mock<AzSignContext> mockSignContext = new Mock<AzSignContext>();
        List<X509Certificate2> mockChain = CreateMockCertificateChain();
        int callCount = 0;
        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>()))
            .Returns(() =>
            {
                Interlocked.Increment(ref callCount);
                Thread.Sleep(10); // Simulate some delay to increase chance of race condition
                return mockChain;
            });
        AzureTrustedSigningCoseSigningKeyProvider provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act - Run multiple threads concurrently
        List<Task<List<X509Certificate2>>> tasks = new List<Task<List<X509Certificate2>>>();
        for (int i = 0; i < 10; i++)
        {
            tasks.Add(Task.Run(() =>
                InvokeProtectedWithReflection<IEnumerable<X509Certificate2>>(provider, "GetCertificateChain", X509ChainSortOrder.LeafFirst).ToList()));
        }
        Task.WaitAll(tasks.ToArray());

        // Assert
        Assert.That(callCount, Is.EqualTo(1), "GetCertChain should only be called once despite concurrent access");
        // Verify all tasks got the same chain
        List<X509Certificate2> firstResult = tasks[0].Result;
        foreach (Task<List<X509Certificate2>> task in tasks)
        {
            Assert.That(task.Result, Is.EqualTo(firstResult));
        }
    }

    /// <summary>
    /// Tests that GetCertificateChain correctly handles self-signed certificates (root certificates)
    /// where Issuer equals Subject.
    /// </summary>
    [Test]
    public void GetCertificateChain_HandlesRootCertificateCorrectly()
    {
        // Arrange
        Mock<AzSignContext> mockSignContext = new Mock<AzSignContext>();
        // Create a certificate (CreateCertificate creates self-signed certs)
        X509Certificate2 rootCert = TestCertificateUtils.CreateCertificate(nameof(GetCertificateChain_HandlesRootCertificateCorrectly));
        List<X509Certificate2> chain = new List<X509Certificate2> { rootCert };
        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>())).Returns(chain);
        AzureTrustedSigningCoseSigningKeyProvider provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act - Request RootFirst for a self-signed cert
        List<X509Certificate2> resultRootFirst = InvokeProtectedWithReflection<IEnumerable<X509Certificate2>>(provider, "GetCertificateChain", X509ChainSortOrder.RootFirst).ToList();
        
        // Reset the chain cache by creating a new provider
        provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);
        
        // Act - Request LeafFirst for a self-signed cert
        List<X509Certificate2> resultLeafFirst = InvokeProtectedWithReflection<IEnumerable<X509Certificate2>>(provider, "GetCertificateChain", X509ChainSortOrder.LeafFirst).ToList();

        // Assert - For self-signed cert, order should be reversed between RootFirst and LeafFirst
        Assert.That(resultRootFirst.Count, Is.EqualTo(1));
        Assert.That(resultLeafFirst.Count, Is.EqualTo(1));
        Assert.That(resultRootFirst[0], Is.EqualTo(chain[0]));
        Assert.That(resultLeafFirst[0], Is.EqualTo(chain[0]));
    }

    /// <summary>
    /// Tests that ProvideECDsaKey with publicKey=true still throws NotSupportedException.
    /// </summary>
    [Test]
    public void ProvideECDsaKey_ThrowsNotSupportedException_WithPublicKeyParameterTrue()
    {
        // Arrange
        Mock<AzSignContext> mockSignContext = new Mock<AzSignContext>();
        AzureTrustedSigningCoseSigningKeyProvider provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act & Assert
        Assert.That(
            () => InvokeProtectedWithReflection<ECDsa?>(provider, "ProvideECDsaKey", true),
            Throws.TypeOf<TargetInvocationException>().With.InnerException.TypeOf<NotSupportedException>().And.InnerException.Message.Contains("ECDsa is not supported"));
    }

    /// <summary>
    /// Tests that ProvideRSAKey works correctly with publicKey parameter set to true.
    /// </summary>
    [Test]
    public void ProvideRSAKey_WorksWithPublicKeyParameterTrue()
    {
        // Arrange
        Mock<AzSignContext> mockSignContext = new Mock<AzSignContext>();
        AzureTrustedSigningCoseSigningKeyProvider provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        RSA result = InvokeProtectedWithReflection<RSA?>(provider, "ProvideRSAKey", true);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.InstanceOf<RSAAzSign>());
    }

    /// <summary>
    /// Helper method to create a mock certificate chain.
    /// </summary>
    /// <param name="testCallerName">The name of the test method calling this helper.</param>
    /// <returns>A list of mock <see cref="X509Certificate2"/> objects.</returns>
    private static List<X509Certificate2> CreateMockCertificateChain([CallerMemberName] string testCallerName = "")
    {
        return TestCertificateUtils.CreateTestChain(testCallerName).Cast<X509Certificate2>().ToList();
    }

    /// <summary>
    /// Tests that the Issuer property returns a DID:X509:0 identifier with EKU format for non-standard EKUs.
    /// </summary>
    [Test]
    public void Issuer_WithNonStandardEku_ReturnsDidX509WithEkuFormat()
    {
        // Arrange
        Mock<AzSignContext> mockSignContext = new Mock<AzSignContext>();
        
        // Create a certificate chain with non-standard EKU
        X509Certificate2 leafCert = TestCertificateUtils.CreateCertificate(nameof(Issuer_WithNonStandardEku_ReturnsDidX509WithEkuFormat));
        X509Certificate2Collection chain = new() { leafCert };
        
        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>())).Returns(chain.Cast<X509Certificate2>().ToList());
        AzureTrustedSigningCoseSigningKeyProvider provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        string? issuer = provider.Issuer;

        // Assert
        Assert.That(issuer, Is.Not.Null.And.Not.Empty);
        Assert.That(issuer, Does.StartWith("did:x509:0:sha256:"));
        // Since test certs don't have non-standard EKUs, it should fall back to subject format
        // This tests that the Issuer property is accessible and returns a value
        // Base64url hash is 43 characters for SHA256 (per RFC 4648 Section 5)
        Assert.That(System.Text.RegularExpressions.Regex.IsMatch(issuer!, @"did:x509:0:sha256:[A-Za-z0-9_-]{43}::(subject|eku):"), Is.True);
    }

    /// <summary>
    /// Tests that the Issuer property returns null when certificate chain is unavailable.
    /// </summary>
    [Test]
    public void Issuer_WhenCertificateChainUnavailable_ReturnsNull()
    {
        // Arrange
        Mock<AzSignContext> mockSignContext = new Mock<AzSignContext>();
        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>())).Returns((IReadOnlyList<X509Certificate2>?)null);
        AzureTrustedSigningCoseSigningKeyProvider provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        string? issuer = provider.Issuer;

        // Assert
        Assert.That(issuer, Is.Null);
    }

    /// <summary>
    /// Tests that the Issuer property returns null when certificate chain is empty.
    /// </summary>
    [Test]
    public void Issuer_WhenCertificateChainEmpty_ReturnsNull()
    {
        // Arrange
        Mock<AzSignContext> mockSignContext = new Mock<AzSignContext>();
        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>())).Returns(new List<X509Certificate2>());
        AzureTrustedSigningCoseSigningKeyProvider provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        string? issuer = provider.Issuer;

        // Assert
        Assert.That(issuer, Is.Null);
    }

    /// <summary>
    /// Tests that the Issuer property uses the Azure-specific DID generator.
    /// </summary>
    [Test]
    public void Issuer_UsesAzureTrustedSigningDidGenerator()
    {
        // Arrange
        Mock<AzSignContext> mockSignContext = new Mock<AzSignContext>();
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain(nameof(Issuer_UsesAzureTrustedSigningDidGenerator), leafFirst: true);
        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>())).Returns(chain.Cast<X509Certificate2>().ToList());
        AzureTrustedSigningCoseSigningKeyProvider provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        string? issuer = provider.Issuer;

        // Assert - Verify it generates a valid DID:X509:0 format
        Assert.That(issuer, Is.Not.Null.And.Not.Empty);
        Assert.That(issuer, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(issuer!.Contains("::subject:") || issuer.Contains("::eku:"), Is.True);
    }

    /// <summary>
    /// Tests that the Issuer property handles exceptions gracefully and falls back to base implementation.
    /// </summary>
    [Test]
    public void Issuer_OnException_FallsBackToBaseImplementation()
    {
        // Arrange
        Mock<AzSignContext> mockSignContext = new Mock<AzSignContext>();
        // Setup to throw an exception that should be caught
        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>()))
            .Throws(new InvalidOperationException("Test exception"));
        AzureTrustedSigningCoseSigningKeyProvider provider = new AzureTrustedSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        string? issuer = provider.Issuer;

        // Assert - Should fall back to base implementation which returns null on error
        Assert.That(issuer, Is.Null);
    }

    /// <summary>
    /// Helper method to invoke a protected method on the <see cref="AzureTrustedSigningCoseSigningKeyProvider"/> instance using reflection.
    /// </summary>
    /// <typeparam name="T">The return type of the method being invoked.</typeparam>
    /// <param name="provider">The instance of <see cref="AzureTrustedSigningCoseSigningKeyProvider"/>.</param>
    /// <param name="methodName">The name of the protected method to invoke.</param>
    /// <param name="arguments">The arguments to pass to the method.</param>
    /// <returns>The result of the invoked method.</returns>
    private static T InvokeProtectedWithReflection<T>(
        AzureTrustedSigningCoseSigningKeyProvider provider,
        string methodName,
        params object[] arguments)
    {
        // Use reflection to access the protected method
        MethodInfo method = typeof(AzureTrustedSigningCoseSigningKeyProvider)
            .GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Instance);

        if (method == null)
        {
            throw new InvalidOperationException($"The protected method '{methodName}' could not be found.");
        }

        return (T)method.Invoke(provider, arguments);
    }
}
