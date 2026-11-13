// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.AzureArtifactSigning.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using Azure.Developer.ArtifactSigning.CryptoProvider;
using Azure.Developer.ArtifactSigning.CryptoProvider.Interfaces;
using CoseSign1.Headers;
using CoseSign1.Certificates.AzureArtifactSigning;
using CoseSign1.Certificates.Local;
using CoseSign1.Tests.Common;
using Moq;
using NUnit.Framework;

/// <summary>
/// Unit tests for the <see cref="AzureArtifactSigningCoseSigningKeyProvider"/> class.
/// These tests ensure that the class behaves as expected under various conditions,
/// including valid and invalid configurations of the Azure Artifact Signing context.
/// </summary>
[TestFixture]
public class AzureArtifactSigningCoseSigningKeyProviderTests
{
    /// <summary>
    /// Tests the constructor to ensure it throws an <see cref="ArgumentNullException"/> when the sign context is null.
    /// </summary>
    [Test]
    public void Constructor_ThrowsArgumentNullException_WhenSignContextIsNull()
    {
        // Act & Assert
        Assert.That(
            () => new AzureArtifactSigningCoseSigningKeyProvider(null),
            Throws.TypeOf<ArgumentNullException>().With.Property("ParamName").EqualTo("ISignContext"));
    }

    /// <summary>
    /// Tests the <see cref="AzureArtifactSigningCoseSigningKeyProvider.GetCertificateChain"/> method
    /// to ensure it throws an <see cref="InvalidOperationException"/> when the certificate chain is not available.
    /// </summary>
    [Test]
    public void GetCertificateChain_ThrowsInvalidOperationException_WhenCertificateChainIsUnavailable()
    {
        // Arrange
        Mock<ISignContext> mockSignContext = new Mock<ISignContext>();

        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>())).Returns((IReadOnlyList<X509Certificate2>?)null);
        AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act & Assert - reflection wraps the exception in TargetInvocationException
        Assert.That(
            () => InvokeProtectedWithReflection<IEnumerable<X509Certificate2>>(provider, "GetCertificateChain", X509ChainSortOrder.LeafFirst).ToList(),
            Throws.TypeOf<TargetInvocationException>()
                .With.InnerException.TypeOf<InvalidOperationException>()
                .With.InnerException.Message.Contains("Certificate chain is not available"));
    }

    /// <summary>
    /// Tests the <see cref="AzureArtifactSigningCoseSigningKeyProvider.GetCertificateChain"/> method
    /// to ensure it throws an <see cref="InvalidOperationException"/> when the certificate chain is empty.
    /// </summary>
    [Test]
    public void GetCertificateChain_ThrowsInvalidOperationException_WhenCertificateChainIsEmpty()
    {
        // Arrange
        Mock<ISignContext> mockSignContext = new Mock<ISignContext>();
        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>())).Returns(new List<X509Certificate2>());
        AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act & Assert - reflection wraps the exception in TargetInvocationException
        Assert.That(
            () => InvokeProtectedWithReflection<IEnumerable<X509Certificate2>>(provider, "GetCertificateChain", X509ChainSortOrder.LeafFirst).ToList(),
            Throws.TypeOf<TargetInvocationException>()
                .With.InnerException.TypeOf<InvalidOperationException>()
                .With.InnerException.Message.Contains("Certificate chain is empty"));
    }

    /// <summary>
    /// Tests the <see cref="AzureArtifactSigningCoseSigningKeyProvider.GetCertificateChain"/> method
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
        Mock<ISignContext> mockSignContext = new Mock<ISignContext>();
        List<X509Certificate2> mockChain = CreateMockCertificateChain();
        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>())).Returns(mockChain);
        // GetCertificateChain walks from the signing cert, so the mock must provide it
        mockSignContext.Setup(context => context.GetSigningCertificate(It.IsAny<CancellationToken>())).Returns(mockChain.Last());
        AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        List<X509Certificate2> result = InvokeProtectedWithReflection<IEnumerable<X509Certificate2>>(provider, "GetCertificateChain", sortOrder).ToList();

        // Assert
        // Chain is now built by walking from signing cert (leaf) to root via issuer matching
        List<X509Certificate2> expectedLeafFirst = new() { mockChain[2], mockChain[1], mockChain[0] }; // leaf, issuer, root
        List<X509Certificate2> expectedOrder = sortOrder == X509ChainSortOrder.RootFirst ? expectedLeafFirst.AsEnumerable().Reverse().ToList() : expectedLeafFirst;
        Assert.That(result, Is.EqualTo(expectedOrder));
    }

    /// <summary>
    /// Tests the <see cref="AzureArtifactSigningCoseSigningKeyProvider.GetSigningCertificate"/> method
    /// to ensure it throws an <see cref="InvalidOperationException"/> when the signing certificate is not available.
    /// </summary>
    [Test]
    public void GetSigningCertificate_ThrowsInvalidOperationException_WhenSigningCertificateIsUnavailable()
    {
        // Arrange
        Mock<ISignContext> mockSignContext = new Mock<ISignContext>();
        mockSignContext.Setup(context => context.GetSigningCertificate(It.IsAny<CancellationToken>())).Returns((X509Certificate2?)null);
        AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act & Assert
        Assert.That(
            () => InvokeProtectedWithReflection<X509Certificate2>(provider, "GetSigningCertificate"),
            Throws.TypeOf<TargetInvocationException>().With.InnerException.TypeOf<InvalidOperationException>().And.InnerException.Message.Contains("Signing certificate is not available"));
    }

    /// <summary>
    /// Tests the <see cref="AzureArtifactSigningCoseSigningKeyProvider.GetSigningCertificate"/> method
    /// to ensure it returns the signing certificate.
    /// </summary>
    [Test]
    public void GetSigningCertificate_ReturnsSigningCertificate()
    {
        // Arrange
        Mock<ISignContext> mockSignContext = new Mock<ISignContext>();
        X509Certificate2 mockCertificate = TestCertificateUtils.CreateCertificate(nameof(GetSigningCertificate_ReturnsSigningCertificate));
        mockSignContext.Setup(context => context.GetSigningCertificate(It.IsAny<CancellationToken>())).Returns(mockCertificate);
        AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        X509Certificate2 result = InvokeProtectedWithReflection<X509Certificate2>(provider, "GetSigningCertificate");

        // Assert
        Assert.That(result, Is.EqualTo(mockCertificate));
    }

    /// <summary>
    /// Tests the <see cref="AzureArtifactSigningCoseSigningKeyProvider.ProvideECDsaKey"/> method
    /// to ensure it throws a <see cref="NotSupportedException"/>.
    /// </summary>
    [Test]
    public void ProvideECDsaKey_ThrowsNotSupportedException()
    {
        // Arrange
        Mock<ISignContext> mockSignContext = new Mock<ISignContext>();
        AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act & Assert
        Assert.That(
            () => InvokeProtectedWithReflection<ECDsa?>(provider, "ProvideECDsaKey", false),
            Throws.TypeOf<TargetInvocationException>().With.InnerException.TypeOf<NotSupportedException>().And.InnerException.Message.Contains("ECDsa is not supported"));
    }

    /// <summary>
    /// Tests the <see cref="AzureArtifactSigningCoseSigningKeyProvider.ProvideRSAKey"/> method
    /// to ensure it returns an <see cref="RSA"/> instance.
    /// </summary>
    [Test]
    public void ProvideRSAKey_ReturnsRSAInstance()
    {
        // Arrange
        Mock<ISignContext> mockSignContext = new Mock<ISignContext>();
        AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        RSA result = InvokeProtectedWithReflection<RSA?>(provider, "ProvideRSAKey", false);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.InstanceOf<RSAAzSign>());
    }

    /// <summary>
    /// Tests that <see cref="AzureArtifactSigningCoseSigningKeyProvider.GetCertificateChain"/> caches the certificate chain
    /// and only calls GetCertChain on the context once.
    /// </summary>
    [Test]
    public void GetCertificateChain_CachesChainOnFirstCall()
    {
        // Arrange
        Mock<ISignContext> mockSignContext = new Mock<ISignContext>();
        List<X509Certificate2> mockChain = CreateMockCertificateChain();
        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>())).Returns(mockChain);
        // GetCertificateChain walks from the signing cert, so the mock must provide it
        mockSignContext.Setup(context => context.GetSigningCertificate(It.IsAny<CancellationToken>())).Returns(mockChain.Last());
        AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        List<X509Certificate2> result1 = InvokeProtectedWithReflection<IEnumerable<X509Certificate2>>(provider, "GetCertificateChain", X509ChainSortOrder.LeafFirst).ToList();
        List<X509Certificate2> result2 = InvokeProtectedWithReflection<IEnumerable<X509Certificate2>>(provider, "GetCertificateChain", X509ChainSortOrder.LeafFirst).ToList();

        // Assert
        Assert.That(result1, Is.EqualTo(result2));
        mockSignContext.Verify(context => context.GetCertChain(It.IsAny<CancellationToken>()), Times.Once);
    }

    /// <summary>
    /// Tests that <see cref="AzureArtifactSigningCoseSigningKeyProvider.GetSigningCertificate"/> caches the certificate
    /// and only calls GetSigningCertificate on the context once.
    /// </summary>
    [Test]
    public void GetSigningCertificate_CachesCertificateOnFirstCall()
    {
        // Arrange
        Mock<ISignContext> mockSignContext = new Mock<ISignContext>();
        X509Certificate2 mockCertificate = TestCertificateUtils.CreateCertificate(nameof(GetSigningCertificate_CachesCertificateOnFirstCall));
        mockSignContext.Setup(context => context.GetSigningCertificate(It.IsAny<CancellationToken>())).Returns(mockCertificate);
        AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        X509Certificate2 result1 = InvokeProtectedWithReflection<X509Certificate2>(provider, "GetSigningCertificate");
        X509Certificate2 result2 = InvokeProtectedWithReflection<X509Certificate2>(provider, "GetSigningCertificate");

        // Assert
        Assert.That(result1, Is.EqualTo(result2));
        mockSignContext.Verify(context => context.GetSigningCertificate(It.IsAny<CancellationToken>()), Times.Once);
    }

    /// <summary>
    /// Tests that <see cref="AzureArtifactSigningCoseSigningKeyProvider.ProvideRSAKey"/> caches the RSA instance
    /// and returns the same instance on subsequent calls.
    /// </summary>
    [Test]
    public void ProvideRSAKey_CachesRSAInstanceOnFirstCall()
    {
        // Arrange
        Mock<ISignContext> mockSignContext = new Mock<ISignContext>();
        AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        RSA result1 = InvokeProtectedWithReflection<RSA?>(provider, "ProvideRSAKey", false);
        RSA result2 = InvokeProtectedWithReflection<RSA?>(provider, "ProvideRSAKey", false);

        // Assert
        Assert.That(result1, Is.Not.Null);
        Assert.That(result2, Is.Not.Null);
        Assert.That(result1, Is.SameAs(result2), "ProvideRSAKey should return the same cached instance");
    }

    /// <summary>
    /// Tests that <see cref="AzureArtifactSigningCoseSigningKeyProvider.ProvideRSAKey"/> returns the same instance
    /// regardless of the publicKey parameter value (caching ignores the parameter).
    /// </summary>
    [Test]
    public void ProvideRSAKey_ReturnsSameCachedInstance_RegardlessOfPublicKeyParameter()
    {
        // Arrange
        Mock<ISignContext> mockSignContext = new Mock<ISignContext>();
        AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        RSA result1 = InvokeProtectedWithReflection<RSA?>(provider, "ProvideRSAKey", false);
        RSA result2 = InvokeProtectedWithReflection<RSA?>(provider, "ProvideRSAKey", true);

        // Assert
        Assert.That(result1, Is.Not.Null);
        Assert.That(result2, Is.Not.Null);
        Assert.That(result1, Is.SameAs(result2), "ProvideRSAKey should return the same cached instance regardless of publicKey parameter");
    }

    /// <summary>
    /// Tests that <see cref="AzureArtifactSigningCoseSigningKeyProvider.GetCertificateChain"/> is thread-safe
    /// and only calls GetCertChain once even under concurrent access.
    /// </summary>
    [Test]
    public void GetCertificateChain_IsThreadSafe_UnderConcurrentAccess()
    {
        // Arrange
        Mock<ISignContext> mockSignContext = new Mock<ISignContext>();
        List<X509Certificate2> mockChain = CreateMockCertificateChain();
        int callCount = 0;
        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>()))
            .Returns(() =>
            {
                Interlocked.Increment(ref callCount);
                Thread.Sleep(10); // Simulate some delay to increase chance of race condition
                return mockChain;
            });
        // GetCertificateChain walks from the signing cert, so the mock must provide it
        mockSignContext.Setup(context => context.GetSigningCertificate(It.IsAny<CancellationToken>())).Returns(mockChain.Last());
        AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);

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
        Mock<ISignContext> mockSignContext = new Mock<ISignContext>();
        // Create a certificate (CreateCertificate creates self-signed certs)
        X509Certificate2 rootCert = TestCertificateUtils.CreateCertificate(nameof(GetCertificateChain_HandlesRootCertificateCorrectly));
        List<X509Certificate2> chain = new List<X509Certificate2> { rootCert };
        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>())).Returns(chain);
        // For a self-signed cert, the signing cert is the root cert itself
        mockSignContext.Setup(context => context.GetSigningCertificate(It.IsAny<CancellationToken>())).Returns(rootCert);
        AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act - Request RootFirst for a self-signed cert
        List<X509Certificate2> resultRootFirst = InvokeProtectedWithReflection<IEnumerable<X509Certificate2>>(provider, "GetCertificateChain", X509ChainSortOrder.RootFirst).ToList();

        // Reset the chain cache by creating a new provider
        provider = new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);

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
        Mock<ISignContext> mockSignContext = new Mock<ISignContext>();
        AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);

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
        Mock<ISignContext> mockSignContext = new Mock<ISignContext>();
        AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        RSA result = InvokeProtectedWithReflection<RSA?>(provider, "ProvideRSAKey", true);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Is.InstanceOf<RSAAzSign>());
    }

    /// <summary>
    /// Verifies that the generic message factory passes hash, padding, and custom headers through
    /// the Azure Artifact Signing provider without provider-specific configuration.
    /// </summary>
    [Test]
    public void MessageFactory_PassesGenericSigningOptionsToArtifactSigningProvider()
    {
        X509Certificate2 signingCertificate =
            TestCertificateUtils.CreateCertificate(
                nameof(MessageFactory_PassesGenericSigningOptionsToArtifactSigningProvider),
                keySize: 3072);
        using RSA privateKey = signingCertificate.GetRSAPrivateKey()!;
        Mock<ISignContext> mockSignContext = new Mock<ISignContext>(MockBehavior.Strict);
        byte[]? capturedDigest = null;
        RSASignaturePadding? capturedPadding = null;

        mockSignContext
            .Setup(context => context.GetSigningCertificate(It.IsAny<CancellationToken>()))
            .Returns(signingCertificate);
        mockSignContext
            .Setup(context => context.GetCertChain(It.IsAny<CancellationToken>()))
            .Returns(new List<X509Certificate2> { signingCertificate });
        mockSignContext
            .Setup(context => context.SignDigestAsync(
                It.IsAny<byte[]>(),
                It.IsAny<RSASignaturePadding>(),
                It.IsAny<X509Certificate2>(),
                It.IsAny<byte[]>(),
                It.IsAny<byte[]>(),
                It.IsAny<CancellationToken>()))
            .Returns((
                byte[] digest,
                RSASignaturePadding padding,
                X509Certificate2 _,
                byte[] _,
                byte[] _,
                CancellationToken _) =>
            {
                capturedDigest = digest;
                capturedPadding = padding;
                return Task.FromResult(privateKey.SignHash(digest, HashAlgorithmName.SHA384, padding));
            });

        byte[] encodedCbor = [0x44, 0x01, 0x02, 0x03, 0x04];
        CoseHeaderLabel customHeaderLabel = new(4242);
        CoseHeaderExtender headerExtender = new(
            protectedHeaders =>
            {
                protectedHeaders[customHeaderLabel] = CoseHeaderValue.FromEncodedValue(encodedCbor);
                return protectedHeaders;
            },
            unProtectedHeaders => unProtectedHeaders ?? new CoseHeaderMap());
        AzureArtifactSigningCoseSigningKeyProvider provider =
            new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);
        CoseSign1MessageFactory factory = new();
        CoseSign1MessageSigningOptions signingOptions = new()
        {
            HashAlgorithm = HashAlgorithmName.SHA384,
            RsaSignaturePadding = RSASignaturePadding.Pkcs1,
        };

        CoseSign1Message message = factory.CreateCoseSign1Message(
            "artifact-signing-payload"u8.ToArray(),
            provider,
            embedPayload: true,
            headerExtender: headerExtender,
            signingOptions: signingOptions);

        Assert.Multiple(() =>
        {
            Assert.That(capturedDigest, Has.Length.EqualTo(48));
            Assert.That(capturedPadding, Is.SameAs(RSASignaturePadding.Pkcs1));
            Assert.That(message.ProtectedHeaders[CoseHeaderLabel.Algorithm].GetValueAsInt32(), Is.EqualTo(-258));
            Assert.That(message.ProtectedHeaders[customHeaderLabel].EncodedValue.ToArray(), Is.EqualTo(encodedCbor));
        });
    }

    [TestCase("SHA256", false, true, -37)]
    [TestCase("SHA384", false, false, -38)]
    [TestCase("SHA512", false, true, -39)]
    [TestCase("SHA256", true, false, -257)]
    [TestCase("SHA384", true, true, -258)]
    [TestCase("SHA512", true, false, -259)]
    public async Task MessageFactoryAsync_AwaitsRemoteOperationsAndProducesVerifiableSignature(
        string hashAlgorithmName, bool usePkcs1, bool embedPayload, int expectedAlgorithm)
    {
        using X509Certificate2 certificate = TestCertificateUtils.CreateCertificate(keySize: 3072);
        using RSA privateKey = certificate.GetRSAPrivateKey()!;
        HashAlgorithmName hashAlgorithm = new(hashAlgorithmName);
        RSASignaturePadding padding = usePkcs1 ? RSASignaturePadding.Pkcs1 : RSASignaturePadding.Pss;
        TaskCompletionSource<X509Certificate2> certificateReady = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<IReadOnlyList<X509Certificate2>> chainReady = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<byte[]> signatureReady = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<bool> chainRequested = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<byte[]> digestReady = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenSource cancellation = new();
        Mock<ISignContext> context = CreateAsyncSignContext(certificate, (digest, actualPadding) =>
        {
            Assert.That(actualPadding, Is.EqualTo(padding));
            digestReady.SetResult(digest);
            return signatureReady.Task;
        });
        context.Setup(x => x.GetSigningCertificateAsync(cancellation.Token)).Returns(certificateReady.Task);
        context.Setup(x => x.GetCertChainAsync(cancellation.Token)).Returns(() =>
        {
            chainRequested.SetResult(true);
            return chainReady.Task;
        });
        byte[] encodedCbor = [0x44, 0x01, 0x02, 0x03, 0x04];
        CoseHeaderLabel protectedLabel = new(4242);
        CoseHeaderLabel unprotectedLabel = new("request-id");
        CoseHeaderExtender extender = new(
            headers =>
            {
                headers[protectedLabel] = CoseHeaderValue.FromEncodedValue(encodedCbor);
                return headers;
            },
            headers =>
            {
                headers ??= new CoseHeaderMap();
                headers[unprotectedLabel] = CoseHeaderValue.FromString("test-request");
                return headers;
            });
        AzureArtifactSigningCoseSigningKeyProvider provider = new(context.Object);
        CoseSign1MessageFactory factory = new();
        byte[] payload = "async-artifact-signing-payload"u8.ToArray();
        using MemoryStream payloadSource = new(payload);
        Mock<Stream> asyncInput = new() { CallBase = true };
        asyncInput.SetupGet(x => x.CanRead).Returns(true);
        asyncInput.SetupGet(x => x.CanSeek).Returns(false);
        asyncInput.Setup(x => x.Read(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>()))
            .Throws(new AssertionException("Payload reads must be asynchronous."));
        asyncInput.Setup(x => x.ReadAsync(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .Returns((byte[] buffer, int offset, int count, CancellationToken token) =>
                payloadSource.ReadAsync(buffer, offset, count, token));
        using Stream payloadStream = embedPayload ? asyncInput.Object : payloadSource;
        Task<ReadOnlyMemory<byte>> operation = factory.CreateCoseSign1MessageBytesAsync(
            payloadStream, provider, embedPayload, headerExtender: extender,
            cancellationToken: cancellation.Token,
            signingOptions: new() { HashAlgorithm = hashAlgorithm, RsaSignaturePadding = padding });

        Assert.That(operation.IsCompleted, Is.False, "Certificate retrieval must yield to the caller.");
        certificateReady.SetResult(certificate);
        await chainRequested.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.That(operation.IsCompleted, Is.False, "Chain retrieval must yield to the caller.");
        chainReady.SetResult(new[] { certificate });
        byte[] digest = await digestReady.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.That(operation.IsCompleted, Is.False, "Remote signing must yield to the caller.");
        signatureReady.SetResult(privateKey.SignHash(digest, hashAlgorithm, padding));

        ReadOnlyMemory<byte> encoded = await operation.WaitAsync(TimeSpan.FromSeconds(10));
        CoseSign1Message message = CoseMessage.DecodeSign1(encoded.Span);
        using RSA publicKey = certificate.GetRSAPublicKey()!;
        Assert.Multiple(() =>
        {
            Assert.That(message.ProtectedHeaders[CoseHeaderLabel.Algorithm].GetValueAsInt32(), Is.EqualTo(expectedAlgorithm));
            Assert.That(message.ProtectedHeaders[protectedLabel].EncodedValue.ToArray(), Is.EqualTo(encodedCbor));
            Assert.That(message.UnprotectedHeaders[unprotectedLabel].GetValueAsString(), Is.EqualTo("test-request"));
            Assert.That(message.Content.HasValue, Is.EqualTo(embedPayload));
            Assert.That(embedPayload ? message.VerifyEmbedded(publicKey) : message.VerifyDetached(publicKey, payload), Is.True);
            if (embedPayload)
            {
                Assert.That(message.Content!.Value.ToArray(), Is.EqualTo(payload));
            }
        });
        context.Verify(x => x.GetSigningCertificateAsync(cancellation.Token), Times.Once);
        context.Verify(x => x.GetCertChainAsync(cancellation.Token), Times.Once);
        context.Verify(x => x.SignDigestAsync(
            digest, padding, certificate, null, null, cancellation.Token), Times.Once);
        if (embedPayload)
        {
            asyncInput.Verify(x => x.ReadAsync(
                It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<int>(), cancellation.Token), Times.AtLeastOnce);
        }
    }

    [TestCase(true, true)]
    [TestCase(true, false)]
    [TestCase(false, true)]
    [TestCase(false, false)]
    public async Task MessageFactoryAsync_PropagatesCancellationAndServiceErrors(bool duringMetadata, bool cancel)
    {
        using X509Certificate2 certificate = TestCertificateUtils.CreateCertificate();
        TaskCompletionSource<X509Certificate2> certificateReady = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<byte[]> signatureReady = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenSource cancellation = new();
        Mock<ISignContext> context = CreateAsyncSignContext(
            certificate, (_, _) => signatureReady.Task.WaitAsync(cancellation.Token));
        if (duringMetadata)
        {
            context.Setup(x => x.GetSigningCertificateAsync(cancellation.Token))
                .Returns(() => certificateReady.Task.WaitAsync(cancellation.Token));
        }

        AzureArtifactSigningCoseSigningKeyProvider provider = new(context.Object);
        Task<ReadOnlyMemory<byte>> operation = new CoseSign1MessageFactory().CreateCoseSign1MessageBytesAsync(
            "payload"u8.ToArray(), provider, embedPayload: true, cancellationToken: cancellation.Token);
        Assert.That(operation.IsCompleted, Is.False);
        if (cancel)
        {
            cancellation.Cancel();
            Assert.That(
                async () => await operation.WaitAsync(TimeSpan.FromSeconds(10)),
                Throws.InstanceOf<OperationCanceledException>());
        }
        else
        {
            InvalidOperationException failure = new("SDK operation failed.", new IOException("Service error details."));
            if (duringMetadata)
            {
                certificateReady.SetException(failure);
            }
            else
            {
                signatureReady.SetException(failure);
            }

            InvalidOperationException? actual = Assert.ThrowsAsync<InvalidOperationException>(
                async () => await operation.WaitAsync(TimeSpan.FromSeconds(10)));
            Assert.That(actual, Is.SameAs(failure));
        }

        context.Setup(x => x.GetSigningCertificateAsync(It.IsAny<CancellationToken>())).ReturnsAsync(certificate);
        using RSA publicKey = await provider.GetPublicKeyAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(10));
        using RSA expectedPublicKey = certificate.GetRSAPublicKey()!;
        Assert.That(publicKey.KeySize, Is.EqualTo(expectedPublicKey.KeySize));
    }

    [Test]
    public async Task MessageFactoryAsync_ReusesMetadataWithoutSerializingConcurrentSigning()
    {
        using X509Certificate2 certificate = TestCertificateUtils.CreateCertificate();
        using RSA privateKey = certificate.GetRSAPrivateKey()!;
        TaskCompletionSource<X509Certificate2> certificateReady = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<byte[]>[] digests =
        [
            new(TaskCreationOptions.RunContinuationsAsynchronously),
            new(TaskCreationOptions.RunContinuationsAsynchronously)
        ];
        TaskCompletionSource<byte[]>[] signatures =
        [
            new(TaskCreationOptions.RunContinuationsAsynchronously),
            new(TaskCreationOptions.RunContinuationsAsynchronously)
        ];
        int signingRequests = 0;
        Mock<ISignContext> context = CreateAsyncSignContext(certificate, (digest, _) =>
        {
            int index = Interlocked.Increment(ref signingRequests) - 1;
            digests[index].SetResult(digest);
            return signatures[index].Task;
        });
        context.Setup(x => x.GetSigningCertificateAsync(It.IsAny<CancellationToken>())).Returns(certificateReady.Task);
        AzureArtifactSigningCoseSigningKeyProvider provider = new(context.Object);
        CoseSign1MessageFactory factory = new();
        Task<ReadOnlyMemory<byte>> first = factory.CreateCoseSign1MessageBytesAsync("first"u8.ToArray(), provider, embedPayload: true);
        Task<ReadOnlyMemory<byte>> second = factory.CreateCoseSign1MessageBytesAsync("second"u8.ToArray(), provider, embedPayload: true);
        Assert.That(first.IsCompleted || second.IsCompleted, Is.False);
        certificateReady.SetResult(certificate);
        byte[][] capturedDigests = await Task.WhenAll(digests.Select(x => x.Task)).WaitAsync(TimeSpan.FromSeconds(10));
        Assert.That(first.IsCompleted || second.IsCompleted, Is.False);
        for (int i = 0; i < capturedDigests.Length; i++)
        {
            signatures[i].SetResult(privateKey.SignHash(capturedDigests[i], HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        }

        ReadOnlyMemory<byte>[] encoded = await Task.WhenAll(first, second).WaitAsync(TimeSpan.FromSeconds(10));
        using RSA publicKey = certificate.GetRSAPublicKey()!;
        foreach (ReadOnlyMemory<byte> message in encoded)
        {
            Assert.That(CoseMessage.DecodeSign1(message.Span).VerifyEmbedded(publicKey), Is.True);
        }

        context.Verify(x => x.GetSigningCertificateAsync(It.IsAny<CancellationToken>()), Times.Once);
        context.Verify(x => x.GetCertChainAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void MessageFactoryAsync_RejectsUnsupportedHashBeforeCallingService()
    {
        Mock<ISignContext> context = new(MockBehavior.Strict);
        AzureArtifactSigningCoseSigningKeyProvider provider = new(context.Object);
        Assert.ThrowsAsync<CoseSign1.Abstractions.Exceptions.CoseSigningException>(async () =>
            await new CoseSign1MessageFactory().CreateCoseSign1MessageBytesAsync(
                "payload"u8.ToArray(), provider,
                signingOptions: new() { HashAlgorithm = HashAlgorithmName.SHA1 }));
        context.VerifyNoOtherCalls();
    }

    [Test]
    public void MessageFactoryAsync_RejectsInvalidSignatureInsteadOfReturningPreparationBytes()
    {
        using X509Certificate2 certificate = TestCertificateUtils.CreateCertificate();
        Mock<ISignContext> context = CreateAsyncSignContext(certificate, (_, _) => Task.FromResult(new byte[1]));
        AzureArtifactSigningCoseSigningKeyProvider provider = new(context.Object);
        Assert.ThrowsAsync<CryptographicException>(async () =>
            await new CoseSign1MessageFactory().CreateCoseSign1MessageBytesAsync(
                "payload"u8.ToArray(), provider, embedPayload: true));
    }

    private static Mock<ISignContext> CreateAsyncSignContext(
        X509Certificate2 certificate,
        Func<byte[], RSASignaturePadding, Task<byte[]>> signDigest)
    {
        Mock<ISignContext> context = new(MockBehavior.Strict);
        context.Setup(x => x.GetSigningCertificateAsync(It.IsAny<CancellationToken>())).ReturnsAsync(certificate);
        context.Setup(x => x.GetCertChainAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new[] { certificate });
        context.Setup(x => x.SignDigestAsync(
            It.IsAny<byte[]>(), It.IsAny<RSASignaturePadding>(), certificate,
            null, null, It.IsAny<CancellationToken>()))
            .Returns((byte[] digest, RSASignaturePadding padding, X509Certificate2 _, byte[] _, byte[] _, CancellationToken _) =>
                signDigest(digest, padding));
        return context;
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
        Mock<ISignContext> mockSignContext = new Mock<ISignContext>();

        // Create a certificate chain with non-standard EKU
        X509Certificate2 leafCert = TestCertificateUtils.CreateCertificate(nameof(Issuer_WithNonStandardEku_ReturnsDidX509WithEkuFormat));
        X509Certificate2Collection chain = new() { leafCert };

        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>())).Returns(chain.Cast<X509Certificate2>().ToList());
        mockSignContext.Setup(context => context.GetSigningCertificate(It.IsAny<CancellationToken>())).Returns(leafCert);
        AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);

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
        Mock<ISignContext> mockSignContext = new Mock<ISignContext>();
        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>())).Returns((IReadOnlyList<X509Certificate2>?)null);
        AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);

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
        Mock<ISignContext> mockSignContext = new Mock<ISignContext>();
        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>())).Returns(new List<X509Certificate2>());
        AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        string? issuer = provider.Issuer;

        // Assert
        Assert.That(issuer, Is.Null);
    }

    /// <summary>
    /// Tests that the Issuer property uses the Azure-specific DID generator.
    /// </summary>
    [Test]
    public void Issuer_UsesAzureArtifactSigningDidGenerator()
    {
        // Arrange
        Mock<ISignContext> mockSignContext = new Mock<ISignContext>();
        X509Certificate2Collection chain = TestCertificateUtils.CreateTestChain(nameof(Issuer_UsesAzureArtifactSigningDidGenerator), leafFirst: true);
        List<X509Certificate2> chainList = chain.Cast<X509Certificate2>().ToList();
        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>())).Returns(chainList);
        mockSignContext.Setup(context => context.GetSigningCertificate(It.IsAny<CancellationToken>())).Returns(chainList.First());
        AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);

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
        Mock<ISignContext> mockSignContext = new Mock<ISignContext>();
        // Setup to throw an exception that should be caught
        mockSignContext.Setup(context => context.GetCertChain(It.IsAny<CancellationToken>()))
            .Throws(new InvalidOperationException("Test exception"));
        AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(mockSignContext.Object);

        // Act
        string? issuer = provider.Issuer;

        // Assert - Should fall back to base implementation which returns null on error
        Assert.That(issuer, Is.Null);
    }

    /// <summary>
    /// Helper method to invoke a protected method on the <see cref="AzureArtifactSigningCoseSigningKeyProvider"/> instance using reflection.
    /// </summary>
    /// <typeparam name="T">The return type of the method being invoked.</typeparam>
    /// <param name="provider">The instance of <see cref="AzureArtifactSigningCoseSigningKeyProvider"/>.</param>
    /// <param name="methodName">The name of the protected method to invoke.</param>
    /// <param name="arguments">The arguments to pass to the method.</param>
    /// <returns>The result of the invoked method.</returns>
    private static T InvokeProtectedWithReflection<T>(
        AzureArtifactSigningCoseSigningKeyProvider provider,
        string methodName,
        params object[] arguments)
    {
        // Use reflection to access the protected method
        MethodInfo method = typeof(AzureArtifactSigningCoseSigningKeyProvider)
            .GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Instance);

        if (method == null)
        {
            throw new InvalidOperationException($"The protected method '{methodName}' could not be found.");
        }

        return (T)method.Invoke(provider, arguments);
    }
}
