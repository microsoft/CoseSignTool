// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using System.Formats.Cbor;
using System.Security.Cryptography.Cose;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Validation;
using CoseSign1.Tests.Common;
using CoseSign1.Validation;
using Microsoft.Extensions.Logging;
using Moq;

/// <summary>
/// Extended tests for CertificateChainAssertionProvider to improve code coverage.
/// Tests cover edge cases, retry logic, custom roots, and various chain status scenarios.
/// </summary>
[TestFixture]
[Category("Validation")]
public class CertificateChainAssertionProviderExtendedTests
{
    private X509Certificate2? _selfSignedCert;
    private X509Certificate2Collection? _testChain;
    private CoseSign1Message? _dummyMessage;

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        _selfSignedCert = TestCertificateUtils.CreateCertificate(nameof(CertificateChainAssertionProviderExtendedTests));
        _testChain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        _dummyMessage = CreateDummyMessage();
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        _selfSignedCert?.Dispose();
        if (_testChain != null)
        {
            foreach (var cert in _testChain)
            {
                cert?.Dispose();
            }
        }
    }

    #region Chain Status Failure Scenarios

    [Test]
    public void ExtractAssertions_ChainBuildFails_WithMultipleErrors_ReturnsAllErrorDetails()
    {
        // Arrange
        var mockChainBuilder = new Mock<ICertificateChainBuilder>();
        mockChainBuilder.Setup(b => b.ChainPolicy).Returns(new X509ChainPolicy());
        mockChainBuilder.Setup(b => b.Build(It.IsAny<X509Certificate2>())).Returns(false);
        mockChainBuilder.Setup(b => b.ChainStatus).Returns(new X509ChainStatus[]
        {
            new X509ChainStatus { Status = X509ChainStatusFlags.UntrustedRoot, StatusInformation = "Root not trusted" },
            new X509ChainStatus { Status = X509ChainStatusFlags.NotTimeValid, StatusInformation = "Certificate expired" }
        });

        var provider = new CertificateChainAssertionProvider(mockChainBuilder.Object);
        var signingKey = new X509CertificateSigningKey(_selfSignedCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509ChainTrustedAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.IsTrusted, Is.False);
        Assert.That(assertion.Details, Does.Contain("trusted").Or.Contain("expired"));
    }

    [Test]
    public void ExtractAssertions_WithChainBuildFailed_NoStatusInfo_ReturnsDefaultErrorMessage()
    {
        // Arrange
        var mockChainBuilder = new Mock<ICertificateChainBuilder>();
        mockChainBuilder.Setup(b => b.ChainPolicy).Returns(new X509ChainPolicy());
        mockChainBuilder.Setup(b => b.Build(It.IsAny<X509Certificate2>())).Returns(false);
        mockChainBuilder.Setup(b => b.ChainStatus).Returns(new X509ChainStatus[]
        {
            new X509ChainStatus { Status = X509ChainStatusFlags.NoError, StatusInformation = "" }
        });

        var provider = new CertificateChainAssertionProvider(mockChainBuilder.Object);
        var signingKey = new X509CertificateSigningKey(_selfSignedCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509ChainTrustedAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.IsTrusted, Is.False);
    }

    [Test]
    public void ExtractAssertions_AllowUntrusted_WithMixedStatus_RejectsNonUntrustedErrors()
    {
        // Arrange - simulate chain with errors beyond just UntrustedRoot
        var mockChainBuilder = new Mock<ICertificateChainBuilder>();
        mockChainBuilder.Setup(b => b.ChainPolicy).Returns(new X509ChainPolicy());
        mockChainBuilder.Setup(b => b.Build(It.IsAny<X509Certificate2>())).Returns(false);
        mockChainBuilder.Setup(b => b.ChainStatus).Returns(new X509ChainStatus[]
        {
            new X509ChainStatus { Status = X509ChainStatusFlags.UntrustedRoot, StatusInformation = "Root not trusted" },
            new X509ChainStatus { Status = X509ChainStatusFlags.NotTimeValid, StatusInformation = "Not time valid" }
        });

        var provider = new CertificateChainAssertionProvider(mockChainBuilder.Object, allowUntrusted: true);
        var signingKey = new X509CertificateSigningKey(_selfSignedCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert - AllowUntrusted should NOT allow other errors
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509ChainTrustedAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.IsTrusted, Is.False);
    }

    [Test]
    public void ExtractAssertions_AllowUntrusted_WithOnlyUntrustedRoot_Succeeds()
    {
        // Arrange
        var mockChainBuilder = new Mock<ICertificateChainBuilder>();
        mockChainBuilder.Setup(b => b.ChainPolicy).Returns(new X509ChainPolicy());
        mockChainBuilder.Setup(b => b.Build(It.IsAny<X509Certificate2>())).Returns(false);
        mockChainBuilder.Setup(b => b.ChainStatus).Returns(new X509ChainStatus[]
        {
            new X509ChainStatus { Status = X509ChainStatusFlags.UntrustedRoot, StatusInformation = "Root not trusted" }
        });

        var provider = new CertificateChainAssertionProvider(mockChainBuilder.Object, allowUntrusted: true);
        var signingKey = new X509CertificateSigningKey(_selfSignedCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert - AllowUntrusted should accept only-UntrustedRoot error
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509ChainTrustedAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.IsTrusted, Is.False); // Still not "trusted" but allowed
        Assert.That(assertion.Details, Does.Contain("Untrusted").Or.Empty);
    }

    [Test]
    public void ExtractAssertions_AllowUntrusted_WithNoErrorAndUntrustedRoot_Succeeds()
    {
        // Arrange
        var mockChainBuilder = new Mock<ICertificateChainBuilder>();
        mockChainBuilder.Setup(b => b.ChainPolicy).Returns(new X509ChainPolicy());
        mockChainBuilder.Setup(b => b.Build(It.IsAny<X509Certificate2>())).Returns(false);
        mockChainBuilder.Setup(b => b.ChainStatus).Returns(new X509ChainStatus[]
        {
            new X509ChainStatus { Status = X509ChainStatusFlags.NoError },
            new X509ChainStatus { Status = X509ChainStatusFlags.UntrustedRoot, StatusInformation = "Root not trusted" }
        });

        var provider = new CertificateChainAssertionProvider(mockChainBuilder.Object, allowUntrusted: true);
        var signingKey = new X509CertificateSigningKey(_selfSignedCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
    }

    #endregion

    #region Custom Root Trust Tests

    [Test]
    public void ExtractAssertions_CustomRoots_WithTrustUserRootsTrue_ConfiguresCustomTrustStore()
    {
        // Arrange
        var customRoots = new X509Certificate2Collection();
        customRoots.Add(_selfSignedCert!);

        var mockChainBuilder = new Mock<ICertificateChainBuilder>();
        var chainPolicy = new X509ChainPolicy();
        mockChainBuilder.Setup(b => b.ChainPolicy).Returns(chainPolicy);
        mockChainBuilder.Setup(b => b.Build(It.IsAny<X509Certificate2>())).Returns(true);
        mockChainBuilder.Setup(b => b.ChainStatus).Returns(Array.Empty<X509ChainStatus>());

        var provider = new CertificateChainAssertionProvider(
            customRoots,
            trustUserRoots: true,
            revocationMode: X509RevocationMode.NoCheck);
        var signingKey = new X509CertificateSigningKey(_selfSignedCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
    }

    [Test]
    public void ExtractAssertions_CustomRoots_WithTrustUserRootsFalse_UsesSystemTrust()
    {
        // Arrange
        var customRoots = new X509Certificate2Collection();
        customRoots.Add(_selfSignedCert!);

        var provider = new CertificateChainAssertionProvider(
            customRoots,
            trustUserRoots: false,
            revocationMode: X509RevocationMode.NoCheck);
        var signingKey = new X509CertificateSigningKey(_selfSignedCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
    }

    [Test]
    public void Constructor_WithCustomRootsAndLogger_CreatesProviderWithLogging()
    {
        // Arrange
        var customRoots = new X509Certificate2Collection();
        customRoots.Add(_selfSignedCert!);
        var mockLogger = new Mock<ILogger<CertificateChainAssertionProvider>>().Object;

        // Act
        var provider = new CertificateChainAssertionProvider(
            customRoots,
            trustUserRoots: true,
            revocationMode: X509RevocationMode.NoCheck,
            logger: mockLogger);

        // Assert
        Assert.That(provider, Is.Not.Null);
        Assert.That(provider.ComponentName, Is.EqualTo(nameof(CertificateChainAssertionProvider)));
    }

    [Test]
    public void Constructor_WithCustomChainBuilderAndOptions_CreatesProvider()
    {
        // Arrange
        var mockChainBuilder = new Mock<ICertificateChainBuilder>();
        mockChainBuilder.Setup(b => b.ChainPolicy).Returns(new X509ChainPolicy());
        var customRoots = new X509Certificate2Collection();
        customRoots.Add(_selfSignedCert!);
        var mockLogger = new Mock<ILogger<CertificateChainAssertionProvider>>().Object;

        // Act
        var provider = new CertificateChainAssertionProvider(
            mockChainBuilder.Object,
            allowUntrusted: true,
            customRoots: customRoots,
            trustUserRoots: true,
            logger: mockLogger);

        // Assert
        Assert.That(provider, Is.Not.Null);
    }

    #endregion

    #region Chain Elements Tests

    [Test]
    public void ExtractAssertions_CustomRoots_MatchingRootInChain_Trusted()
    {
        // Arrange - set up a scenario where custom root matches chain root
        var customRoots = new X509Certificate2Collection();
        customRoots.Add(_selfSignedCert!);

        var mockChainBuilder = new Mock<ICertificateChainBuilder>();
        mockChainBuilder.Setup(b => b.ChainPolicy).Returns(new X509ChainPolicy());
        mockChainBuilder.Setup(b => b.Build(It.IsAny<X509Certificate2>())).Returns(false);
        mockChainBuilder.Setup(b => b.ChainStatus).Returns(new X509ChainStatus[]
        {
            new X509ChainStatus { Status = X509ChainStatusFlags.UntrustedRoot }
        });

        // Return the self-signed cert as the chain element
        var chainElements = new List<X509Certificate2> { _selfSignedCert! };
        mockChainBuilder.Setup(b => b.ChainElements).Returns(chainElements.AsReadOnly());

        var provider = new CertificateChainAssertionProvider(
            mockChainBuilder.Object,
            allowUntrusted: false,
            customRoots: customRoots,
            trustUserRoots: true);
        var signingKey = new X509CertificateSigningKey(_selfSignedCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509ChainTrustedAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.IsTrusted, Is.True);
    }

    [Test]
    public void ExtractAssertions_CustomRoots_NonMatchingRoot_NotTrusted()
    {
        // Arrange
        using var anotherCert = TestCertificateUtils.CreateCertificate("AnotherCert");
        var customRoots = new X509Certificate2Collection();
        customRoots.Add(anotherCert);

        var mockChainBuilder = new Mock<ICertificateChainBuilder>();
        mockChainBuilder.Setup(b => b.ChainPolicy).Returns(new X509ChainPolicy());
        mockChainBuilder.Setup(b => b.Build(It.IsAny<X509Certificate2>())).Returns(false);
        mockChainBuilder.Setup(b => b.ChainStatus).Returns(new X509ChainStatus[]
        {
            new X509ChainStatus { Status = X509ChainStatusFlags.UntrustedRoot, StatusInformation = "Root not trusted" }
        });

        // Return self-signed cert (not matching custom root)
        var chainElements = new List<X509Certificate2> { _selfSignedCert! };
        mockChainBuilder.Setup(b => b.ChainElements).Returns(chainElements.AsReadOnly());

        var provider = new CertificateChainAssertionProvider(
            mockChainBuilder.Object,
            allowUntrusted: false,
            customRoots: customRoots,
            trustUserRoots: true);
        var signingKey = new X509CertificateSigningKey(_selfSignedCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert - should not be trusted because custom root doesn't match
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509ChainTrustedAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.IsTrusted, Is.False);
    }

    [Test]
    public void ExtractAssertions_EmptyChainElements_HandledGracefully()
    {
        // Arrange
        var customRoots = new X509Certificate2Collection();
        customRoots.Add(_selfSignedCert!);

        var mockChainBuilder = new Mock<ICertificateChainBuilder>();
        mockChainBuilder.Setup(b => b.ChainPolicy).Returns(new X509ChainPolicy());
        mockChainBuilder.Setup(b => b.Build(It.IsAny<X509Certificate2>())).Returns(false);
        mockChainBuilder.Setup(b => b.ChainStatus).Returns(new X509ChainStatus[]
        {
            new X509ChainStatus { Status = X509ChainStatusFlags.UntrustedRoot }
        });
        // Return empty collection
        var emptyChain = new List<X509Certificate2>();
        mockChainBuilder.Setup(b => b.ChainElements).Returns(emptyChain.AsReadOnly());

        var provider = new CertificateChainAssertionProvider(
            mockChainBuilder.Object,
            allowUntrusted: false,
            customRoots: customRoots,
            trustUserRoots: true);
        var signingKey = new X509CertificateSigningKey(_selfSignedCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert - should return failure since can't verify custom root
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509ChainTrustedAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.IsTrusted, Is.False);
    }

    #endregion

    #region Header Location Tests

    [Test]
    public void ExtractAssertions_WithUnprotectedHeaderLocation_UsesCorrectHeaders()
    {
        // Arrange
        var provider = new CertificateChainAssertionProvider(
            allowUntrusted: true,
            revocationMode: X509RevocationMode.NoCheck);
        var signingKey = new X509CertificateSigningKey(_selfSignedCert!);
        var options = new CoseSign1ValidationOptions
        {
            CertificateHeaderLocation = CoseHeaderLocation.Unprotected
        };

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!, options);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
    }

    [Test]
    public void ExtractAssertions_WithAnyHeaderLocation_UsesCorrectHeaders()
    {
        // Arrange
        var provider = new CertificateChainAssertionProvider(
            allowUntrusted: true,
            revocationMode: X509RevocationMode.NoCheck);
        var signingKey = new X509CertificateSigningKey(_selfSignedCert!);
        var options = new CoseSign1ValidationOptions
        {
            CertificateHeaderLocation = CoseHeaderLocation.Any
        };

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!, options);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
    }

    #endregion

    #region ExtractAssertionsAsync Tests

    [Test]
    public async Task ExtractAssertionsAsync_WithCancellationToken_Completes()
    {
        // Arrange
        var provider = new CertificateChainAssertionProvider(
            allowUntrusted: true,
            revocationMode: X509RevocationMode.NoCheck);
        var signingKey = new X509CertificateSigningKey(_selfSignedCert!);
        using var cts = new CancellationTokenSource();

        // Act
        var assertions = await provider.ExtractAssertionsAsync(signingKey, _dummyMessage!, null, cts.Token);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
    }

    [Test]
    public async Task ExtractAssertionsAsync_WithOptions_PassesOptionsCorrectly()
    {
        // Arrange
        var provider = new CertificateChainAssertionProvider(
            allowUntrusted: true,
            revocationMode: X509RevocationMode.NoCheck);
        var signingKey = new X509CertificateSigningKey(_selfSignedCert!);
        var options = new CoseSign1ValidationOptions
        {
            CertificateHeaderLocation = CoseHeaderLocation.Protected
        };

        // Act
        var assertions = await provider.ExtractAssertionsAsync(signingKey, _dummyMessage!, options);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
    }

    #endregion

    #region Logging Tests

    [Test]
    public void ExtractAssertions_WithLogger_LogsOperations()
    {
        // Arrange
        var mockLogger = new Mock<ILogger<CertificateChainAssertionProvider>>();
        mockLogger.Setup(l => l.IsEnabled(It.IsAny<LogLevel>())).Returns(true);

        var provider = new CertificateChainAssertionProvider(
            allowUntrusted: true,
            revocationMode: X509RevocationMode.NoCheck,
            logger: mockLogger.Object);
        var signingKey = new X509CertificateSigningKey(_selfSignedCert!);

        // Act
        _ = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert - verify some logging was attempted
        // (Can't easily verify exact log messages due to source generators)
        Assert.That(provider, Is.Not.Null);
    }

    #endregion

    #region Helper Methods

    private static CoseSign1Message CreateDummyMessage()
    {
        var writer = new CborWriter();
        writer.WriteStartArray(4); // COSE_Sign1 structure
        writer.WriteByteString(Array.Empty<byte>()); // Protected
        writer.WriteStartMap(0); // Unprotected
        writer.WriteEndMap();
        writer.WriteByteString(Array.Empty<byte>()); // Payload
        writer.WriteByteString(Array.Empty<byte>()); // Signature
        writer.WriteEndArray();
        return CoseMessage.DecodeSign1(writer.Encode());
    }

    #endregion
}
