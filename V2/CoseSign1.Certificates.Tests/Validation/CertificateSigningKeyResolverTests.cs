// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Validation;
using CoseSign1.Tests.Common;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;

/// <summary>
/// Tests for CertificateSigningKeyResolver.
/// </summary>
[TestFixture]
[Category("Validation")]
public class CertificateSigningKeyResolverTests
{
    private X509Certificate2? _testCert;
    private X509Certificate2Collection? _testChain;

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        // Create a test chain with leaf, intermediate, and root
        _testChain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        _testCert = _testChain[0]; // Leaf certificate
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        if (_testChain != null)
        {
            foreach (var cert in _testChain)
            {
                cert?.Dispose();
            }
        }
    }

    #region Constructor Tests

    [Test]
    public void Constructor_Default_CreatesResolver()
    {
        // Act
        var resolver = new CertificateSigningKeyResolver();

        // Assert
        Assert.That(resolver, Is.Not.Null);
        Assert.That(resolver.ComponentName, Is.EqualTo(nameof(CertificateSigningKeyResolver)));
    }

    [Test]
    public void Constructor_WithProtectedLocation_CreatesResolver()
    {
        // Act
        var resolver = new CertificateSigningKeyResolver(CoseHeaderLocation.Protected);

        // Assert
        Assert.That(resolver, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithUnprotectedLocation_CreatesResolver()
    {
        // Act
        var resolver = new CertificateSigningKeyResolver(CoseHeaderLocation.Unprotected);

        // Assert
        Assert.That(resolver, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithLogger_CreatesResolver()
    {
        // Arrange
        var mockLogger = new Mock<ILogger<CertificateSigningKeyResolver>>().Object;

        // Act
        var resolver = new CertificateSigningKeyResolver(CoseHeaderLocation.Protected, mockLogger);

        // Assert
        Assert.That(resolver, Is.Not.Null);
    }

    #endregion

    #region Resolve Tests

    [Test]
    public void Resolve_WithNullMessage_ReturnsFailure()
    {
        // Arrange
        var resolver = new CertificateSigningKeyResolver();

        // Act
        var result = resolver.Resolve(null!);

        // Assert
        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo("NULL_INPUT"));
    }

    [Test]
    public void Resolve_WithMessageMissingX5Chain_ReturnsFailure()
    {
        // Arrange
        var resolver = new CertificateSigningKeyResolver();
        var message = CreateMinimalCoseMessage(); // No x5chain

        // Act
        var result = resolver.Resolve(message);

        // Assert
        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo("X5CHAIN_INVALID"));
    }

    [Test]
    public void Resolve_WithMessageMissingX5T_ReturnsFailure()
    {
        // Arrange
        var resolver = new CertificateSigningKeyResolver();
        var message = CreateCoseMessageWithX5ChainOnly(_testChain!);

        // Act
        var result = resolver.Resolve(message);

        // Assert
        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo("X5T_INVALID"));
    }

    [Test]
    public void Resolve_WithValidMessageProtectedHeaders_ReturnsSuccess()
    {
        // Arrange
        var resolver = new CertificateSigningKeyResolver(CoseHeaderLocation.Protected);
        var message = CreateValidCoseMessage(_testCert!, _testChain!, CoseHeaderLocation.Protected);

        // Act
        var result = resolver.Resolve(message);

        // Assert
        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.SigningKey, Is.Not.Null);
        Assert.That(result.SigningKey, Is.InstanceOf<X509CertificateSigningKey>());
    }

    [Test]
    public void Resolve_WithMismatchedThumbprint_ReturnsFailure()
    {
        // Arrange
        var resolver = new CertificateSigningKeyResolver();
        var differentCert = TestCertificateUtils.CreateCertificate("DifferentCert");
        var message = CreateCoseMessageWithMismatchedThumbprint(_testChain!, differentCert);

        // Act
        var result = resolver.Resolve(message);

        // Assert
        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo("SIGNING_CERT_NOT_FOUND"));

        differentCert.Dispose();
    }

    #endregion

    #region ResolveAsync Tests

    [Test]
    public async Task ResolveAsync_WithNullMessage_ReturnsFailure()
    {
        // Arrange
        var resolver = new CertificateSigningKeyResolver();

        // Act
        var result = await resolver.ResolveAsync(null!);

        // Assert
        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.ErrorCode, Is.EqualTo("NULL_INPUT"));
    }

    [Test]
    public async Task ResolveAsync_WithValidMessage_ReturnsSuccess()
    {
        // Arrange
        var resolver = new CertificateSigningKeyResolver(CoseHeaderLocation.Protected);
        var message = CreateValidCoseMessage(_testCert!, _testChain!, CoseHeaderLocation.Protected);

        // Act
        var result = await resolver.ResolveAsync(message);

        // Assert
        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.SigningKey, Is.Not.Null);
    }

    [Test]
    public void ResolveAsync_WithCancellation_ThrowsOperationCanceled()
    {
        // Arrange
        var resolver = new CertificateSigningKeyResolver();
        var message = CreateMinimalCoseMessage();
        var cts = new CancellationTokenSource();
        cts.Cancel();

        // Act & Assert
        Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await resolver.ResolveAsync(message, cts.Token));
    }

    #endregion

    #region ComponentName Tests

    [Test]
    public void ComponentName_ReturnsCorrectName()
    {
        // Arrange
        var resolver = new CertificateSigningKeyResolver();

        // Act & Assert
        Assert.That(resolver.ComponentName, Is.EqualTo(nameof(CertificateSigningKeyResolver)));
    }

    #endregion

    #region Helper Methods

    private static CoseSign1Message CreateMinimalCoseMessage()
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

    private static CoseSign1Message CreateCoseMessageWithX5ChainOnly(X509Certificate2Collection chain)
    {
        // Create protected header with x5chain only (no x5t)
        var protectedWriter = new CborWriter();
        protectedWriter.WriteStartMap(1);
        protectedWriter.WriteInt32(33); // x5chain label
        protectedWriter.WriteStartArray(chain.Count);
        foreach (var cert in chain)
        {
            protectedWriter.WriteByteString(cert.RawData);
        }
        protectedWriter.WriteEndArray();
        protectedWriter.WriteEndMap();
        var protectedBytes = protectedWriter.Encode();

        var msgWriter = new CborWriter();
        msgWriter.WriteStartArray(4);
        msgWriter.WriteByteString(protectedBytes);
        msgWriter.WriteStartMap(0);
        msgWriter.WriteEndMap();
        msgWriter.WriteByteString(Array.Empty<byte>());
        msgWriter.WriteByteString(Array.Empty<byte>());
        msgWriter.WriteEndArray();
        return CoseMessage.DecodeSign1(msgWriter.Encode());
    }

    private static CoseSign1Message CreateValidCoseMessage(
        X509Certificate2 signingCert,
        X509Certificate2Collection chain,
        CoseHeaderLocation location)
    {
        // Create thumbprint using SHA256
        using var sha256 = SHA256.Create();
        var thumbprint = sha256.ComputeHash(signingCert.RawData);

        // Create protected header with x5chain and x5t
        var protectedWriter = new CborWriter();
        protectedWriter.WriteStartMap(2);

        // x5chain (label 33)
        protectedWriter.WriteInt32(33);
        protectedWriter.WriteStartArray(chain.Count);
        foreach (var cert in chain)
        {
            protectedWriter.WriteByteString(cert.RawData);
        }
        protectedWriter.WriteEndArray();

        // x5t (label 34) - [alg, thumbprint]
        protectedWriter.WriteInt32(34);
        protectedWriter.WriteStartArray(2);
        protectedWriter.WriteInt32(-16); // SHA-256
        protectedWriter.WriteByteString(thumbprint);
        protectedWriter.WriteEndArray();

        protectedWriter.WriteEndMap();
        var protectedBytes = protectedWriter.Encode();

        var msgWriter = new CborWriter();
        msgWriter.WriteStartArray(4);
        msgWriter.WriteByteString(protectedBytes);
        msgWriter.WriteStartMap(0);
        msgWriter.WriteEndMap();
        msgWriter.WriteByteString(Array.Empty<byte>());
        msgWriter.WriteByteString(Array.Empty<byte>());
        msgWriter.WriteEndArray();
        return CoseMessage.DecodeSign1(msgWriter.Encode());
    }

    private static CoseSign1Message CreateCoseMessageWithMismatchedThumbprint(
        X509Certificate2Collection chain,
        X509Certificate2 differentCert)
    {
        // Use thumbprint from a different certificate
        using var sha256 = SHA256.Create();
        var thumbprint = sha256.ComputeHash(differentCert.RawData);

        var protectedWriter = new CborWriter();
        protectedWriter.WriteStartMap(2);

        // x5chain with the chain certs
        protectedWriter.WriteInt32(33);
        protectedWriter.WriteStartArray(chain.Count);
        foreach (var cert in chain)
        {
            protectedWriter.WriteByteString(cert.RawData);
        }
        protectedWriter.WriteEndArray();

        // x5t with different cert's thumbprint
        protectedWriter.WriteInt32(34);
        protectedWriter.WriteStartArray(2);
        protectedWriter.WriteInt32(-16);
        protectedWriter.WriteByteString(thumbprint);
        protectedWriter.WriteEndArray();

        protectedWriter.WriteEndMap();
        var protectedBytes = protectedWriter.Encode();

        var msgWriter = new CborWriter();
        msgWriter.WriteStartArray(4);
        msgWriter.WriteByteString(protectedBytes);
        msgWriter.WriteStartMap(0);
        msgWriter.WriteEndMap();
        msgWriter.WriteByteString(Array.Empty<byte>());
        msgWriter.WriteByteString(Array.Empty<byte>());
        msgWriter.WriteEndArray();
        return CoseMessage.DecodeSign1(msgWriter.Encode());
    }

    #endregion
}
