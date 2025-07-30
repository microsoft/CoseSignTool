// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests;

using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Extensions;

/// <summary>
/// Unit tests for the CoseSign1MessageExtensions methods that verify COSE_Sign1 messages with embedded certificates.
/// Covers all overloads and edge cases.
/// </summary>
public class CoseSign1MessageExtensionsTests
{
    /// <summary>
    /// Setup method
    /// </summary>
    [SetUp]
    public void Setup()
    {
    }
    
    private static CoseSign1MessageFactory CoseSign1MessageFactory = new CoseSign1MessageFactory();
    // Helper: Create a valid COSE_Sign1 message with embedded certificate and content
    private static CoseSign1Message CreateValidCoseSign1Message(byte[] content, X509Certificate2 cert, out byte[] coseBytes, bool detached = false)
    {
        X509Certificate2CoseSigningKeyProvider testObjRsa = new(cert);
        coseBytes = CoseSign1MessageFactory.CreateCoseSign1MessageBytes(content, testObjRsa, !detached).ToArray();
        return CoseMessage.DecodeSign1(coseBytes);
    }

    /// <summary>
    /// Helper to create a COSE_Sign1 message with NO embedded certificate (no x5c/x5t headers).
    /// </summary>
    private static CoseSign1Message CreateCoseSign1MessageWithoutCert(byte[] content)
    {
        using RSA rsa = RSA.Create(2048);

        CoseSigner coseSigner = new CoseSigner(rsa, RSASignaturePadding.Pkcs1, HashAlgorithmName.SHA256, new CoseHeaderMap(), new CoseHeaderMap());
        byte[] coseBytes = CoseSign1Message.SignEmbedded(content, coseSigner);
        return CoseMessage.DecodeSign1(coseBytes);
    }

    /// <summary>
    /// Test that VerifyEmbeddedWithCertificate returns true for a valid message with embedded certificate.
    /// </summary>
    [Test]
    public void VerifyEmbeddedWithCertificate_ValidMessage_ReturnsTrue()
    {
        // Arrange
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate();
        byte[] content = new byte[] { 1, 2, 3, 4 };
        CoseSign1Message msg = CreateValidCoseSign1Message(content, cert, out _);

        // Act
        bool result = msg.VerifyEmbeddedWithCertificate();

        // Assert
        Assert.That(result, Is.True, "Expected verification to succeed for valid message.");
    }

    /// <summary>
    /// Test that VerifyEmbeddedWithCertificate returns false if message is null.
    /// </summary>
    [Test]
    public void VerifyEmbeddedWithCertificate_NullMessage_ReturnsFalse()
    {
        // Arrange
        CoseSign1Message? msg = null!;

        // Act & Assert
        Assert.That(msg.VerifyEmbeddedWithCertificate(), Is.False, "Expected false when message is null.");
    }

    /// <summary>
    /// Test that VerifyEmbeddedWithCertificate returns false if no embedded certificate is present.
    /// </summary>
    [Test]
    public void VerifyEmbeddedWithCertificate_NoCertificate_ReturnsFalse()
    {
        // Arrange
        byte[] content = new byte[] { 1, 2, 3, 4 };
        CoseSign1Message msg = CreateCoseSign1MessageWithoutCert(content);
        // Act
        bool result = msg.VerifyEmbeddedWithCertificate();
        // Assert
        Assert.That(result, Is.False, "Expected verification to fail when no certificate is present.");
    }

    /// <summary>
    /// Test that VerifyDetachedWithCertificate (byte[]) returns true for valid message and content.
    /// </summary>
    [Test]
    public void VerifyDetachedWithCertificate_ByteArray_Valid_ReturnsTrue()
    {
        // Arrange
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate();
        byte[] content = new byte[] { 10, 20, 30 };
        CoseSign1Message msg = CreateValidCoseSign1Message(content, cert, out _, detached: true); // Detached
        // Act
        bool result = msg.VerifyDetachedWithCertificate(content);
        // Assert
        Assert.That(result, Is.True, "Expected verification to succeed for valid detached message.");
    }

    /// <summary>
    /// Test that VerifyDetachedWithCertificate (byte[]) returns false if message is null.
    /// </summary>
    [Test]
    public void VerifyDetachedWithCertificate_ByteArray_NullMessage_ReturnsFalse()
    {
        // Arrange
        CoseSign1Message msg = null!;
        byte[] content = new byte[] { 1, 2 };
        // Act & Assert
        Assert.That(msg.VerifyDetachedWithCertificate(content), Is.False, "Expected false when message is null.");
    }

    /// <summary>
    /// Test that VerifyDetachedWithCertificate (byte[]) returns false if content is null.
    /// </summary>
    [Test]
    public void VerifyDetachedWithCertificate_ByteArray_NullContent_ReturnsFalse()
    {
        // Arrange
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate();
        byte[] content = new byte[] { 1, 2 };
        CoseSign1Message msg = CreateValidCoseSign1Message(content, cert, out _, detached: true); // Detached
        // Act & Assert
        Assert.That(msg.VerifyDetachedWithCertificate((byte[])null!), Is.False, "Expected false when detached content is null.");
    }

    /// <summary>
    /// Test that VerifyDetachedWithCertificate (ReadOnlySpan) returns true for valid message and content.
    /// </summary>
    [Test]
    public void VerifyDetachedWithCertificate_ReadOnlySpan_Valid_ReturnsTrue()
    {
        // Arrange
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate();
        byte[] content = new byte[] { 42, 43, 44 };
        CoseSign1Message msg = CreateValidCoseSign1Message(content, cert, out _, detached: true); // Detached
        // Act
        bool result = msg.VerifyDetachedWithCertificate(content.AsSpan());
        // Assert
        Assert.That(result, Is.True, "Expected verification to succeed for valid detached message.");
    }

    /// <summary>
    /// Test that VerifyDetachedWithCertificate (ReadOnlySpan) returns false if content is empty.
    /// </summary>
    [Test]
    public void VerifyDetachedWithCertificate_ReadOnlySpan_EmptyContent_ReturnsFalse()
    {
        // Arrange
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate();
        byte[] contentCreate = new byte[] { 99, 100, 101 };
        byte[] contentVerify = Array.Empty<byte>();
        CoseSign1Message msg = CreateValidCoseSign1Message(contentCreate, cert, out _, detached: true); // Detached
        // Act
        bool result = msg.VerifyDetachedWithCertificate(contentVerify.AsSpan());
        // Assert
        Assert.That(result, Is.False, "Expected verification to fail for empty detached content.");
    }

    /// <summary>
    /// Test that VerifyDetachedWithCertificate (Stream) returns true for valid message and content.
    /// </summary>
    [Test]
    public void VerifyDetachedWithCertificate_Stream_Valid_ReturnsTrue()
    {
        // Arrange
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate();
        byte[] content = new byte[] { 99, 100, 101 };
        using MemoryStream stream = new MemoryStream(content);
        CoseSign1Message msg = CreateValidCoseSign1Message(content, cert, out _, detached: true); // Detached
        // Act
        bool result = msg.VerifyDetachedWithCertificate(stream);
        // Assert
        Assert.That(result, Is.True, "Expected verification to succeed for valid detached message.");
    }

    /// <summary>
    /// Test that VerifyDetachedWithCertificate (Stream) returns false if message is null.
    /// </summary>
    [Test]
    public void VerifyDetachedWithCertificate_Stream_NullMessage_ReturnsFalse()
    {
        // Arrange
        CoseSign1Message msg = null!;
        using MemoryStream stream = new MemoryStream(new byte[] { 1 });
        // Act & Assert
        Assert.That(msg.VerifyDetachedWithCertificate(stream), Is.False, "Expected false when message is null.");
    }

    /// <summary>
    /// Test that VerifyDetachedWithCertificate (Stream) returns false if stream is null.
    /// </summary>
    [Test]
    public void VerifyDetachedWithCertificate_Stream_NullStream_ReturnsFalse()
    {
        // Arrange
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate();
        byte[] content = new byte[] { 99, 100, 101 };
        CoseSign1Message msg = CreateValidCoseSign1Message(content, cert, out _, detached: true); // Detached
        // Act & Assert
        Assert.That(msg.VerifyDetachedWithCertificate((Stream)null!), Is.False, "Expected false when detached stream is null.");
    }

    /// <summary>
    /// Test that VerifyEmbeddedWithCertificate returns false for a detached message (Content is null).
    /// </summary>
    [Test]
    public void VerifyEmbeddedWithCertificate_DetachedMessage_ReturnsFalse()
    {
        // Arrange
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate();
        byte[] content = new byte[] { 1, 2, 3, 4 };
        byte[] coseBytes;
        // Create a detached message: pass null as content and detached=true
        CoseSign1Message msg = CreateValidCoseSign1Message(content, cert, out coseBytes, detached: true);

        // Act
        bool result = msg.VerifyEmbeddedWithCertificate();

        // Assert
        Assert.That(result, Is.False, "Expected verification to fail for detached message (no content).");
    }

    /// <summary>
    /// Test that VerifyDetachedWithCertificate (byte[]) returns false if no signing certificate is present.
    /// </summary>
    [Test]
    public void VerifyDetachedWithCertificate_ByteArray_NoCertificate_ReturnsFalse()
    {
        // Arrange
        byte[] content = new byte[] { 1, 2, 3 };
        CoseSign1Message msg = CreateCoseSign1MessageWithoutCert(content); // No cert in headers
        // Act
        bool result = msg.VerifyDetachedWithCertificate(content);
        // Assert
        Assert.That(result, Is.False, "Expected verification to fail when no signing certificate is present.");
    }

    /// <summary>
    /// Test that VerifyDetachedWithCertificate (ReadOnlySpan) returns false if no signing certificate is present.
    /// </summary>
    [Test]
    public void VerifyDetachedWithCertificate_ReadOnlySpan_NoCertificate_ReturnsFalse()
    {
        // Arrange
        byte[] content = new byte[] { 1, 2, 3 };
        CoseSign1Message msg = CreateCoseSign1MessageWithoutCert(content); // No cert in headers
        // Act
        bool result = msg.VerifyDetachedWithCertificate(content.AsSpan());
        // Assert
        Assert.That(result, Is.False, "Expected verification to fail when no signing certificate is present.");
    }

    /// <summary>
    /// Test that VerifyDetachedWithCertificate (Stream) returns false if no signing certificate is present.
    /// </summary>
    [Test]
    public void VerifyDetachedWithCertificate_Stream_NoCertificate_ReturnsFalse()
    {
        // Arrange
        byte[] content = new byte[] { 1, 2, 3 };
        using MemoryStream stream = new MemoryStream(content);
        CoseSign1Message msg = CreateCoseSign1MessageWithoutCert(content); // No cert in headers
        // Act
        bool result = msg.VerifyDetachedWithCertificate(stream);
        // Assert
        Assert.That(result, Is.False, "Expected verification to fail when no signing certificate is present.");
    }

    /// <summary>
    /// Test that VerifyDetachedWithCertificate (Stream) returns false if no signing certificate is present or public key is null.
    /// </summary>
    [Test]
    public void VerifyDetachedWithCertificate_Stream_NoCertificateOrPublicKey_ReturnsFalse()
    {
        // Arrange
        byte[] content = new byte[] { 1, 2, 3 };
        using MemoryStream stream = new MemoryStream(content);
        CoseSign1Message msg = CreateCoseSign1MessageWithoutCert(content); // No cert in headers
        // Act
        bool result = msg.VerifyDetachedWithCertificate(stream);
        // Assert
        Assert.That(result, Is.False, "Expected verification to fail when no signing certificate or public key is present.");
    }
}
