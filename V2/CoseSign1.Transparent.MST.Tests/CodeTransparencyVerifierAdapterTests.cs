// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using Azure.Security.CodeTransparency;

namespace CoseSign1.Transparent.MST.Tests;

[TestFixture]
public class CodeTransparencyVerifierAdapterTests
{
    [Test]
    public void Default_ReturnsSingletonInstance()
    {
        // Act
        var instance1 = CodeTransparencyVerifierAdapter.Default;
        var instance2 = CodeTransparencyVerifierAdapter.Default;

        // Assert
        Assert.That(instance1, Is.Not.Null);
        Assert.That(instance2, Is.Not.Null);
        Assert.That(instance1, Is.SameAs(instance2));
    }

    [Test]
    public void Default_ImplementsInterface()
    {
        // Act
        var adapter = CodeTransparencyVerifierAdapter.Default;

        // Assert
        Assert.That(adapter, Is.InstanceOf<ICodeTransparencyVerifier>());
    }

    [Test]
    public void Constructor_CreatesInstance()
    {
        // Act
        var adapter = new CodeTransparencyVerifierAdapter();

        // Assert
        Assert.That(adapter, Is.Not.Null);
        Assert.That(adapter, Is.InstanceOf<ICodeTransparencyVerifier>());
    }

    [Test]
    public void VerifyTransparentStatement_WithNullBytes_ThrowsArgumentNullException()
    {
        // Arrange
        var adapter = new CodeTransparencyVerifierAdapter();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            adapter.VerifyTransparentStatement(null!, null, null));
    }

    [Test]
    public void VerifyTransparentStatement_WithEmptyBytes_ThrowsCryptographicException()
    {
        // Arrange
        var adapter = new CodeTransparencyVerifierAdapter();
        var emptyBytes = Array.Empty<byte>();

        // Act & Assert - Empty bytes will fail COSE decoding
        Assert.Throws<CryptographicException>(() =>
            adapter.VerifyTransparentStatement(emptyBytes, null, null));
    }

    [Test]
    public void VerifyTransparentStatement_WithInvalidCose_ThrowsCryptographicException()
    {
        // Arrange
        var adapter = new CodeTransparencyVerifierAdapter();
        var invalidBytes = new byte[] { 0x00, 0x01, 0x02, 0x03 };

        // Act & Assert - Invalid COSE will fail decoding
        Assert.Throws<CryptographicException>(() =>
            adapter.VerifyTransparentStatement(invalidBytes, null, null));
    }

    [Test]
    public void VerifyTransparentStatement_WithOptions_AcceptsParameters()
    {
        // Arrange
        var adapter = new CodeTransparencyVerifierAdapter();
        var verificationOptions = new CodeTransparencyVerificationOptions();
        var clientOptions = new CodeTransparencyClientOptions();
        var invalidBytes = new byte[] { 0x00, 0x01, 0x02 };

        // Act & Assert - Will still fail due to invalid data, but verifies parameter passing
        Assert.Throws<CryptographicException>(() =>
            adapter.VerifyTransparentStatement(invalidBytes, verificationOptions, clientOptions));
    }
}
