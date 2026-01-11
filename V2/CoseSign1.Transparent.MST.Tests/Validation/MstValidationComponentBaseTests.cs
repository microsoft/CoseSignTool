// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests.Validation;

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Transparent.MST.Validation;
using CoseSign1.Tests.Common;
using CoseSign1.Validation;
using CoseSign1.Validation.Abstractions;
using NUnit.Framework;

/// <summary>
/// Tests for <see cref="MstValidationComponentBase"/>.
/// </summary>
[TestFixture]
[Category("MST")]
[Category("Validation")]
public class MstValidationComponentBaseTests
{
    private static X509Certificate2 CreateTestCert() =>
        TestCertificateUtils.CreateCertificate("MstBaseTestCert", useEcc: true);

    #region RequireMstReceipt Property Tests

    [Test]
    public void DefaultRequireMstReceipt_IsFalse()
    {
        // Arrange
        var testComponent = new TestMstValidationComponent();

        // Act & Assert
        Assert.That(testComponent.RequireMstReceiptPublic, Is.False);
    }

    [Test]
    public void OverriddenRequireMstReceipt_ReturnsTrue()
    {
        // Arrange
        var testComponent = new TestMstValidationComponentRequiringReceipt();

        // Act & Assert - verify that the derived class correctly overrides the property
        Assert.That(testComponent.TestRequireMstReceipt, Is.True);
    }

    #endregion

    #region ComputeApplicability Tests

    [Test]
    public void ComputeApplicability_WithNullMessage_WhenReceiptNotRequired_ReturnsTrue()
    {
        // Arrange
        var testComponent = new TestMstValidationComponent();

        // Act
        var result = testComponent.ComputeApplicabilityPublic(null!, null);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void ComputeApplicability_WithNullMessage_WhenReceiptRequired_ReturnsFalse()
    {
        // Arrange
        var testComponent = new TestMstValidationComponentRequiringReceipt();

        // Act
        var result = testComponent.ComputeApplicabilityPublic(null!, null);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void ComputeApplicability_WithMessageWithoutReceipt_WhenReceiptNotRequired_ReturnsTrue()
    {
        // Arrange
        var testComponent = new TestMstValidationComponent();
        using var cert = CreateTestCert();
        var message = CreateTestSignedMessage(cert, "test payload");

        // Act
        var result = testComponent.ComputeApplicabilityPublic(message, null);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void ComputeApplicability_WithMessageWithoutReceipt_WhenReceiptRequired_ReturnsFalse()
    {
        // Arrange
        var testComponent = new TestMstValidationComponentRequiringReceipt();
        using var cert = CreateTestCert();
        var message = CreateTestSignedMessage(cert, "test payload");

        // Act
        var result = testComponent.ComputeApplicabilityPublic(message, null);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void ComputeApplicability_WithMessageWithReceipt_WhenReceiptRequired_ReturnsTrue()
    {
        // Arrange
        var testComponent = new TestMstValidationComponentRequiringReceipt();
        using var cert = CreateTestCert();
        var message = CreateMessageWithMstReceipt(cert);

        // Act
        var result = testComponent.ComputeApplicabilityPublic(message, null);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void ComputeApplicability_WithMessageWithReceipt_WhenReceiptNotRequired_ReturnsTrue()
    {
        // Arrange
        var testComponent = new TestMstValidationComponent();
        using var cert = CreateTestCert();
        var message = CreateMessageWithMstReceipt(cert);

        // Act
        var result = testComponent.ComputeApplicabilityPublic(message, null);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void ComputeApplicability_WithOptions_DoesNotAffectResult()
    {
        // Arrange
        var testComponent = new TestMstValidationComponent();
        using var cert = CreateTestCert();
        var message = CreateTestSignedMessage(cert, "test payload");
        var options = new CoseSign1ValidationOptions();

        // Act
        var result = testComponent.ComputeApplicabilityPublic(message, options);

        // Assert
        Assert.That(result, Is.True);
    }

    #endregion

    #region HasMstReceipt Tests

    [Test]
    public void HasMstReceipt_WithNullMessage_ReturnsFalse()
    {
        // Act
        var result = TestMstValidationComponent.HasMstReceiptPublic(null);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void HasMstReceipt_WithMessageWithoutReceipt_ReturnsFalse()
    {
        // Arrange
        using var cert = CreateTestCert();
        var message = CreateTestSignedMessage(cert, "test payload");

        // Act
        var result = TestMstValidationComponent.HasMstReceiptPublic(message);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void HasMstReceipt_WithMessageWithReceipt_ReturnsTrue()
    {
        // Arrange
        using var cert = CreateTestCert();
        var message = CreateMessageWithMstReceipt(cert);

        // Act
        var result = TestMstValidationComponent.HasMstReceiptPublic(message);

        // Assert
        Assert.That(result, Is.True);
    }

    #endregion

    #region IsApplicableTo Integration Tests

    [Test]
    public void IsApplicableTo_WhenBaseComponentApplicabilityInvoked_UsesComputeApplicability()
    {
        // Arrange
        var testComponent = new TestMstValidationComponent();
        using var cert = CreateTestCert();
        var message = CreateTestSignedMessage(cert, "test payload");

        // Act
        var isApplicable = testComponent.IsApplicableTo(message);

        // Assert
        Assert.That(isApplicable, Is.True);
    }

    [Test]
    public void IsApplicableTo_WithRequiredReceipt_ChecksForReceipt()
    {
        // Arrange
        var testComponent = new TestMstValidationComponentRequiringReceipt();
        using var cert = CreateTestCert();
        var messageWithoutReceipt = CreateTestSignedMessage(cert, "test payload");
        var messageWithReceipt = CreateMessageWithMstReceipt(cert);

        // Act & Assert
        Assert.That(testComponent.IsApplicableTo(messageWithoutReceipt), Is.False);
        Assert.That(testComponent.IsApplicableTo(messageWithReceipt), Is.True);
    }

    #endregion

    #region Inheritance Tests

    [Test]
    public void DerivedClass_ExtendsValidationComponentBase()
    {
        // Arrange
        var testComponent = new TestMstValidationComponent();

        // Assert
        Assert.That(testComponent, Is.InstanceOf<ValidationComponentBase>());
    }

    [Test]
    public void DerivedClass_HasComponentName()
    {
        // Arrange
        var testComponent = new TestMstValidationComponent();

        // Assert
        Assert.That(testComponent.ComponentName, Is.EqualTo("TestMstValidationComponent"));
    }

    #endregion

    #region Test Helper Classes

    /// <summary>
    /// Test implementation that does not require MST receipt (default behavior).
    /// </summary>
    private class TestMstValidationComponent : MstValidationComponentBase
    {
        public override string ComponentName => nameof(TestMstValidationComponent);

        public bool RequireMstReceiptPublic => base.RequireMstReceipt;

        public bool ComputeApplicabilityPublic(CoseSign1Message message, CoseSign1ValidationOptions? options)
        {
            return base.ComputeApplicability(message, options);
        }

        public static bool HasMstReceiptPublic(CoseSign1Message? message)
        {
            return HasMstReceipt(message);
        }
    }

    /// <summary>
    /// Test implementation that requires MST receipt.
    /// </summary>
    private class TestMstValidationComponentRequiringReceipt : MstValidationComponentBase
    {
        public override string ComponentName => nameof(TestMstValidationComponentRequiringReceipt);

        protected override bool RequireMstReceipt => true;

        public bool TestRequireMstReceipt => RequireMstReceipt;

        public bool ComputeApplicabilityPublic(CoseSign1Message message, CoseSign1ValidationOptions? options)
        {
            return base.ComputeApplicability(message, options);
        }
    }

    #endregion

    #region Helper Methods

    private const CborTag CoseSign1Tag = (CborTag)18;

    /// <summary>
    /// Creates a basic CoseSign1Message without MST receipt.
    /// </summary>
    private static CoseSign1Message CreateTestSignedMessage(X509Certificate2 cert, string payload)
    {
        var payloadBytes = System.Text.Encoding.UTF8.GetBytes(payload);
        using var key = cert.GetECDsaPrivateKey()!;
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var signedBytes = CoseSign1Message.SignEmbedded(payloadBytes, signer);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    /// <summary>
    /// Creates a CoseSign1Message with an MST receipt in unprotected headers.
    /// </summary>
    private static CoseSign1Message CreateMessageWithMstReceipt(X509Certificate2 cert)
    {
        // Create a minimal MST receipt (COSE_Sign1 structure for label 394)
        var receiptWriter = new CborWriter();
        receiptWriter.WriteStartArray(4);  // COSE_Sign1: [protected, unprotected, payload, signature]
        receiptWriter.WriteByteString(new byte[] { 0xA0 });  // Empty protected header map
        receiptWriter.WriteStartMap(0);  // Empty unprotected headers
        receiptWriter.WriteEndMap();
        receiptWriter.WriteNull();  // No payload
        receiptWriter.WriteByteString(new byte[64]);  // Dummy signature
        receiptWriter.WriteEndArray();
        var receiptBytes = receiptWriter.Encode();

        // Build the message with the receipt in unprotected headers
        // Protected header with algorithm
        var protectedWriter = new CborWriter();
        protectedWriter.WriteStartMap(1);
        protectedWriter.WriteInt32(1);  // alg label
        protectedWriter.WriteInt32(-7); // ES256
        protectedWriter.WriteEndMap();
        var protectedBytes = protectedWriter.Encode();

        // Payload
        var payload = System.Text.Encoding.UTF8.GetBytes("test payload");

        // Create signature
        using var key = cert.GetECDsaPrivateKey()!;
        var toBeSigned = CreateToBeSigned(protectedBytes, payload);
        var signature = key.SignData(toBeSigned, HashAlgorithmName.SHA256);

        // Build the complete COSE_Sign1 structure
        var messageWriter = new CborWriter();
        messageWriter.WriteTag(CoseSign1Tag);
        messageWriter.WriteStartArray(4);
        messageWriter.WriteByteString(protectedBytes);

        // Write unprotected headers map directly
        messageWriter.WriteStartMap(1);
        messageWriter.WriteInt32(394);
        messageWriter.WriteByteString(receiptBytes);
        messageWriter.WriteEndMap();

        messageWriter.WriteByteString(payload);
        messageWriter.WriteByteString(signature);
        messageWriter.WriteEndArray();

        return CoseMessage.DecodeSign1(messageWriter.Encode());
    }

    private static byte[] CreateToBeSigned(byte[] protectedHeaders, byte[] payload)
    {
        var writer = new CborWriter();
        writer.WriteStartArray(4);
        writer.WriteTextString("Signature1");
        writer.WriteByteString(protectedHeaders);
        writer.WriteByteString(Array.Empty<byte>()); // external_aad
        writer.WriteByteString(payload);
        writer.WriteEndArray();
        return writer.Encode();
    }

    #endregion
}
