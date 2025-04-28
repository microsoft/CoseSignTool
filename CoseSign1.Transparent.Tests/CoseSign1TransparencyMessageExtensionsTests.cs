// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.Tests;

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CoseSign1.Abstractions.Interfaces;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Local;
using CoseSign1.Interfaces;
using CoseSign1.Tests.Common;
using CoseSign1.Transparent.Extensions;
using CoseSign1.Transparent.Interfaces;
using Moq;
using NUnit.Framework;

/// <summary>
/// Unit tests for the <see cref="CoseSign1TransparencyMessageExtensions"/> class.
/// </summary>
[TestFixture]
[Parallelizable(ParallelScope.All)]
public class CoseSign1TransparencyMessageExtensionsTests
{
    private CoseSign1MessageFactory? messageFactory;
    private ICoseSigningKeyProvider? signingKeyProvider;

    [SetUp]
    public void Setup()
    {
        X509Certificate2 testSigningCert = TestCertificateUtils.CreateCertificate();

        //create object of custom ChainBuilder
        ICertificateChainBuilder testChainBuilder = new TestChainBuilder();

        //create coseSignKeyProvider with custom chainbuilder and local cert
        //if no chainbuilder is specified, it will default to X509ChainBuilder, but that can't be used for integration tests
        signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(testChainBuilder, testSigningCert);

        messageFactory = new();
    }

    /// <summary>
    /// Tests the <see cref="CoseSign1TransparencyMessageExtensions.MakeTransparentAsync"/> method.
    /// </summary>
    /// <param name="messageIsNull">Indicates whether the message is null.</param>
    /// <param name="serviceIsNull">Indicates whether the transparency service is null.</param>
    [Test]
    [TestCase(true, false, TestName = "MakeTransparentAsync_ThrowsArgumentNullException_WhenMessageIsNull")]
    [TestCase(false, true, TestName = "MakeTransparentAsync_ThrowsArgumentNullException_WhenServiceIsNull")]
    public void MakeTransparentAsync_ThrowsArgumentNullException(bool messageIsNull, bool serviceIsNull)
    {
        // Arrange
        CoseSign1Message message = messageIsNull ? null : CreateMockCoseSign1Message();
        ITransparencyService transparencyService = serviceIsNull ? null : Mock.Of<ITransparencyService>();

        // Act & Assert
        Assert.That(
            () => message.MakeTransparentAsync(transparencyService),
            Throws.TypeOf<ArgumentNullException>());
    }

    /// <summary>
    /// Tests the <see cref="CoseSign1TransparencyMessageExtensions.MakeTransparentAsync"/> method for successful execution.
    /// </summary>
    [Test]
    public async Task MakeTransparentAsync_ReturnsExpectedResult()
    {
        // Arrange
        CoseSign1Message message = CreateMockCoseSign1Message();
        MockCoseHeaderValue(message, new List<byte[]> { new byte[] { 1, 2, 3 } });
        Mock<ITransparencyService> mockService = new Mock<ITransparencyService>();
        CoseSign1Message expectedMessage = CreateMockCoseSign1Message();
        MockCoseHeaderValue(expectedMessage, new List<byte[]> { new byte[] { 1, 2, 3 } });
        mockService
            .Setup(service => service.MakeTransparentAsync(message, It.IsAny<CancellationToken>()))
            .ReturnsAsync(expectedMessage);

        // Act
        CoseSign1Message result = await message.MakeTransparentAsync(mockService.Object);

        // Assert
        Assert.That(result, Is.EqualTo(expectedMessage));
    }

    /// <summary>
    /// Tests the <see cref="CoseSign1TransparencyMessageExtensions.ContainsTransparencyHeader"/> method.
    /// </summary>
    /// <param name="messageIsNull">Indicates whether the message is null.</param>
    [Test]
    [TestCase(true, TestName = "ContainsTransparencyHeader_ThrowsArgumentNullException_WhenMessageIsNull")]
    public void ContainsTransparencyHeader_ThrowsArgumentNullException(bool messageIsNull)
    {
        // Arrange
        CoseSign1Message message = messageIsNull ? null : CreateMockCoseSign1Message();

        // Act & Assert
        Assert.That(
            () => message.ContainsTransparencyHeader(),
            Throws.TypeOf<ArgumentNullException>());
    }

    /// <summary>
    /// Tests the <see cref="CoseSign1TransparencyMessageExtensions.ContainsTransparencyHeader"/> method for valid cases.
    /// </summary>
    [Test]
    public void ContainsTransparencyHeader_ReturnsExpectedResult()
    {
        // Arrange
        CoseSign1Message message = CreateMockCoseSign1Message();
        MockCoseHeaderValue(message, new List<byte[]> { new byte[] { 1, 2, 3 } });

        // Act
        bool result = message.ContainsTransparencyHeader();

        // Assert
        Assert.That(result, Is.True);
    }

    /// <summary>
    /// Tests the <see cref="CoseSign1TransparencyMessageExtensions.VerifyTransparencyAsync"/> method.
    /// </summary>
    /// <param name="messageIsNull">Indicates whether the message is null.</param>
    /// <param name="serviceIsNull">Indicates whether the transparency service is null.</param>
    [Test]
    [TestCase(true, false, TestName = "VerifyTransparencyAsync_ThrowsArgumentNullException_WhenMessageIsNull")]
    [TestCase(false, true, TestName = "VerifyTransparencyAsync_ThrowsArgumentNullException_WhenServiceIsNull")]
    public void VerifyTransparencyAsync_ThrowsArgumentNullException(bool messageIsNull, bool serviceIsNull)
    {
        // Arrange
        CoseSign1Message message = messageIsNull ? null : CreateMockCoseSign1Message();
        ITransparencyService transparencyService = serviceIsNull ? null : Mock.Of<ITransparencyService>();

        // Act & Assert
        Assert.That(
            () => message.VerifyTransparencyAsync(transparencyService),
            Throws.TypeOf<ArgumentNullException>());
    }

    /// <summary>
    /// Tests the <see cref="CoseSign1TransparencyMessageExtensions.VerifyTransparencyAsync"/> method for successful execution.
    /// </summary>
    [Test]
    public async Task VerifyTransparencyAsync_ReturnsExpectedResult()
    {
        // Arrange
        CoseSign1Message message = CreateMockCoseSign1Message();
        MockCoseHeaderValue(message, new List<byte[]> { new byte[] { 1, 2, 3 } });
        Mock<ITransparencyService> mockService = new Mock<ITransparencyService>();
        mockService
            .Setup(service => service.VerifyTransparencyAsync(message, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        bool result = await message.VerifyTransparencyAsync(mockService.Object);

        // Assert
        Assert.That(result, Is.True);
    }

    /// <summary>
    /// Tests the <see cref="CoseSign1TransparencyMessageExtensions.TryGetReceipts"/> method.
    /// </summary>
    [Test]
    public void TryGetReceipts_ReturnsExpectedResult()
    {
        // Arrange
        CoseSign1Message message = CreateMockCoseSign1Message();
        List<byte[]> expectedReceipts = new List<byte[]> { new byte[] { 1, 2, 3 } };
        MockCoseHeaderValue(message, expectedReceipts);
        

        // Act
        bool result = message.TryGetReceipts(out List<byte[]>? receipts);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(receipts, Is.EquivalentTo(expectedReceipts));
    }

    /// <summary>
    /// Tests the <see cref="CoseSign1TransparencyMessageExtensions.TryGetReceipts"/> method.
    /// </summary>
    [Test]
    public void TryGetReceipts_ThrowsArgumentNullException_WhenArgumentsAreNull()
    {
        // Arrange
        CoseSign1Message message = null;

        // Act & Assert
        Assert.That(
               () => message.TryGetReceipts(out _),
               Throws.TypeOf<ArgumentNullException>().With.Property("ParamName").EqualTo("message"));
    }

    /// <summary>
    /// Tests the <see cref="CoseSign1TransparencyMessageExtensions.TryGetReceipts"/> method.
    /// </summary>
    [Test]
    public void TryGetReceipts_NoProtectedHeader_ReturnsFalse()
    {
        // Arrange
        CoseSign1Message message = CreateMockCoseSign1Message();

        // Act & Assert
        Assert.That(message.TryGetReceipts(out _), Is.False);
    }

    /// <summary>
    /// Tests the <see cref="CoseSign1TransparencyMessageExtensions.TryGetReceipts"/> method.
    /// </summary>
    [Test]
    public void TryGetReceipts_InvalidProtectedHeader_ReturnsFalse()
    {
        // Arrange
        CoseSign1Message message = CreateMockCoseSign1Message();
        message.UnprotectedHeaders.Add(CoseSign1TransparencyMessageExtensions.TransparencyHeaderLabel, CoseHeaderValue.FromBytes(new byte[]{ 1, 2, 3}));

        // Act & Assert
        Assert.That(message.TryGetReceipts(out _), Is.False);
    }

    /// <summary>
    /// Tests the <see cref="CoseSign1TransparencyMessageExtensions.TryGetReceipts"/> method.
    /// </summary>
    [Test]
    public void TryGetReceipts_ValidProtectedHeader_AdditionalFields_ReturnsTrue()
    {
        // Arrange
        CoseSign1Message message = CreateMockCoseSign1Message();
        CborWriter cborWriter = new CborWriter();
        cborWriter.WriteStartArray(2);
        cborWriter.WriteDouble(1.0);
        cborWriter.WriteByteString(new byte[] { 1, 2, 3 });
        cborWriter.WriteEndArray();

        message.UnprotectedHeaders.Add(CoseSign1TransparencyMessageExtensions.TransparencyHeaderLabel, CoseHeaderValue.FromEncodedValue(cborWriter.Encode()));

        // Act & Assert
        Assert.That(message.TryGetReceipts(out _), Is.True);
    }

    /// <summary>
    /// Tests the <see cref="CoseSign1TransparencyMessageExtensions.AddReceipts"/> method for null arguments.
    /// </summary>
    [Test]
    public void AddReceipts_ThrowsArgumentNullException_WhenArgumentsAreNull()
    {
        // Arrange  
        CoseSign1Message message = null;
        CoseSign1Message message2 = CreateMockCoseSign1Message();
        List<byte[]> receipts = null;
        List<byte[]> receipts2 = new List<byte[]>();

        // Act & Assert  
        Assert.Multiple(() =>
        {
            Assert.That(
                () => message.AddReceipts(receipts),
                Throws.TypeOf<ArgumentNullException>().With.Property("ParamName").EqualTo("message"));

            Assert.That(
                () => message2.AddReceipts(receipts),
                Throws.TypeOf<ArgumentNullException>().With.Property("ParamName").EqualTo("receipts"));

            Assert.That(
                () => message2.AddReceipts(receipts2),
                Throws.TypeOf<ArgumentOutOfRangeException>().With.Property("ParamName").EqualTo("receipts"));
        });
    }

    /// <summary>
    /// Tests the <see cref="CoseSign1TransparencyMessageExtensions.AddReceipts"/> method for valid cases.
    /// </summary>
    [Test]
    public void AddReceipts_AddsReceiptsSuccessfully()
    {
        // Arrange
        CoseSign1Message message = CreateMockCoseSign1Message();
        List<byte[]> receipts = new List<byte[]> { new byte[] { 1, 2, 3 } };
        // Act
        message.AddReceipts(receipts);
        // Assert
        Assert.That(message.TryGetReceipts(out List<byte[]>? result), Is.True);
        Assert.That(result, Is.EquivalentTo(receipts));
    }

    /// <summary>
    /// Tests the <see cref="CoseSign1TransparencyMessageExtensions.AddReceipts"/> method for valid cases.
    /// </summary>
    [Test]
    public void AddReceipts_AddsReceipts_WithExistingReceipts_Successfully()
    {
        // Arrange
        CoseSign1Message message = CreateMockCoseSign1Message();
        byte[] firstReceipt = new byte[] { 4, 5, 6 };
        byte[] secondReceipt = new byte[] { 1, 2, 3 };
        message.AddReceipts(new List<byte[]> { firstReceipt });
        List<byte[]> receipts = new List<byte[]> { secondReceipt };
        // Act
        message.AddReceipts(receipts);
        // Assert
        Assert.That(message.TryGetReceipts(out List<byte[]>? result), Is.True);
        Assert.That(result[0], Is.EquivalentTo(firstReceipt));
        Assert.That(result[1], Is.EquivalentTo(secondReceipt));
    }

    /// <summary>
    /// Helper method to mock the behavior of a <see cref="CoseHeaderValue"/> for receipts.
    /// </summary>
    /// <param name="message">The <see cref="CoseSign1Message"/> to mock.</param>
    /// <param name="receipts">The list of receipts to return.</param>
    private static void MockCoseHeaderValue(CoseSign1Message message, List<byte[]> receipts)
    {
        message.AddReceipts(receipts);
    }

    private CoseSign1Message CreateMockCoseSign1Message()
    {
        byte[] testPayload = Encoding.ASCII.GetBytes("Payload1!");
        return messageFactory!.CreateCoseSign1Message(testPayload, signingKeyProvider!, embedPayload: false);
    }
}
