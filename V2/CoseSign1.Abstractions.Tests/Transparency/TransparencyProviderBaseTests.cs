// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions.Tests.Transparency;

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions.Transparency;
using CoseSign1.Tests.Common;

[TestFixture]
[System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
public class TransparencyProviderBaseTests
{
    private static X509Certificate2 CreateTestCert() =>
        TestCertificateUtils.CreateCertificate("TransparencyBaseTestCert", useEcc: true);

    #region AddTransparencyProofAsync - Receipt Preservation Tests

    [Test]
    public async Task AddTransparencyProofAsync_PreservesExistingReceipts_WhenCoreReturnsNewMessage()
    {
        // Arrange - create a message with an existing receipt
        using X509Certificate2 cert = CreateTestCert();
        CoseSign1Message originalMessage = CreateMessageWithReceipts(cert, new byte[][] { new byte[] { 0x01, 0x02, 0x03 } });

        // The "core" implementation returns a brand new message (simulating CTS behavior) with its own receipt
        byte[] newReceipt = new byte[] { 0x04, 0x05, 0x06 };
        CoseSign1Message newMessageFromService = CreateMessageWithReceipts(cert, new byte[][] { newReceipt });

        TestTransparencyProvider provider = new(_ => Task.FromResult(newMessageFromService));

        // Act
        CoseSign1Message result = await provider.AddTransparencyProofAsync(originalMessage);

        // Assert - result should contain both the new receipt AND the original receipt
        bool hasReceipts = TransparencyProviderBase.TryGetReceipts(result, out List<byte[]>? receipts);
        Assert.That(hasReceipts, Is.True);
        Assert.That(receipts, Has.Count.EqualTo(2), "Result should have both the new receipt from the service and the preserved original receipt");
    }

    [Test]
    public async Task AddTransparencyProofAsync_DeduplicatesReceipts_WhenSameReceiptExists()
    {
        // Arrange - create a message with a receipt
        using X509Certificate2 cert = CreateTestCert();
        byte[] sharedReceipt = new byte[] { 0x01, 0x02, 0x03 };
        CoseSign1Message originalMessage = CreateMessageWithReceipts(cert, new byte[][] { sharedReceipt });

        // The core returns a message that contains the same receipt
        CoseSign1Message newMessageFromService = CreateMessageWithReceipts(cert, new byte[][] { sharedReceipt });

        TestTransparencyProvider provider = new(_ => Task.FromResult(newMessageFromService));

        // Act
        CoseSign1Message result = await provider.AddTransparencyProofAsync(originalMessage);

        // Assert - should deduplicate and have only 1 receipt
        bool hasReceipts = TransparencyProviderBase.TryGetReceipts(result, out List<byte[]>? receipts);
        Assert.That(hasReceipts, Is.True);
        Assert.That(receipts, Has.Count.EqualTo(1), "Duplicate receipts should be merged into one");
    }

    [Test]
    public async Task AddTransparencyProofAsync_WorksCorrectly_WhenNoExistingReceipts()
    {
        // Arrange - message with no receipts
        using X509Certificate2 cert = CreateTestCert();
        CoseSign1Message originalMessage = CreateTestMessage(cert, "test payload");

        // The core returns a message with a receipt from the service
        byte[] newReceipt = new byte[] { 0x04, 0x05, 0x06 };
        CoseSign1Message newMessageFromService = CreateMessageWithReceipts(cert, new byte[][] { newReceipt });

        TestTransparencyProvider provider = new(_ => Task.FromResult(newMessageFromService));

        // Act
        CoseSign1Message result = await provider.AddTransparencyProofAsync(originalMessage);

        // Assert - should just have the new receipt
        bool hasReceipts = TransparencyProviderBase.TryGetReceipts(result, out List<byte[]>? receipts);
        Assert.That(hasReceipts, Is.True);
        Assert.That(receipts, Has.Count.EqualTo(1));
    }

    [Test]
    public async Task AddTransparencyProofAsync_PreservesMultipleExistingReceipts()
    {
        // Arrange - create a message with two existing receipts
        using X509Certificate2 cert = CreateTestCert();
        byte[][] existingReceipts = new byte[][]
        {
            new byte[] { 0x01, 0x02 },
            new byte[] { 0x03, 0x04 }
        };
        CoseSign1Message originalMessage = CreateMessageWithReceipts(cert, existingReceipts);

        // The core returns a message with a new receipt
        byte[] newReceipt = new byte[] { 0x05, 0x06 };
        CoseSign1Message newMessageFromService = CreateMessageWithReceipts(cert, new byte[][] { newReceipt });

        TestTransparencyProvider provider = new(_ => Task.FromResult(newMessageFromService));

        // Act
        CoseSign1Message result = await provider.AddTransparencyProofAsync(originalMessage);

        // Assert - should have all 3 receipts
        bool hasReceipts = TransparencyProviderBase.TryGetReceipts(result, out List<byte[]>? receipts);
        Assert.That(hasReceipts, Is.True);
        Assert.That(receipts, Has.Count.EqualTo(3), "Result should have the new receipt plus both original receipts");
    }

    #endregion

    #region AddTransparencyProofAsync - Error Handling Tests

    [Test]
    public void AddTransparencyProofAsync_WithNullMessage_ThrowsArgumentNullException()
    {
        // Arrange
        TestTransparencyProvider provider = new(_ => Task.FromResult<CoseSign1Message>(null!));

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await provider.AddTransparencyProofAsync(null!));
    }

    [Test]
    public void AddTransparencyProofAsync_WhenCoreReturnsNull_ThrowsInvalidOperationException()
    {
        // Arrange
        using X509Certificate2 cert = CreateTestCert();
        CoseSign1Message message = CreateTestMessage(cert, "test payload");
        TestTransparencyProvider provider = new(_ => Task.FromResult<CoseSign1Message>(null!));

        // Act & Assert
        InvalidOperationException? ex = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await provider.AddTransparencyProofAsync(message));

        Assert.That(ex!.Message, Does.Contain("returned null"));
    }

    [Test]
    public void AddTransparencyProofAsync_WhenCoreThrows_PropagatesException()
    {
        // Arrange
        using X509Certificate2 cert = CreateTestCert();
        CoseSign1Message message = CreateTestMessage(cert, "test payload");
        TestTransparencyProvider provider = new(_ =>
            Task.FromException<CoseSign1Message>(new InvalidOperationException("Service down")));

        // Act & Assert
        InvalidOperationException? ex = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await provider.AddTransparencyProofAsync(message));

        Assert.That(ex!.Message, Is.EqualTo("Service down"));
    }

    #endregion

    #region AddTransparencyProofAsync - Logging Tests

    [Test]
    public async Task AddTransparencyProofAsync_LogsReceiptCounts()
    {
        // Arrange
        using X509Certificate2 cert = CreateTestCert();
        List<string> logs = new();
        CoseSign1Message originalMessage = CreateMessageWithReceipts(cert, new byte[][] { new byte[] { 0x01 } });

        byte[] newReceipt = new byte[] { 0x02 };
        CoseSign1Message newMessageFromService = CreateMessageWithReceipts(cert, new byte[][] { newReceipt });

        TestTransparencyProvider provider = new(
            _ => Task.FromResult(newMessageFromService),
            logVerbose: msg => logs.Add(msg));

        // Act
        await provider.AddTransparencyProofAsync(originalMessage);

        // Assert
        Assert.That(logs.Any(l => l.Contains("Input receipts: 1")), Is.True, "Should log the input receipt count");
        Assert.That(logs.Any(l => l.Contains("Result receipts:")), Is.True, "Should log the result receipt counts");
    }

    [Test]
    public async Task AddTransparencyProofAsync_LogsErrorOnFailure()
    {
        // Arrange
        using X509Certificate2 cert = CreateTestCert();
        List<string> errorLogs = new();
        CoseSign1Message message = CreateTestMessage(cert, "test payload");

        TestTransparencyProvider provider = new(
            _ => Task.FromException<CoseSign1Message>(new InvalidOperationException("fail")),
            logError: msg => errorLogs.Add(msg));

        // Act & Assert
        try
        {
            await provider.AddTransparencyProofAsync(message);
        }
        catch (InvalidOperationException)
        {
            // Expected
        }

        Assert.That(errorLogs.Any(l => l.Contains("failed")), Is.True, "Should log the error");
    }

    #endregion

    #region VerifyTransparencyProofAsync Tests

    [Test]
    public void VerifyTransparencyProofAsync_WithNullMessage_ThrowsArgumentNullException()
    {
        // Arrange
        TestTransparencyProvider provider = new(_ => Task.FromResult<CoseSign1Message>(null!));

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await provider.VerifyTransparencyProofAsync(null!));
    }

    [Test]
    public async Task VerifyTransparencyProofAsync_DelegatesToCore()
    {
        // Arrange
        using X509Certificate2 cert = CreateTestCert();
        CoseSign1Message message = CreateTestMessage(cert, "test payload");
        TransparencyValidationResult expectedResult = TransparencyValidationResult.Success("TestProvider");
        TestTransparencyProvider provider = new(
            _ => Task.FromResult<CoseSign1Message>(null!),
            verifyResult: expectedResult);

        // Act
        TransparencyValidationResult result = await provider.VerifyTransparencyProofAsync(message);

        // Assert
        Assert.That(result, Is.SameAs(expectedResult));
    }

    #endregion

    #region TryGetReceipts / MergeReceipts Static Tests

    [Test]
    public void TryGetReceipts_WithNoReceiptHeader_ReturnsFalse()
    {
        // Arrange
        using X509Certificate2 cert = CreateTestCert();
        CoseSign1Message message = CreateTestMessage(cert, "test payload");

        // Act
        bool result = TransparencyProviderBase.TryGetReceipts(message, out List<byte[]>? receipts);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(receipts, Is.Null);
    }

    [Test]
    public void TryGetReceipts_WithValidReceipts_ReturnsTrue()
    {
        // Arrange
        using X509Certificate2 cert = CreateTestCert();
        CoseSign1Message message = CreateMessageWithReceipts(cert, new byte[][] { new byte[] { 0x01, 0x02 } });

        // Act
        bool result = TransparencyProviderBase.TryGetReceipts(message, out List<byte[]>? receipts);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(receipts, Has.Count.EqualTo(1));
    }

    [Test]
    public void MergeReceipts_WithNullMessage_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            TransparencyProviderBase.MergeReceipts(null!, new List<byte[]> { new byte[] { 0x01 } }));
    }

    [Test]
    public void MergeReceipts_WithNullReceipts_ThrowsArgumentNullException()
    {
        // Arrange
        using X509Certificate2 cert = CreateTestCert();
        CoseSign1Message message = CreateTestMessage(cert, "test payload");

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            TransparencyProviderBase.MergeReceipts(message, null!));
    }

    [Test]
    public void MergeReceipts_WithEmptyReceipts_DoesNotModifyMessage()
    {
        // Arrange
        using X509Certificate2 cert = CreateTestCert();
        CoseSign1Message message = CreateTestMessage(cert, "test payload");

        // Act - merge empty list (all entries are null/empty so mergedReceipts.Count == 0)
        TransparencyProviderBase.MergeReceipts(message, new List<byte[]>());

        // Assert - no receipt header should be added
        bool hasReceipts = TransparencyProviderBase.TryGetReceipts(message, out _);
        Assert.That(hasReceipts, Is.False);
    }

    #endregion

    #region Test Helpers

    /// <summary>
    /// A test implementation of TransparencyProviderBase for testing the base class behavior.
    /// </summary>
    private sealed class TestTransparencyProvider : TransparencyProviderBase
    {
        private readonly Func<CoseSign1Message, Task<CoseSign1Message>> CoreFunc;
        private readonly TransparencyValidationResult? VerifyResult;

        public override string ProviderName => "TestProvider";

        public TestTransparencyProvider(
            Func<CoseSign1Message, Task<CoseSign1Message>> coreFunc,
            Action<string>? logVerbose = null,
            Action<string>? logError = null,
            TransparencyValidationResult? verifyResult = null)
            : base(logVerbose, logError)
        {
            CoreFunc = coreFunc;
            VerifyResult = verifyResult;
        }

        protected override Task<CoseSign1Message> AddTransparencyProofCoreAsync(
            CoseSign1Message message,
            CancellationToken cancellationToken = default)
            => CoreFunc(message);

        protected override Task<TransparencyValidationResult> VerifyTransparencyProofCoreAsync(
            CoseSign1Message message,
            CancellationToken cancellationToken = default)
            => Task.FromResult(VerifyResult ?? TransparencyValidationResult.Success(ProviderName));
    }

    private static CoseSign1Message CreateTestMessage(X509Certificate2 cert, string payload)
    {
        using ECDsa key = cert.GetECDsaPrivateKey()!;
        CoseSigner signer = new(key, HashAlgorithmName.SHA256);
        byte[] payloadBytes = System.Text.Encoding.UTF8.GetBytes(payload);
        byte[] signedBytes = CoseSign1Message.SignEmbedded(payloadBytes, signer);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    /// <summary>
    /// Creates a CoseSign1Message with receipts embedded in the unprotected header at label 394.
    /// </summary>
    private static CoseSign1Message CreateMessageWithReceipts(X509Certificate2 cert, byte[][] receipts)
    {
        // Build receipts as CBOR array of byte strings
        CborWriter arrayWriter = new();
        arrayWriter.WriteStartArray(receipts.Length);
        foreach (byte[] receipt in receipts)
        {
            arrayWriter.WriteByteString(receipt);
        }
        arrayWriter.WriteEndArray();
        byte[] receiptsArrayBytes = arrayWriter.Encode();

        return CreateMessageWithHeaderValue(cert, 394, receiptsArrayBytes);
    }

    private static CoseSign1Message CreateMessageWithHeaderValue(X509Certificate2 cert, int headerLabel, byte[] headerValue)
    {
        // Build protected headers with algorithm
        CborWriter protectedWriter = new();
        protectedWriter.WriteStartMap(1);
        protectedWriter.WriteInt32(1);  // alg label
        protectedWriter.WriteInt32(-7); // ES256
        protectedWriter.WriteEndMap();
        byte[] protectedBytes = protectedWriter.Encode();

        // Payload
        byte[] payload = System.Text.Encoding.UTF8.GetBytes("test payload");

        // Create signature
        using ECDsa key = cert.GetECDsaPrivateKey()!;
        byte[] toBeSigned = CreateToBeSigned(protectedBytes, payload);
        byte[] signature = key.SignData(toBeSigned, HashAlgorithmName.SHA256);

        // Build the complete COSE_Sign1 structure with unprotected header
        CborWriter messageWriter = new();
        messageWriter.WriteTag((CborTag)18);  // COSE_Sign1 tag
        messageWriter.WriteStartArray(4);
        messageWriter.WriteByteString(protectedBytes);

        // Write unprotected headers map with receipt
        messageWriter.WriteStartMap(1);
        messageWriter.WriteInt32(headerLabel);
        messageWriter.WriteEncodedValue(headerValue);
        messageWriter.WriteEndMap();

        messageWriter.WriteByteString(payload);
        messageWriter.WriteByteString(signature);
        messageWriter.WriteEndArray();

        return CoseMessage.DecodeSign1(messageWriter.Encode());
    }

    private static byte[] CreateToBeSigned(byte[] protectedHeaders, byte[] payload)
    {
        CborWriter writer = new();
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
