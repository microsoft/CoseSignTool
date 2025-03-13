// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Ignore Spelling: Cose Deserialization

namespace CoseIndirectSignature.Tests;

using System.Net.Mime;
using Microsoft.VisualStudio.TestTools.UnitTesting;     // Do not make global because it will conflict with NUnit.

public class CoseHashEnvelopeTests
{
    [SetUp]
    public void Setup()
    {
    }

    [Test]
    public void TestFactoryDefaultCreatesCoseHashEnvelop()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = TestUtils.SetupMockSigningKeyProvider();
        using IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        using HashAlgorithm hasher = CoseSign1MessageIndirectSignatureExtensions.CreateHashAlgorithmFromName(factory.HashAlgorithmName)
                 ?? throw new Exception($"Failed to get hash algorithm from {nameof(CoseSign1MessageIndirectSignatureExtensions.CreateHashAlgorithmFromName)}");
        byte[] hash = hasher!.ComputeHash(randomBytes);

        CoseSign1Message coseSign1Message = factory.CreateIndirectSignature(
            randomBytes,
            coseSigningKeyProvider,
            "application/test.payload");

        // should be CoseHashEnvelope
        coseSign1Message.TryGetIsCoseHashEnvelope().Should().BeTrue();
        // should not be CoseHashV
        coseSign1Message.TryGetIsCoseHashVContentType().Should().BeFalse();
        // should not be IndirectSignature type.
        coseSign1Message.TryGetIndirectSignatureAlgorithm(out _).Should().BeFalse();

        // check attributes
        coseSign1Message.TryGetPayloadHashAlgorithm(out CoseHashAlgorithm? algoName).Should().BeTrue();
        algoName.Should().Be(CoseHashAlgorithm.SHA256);

        coseSign1Message.TryGetPreImageContentType(out string? contentType).Should().BeTrue();
        contentType.Should().Be("application/test.payload");

        coseSign1Message.TryGetPayloadLocation(out string? payloadLocation).Should().BeFalse();
        payloadLocation.Should().BeNull();

        // hashes should match
        coseSign1Message.Content.Value.ToArray().Should().BeEquivalentTo(hash);

        // signatures should match
        coseSign1Message.SignatureMatches(randomBytes).Should().BeTrue();
    }

    [Test]
    public void TestFactoryExplicitCreatesCoseHashEnvelop()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = TestUtils.SetupMockSigningKeyProvider();
        using IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        using HashAlgorithm hasher = CoseSign1MessageIndirectSignatureExtensions.CreateHashAlgorithmFromName(factory.HashAlgorithmName)
                 ?? throw new Exception($"Failed to get hash algorithm from {nameof(CoseSign1MessageIndirectSignatureExtensions.CreateHashAlgorithmFromName)}");
        byte[] hash = hasher!.ComputeHash(randomBytes);

        CoseSign1Message coseSign1Message = factory.CreateIndirectSignature(
            randomBytes, coseSigningKeyProvider,
            "application/test.payload",
            IndirectSignatureFactory.IndirectSignatureVersion.CoseHashEnvelope);
        // should be CoseHashEnvelope
        coseSign1Message.TryGetIsCoseHashEnvelope().Should().BeTrue();
        // should not be CoseHashV
        coseSign1Message.TryGetIsCoseHashVContentType().Should().BeFalse();
        // should not be IndirectSignature type.
        coseSign1Message.TryGetIndirectSignatureAlgorithm(out _).Should().BeFalse();

        // check attributes
        coseSign1Message.TryGetPayloadHashAlgorithm(out CoseHashAlgorithm? algoName).Should().BeTrue();
        algoName.Should().Be(CoseHashAlgorithm.SHA256);

        coseSign1Message.TryGetPreImageContentType(out string? contentType).Should().BeTrue();
        contentType.Should().Be("application/test.payload");

        coseSign1Message.TryGetPayloadLocation(out string? payloadLocation).Should().BeFalse();
        payloadLocation.Should().BeNull();

        // hashes should match
        coseSign1Message.Content.Value.ToArray().Should().BeEquivalentTo(hash);

        // signatures should match
        coseSign1Message.SignatureMatches(randomBytes).Should().BeTrue();
    }

    [Test]
    [TestCase(1, Description = "TryGetIsCoseHashEnvelope")]
    [TestCase(2, Description = "TryGetPayloadHashAlgorithm")]
    [TestCase(3, Description = "TryGetPreImageContentType")]
    [TestCase(4, Description = "TryGetPayloadLocation")]
    public void TestExtensionMethodNullHandling(int testCase)
    {
        CoseSign1Message? coseSign1Message = null;
        switch (testCase)
        {
            case 1:
                coseSign1Message.TryGetIsCoseHashEnvelope().Should().BeFalse();
                break;
            case 2:
                coseSign1Message.TryGetPayloadHashAlgorithm(out CoseHashAlgorithm? algoName).Should().BeFalse();
                algoName.Should().BeNull();
                break;
            case 3:
                coseSign1Message.TryGetPreImageContentType(out string? contentType).Should().BeFalse();
                contentType.Should().BeNull();
                break;
            case 4:
                coseSign1Message.TryGetPayloadLocation(out string? payloadLocation).Should().BeFalse();
                payloadLocation.Should().BeNull();
                break;
        }
    }

    [Test]
    public void ValidCoseHashEnvelopeMinusContentShouldInvalidate()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = TestUtils.SetupMockSigningKeyProvider();
        CoseSign1MessageFactory factory = new();

        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);

        CoseSign1Message? message = factory.CreateCoseSign1Message(
                            randomBytes,
                            coseSigningKeyProvider,
                            embedPayload: false,
                            headerExtender: new CoseHashEnvelopeHeaderExtender(HashAlgorithmName.SHA256, "application/test"));
        message.Should().NotBeNull();
        message!.TryGetIsCoseHashEnvelope().Should().BeFalse();
        message.TryGetPayloadHashAlgorithm(out CoseHashAlgorithm? algoName).Should().BeTrue();
        algoName.Should().Be(CoseHashAlgorithm.SHA256);
        message.TryGetPreImageContentType(out string? contentType).Should().BeTrue();
        contentType.Should().Be("application/test");
    }

    [Test]
    public void ValidCoseHashEnvelopePayloadHashAlgorithmUnprotectedHeaderShouldInvalidate()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = TestUtils.SetupMockSigningKeyProvider();
        CoseSign1MessageFactory factory = new();

        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        Mock<ICoseHeaderExtender> mockHeaderExtender = new(MockBehavior.Strict);
        CoseHeaderMap protectedHeader = new();
        CoseHeaderMap unProtectedHeader = new();

        CoseHashEnvelopeHeaderExtender headerExtender = new CoseHashEnvelopeHeaderExtender(HashAlgorithmName.SHA256, "application/test");
        protectedHeader = headerExtender.ExtendProtectedHeaders(protectedHeader);
        protectedHeader.Remove(CoseHashEnvelopeHeaderExtender.CoseHashEnvelopeHeaderLabels[CoseHashEnvelopeHeaderLabels.PayloadHashAlg]);
        unProtectedHeader = headerExtender.ExtendProtectedHeaders(unProtectedHeader);
        unProtectedHeader.Remove(CoseHashEnvelopeHeaderExtender.CoseHashEnvelopeHeaderLabels[CoseHashEnvelopeHeaderLabels.PreimageContentType]);
        unProtectedHeader.Remove(CoseHashEnvelopeHeaderExtender.CoseHashEnvelopeHeaderLabels[CoseHashEnvelopeHeaderLabels.PayloadLocation]);

        mockHeaderExtender.Setup(x => x.ExtendProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns(protectedHeader);
        mockHeaderExtender.Setup(x => x.ExtendUnProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns(unProtectedHeader);

        CoseSign1Message? message = factory.CreateCoseSign1Message(
                            randomBytes,
                            coseSigningKeyProvider,
                            embedPayload: true,
                            headerExtender: mockHeaderExtender.Object);
        message.Should().NotBeNull();
        message!.TryGetIsCoseHashEnvelope().Should().BeFalse();
        message.TryGetPayloadHashAlgorithm(out CoseHashAlgorithm? algoName).Should().BeFalse();
        algoName.Should().BeNull();
        message.TryGetPreImageContentType(out string? contentType).Should().BeTrue();
        contentType.Should().Be("application/test");
    }

    [Test]
    public void ValidCoseHashEnvelopeInvalidPayloadHashAlgorithmShouldInvalidate()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = TestUtils.SetupMockSigningKeyProvider();
        CoseSign1MessageFactory factory = new();

        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        Mock<ICoseHeaderExtender> mockHeaderExtender = new(MockBehavior.Strict);
        CoseHeaderMap protectedHeader = new();

        CoseHashEnvelopeHeaderExtender headerExtender = new CoseHashEnvelopeHeaderExtender(HashAlgorithmName.SHA256, "application/test");
        protectedHeader = headerExtender.ExtendProtectedHeaders(protectedHeader);
        protectedHeader.Remove(CoseHashEnvelopeHeaderExtender.CoseHashEnvelopeHeaderLabels[CoseHashEnvelopeHeaderLabels.PayloadHashAlg]);
        // add a bogus payload hash algo
        protectedHeader.Add(CoseHashEnvelopeHeaderExtender.CoseHashEnvelopeHeaderLabels[CoseHashEnvelopeHeaderLabels.PayloadHashAlg], CoseHeaderValue.FromInt32(9953));

        mockHeaderExtender.Setup(x => x.ExtendProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns(protectedHeader);
        mockHeaderExtender.Setup(x => x.ExtendUnProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns([]);

        CoseSign1Message? message = factory.CreateCoseSign1Message(
                            randomBytes,
                            coseSigningKeyProvider,
                            embedPayload: true,
                            headerExtender: mockHeaderExtender.Object);
        message.Should().NotBeNull();
        message!.TryGetIsCoseHashEnvelope().Should().BeFalse();
        message.TryGetPayloadHashAlgorithm(out CoseHashAlgorithm? algoName).Should().BeFalse();
        algoName.Should().BeNull();
        message.TryGetPreImageContentType(out string? contentType).Should().BeTrue();
        contentType.Should().Be("application/test");
    }

    [Test]
    public void ValidCoseHashEnvelopePayloadPreImageContentTypeUnprotectedHeaderShouldValidate()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = TestUtils.SetupMockSigningKeyProvider();
        CoseSign1MessageFactory factory = new();

        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        Mock<ICoseHeaderExtender> mockHeaderExtender = new(MockBehavior.Strict);
        CoseHeaderMap protectedHeader = new();
        CoseHeaderMap unProtectedHeader = new();

        CoseHashEnvelopeHeaderExtender headerExtender = new CoseHashEnvelopeHeaderExtender(HashAlgorithmName.SHA256, "application/test");
        protectedHeader = headerExtender.ExtendProtectedHeaders(protectedHeader);
        protectedHeader.Remove(CoseHashEnvelopeHeaderExtender.CoseHashEnvelopeHeaderLabels[CoseHashEnvelopeHeaderLabels.PreimageContentType]);
        unProtectedHeader = headerExtender.ExtendProtectedHeaders(unProtectedHeader);
        unProtectedHeader.Remove(CoseHashEnvelopeHeaderExtender.CoseHashEnvelopeHeaderLabels[CoseHashEnvelopeHeaderLabels.PayloadHashAlg]);
        unProtectedHeader.Remove(CoseHashEnvelopeHeaderExtender.CoseHashEnvelopeHeaderLabels[CoseHashEnvelopeHeaderLabels.PayloadLocation]);

        mockHeaderExtender.Setup(x => x.ExtendProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns(protectedHeader);
        mockHeaderExtender.Setup(x => x.ExtendUnProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns(unProtectedHeader);

        CoseSign1Message? message = factory.CreateCoseSign1Message(
                            randomBytes,
                            coseSigningKeyProvider,
                            embedPayload: true,
                            headerExtender: mockHeaderExtender.Object);
        message.Should().NotBeNull();
        message!.TryGetIsCoseHashEnvelope().Should().BeTrue();
        message.TryGetPayloadHashAlgorithm(out CoseHashAlgorithm? algoName).Should().BeTrue();
        algoName.Should().Be(CoseHashAlgorithm.SHA256);
        message.TryGetPreImageContentType(out string? contentType).Should().BeTrue();
        contentType.Should().Be("application/test");
    }

    [Test]
    public void ValidCoseHashEnvelopePayloadNoPreImageContentShouldValidate()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = TestUtils.SetupMockSigningKeyProvider();
        CoseSign1MessageFactory factory = new();

        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        Mock<ICoseHeaderExtender> mockHeaderExtender = new(MockBehavior.Strict);
        CoseHeaderMap protectedHeader = new();
        CoseHeaderMap unProtectedHeader = new();

        CoseHashEnvelopeHeaderExtender headerExtender = new CoseHashEnvelopeHeaderExtender(HashAlgorithmName.SHA256, "application/test");
        protectedHeader = headerExtender.ExtendProtectedHeaders(protectedHeader);
        protectedHeader.Remove(CoseHashEnvelopeHeaderExtender.CoseHashEnvelopeHeaderLabels[CoseHashEnvelopeHeaderLabels.PreimageContentType]);

        mockHeaderExtender.Setup(x => x.ExtendProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns(protectedHeader);
        mockHeaderExtender.Setup(x => x.ExtendUnProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns(unProtectedHeader);

        CoseSign1Message? message = factory.CreateCoseSign1Message(
                            randomBytes,
                            coseSigningKeyProvider,
                            embedPayload: true,
                            headerExtender: mockHeaderExtender.Object);
        message.Should().NotBeNull();
        message!.TryGetIsCoseHashEnvelope().Should().BeTrue();
        message.TryGetPayloadHashAlgorithm(out CoseHashAlgorithm? algoName).Should().BeTrue();
        algoName.Should().Be(CoseHashAlgorithm.SHA256);
        message.TryGetPreImageContentType(out string? contentType).Should().BeFalse();
        contentType.Should().BeNullOrEmpty();
    }

    [Test]
    public void ValidCoseHashEnvelopePayloadLocationProtectedHeaderShouldValidate()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = TestUtils.SetupMockSigningKeyProvider();
        CoseSign1MessageFactory factory = new();

        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);

        CoseHashEnvelopeHeaderExtender headerExtender = new CoseHashEnvelopeHeaderExtender(HashAlgorithmName.SHA256, "application/test", "payload_location");
        CoseSign1Message? message = factory.CreateCoseSign1Message(
                            randomBytes,
                            coseSigningKeyProvider,
                            embedPayload: true,
                            headerExtender: headerExtender);
        message.Should().NotBeNull();
        message!.TryGetIsCoseHashEnvelope().Should().BeTrue();
        message.TryGetPayloadHashAlgorithm(out CoseHashAlgorithm? algoName).Should().BeTrue();
        algoName.Should().Be(CoseHashAlgorithm.SHA256);
        message.TryGetPreImageContentType(out string? contentType).Should().BeTrue();
        contentType.Should().Be("application/test");
        message.TryGetPayloadLocation(out string? payloadLocation).Should().BeTrue();
        payloadLocation.Should().Be("payload_location");
    }

    [Test]
    public void ValidCoseHashEnvelopePayloadLocationUnProtectedHeaderShouldInvalidate()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = TestUtils.SetupMockSigningKeyProvider();
        CoseSign1MessageFactory factory = new();

        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        Mock<ICoseHeaderExtender> mockHeaderExtender = new(MockBehavior.Strict);
        CoseHeaderMap protectedHeader = new();
        CoseHeaderMap unProtectedHeader = new();

        CoseHashEnvelopeHeaderExtender headerExtender = new CoseHashEnvelopeHeaderExtender(HashAlgorithmName.SHA256, "application/test", "payload_location");
        protectedHeader = headerExtender.ExtendProtectedHeaders(protectedHeader);
        protectedHeader.Remove(CoseHashEnvelopeHeaderExtender.CoseHashEnvelopeHeaderLabels[CoseHashEnvelopeHeaderLabels.PayloadLocation]);
        unProtectedHeader = headerExtender.ExtendProtectedHeaders(unProtectedHeader);
        unProtectedHeader.Remove(CoseHashEnvelopeHeaderExtender.CoseHashEnvelopeHeaderLabels[CoseHashEnvelopeHeaderLabels.PayloadHashAlg]);
        unProtectedHeader.Remove(CoseHashEnvelopeHeaderExtender.CoseHashEnvelopeHeaderLabels[CoseHashEnvelopeHeaderLabels.PreimageContentType]);

        mockHeaderExtender.Setup(x => x.ExtendProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns(protectedHeader);
        mockHeaderExtender.Setup(x => x.ExtendUnProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns(unProtectedHeader);

        CoseSign1Message? message = factory.CreateCoseSign1Message(
                            randomBytes,
                            coseSigningKeyProvider,
                            embedPayload: true,
                            headerExtender: mockHeaderExtender.Object);
        message.Should().NotBeNull();
        message!.TryGetIsCoseHashEnvelope().Should().BeTrue();
        message.TryGetPayloadHashAlgorithm(out CoseHashAlgorithm? algoName).Should().BeTrue();
        algoName.Should().Be(CoseHashAlgorithm.SHA256);
        message.TryGetPreImageContentType(out string? contentType).Should().BeTrue();
        contentType.Should().Be("application/test");
        message.TryGetPayloadLocation(out string? payloadLocation).Should().BeFalse();
        payloadLocation.Should().BeNullOrEmpty();
    }

    [Test]
    public void CoseMessage1MinusContentShouldNotHashMatch()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = TestUtils.SetupMockSigningKeyProvider();
        CoseSign1MessageFactory factory = new();

        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);

        CoseSign1Message? message = factory.CreateCoseSign1Message(
                            randomBytes,
                            coseSigningKeyProvider,
                            embedPayload: false,
                            headerExtender: new CoseHashEnvelopeHeaderExtender(HashAlgorithmName.SHA256, "application/test"));
        message.Should().NotBeNull();
        Assert.ThrowsException<InvalidCoseDataException>(() => message.SignatureMatchesInternalCoseHashEnvelope(randomBytes));
    }

    [Test]
    public void CoseMessage1BadAlgorithmShouldNotHashMatch()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = TestUtils.SetupMockSigningKeyProvider();
        CoseSign1MessageFactory factory = new();

        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        Mock<ICoseHeaderExtender> mockHeaderExtender = new(MockBehavior.Strict);
        CoseHeaderMap protectedHeader = new();

        CoseHashEnvelopeHeaderExtender headerExtender = new CoseHashEnvelopeHeaderExtender(HashAlgorithmName.SHA256, "application/test");
        protectedHeader = headerExtender.ExtendProtectedHeaders(protectedHeader);
        protectedHeader.Remove(CoseHashEnvelopeHeaderExtender.CoseHashEnvelopeHeaderLabels[CoseHashEnvelopeHeaderLabels.PayloadHashAlg]);
        // add a bogus payload hash algo
        protectedHeader.Add(CoseHashEnvelopeHeaderExtender.CoseHashEnvelopeHeaderLabels[CoseHashEnvelopeHeaderLabels.PayloadHashAlg], CoseHeaderValue.FromInt32(9953));

        mockHeaderExtender.Setup(x => x.ExtendProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns(protectedHeader);
        mockHeaderExtender.Setup(x => x.ExtendUnProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns([]);

        CoseSign1Message? message = factory.CreateCoseSign1Message(
                            randomBytes,
                            coseSigningKeyProvider,
                            embedPayload: true,
                            headerExtender: mockHeaderExtender.Object);
        message.Should().NotBeNull();
        Assert.ThrowsException<InvalidCoseDataException>(() => message.SignatureMatchesInternalCoseHashEnvelope(randomBytes));
    }
}
