﻿// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Ignore Spelling: Cose

namespace CoseIndirectSignature.Tests;

using System.IO;
using CoseIndirectSignature;
using CoseIndirectSignature.Extensions;

/// <summary>
/// Class for Testing Methods of <see cref="CoseSign1MessageIndirectSignatureExtensions"/>
/// </summary>
public class CoseSign1MessageIndirectSignatureExtensionsTests
{
    [SetUp]
    public void Setup()
    {
    }

    [Test]
    public void TestTryGetIndirectSignatureAlgorithmSuccess()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestTryGetIndirectSignatureAlgorithmSuccess));
        IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);

        CoseSign1Message IndirectSignature = factory.CreateIndirectSignature(randomBytes, coseSigningKeyProvider, "application/test.payload", useOldFormat: true);
        IndirectSignature.TryGetIndirectSignatureAlgorithm(out HashAlgorithmName hashAlgorithmName).Should().BeTrue();
        hashAlgorithmName.Should().Be(HashAlgorithmName.SHA256);
    }

    [Test]
    public void TestTryGetIndirectSignatureAlgorithmFailure()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestTryGetIndirectSignatureAlgorithmFailure));

        // no content type
        Mock<ICoseHeaderExtender> removeContentTypeHeaderExtender = new Mock<ICoseHeaderExtender>(MockBehavior.Strict);
        removeContentTypeHeaderExtender.Setup(m => m.ExtendProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns<CoseHeaderMap>((input) =>
        {
            // remove ContentType
            if (input.ContainsKey(CoseHeaderLabel.ContentType))
            {
                input.Remove(CoseHeaderLabel.ContentType);
            }
            return input;
        });
        removeContentTypeHeaderExtender.Setup(m => m.ExtendUnProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns<CoseHeaderMap>((input) => input);

        // empty content type
        Mock<ICoseHeaderExtender> emptyContentTypeHeaderExtender = new Mock<ICoseHeaderExtender>(MockBehavior.Strict);
        emptyContentTypeHeaderExtender.Setup(m => m.ExtendProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns<CoseHeaderMap>((input) =>
        {
            // remove content type
            input = removeContentTypeHeaderExtender.Object.ExtendProtectedHeaders(input);

            // add content type with an empty string value
            input.Add(CoseHeaderLabel.ContentType, string.Empty);

            return input;
        });
        emptyContentTypeHeaderExtender.Setup(m => m.ExtendUnProtectedHeaders(It.IsAny<CoseHeaderMap>())).Returns<CoseHeaderMap>((input) => input);

        IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);

        // call TryGetIndirectSignatureAlgoithm on a null message object should fail
        CoseSign1Message? objectUnderTest = null;
        objectUnderTest.TryGetIndirectSignatureAlgorithm(out HashAlgorithmName hashAlgorithmName).Should().BeFalse();

        // call TryGetIndirectSignatureAlgorithm on a CoseSign1Message with no ContentType header should fail
        objectUnderTest = factory.MessageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: true, @"application\test.output", removeContentTypeHeaderExtender.Object);
        objectUnderTest.TryGetIndirectSignatureAlgorithm(out hashAlgorithmName).Should().BeFalse("missing content type should fail the test");

        // call TryGetIndirectSignatureAlgorithm on a CoseSign1Message with empty ContentType should fail
        objectUnderTest = factory.MessageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: true, @"application\test.output", emptyContentTypeHeaderExtender.Object);
        objectUnderTest.TryGetIndirectSignatureAlgorithm(out hashAlgorithmName).Should().BeFalse("empty content type should fail the test");

        // call TryGetIndirectSignatureAlgorithm on a CoseSign1Message with invalid mime type hash extension ContentType should fail
        objectUnderTest = factory.MessageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: true, @"application\test.output");
        objectUnderTest.TryGetIndirectSignatureAlgorithm(out hashAlgorithmName).Should().BeFalse("missing mime type hash extension in content type should fail the test");

        // call TryGetIndirectSignatureAlgorithm on a CoseSign1Message with invalid mime type hash extension ContentType should succeed
        objectUnderTest = factory.MessageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: true, @"application\test.output+hash-notavalidvalue");
        objectUnderTest.TryGetIndirectSignatureAlgorithm(out hashAlgorithmName).Should().BeTrue("invalid mime type hash extension in content type should not fail this call");
    }

    [Test]
    public void TestIsIndirectSignatureSuccess()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestIsIndirectSignatureSuccess));
        IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);

        CoseSign1Message IndirectSignature = factory.CreateIndirectSignature(randomBytes, coseSigningKeyProvider, "application/test.payload");
        IndirectSignature.IsIndirectSignature().Should().BeTrue();
    }

    [Test]
    public void TestIsIndirectSignatureFailure()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestIsIndirectSignatureFailure));
        IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);

        CoseSign1Message IndirectSignature = factory.MessageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: true, "application/test.payload");
        IndirectSignature.IsIndirectSignature().Should().BeFalse();
    }

    [Test]
    public void TestSignatureMatchesStreamSuccess()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestSignatureMatchesStreamSuccess));
        IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        using MemoryStream stream = new(randomBytes);

        CoseSign1Message IndirectSignature = factory.CreateIndirectSignature(randomBytes, coseSigningKeyProvider, "application/test.payload");
        IndirectSignature.SignatureMatches(stream).Should().BeTrue();
    }

    [Test]
    public void TestSignatureMatchesStreamFailure()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestSignatureMatchesStreamFailure));
        IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        byte[] randomBytes2 = new byte[50];
        new Random().NextBytes(randomBytes);
        new Random().NextBytes(randomBytes2);
        using MemoryStream stream = new(randomBytes2);

        // test mismatched signature
        CoseSign1Message? IndirectSignature = factory.CreateIndirectSignature(randomBytes, coseSigningKeyProvider, "application/test.payload");
        IndirectSignature.SignatureMatches(stream).Should().BeFalse();
        stream.Dispose();
        using MemoryStream stream2 = new(randomBytes);

        // test invalid hash extension case
        IndirectSignature = factory.MessageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: true, "application/test.payload");
        IndirectSignature.SignatureMatches(stream2).Should().BeFalse();
        stream2.Seek(stream2.Length, SeekOrigin.Begin);

        // test null object case
        IndirectSignature = null;
        CoseSign1MessageIndirectSignatureExtensions.SignatureMatches(IndirectSignature, stream2).Should().BeFalse();
    }

    [Test]
    public void TestSignatureMatchesBytesSuccess()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestSignatureMatchesBytesSuccess));
        IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);

        CoseSign1Message IndirectSignature = factory.CreateIndirectSignature(randomBytes, coseSigningKeyProvider, "application/test.payload");
        IndirectSignature.SignatureMatches(randomBytes).Should().BeTrue();
    }

    [Test]
    public void TestSignatureMatchesBytesFailure()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestSignatureMatchesBytesFailure));
        IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        byte[] randomBytes2 = new byte[50];
        new Random().NextBytes(randomBytes);
        new Random().NextBytes(randomBytes2);

        // test mismatched signature
        CoseSign1Message? IndirectSignature = factory.CreateIndirectSignature(randomBytes, coseSigningKeyProvider, "application/test.payload");
        IndirectSignature.SignatureMatches(randomBytes2).Should().BeFalse();

        // test invalid hash extension case
        IndirectSignature = factory.MessageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: true, "application/test.payload");
        IndirectSignature.SignatureMatches(randomBytes).Should().BeFalse();

        // test null object case
        IndirectSignature = null;
        CoseSign1MessageIndirectSignatureExtensions.SignatureMatches(IndirectSignature, randomBytes).Should().BeFalse();
    }

    [Test]
    public void TestTryGetHashAlgorithmSuccess()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestTryGetHashAlgorithmSuccess));
        IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);

        CoseSign1Message IndirectSignature = factory.CreateIndirectSignature(randomBytes, coseSigningKeyProvider, "application/test.payload", useOldFormat: true);
        IndirectSignature.TryGetHashAlgorithm(out HashAlgorithm? hashAlgorithm).Should().BeTrue();
        hashAlgorithm.Should().NotBeNull();
        hashAlgorithm.Should().BeAssignableTo<SHA256>();
    }

    [Test]
    public void TestTryGetHashAlgorithmFailure()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestTryGetHashAlgorithmFailure));
        IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        byte[] randomBytes2 = new byte[50];
        new Random().NextBytes(randomBytes);
        new Random().NextBytes(randomBytes2);

        // Fail to extract a hash algorithm name
        CoseSign1Message? IndirectSignature = factory.MessageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: true, "application/test.payload");
        IndirectSignature.TryGetHashAlgorithm(out HashAlgorithm? hashAlgorithm).Should().BeFalse();
        hashAlgorithm.Should().BeNull();

        // COSE Sign1 Indirect signature case with other things being valid
        // content should be null in this case.
        IndirectSignature = factory.MessageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: false, "application/test.payload+hash-sha256");
        IndirectSignature.TryGetHashAlgorithm(out hashAlgorithm).Should().BeFalse();
        hashAlgorithm.Should().BeNull();

        // Invalid hash definition case
        IndirectSignature = factory.MessageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: true, "application/test.payload+hash-notavalidhashalgorithm");
        IndirectSignature.TryGetHashAlgorithm(out hashAlgorithm).Should().BeFalse();
        hashAlgorithm.Should().BeNull();

        // test null object case
        IndirectSignature = null;
        CoseSign1MessageIndirectSignatureExtensions.TryGetHashAlgorithm(IndirectSignature, out hashAlgorithm).Should().BeFalse();
        hashAlgorithm.Should().BeNull();
    }

    private ICoseSigningKeyProvider SetupMockSigningKeyProvider(string testName)
    {
        Mock<ICoseSigningKeyProvider> mockedSignerKeyProvider = new(MockBehavior.Strict);
        X509Certificate2 selfSignedCertWithRSA = TestCertificateUtils.CreateCertificate(testName);

        mockedSignerKeyProvider.Setup(x => x.GetProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.GetUnProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.HashAlgorithm).Returns(HashAlgorithmName.SHA256);
        mockedSignerKeyProvider.Setup(x => x.GetECDsaKey(It.IsAny<bool>())).Returns<ECDsa>(null);
        mockedSignerKeyProvider.Setup(x => x.GetRSAKey(It.IsAny<bool>())).Returns(selfSignedCertWithRSA.GetRSAPrivateKey());
        mockedSignerKeyProvider.Setup(x => x.IsRSA).Returns(true);

        return mockedSignerKeyProvider.Object;
    }
}
