// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Tests;

using System.IO;

/// <summary>
/// Class for Testing Methods of <see cref="CoseSign1MessageDetachedSignatureExtensions"/>
/// </summary>
public class CoseSign1MessageDetachedSignatureExtensionsTests
{
    [SetUp]
    public void Setup()
    {
    }

    [Test]
    public void TestTryGetDetachedSignatureAlgorithmSuccess()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestTryGetDetachedSignatureAlgorithmSuccess));
        DetachedSignatureFactory factory = new DetachedSignatureFactory();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);

        CoseSign1Message detachedSignature = factory.CreateDetachedSignature(randomBytes, coseSigningKeyProvider, "application/test.payload");
        detachedSignature.TryGetDetachedSignatureAlgorithm(out HashAlgorithmName hashAlgorithmName).Should().BeTrue();
        hashAlgorithmName.Should().Be(HashAlgorithmName.SHA256);
    }

    [Test]
    public void TestTryGetDetachedSignatureAlgorithmFailure()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestTryGetDetachedSignatureAlgorithmFailure));

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

        DetachedSignatureFactory factory = new DetachedSignatureFactory();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);

        // call TryGetDetachedSignatureAlgoithm on a null message object should fail
        CoseSign1Message? objectUnderTest = null;
        objectUnderTest.TryGetDetachedSignatureAlgorithm(out HashAlgorithmName hashAlgorithmName).Should().BeFalse();

        // call TryGetDetachedSignatureAlgorithm on a CoseSign1Message with no ContentType header should fail
        objectUnderTest = factory.MessageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: true, @"application\test.output", removeContentTypeHeaderExtender.Object);
        objectUnderTest.TryGetDetachedSignatureAlgorithm(out hashAlgorithmName).Should().BeFalse("missing content type should fail the test");

        // call TryGetDetachedSignatureAlgorithm on a CoseSign1Message with empty ContentType should fail
        objectUnderTest = factory.MessageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: true, @"application\test.output", emptyContentTypeHeaderExtender.Object);
        objectUnderTest.TryGetDetachedSignatureAlgorithm(out hashAlgorithmName).Should().BeFalse("empty content type should fail the test");

        // call TryGetDetachedSignatureAlgorithm on a CoseSign1Message with invalid mime type hash extension ContentType should fail
        objectUnderTest = factory.MessageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: true, @"application\test.output");
        objectUnderTest.TryGetDetachedSignatureAlgorithm(out hashAlgorithmName).Should().BeFalse("missing mime type hash extension in content type should fail the test");

        // call TryGetDetachedSignatureAlgorithm on a CoseSign1Message with invalid mime type hash extension ContentType should succeed
        objectUnderTest = factory.MessageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: true, @"application\test.output+hash-notavalidvalue");
        objectUnderTest.TryGetDetachedSignatureAlgorithm(out hashAlgorithmName).Should().BeTrue("invalid mime type hash extension in content type should not fail this call");
    }

    [Test]
    public void TestIsDetachedSignatureSuccess()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestTryGetDetachedSignatureAlgorithmSuccess));
        DetachedSignatureFactory factory = new DetachedSignatureFactory();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);

        CoseSign1Message detachedSignature = factory.CreateDetachedSignature(randomBytes, coseSigningKeyProvider, "application/test.payload");
        detachedSignature.IsDetachedSignature().Should().BeTrue();
    }

    [Test]
    public void TestIsDetachedSignatureFailure()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestTryGetDetachedSignatureAlgorithmSuccess));
        DetachedSignatureFactory factory = new DetachedSignatureFactory();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);

        CoseSign1Message detachedSignature = factory.MessageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: true, "application/test.payload");
        detachedSignature.IsDetachedSignature().Should().BeFalse();
    }

    [Test]
    public void TestSignatureMatchesStreamSuccess()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestTryGetDetachedSignatureAlgorithmSuccess));
        DetachedSignatureFactory factory = new DetachedSignatureFactory();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        using MemoryStream stream = new MemoryStream(randomBytes);

        CoseSign1Message detachedSignature = factory.CreateDetachedSignature(randomBytes, coseSigningKeyProvider, "application/test.payload");
        detachedSignature.SignatureMatches(stream).Should().BeTrue();
    }

    [Test]
    public void TestSignatureMatchesStreamFailure()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestTryGetDetachedSignatureAlgorithmSuccess));
        DetachedSignatureFactory factory = new DetachedSignatureFactory();
        byte[] randomBytes = new byte[50];
        byte[] randomBytes2 = new byte[50];
        new Random().NextBytes(randomBytes);
        new Random().NextBytes(randomBytes2);
        MemoryStream stream = new MemoryStream(randomBytes2);

        // test mismatched signature
        CoseSign1Message? detachedSignature = factory.CreateDetachedSignature(randomBytes, coseSigningKeyProvider, "application/test.payload");
        detachedSignature.SignatureMatches(stream).Should().BeFalse();
        stream.Dispose();
        stream = new MemoryStream(randomBytes);

        // test invalid hash extension case
        detachedSignature = factory.MessageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: true, "application/test.payload");
        detachedSignature.SignatureMatches(stream).Should().BeFalse();
        stream.Seek(stream.Length, SeekOrigin.Begin);

        // test null object case
        detachedSignature = null;
        detachedSignature.SignatureMatches(stream).Should().BeFalse();
        stream.Dispose();
    }

    [Test]
    public void TestSignatureMatchesBytesSuccess()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestTryGetDetachedSignatureAlgorithmSuccess));
        DetachedSignatureFactory factory = new DetachedSignatureFactory();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);

        CoseSign1Message detachedSignature = factory.CreateDetachedSignature(randomBytes, coseSigningKeyProvider, "application/test.payload");
        detachedSignature.SignatureMatches(randomBytes).Should().BeTrue();
    }

    [Test]
    public void TestSignatureMatchesBytesFailure()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestTryGetDetachedSignatureAlgorithmSuccess));
        DetachedSignatureFactory factory = new DetachedSignatureFactory();
        byte[] randomBytes = new byte[50];
        byte[] randomBytes2 = new byte[50];
        new Random().NextBytes(randomBytes);
        new Random().NextBytes(randomBytes2);

        // test mismatched signature
        CoseSign1Message? detachedSignature = factory.CreateDetachedSignature(randomBytes, coseSigningKeyProvider, "application/test.payload");
        detachedSignature.SignatureMatches(randomBytes2).Should().BeFalse();

        // test invalid hash extension case
        detachedSignature = factory.MessageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: true, "application/test.payload");
        detachedSignature.SignatureMatches(randomBytes).Should().BeFalse();

        // test null object case
        detachedSignature = null;
        detachedSignature.SignatureMatches(randomBytes).Should().BeFalse();
    }

    [Test]
    public void TestTryGetHashAlgorithmSuccess()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestTryGetDetachedSignatureAlgorithmSuccess));
        DetachedSignatureFactory factory = new DetachedSignatureFactory();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);

        CoseSign1Message detachedSignature = factory.CreateDetachedSignature(randomBytes, coseSigningKeyProvider, "application/test.payload");
        detachedSignature.TryGetHashAlgorithm(out HashAlgorithm hashAlgorithm).Should().BeTrue();
        hashAlgorithm.Should().NotBeNull();
        hashAlgorithm.Should().BeAssignableTo<SHA256>();
    }

    [Test]
    public void TestTryGetHashAlgorithmFailure()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestTryGetDetachedSignatureAlgorithmSuccess));
        DetachedSignatureFactory factory = new DetachedSignatureFactory();
        byte[] randomBytes = new byte[50];
        byte[] randomBytes2 = new byte[50];
        new Random().NextBytes(randomBytes);
        new Random().NextBytes(randomBytes2);

        // Fail to extract a hash algorithm name
        CoseSign1Message? detachedSignature = factory.MessageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: true, "application/test.payload");
        detachedSignature.TryGetHashAlgorithm(out HashAlgorithm hashAlgorithm).Should().BeFalse();
        hashAlgorithm.Should().BeNull();

        // COSE Sign1 Detached signature case with other things being valid
        // content should be null in this case.
        detachedSignature = factory.MessageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: false, "application/test.payload+hash-sha256");
        detachedSignature.TryGetHashAlgorithm(out hashAlgorithm).Should().BeFalse();
        hashAlgorithm.Should().BeNull();

        // Invalid hash definition case
        detachedSignature = factory.MessageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: true, "application/test.payload+hash-notavalidhashalgorithm");
        detachedSignature.TryGetHashAlgorithm(out hashAlgorithm).Should().BeFalse();
        hashAlgorithm.Should().BeNull();

        // test null object case
        detachedSignature = null;
        detachedSignature.TryGetHashAlgorithm(out hashAlgorithm).Should().BeFalse();
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
