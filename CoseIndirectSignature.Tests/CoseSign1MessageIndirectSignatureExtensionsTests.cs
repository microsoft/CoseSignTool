// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Ignore Spelling: Cose

namespace CoseIndirectSignature.Tests;

//using Microsoft.VisualStudio.TestTools.UnitTesting;

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
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider();
        IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
#pragma warning disable CS0618 // Type or member is obsolete
        CoseSign1Message IndirectSignature = factory.CreateIndirectSignature(randomBytes, coseSigningKeyProvider, "application/test.payload", IndirectSignatureFactory.IndirectSignatureVersion.Direct);
#pragma warning restore CS0618 // Type or member is obsolete
        IndirectSignature.TryGetIndirectSignatureAlgorithm(out HashAlgorithmName hashAlgorithmName).Should().BeTrue();
        hashAlgorithmName.Should().Be(HashAlgorithmName.SHA256);
    }

    [Test]
    public void TestTryGetIndirectSignatureAlgorithmFailure()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider();

        // no content type
        Mock<ICoseHeaderExtender> removeContentTypeHeaderExtender = new(MockBehavior.Strict);
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
        Mock<ICoseHeaderExtender> emptyContentTypeHeaderExtender = new(MockBehavior.Strict);
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
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider();
        IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
#pragma warning disable CS0618 // Type or member is obsolete
        CoseSign1Message IndirectSignature = factory.CreateIndirectSignature(randomBytes, coseSigningKeyProvider, "application/test.payload", IndirectSignatureFactory.IndirectSignatureVersion.Direct);
#pragma warning restore CS0618 // Type or member is obsolete
        IndirectSignature.IsIndirectSignature().Should().BeTrue();
    }

    [Test]
    public void TestIsIndirectSignatureFailure()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider();
        IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);

        CoseSign1Message IndirectSignature = factory.MessageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: true, "application/test.payload");
        IndirectSignature.IsIndirectSignature().Should().BeFalse();
    }

    [Test]
    public void TestSignatureMatchesStreamSuccess()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider();
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
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider();
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
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider();
        IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);

        CoseSign1Message IndirectSignature = factory.CreateIndirectSignature(randomBytes, coseSigningKeyProvider, "application/test.payload");
        IndirectSignature.SignatureMatches(randomBytes).Should().BeTrue();
    }

    [Test]
    public void TestSignatureMatchesBytesFailure()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider();
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
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider();
        IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);

#pragma warning disable CS0618 // Type or member is obsolete
        CoseSign1Message IndirectSignature = factory.CreateIndirectSignature(randomBytes, coseSigningKeyProvider, "application/test.payload", IndirectSignatureFactory.IndirectSignatureVersion.Direct);
#pragma warning restore CS0618 // Type or member is obsolete
        IndirectSignature.TryGetHashAlgorithm(out HashAlgorithm? hashAlgorithm).Should().BeTrue();
        hashAlgorithm.Should().NotBeNull();
        hashAlgorithm.Should().BeAssignableTo<SHA256>();
    }

    [Test]
    [TestCase(1, Description = "Success return")]
    [TestCase(2, Description = "Invalid CoseHashV - ContentType")]
    [TestCase(3, Description = "Invalid CoseHashV - detached signature")]
    [TestCase(4, Description = "Invalid CoseHshV - invalid content")]
    [TestCase(5, Description = "Success TryGet")]
    [TestCase(6, Description = "Failure TryGet")]
    [TestCase(7, Description = "Get - Null")]
    [TestCase(8, Description = "TryGet - Null")]
    public void TestGetCoseHashVScenarios(int testCase)
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider();
        IndirectSignatureFactory signaturefactory = new();
        CoseSign1MessageFactory messageFactory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);

        switch (testCase)
        {
            // test the fetching case
            case 1:
                CoseSign1Message? testObj1 = signaturefactory.CreateIndirectSignature(randomBytes, coseSigningKeyProvider, "application/test.payload", useOldFormat: true);
                CoseHashV hashObject = testObj1.GetCoseHashV();
                hashObject.ContentMatches(randomBytes).Should().BeTrue();
                break;
            // test the invalid content type case.
            case 2:
                CoseSign1Message? testObj2 = messageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: true, "application/test.payload+hash-sha256");
                Action test2 = () => testObj2.GetCoseHashV();
                test2.Should().Throw<InvalidDataException>();
                break;
            // test detached signature.
            case 3:
                CoseSign1Message? testObj3 = messageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: false, "application/test.payload+hash-sha256");
                Action test3 = () => testObj3.GetCoseHashV();
                test3.Should().Throw<InvalidDataException>();
                break;
            // test invalid content
            case 4:
                CoseSign1Message? testObj4 = messageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: true, "application/test.payload+cose-hash-v");
                Action test4 = () => testObj4.GetCoseHashV();
                test4.Should().Throw<InvalidCoseDataException>();
                break;
            // tryget success
            case 5:
                CoseSign1Message? testObj5 = signaturefactory.CreateIndirectSignature(randomBytes, coseSigningKeyProvider, "application/test.payload", useOldFormat: true);
                testObj5.TryGetCoseHashV(out CoseHashV? hashObject5).Should().BeTrue();
                hashObject5.ContentMatches(randomBytes).Should().BeTrue();
                break;
            // tryget failure
            case 6:
                CoseSign1Message? testObj6 = messageFactory.CreateCoseSign1Message(randomBytes, coseSigningKeyProvider, embedPayload: false, "application/test.payload+hash-sha256");
                testObj6.TryGetCoseHashV(out _).Should().BeFalse();
                break;
            // get null
            case 7:
#nullable disable
                Action test7 = () => ((CoseSign1Message)null).GetCoseHashV();
#nullable enable
                test7.Should().Throw<InvalidDataException>();
                break;
            // tryget null
            case 8:
#nullable disable
                ((CoseSign1Message)null).TryGetCoseHashV(out _).Should().BeFalse();
#nullable enable
                break;
            default:
                throw new InvalidDataException($"TestCase {testCase} is not defined in {nameof(TestGetCoseHashVScenarios)}");
        }
    }

    [Test]
    public void TestTryGetHashAlgorithmFailure()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider();
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

    private static ICoseSigningKeyProvider SetupMockSigningKeyProvider([CallerMemberName] string testName = "none")
    {
        Mock<ICoseSigningKeyProvider> mockedSignerKeyProvider = new(MockBehavior.Strict);
        X509Certificate2 selfSignedCertWithRSA = TestCertificateUtils.CreateCertificate(testName);

        mockedSignerKeyProvider.Setup(x => x.GetProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.GetUnProtectedHeaders()).Returns<CoseHeaderMap>(null);
        mockedSignerKeyProvider.Setup(x => x.HashAlgorithm).Returns(HashAlgorithmName.SHA256);
        mockedSignerKeyProvider.Setup(x => x.GetECDsaKey(It.IsAny<bool>())).Returns<ECDsa>(null);
        mockedSignerKeyProvider.Setup(x => x.GetRSAKey(It.IsAny<bool>())).Returns(selfSignedCertWithRSA.GetRSAPrivateKey());
        mockedSignerKeyProvider.Setup(x => x.IsRSA).Returns(true);

        // Setup KeyChain property to return the public key from the certificate
        RSA? publicKey = selfSignedCertWithRSA.GetRSAPublicKey();
        System.Collections.ObjectModel.ReadOnlyCollection<AsymmetricAlgorithm> keyChain = publicKey != null ? new List<AsymmetricAlgorithm> { publicKey }.AsReadOnly() : new List<AsymmetricAlgorithm>().AsReadOnly();
        mockedSignerKeyProvider.Setup(x => x.KeyChain).Returns(keyChain);

        return mockedSignerKeyProvider.Object;
    }
}
