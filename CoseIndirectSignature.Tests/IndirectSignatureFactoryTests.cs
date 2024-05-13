// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseIndirectSignature.Tests;

using System.Runtime.CompilerServices;

/// <summary>
/// Class for Testing Methods of <see cref="IndirectSignatureFactory"/>
/// </summary>
public class IndirectSignatureFactoryTests
{
    [SetUp]
    public void Setup()
    {
    }

    [Test]
    public void TestConstructors()
    {
        Mock<ICoseSign1MessageFactory> mockFactory = new(MockBehavior.Strict);
        using IndirectSignatureFactory factory = new();
        using IndirectSignatureFactory factory2 = new(HashAlgorithmName.SHA384);
        using IndirectSignatureFactory factory3 = new(HashAlgorithmName.SHA512, mockFactory.Object);

        factory.HashAlgorithm.Should().BeAssignableTo<SHA256>();
        factory.HashAlgorithmName.Should().Be(HashAlgorithmName.SHA256);
        factory.MessageFactory.Should().BeOfType<CoseSign1MessageFactory>();

        factory2.HashAlgorithm.Should().BeAssignableTo<SHA384>();
        factory2.HashAlgorithmName.Should().Be(HashAlgorithmName.SHA384);
        factory2.MessageFactory.Should().BeOfType<CoseSign1MessageFactory>();

        factory3.HashAlgorithm.Should().BeAssignableTo<SHA512>();
        factory3.HashAlgorithmName.Should().Be(HashAlgorithmName.SHA512);
        factory3.MessageFactory.Should().Be(mockFactory.Object);
    }

    [Test]
    public async Task TestCreateIndirectSignatureAsync()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider();
        using IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        using MemoryStream memStream = new(randomBytes);

        // test the sync method
        Assert.Throws<ArgumentNullException>(() => factory.CreateIndirectSignature(randomBytes, coseSigningKeyProvider, string.Empty));
        CoseSign1Message IndirectSignature = factory.CreateIndirectSignature(randomBytes, coseSigningKeyProvider, "application/test.payload");
        IndirectSignature.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.Throws<ArgumentNullException>(() => factory.CreateIndirectSignature(memStream, coseSigningKeyProvider, string.Empty));
        memStream.Seek(0, SeekOrigin.Begin);
        CoseSign1Message IndirectSignature2 = factory.CreateIndirectSignature(memStream, coseSigningKeyProvider, "application/test.payload");
        IndirectSignature2.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature2.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature2.SignatureMatches(randomBytes).Should().BeTrue();
        memStream.Seek(0, SeekOrigin.Begin);

        // test the async methods
        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateIndirectSignatureAsync(randomBytes, coseSigningKeyProvider, string.Empty));
        CoseSign1Message IndirectSignature3 = await factory.CreateIndirectSignatureAsync(randomBytes, coseSigningKeyProvider, "application/test.payload");
        IndirectSignature3.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature3.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature3.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateIndirectSignatureAsync(memStream, coseSigningKeyProvider, string.Empty));
        memStream.Seek(0, SeekOrigin.Begin);
        CoseSign1Message IndirectSignature4 = await factory.CreateIndirectSignatureAsync(memStream, coseSigningKeyProvider, "application/test.payload");
        IndirectSignature4.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature4.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature4.SignatureMatches(randomBytes).Should().BeTrue();
        memStream.Seek(0, SeekOrigin.Begin);
    }

    [Test]
    public async Task TestCreateIndirectSignatureHashProvidedAsync()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider();
        using IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        using HashAlgorithm hasher = CoseSign1MessageIndirectSignatureExtensions.CreateHashAlgorithmFromName(factory.HashAlgorithmName)
                         ?? throw new Exception($"Failed to get hash algorithm from {nameof(CoseSign1MessageIndirectSignatureExtensions.CreateHashAlgorithmFromName)}");
        byte[] hash = hasher!.ComputeHash(randomBytes);
        using MemoryStream hashStream = new(hash);

        // test the sync method
        Assert.Throws<ArgumentNullException>(() => factory.CreateIndirectSignatureFromHash(hash, coseSigningKeyProvider, string.Empty));
        CoseSign1Message IndirectSignature = factory.CreateIndirectSignatureFromHash(hash, coseSigningKeyProvider, "application/test.payload");
        IndirectSignature.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.Throws<ArgumentNullException>(() => factory.CreateIndirectSignature(hashStream, coseSigningKeyProvider, string.Empty));
        hashStream.Seek(0, SeekOrigin.Begin);
        CoseSign1Message IndirectSignature2 = factory.CreateIndirectSignatureFromHash(hashStream, coseSigningKeyProvider, "application/test.payload");
        IndirectSignature2.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature2.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature2.SignatureMatches(randomBytes).Should().BeTrue();
        hashStream.Seek(0, SeekOrigin.Begin);

        // test the async methods
        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateIndirectSignatureFromHashAsync(hash, coseSigningKeyProvider, string.Empty));
        CoseSign1Message IndirectSignature3 = await factory.CreateIndirectSignatureFromHashAsync(hash, coseSigningKeyProvider, "application/test.payload");
        IndirectSignature3.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature3.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature3.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateIndirectSignatureFromHashAsync(hashStream, coseSigningKeyProvider, string.Empty));
        hashStream.Seek(0, SeekOrigin.Begin);
        CoseSign1Message IndirectSignature4 = await factory.CreateIndirectSignatureFromHashAsync(hashStream, coseSigningKeyProvider, "application/test.payload");
        IndirectSignature4.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature4.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature4.SignatureMatches(randomBytes).Should().BeTrue();
        hashStream.Seek(0, SeekOrigin.Begin);
    }

    [Test]
    public async Task TestCreateIndirectSignatureBytesAsync()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider();
        using IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        using MemoryStream memStream = new(randomBytes);

        // test the sync method
        Assert.Throws<ArgumentNullException>(() => factory.CreateIndirectSignatureBytes(randomBytes, coseSigningKeyProvider, string.Empty));
        CoseSign1Message IndirectSignature = CoseMessage.DecodeSign1(factory.CreateIndirectSignatureBytes(randomBytes, coseSigningKeyProvider, "application/test.payload").ToArray());
        IndirectSignature.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.Throws<ArgumentNullException>(() => factory.CreateIndirectSignatureBytes(memStream, coseSigningKeyProvider, string.Empty));
        memStream.Seek(0, SeekOrigin.Begin);
        CoseSign1Message IndirectSignature2 = CoseMessage.DecodeSign1(factory.CreateIndirectSignatureBytes(memStream, coseSigningKeyProvider, "application/test.payload").ToArray());
        IndirectSignature2.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature2.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature2.SignatureMatches(randomBytes).Should().BeTrue();
        memStream.Seek(0, SeekOrigin.Begin);

        // test the async methods
        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateIndirectSignatureBytesAsync(randomBytes, coseSigningKeyProvider, string.Empty));
        CoseSign1Message IndirectSignature3 = CoseMessage.DecodeSign1((await factory.CreateIndirectSignatureBytesAsync(randomBytes, coseSigningKeyProvider, "application/test.payload")).ToArray());
        IndirectSignature3.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature3.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature3.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateIndirectSignatureBytesAsync(memStream, coseSigningKeyProvider, string.Empty));
        memStream.Seek(0, SeekOrigin.Begin);
        CoseSign1Message IndirectSignature4 = CoseMessage.DecodeSign1((await factory.CreateIndirectSignatureBytesAsync(memStream, coseSigningKeyProvider, "application/test.payload")).ToArray());
        IndirectSignature4.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature4.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        memStream.Seek(0, SeekOrigin.Begin);
        IndirectSignature4.SignatureMatches(memStream).Should().BeTrue();
    }

    [Test]
    public async Task TestCreateIndirectSignatureBytesHashProvidedAsync()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider();
        using IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        using HashAlgorithm hasher = CoseSign1MessageIndirectSignatureExtensions.CreateHashAlgorithmFromName(factory.HashAlgorithmName)
                 ?? throw new Exception($"Failed to get hash algorithm from {nameof(CoseSign1MessageIndirectSignatureExtensions.CreateHashAlgorithmFromName)}");
        byte[] hash = hasher!.ComputeHash(randomBytes);
        using MemoryStream hashStream = new(hash);

        // test the sync method
        Assert.Throws<ArgumentNullException>(() => factory.CreateIndirectSignatureBytesFromHash(hash, coseSigningKeyProvider, string.Empty));
        CoseSign1Message IndirectSignature = CoseMessage.DecodeSign1(factory.CreateIndirectSignatureBytesFromHash(hash, coseSigningKeyProvider, "application/test.payload").ToArray());
        IndirectSignature.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.Throws<ArgumentNullException>(() => factory.CreateIndirectSignatureBytesFromHash(hashStream, coseSigningKeyProvider, string.Empty));
        hashStream.Seek(0, SeekOrigin.Begin);
        CoseSign1Message IndirectSignature2 = CoseMessage.DecodeSign1(factory.CreateIndirectSignatureBytesFromHash(hashStream, coseSigningKeyProvider, "application/test.payload").ToArray());
        IndirectSignature2.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature2.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature2.SignatureMatches(randomBytes).Should().BeTrue();
        hashStream.Seek(0, SeekOrigin.Begin);

        // test the async methods
        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateIndirectSignatureBytesFromHashAsync(hash, coseSigningKeyProvider, string.Empty));
        CoseSign1Message IndirectSignature3 = CoseMessage.DecodeSign1((await factory.CreateIndirectSignatureBytesFromHashAsync(hash, coseSigningKeyProvider, "application/test.payload")).ToArray());
        IndirectSignature3.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature3.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature3.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateIndirectSignatureBytesFromHashAsync(hashStream, coseSigningKeyProvider, string.Empty));
        hashStream.Seek(0, SeekOrigin.Begin);
        CoseSign1Message IndirectSignature4 = CoseMessage.DecodeSign1((await factory.CreateIndirectSignatureBytesFromHashAsync(hashStream, coseSigningKeyProvider, "application/test.payload")).ToArray());
        IndirectSignature4.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature4.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        hashStream.Seek(0, SeekOrigin.Begin);
        IndirectSignature4.SignatureMatches(randomBytes).Should().BeTrue();
    }

    [Test]
    public void TestCreateIndirectSignatureMd5Failure()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider();
        Action act = () => { IndirectSignatureFactory factory = new(HashAlgorithmName.MD5); };
        act.Should().Throw<ArgumentException>();
    }

    [Test]
    public void TestCreateIndirectSignatureMd5HashProvidedFailure()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider();
        using IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        using HashAlgorithm hasher = CoseSign1MessageIndirectSignatureExtensions.CreateHashAlgorithmFromName(HashAlgorithmName.MD5)
         ?? throw new Exception($"Failed to get hash algorithm from {nameof(CoseSign1MessageIndirectSignatureExtensions.CreateHashAlgorithmFromName)}");
        byte[] hash = hasher!.ComputeHash(randomBytes);

        // test the sync method
        Assert.Throws<ArgumentNullException>(() => factory.CreateIndirectSignatureFromHash(hash, coseSigningKeyProvider, string.Empty));
        Assert.Throws<ArgumentException>(() => factory.CreateIndirectSignatureBytesFromHash(hash, coseSigningKeyProvider, "application/test.payload"));
    }

    [Test]
    public void TestCreateIndirectSignatureAlreadyProvided()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider();
        using IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        using HashAlgorithm hasher = CoseSign1MessageIndirectSignatureExtensions.CreateHashAlgorithmFromName(factory.HashAlgorithmName)
                                     ?? throw new Exception($"Failed to get hash algorithm from {nameof(CoseSign1MessageIndirectSignatureExtensions.CreateHashAlgorithmFromName)}");
        ReadOnlyMemory<byte> hash = hasher!.ComputeHash(randomBytes);

        // test the sync method
        Assert.Throws<ArgumentNullException>(() => factory.CreateIndirectSignature(hash, coseSigningKeyProvider, string.Empty));
        CoseSign1Message IndirectSignature = CoseMessage.DecodeSign1(factory.CreateIndirectSignatureBytes(randomBytes, coseSigningKeyProvider, "application/test.payload").ToArray());
        IndirectSignature.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature.SignatureMatches(randomBytes).Should().BeTrue();
    }

    private ICoseSigningKeyProvider SetupMockSigningKeyProvider([CallerMemberName] string testName = "none")
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
