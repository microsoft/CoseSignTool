// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseDetachedSignature.Tests;

/// <summary>
/// Class for Testing Methods of <see cref="DetachedSignatureFactory"/>
/// </summary>
public class DetachedSignatureFactoryTests
{
    [SetUp]
    public void Setup()
    {
    }

    [Test]
    public void TestConstructors()
    {
        Mock<ICoseSign1MessageFactory> mockFactory = new(MockBehavior.Strict);
        using DetachedSignatureFactory factory = new();
        using DetachedSignatureFactory factory2 = new(HashAlgorithmName.SHA384);
        using DetachedSignatureFactory factory3 = new(HashAlgorithmName.SHA512, mockFactory.Object);

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
    public async Task TestCreateDetachedSignatureAsync()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestCreateDetachedSignatureAsync));
        using DetachedSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        using MemoryStream memStream = new(randomBytes);

        // test the sync method
        Assert.Throws<ArgumentNullException>(() => factory.CreateDetachedSignature(randomBytes, coseSigningKeyProvider, string.Empty));
        CoseSign1Message detachedSignature = factory.CreateDetachedSignature(randomBytes, coseSigningKeyProvider, "application/test.payload");
        detachedSignature.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        detachedSignature.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+hash-sha256");
        detachedSignature.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.Throws<ArgumentNullException>(() => factory.CreateDetachedSignature(memStream, coseSigningKeyProvider, string.Empty));
        memStream.Seek(0, SeekOrigin.Begin);
        CoseSign1Message detachedSignature2 = factory.CreateDetachedSignature(memStream, coseSigningKeyProvider, "application/test.payload");
        detachedSignature2.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        detachedSignature2.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+hash-sha256");
        detachedSignature2.SignatureMatches(randomBytes).Should().BeTrue();
        memStream.Seek(0, SeekOrigin.Begin);

        // test the async methods
        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateDetachedSignatureAsync(randomBytes, coseSigningKeyProvider, string.Empty));
        CoseSign1Message detachedSignature3 = await factory.CreateDetachedSignatureAsync(randomBytes, coseSigningKeyProvider, "application/test.payload");
        detachedSignature3.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        detachedSignature3.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+hash-sha256");
        detachedSignature3.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateDetachedSignatureAsync(memStream, coseSigningKeyProvider, string.Empty));
        memStream.Seek(0, SeekOrigin.Begin);
        CoseSign1Message detachedSignature4 = await factory.CreateDetachedSignatureAsync(memStream, coseSigningKeyProvider, "application/test.payload");
        detachedSignature4.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        detachedSignature4.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+hash-sha256");
        detachedSignature4.SignatureMatches(randomBytes).Should().BeTrue();
        memStream.Seek(0, SeekOrigin.Begin);
    }

    [Test]
    public async Task TestCreateDetachedSignatureHashProvidedAsync()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestCreateDetachedSignatureHashProvidedAsync));
        using DetachedSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        using HashAlgorithm hasher = CoseSign1MessageDetachedSignatureExtensions.CreateHashAlgorithmFromName(factory.HashAlgorithmName)
                         ?? throw new Exception($"Failed to get hash algorithm from {nameof(CoseSign1MessageDetachedSignatureExtensions.CreateHashAlgorithmFromName)}");
        byte[] hash = hasher!.ComputeHash(randomBytes);
        using MemoryStream hashStream = new(hash);

        // test the sync method
        Assert.Throws<ArgumentNullException>(() => factory.CreateDetachedSignatureFromHash(hash, coseSigningKeyProvider, string.Empty));
        CoseSign1Message detachedSignature = factory.CreateDetachedSignatureFromHash(hash, coseSigningKeyProvider, "application/test.payload");
        detachedSignature.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        detachedSignature.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+hash-sha256");
        detachedSignature.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.Throws<ArgumentNullException>(() => factory.CreateDetachedSignature(hashStream, coseSigningKeyProvider, string.Empty));
        hashStream.Seek(0, SeekOrigin.Begin);
        CoseSign1Message detachedSignature2 = factory.CreateDetachedSignatureFromHash(hashStream, coseSigningKeyProvider, "application/test.payload");
        detachedSignature2.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        detachedSignature2.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+hash-sha256");
        detachedSignature2.SignatureMatches(randomBytes).Should().BeTrue();
        hashStream.Seek(0, SeekOrigin.Begin);

        // test the async methods
        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateDetachedSignatureFromHashAsync(hash, coseSigningKeyProvider, string.Empty));
        CoseSign1Message detachedSignature3 = await factory.CreateDetachedSignatureFromHashAsync(hash, coseSigningKeyProvider, "application/test.payload");
        detachedSignature3.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        detachedSignature3.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+hash-sha256");
        detachedSignature3.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateDetachedSignatureFromHashAsync(hashStream, coseSigningKeyProvider, string.Empty));
        hashStream.Seek(0, SeekOrigin.Begin);
        CoseSign1Message detachedSignature4 = await factory.CreateDetachedSignatureFromHashAsync(hashStream, coseSigningKeyProvider, "application/test.payload");
        detachedSignature4.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        detachedSignature4.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+hash-sha256");
        detachedSignature4.SignatureMatches(randomBytes).Should().BeTrue();
        hashStream.Seek(0, SeekOrigin.Begin);
    }

    [Test]
    public async Task TestCreateDetachedSignatureBytesAsync()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestCreateDetachedSignatureBytesAsync));
        using DetachedSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        using MemoryStream memStream = new(randomBytes);

        // test the sync method
        Assert.Throws<ArgumentNullException>(() => factory.CreateDetachedSignatureBytes(randomBytes, coseSigningKeyProvider, string.Empty));
        CoseSign1Message detachedSignature = CoseMessage.DecodeSign1(factory.CreateDetachedSignatureBytes(randomBytes, coseSigningKeyProvider, "application/test.payload").ToArray());
        detachedSignature.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        detachedSignature.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+hash-sha256");
        detachedSignature.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.Throws<ArgumentNullException>(() => factory.CreateDetachedSignatureBytes(memStream, coseSigningKeyProvider, string.Empty));
        memStream.Seek(0, SeekOrigin.Begin);
        CoseSign1Message detachedSignature2 = CoseMessage.DecodeSign1(factory.CreateDetachedSignatureBytes(memStream, coseSigningKeyProvider, "application/test.payload").ToArray());
        detachedSignature2.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        detachedSignature2.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+hash-sha256");
        detachedSignature2.SignatureMatches(randomBytes).Should().BeTrue();
        memStream.Seek(0, SeekOrigin.Begin);

        // test the async methods
        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateDetachedSignatureBytesAsync(randomBytes, coseSigningKeyProvider, string.Empty));
        CoseSign1Message detachedSignature3 = CoseMessage.DecodeSign1((await factory.CreateDetachedSignatureBytesAsync(randomBytes, coseSigningKeyProvider, "application/test.payload")).ToArray());
        detachedSignature3.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        detachedSignature3.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+hash-sha256");
        detachedSignature3.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateDetachedSignatureBytesAsync(memStream, coseSigningKeyProvider, string.Empty));
        memStream.Seek(0, SeekOrigin.Begin);
        CoseSign1Message detachedSignature4 = CoseMessage.DecodeSign1((await factory.CreateDetachedSignatureBytesAsync(memStream, coseSigningKeyProvider, "application/test.payload")).ToArray());
        detachedSignature4.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        detachedSignature4.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+hash-sha256");
        memStream.Seek(0, SeekOrigin.Begin);
        detachedSignature4.SignatureMatches(memStream).Should().BeTrue();
    }

    [Test]
    public async Task TestCreateDetachedSignatureBytesHashProvidedAsync()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestCreateDetachedSignatureBytesHashProvidedAsync));
        using DetachedSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        using HashAlgorithm hasher = CoseSign1MessageDetachedSignatureExtensions.CreateHashAlgorithmFromName(factory.HashAlgorithmName)
                 ?? throw new Exception($"Failed to get hash algorithm from {nameof(CoseSign1MessageDetachedSignatureExtensions.CreateHashAlgorithmFromName)}");
        byte[] hash = hasher!.ComputeHash(randomBytes);
        using MemoryStream hashStream = new(hash);

        // test the sync method
        Assert.Throws<ArgumentNullException>(() => factory.CreateDetachedSignatureBytesFromHash(hash, coseSigningKeyProvider, string.Empty));
        CoseSign1Message detachedSignature = CoseMessage.DecodeSign1(factory.CreateDetachedSignatureBytesFromHash(hash, coseSigningKeyProvider, "application/test.payload").ToArray());
        detachedSignature.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        detachedSignature.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+hash-sha256");
        detachedSignature.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.Throws<ArgumentNullException>(() => factory.CreateDetachedSignatureBytesFromHash(hashStream, coseSigningKeyProvider, string.Empty));
        hashStream.Seek(0, SeekOrigin.Begin);
        CoseSign1Message detachedSignature2 = CoseMessage.DecodeSign1(factory.CreateDetachedSignatureBytesFromHash(hashStream, coseSigningKeyProvider, "application/test.payload").ToArray());
        detachedSignature2.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        detachedSignature2.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+hash-sha256");
        detachedSignature2.SignatureMatches(randomBytes).Should().BeTrue();
        hashStream.Seek(0, SeekOrigin.Begin);

        // test the async methods
        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateDetachedSignatureBytesFromHashAsync(hash, coseSigningKeyProvider, string.Empty));
        CoseSign1Message detachedSignature3 = CoseMessage.DecodeSign1((await factory.CreateDetachedSignatureBytesFromHashAsync(hash, coseSigningKeyProvider, "application/test.payload")).ToArray());
        detachedSignature3.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        detachedSignature3.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+hash-sha256");
        detachedSignature3.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateDetachedSignatureBytesFromHashAsync(hashStream, coseSigningKeyProvider, string.Empty));
        hashStream.Seek(0, SeekOrigin.Begin);
        CoseSign1Message detachedSignature4 = CoseMessage.DecodeSign1((await factory.CreateDetachedSignatureBytesFromHashAsync(hashStream, coseSigningKeyProvider, "application/test.payload")).ToArray());
        detachedSignature4.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        detachedSignature4.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+hash-sha256");
        hashStream.Seek(0, SeekOrigin.Begin);
        detachedSignature4.SignatureMatches(randomBytes).Should().BeTrue();
    }

    [Test]
    public void TestCreateDetachedSignatureMd5()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestCreateDetachedSignatureMd5));
        using DetachedSignatureFactory factory = new(HashAlgorithmName.MD5);
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);

        // test the sync method
        Assert.Throws<ArgumentNullException>(() => factory.CreateDetachedSignature(randomBytes, coseSigningKeyProvider, string.Empty));
        CoseSign1Message detachedSignature = CoseMessage.DecodeSign1(factory.CreateDetachedSignatureBytes(randomBytes, coseSigningKeyProvider, "application/test.payload").ToArray());
        detachedSignature.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        detachedSignature.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+hash-md5");
        detachedSignature.SignatureMatches(randomBytes).Should().BeTrue();
    }

    [Test]
    public void TestCreateDetachedSignatureMd5HashProvided()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestCreateDetachedSignatureMd5));
        using DetachedSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        using HashAlgorithm hasher = CoseSign1MessageDetachedSignatureExtensions.CreateHashAlgorithmFromName(HashAlgorithmName.MD5)
         ?? throw new Exception($"Failed to get hash algorithm from {nameof(CoseSign1MessageDetachedSignatureExtensions.CreateHashAlgorithmFromName)}");
        byte[] hash = hasher!.ComputeHash(randomBytes);

        // test the sync method
        Assert.Throws<ArgumentNullException>(() => factory.CreateDetachedSignatureFromHash(hash, coseSigningKeyProvider, string.Empty));
        CoseSign1Message detachedSignature = CoseMessage.DecodeSign1(factory.CreateDetachedSignatureBytesFromHash(hash, coseSigningKeyProvider, "application/test.payload").ToArray());
        detachedSignature.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        detachedSignature.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+hash-md5");
        detachedSignature.SignatureMatches(randomBytes).Should().BeTrue();

        // test unknown hash length
        // test the sync method
        Assert.Throws<ArgumentException>(() => factory.CreateDetachedSignatureFromHash(randomBytes, coseSigningKeyProvider, "application/test.payload"));
    }

    [Test]
    public void TestCreateDetachedSignatureAlreadyProvided()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = SetupMockSigningKeyProvider(nameof(TestCreateDetachedSignatureAlreadyProvided));
        using DetachedSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        using HashAlgorithm hasher = CoseSign1MessageDetachedSignatureExtensions.CreateHashAlgorithmFromName(factory.HashAlgorithmName)
                                     ?? throw new Exception($"Failed to get hash algorithm from {nameof(CoseSign1MessageDetachedSignatureExtensions.CreateHashAlgorithmFromName)}");
        ReadOnlyMemory<byte> hash = hasher!.ComputeHash(randomBytes);

        // test the sync method
        Assert.Throws<ArgumentNullException>(() => factory.CreateDetachedSignature(hash, coseSigningKeyProvider, string.Empty));
        CoseSign1Message detachedSignature = CoseMessage.DecodeSign1(factory.CreateDetachedSignatureBytes(randomBytes, coseSigningKeyProvider, "application/test.payload+hash-sha256").ToArray());
        detachedSignature.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        detachedSignature.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+hash-sha256");
        detachedSignature.SignatureMatches(randomBytes).Should().BeTrue();
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
