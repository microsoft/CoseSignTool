// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseIndirectSignature.Tests;

public class TestCoseHeaderExtender : ICoseHeaderExtender
{
    public Func<CoseHeaderMap, CoseHeaderMap>? ExtendProtectedHeadersFunc { get; set; }
    public Func<CoseHeaderMap?, CoseHeaderMap>? ExtendUnProtectedHeadersFunc { get; set; }

    public CoseHeaderMap ExtendProtectedHeaders(CoseHeaderMap protectedHeaders)
    {
        return ExtendProtectedHeadersFunc == null ? protectedHeaders : ExtendProtectedHeadersFunc(protectedHeaders);
    }

    public CoseHeaderMap ExtendUnProtectedHeaders(CoseHeaderMap? unProtectedHeaders)
    {
        return ExtendUnProtectedHeadersFunc == null ? new CoseHeaderMap() : ExtendUnProtectedHeadersFunc(unProtectedHeaders);
    }
}

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
        ICoseSigningKeyProvider coseSigningKeyProvider = TestUtils.SetupMockSigningKeyProvider();
        using IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        using MemoryStream memStream = new(randomBytes);

        // test the sync method
        Assert.Throws<ArgumentNullException>(() => factory.CreateIndirectSignature(randomBytes, coseSigningKeyProvider, string.Empty));

        CoseSign1Message IndirectSignatureCurrent = factory.CreateIndirectSignature(randomBytes, coseSigningKeyProvider, "application/test.payload");
        IndirectSignatureCurrent.IsIndirectSignature().Should().BeTrue();
        IndirectSignatureCurrent.SignatureMatches(randomBytes).Should().BeTrue();
        IndirectSignatureCurrent.TryGetPreImageContentType(out string? payloadType).Should().Be(true);
        payloadType!.Should().Be("application/test.payload");
        IndirectSignatureCurrent.TryGetPayloadHashAlgorithm(out CoseHashAlgorithm? algo).Should().BeTrue();
        algo!.Should().Be(CoseHashAlgorithm.SHA256);

#pragma warning disable CS0618 // Type or member is obsolete
        CoseSign1Message IndirectSignature = factory.CreateIndirectSignature(randomBytes, coseSigningKeyProvider, "application/test.payload", IndirectSignatureFactory.IndirectSignatureVersion.CoseHashV);
#pragma warning restore CS0618 // Type or member is obsolete
        IndirectSignature.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature.SignatureMatches(randomBytes).Should().BeTrue();
        memStream.Seek(0, SeekOrigin.Begin);


        Assert.Throws<ArgumentNullException>(() => factory.CreateIndirectSignature(memStream, coseSigningKeyProvider, string.Empty));
        memStream.Seek(0, SeekOrigin.Begin);

#pragma warning disable CS0618 // Type or member is obsolete
        CoseSign1Message IndirectSignature2 = factory.CreateIndirectSignature(memStream, coseSigningKeyProvider, "application/test.payload", IndirectSignatureFactory.IndirectSignatureVersion.CoseHashV);
#pragma warning restore CS0618 // Type or member is obsolete
        IndirectSignature2.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature2.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature2.SignatureMatches(randomBytes).Should().BeTrue();
        memStream.Seek(0, SeekOrigin.Begin);

        // test the async methods
        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateIndirectSignatureAsync(randomBytes, coseSigningKeyProvider, string.Empty));

        CoseSign1Message IndirectSignatureCurrentAsync = await factory.CreateIndirectSignatureAsync(randomBytes, coseSigningKeyProvider, "application/test.payload");
        IndirectSignatureCurrentAsync.IsIndirectSignature().Should().BeTrue();
        IndirectSignatureCurrentAsync.SignatureMatches(randomBytes).Should().BeTrue();
        IndirectSignatureCurrentAsync.TryGetPreImageContentType(out payloadType).Should().Be(true);
        payloadType!.Should().Be("application/test.payload");
        IndirectSignatureCurrentAsync.TryGetPayloadHashAlgorithm(out algo).Should().BeTrue();
        algo!.Should().Be(CoseHashAlgorithm.SHA256);

#pragma warning disable CS0618 // Type or member is obsolete
        CoseSign1Message IndirectSignature3 = await factory.CreateIndirectSignatureAsync(randomBytes, coseSigningKeyProvider, "application/test.payload", IndirectSignatureFactory.IndirectSignatureVersion.CoseHashV);
#pragma warning restore CS0618 // Type or member is obsolete
        IndirectSignature3.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature3.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature3.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateIndirectSignatureAsync(memStream, coseSigningKeyProvider, string.Empty));
        memStream.Seek(0, SeekOrigin.Begin);

        CoseSign1Message IndirectSignatureCurrentStreamAsync = await factory.CreateIndirectSignatureAsync(memStream, coseSigningKeyProvider, "application/test.payload");
        IndirectSignatureCurrentStreamAsync.IsIndirectSignature().Should().BeTrue();
        IndirectSignatureCurrentStreamAsync.SignatureMatches(randomBytes).Should().BeTrue();
        IndirectSignatureCurrentStreamAsync.TryGetPreImageContentType(out payloadType).Should().Be(true);
        payloadType!.Should().Be("application/test.payload");
        IndirectSignatureCurrentStreamAsync.TryGetPayloadHashAlgorithm(out algo).Should().BeTrue();
        algo!.Should().Be(CoseHashAlgorithm.SHA256);
        memStream.Seek(0, SeekOrigin.Begin);

#pragma warning disable CS0618 // Type or member is obsolete
        CoseSign1Message IndirectSignature4 = await factory.CreateIndirectSignatureAsync(memStream, coseSigningKeyProvider, "application/test.payload", IndirectSignatureFactory.IndirectSignatureVersion.CoseHashV);
#pragma warning restore CS0618 // Type or member is obsolete
        IndirectSignature4.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature4.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature4.SignatureMatches(randomBytes).Should().BeTrue();
        memStream.Seek(0, SeekOrigin.Begin);

        TestCoseHeaderExtender testExtender = new TestCoseHeaderExtender();
        CoseHeaderLabel coseHeaderLabel = new("test-header");
        testExtender.ExtendProtectedHeadersFunc = (CoseHeaderMap protectedHeaders) =>
        {
            protectedHeaders[coseHeaderLabel] = CoseHeaderValue.FromString("test-value");
            return protectedHeaders;
        };

        CoseSign1Message IndirectSignature5 = factory.CreateIndirectSignature(randomBytes, coseSigningKeyProvider, "application/test.payload", coseHeaderExtender: testExtender);
        IndirectSignature5.IsIndirectSignature().Should().BeTrue();
        IndirectSignature5.SignatureMatches(randomBytes).Should().BeTrue();
        IndirectSignature5.TryGetPreImageContentType(out payloadType).Should().Be(true);
        payloadType!.Should().Be("application/test.payload");
        IndirectSignature5.TryGetPayloadHashAlgorithm(out algo).Should().BeTrue();
        algo!.Should().Be(CoseHashAlgorithm.SHA256);
        IndirectSignature5.ProtectedHeaders.ContainsKey(coseHeaderLabel).Should().BeTrue();
        IndirectSignature5.ProtectedHeaders[coseHeaderLabel].GetValueAsString().Should().Be("test-value");
    }

    [Test]
    public async Task TestCreateIndirectSignatureHashProvidedAsync()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = TestUtils.SetupMockSigningKeyProvider();
        using IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        using HashAlgorithm hasher = CoseSign1MessageIndirectSignatureExtensions.CreateHashAlgorithmFromName(factory.HashAlgorithmName)
                         ?? throw new Exception($"Failed to get hash algorithm from {nameof(CoseSign1MessageIndirectSignatureExtensions.CreateHashAlgorithmFromName)}");
        byte[] hash = hasher!.ComputeHash(randomBytes);
        using MemoryStream hashStream = new(hash);

        // test the sync method
        Assert.Throws<ArgumentNullException>(() => factory.CreateIndirectSignatureFromHash(hash, coseSigningKeyProvider, string.Empty));

        CoseSign1Message IndirectSignatureCurrent = factory.CreateIndirectSignatureFromHash(hash, coseSigningKeyProvider, "application/test.payload");
        IndirectSignatureCurrent.IsIndirectSignature().Should().BeTrue();
        IndirectSignatureCurrent.SignatureMatches(randomBytes).Should().BeTrue();
        IndirectSignatureCurrent.TryGetPreImageContentType(out string? payloadType).Should().Be(true);
        payloadType!.Should().Be("application/test.payload");
        IndirectSignatureCurrent.TryGetPayloadHashAlgorithm(out CoseHashAlgorithm? algo).Should().BeTrue();
        algo!.Should().Be(CoseHashAlgorithm.SHA256);

#pragma warning disable CS0618 // Type or member is obsolete
        CoseSign1Message IndirectSignature = factory.CreateIndirectSignatureFromHash(hash, coseSigningKeyProvider, "application/test.payload", IndirectSignatureFactory.IndirectSignatureVersion.CoseHashV);
#pragma warning restore CS0618 // Type or member is obsolete
        IndirectSignature.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.Throws<ArgumentNullException>(() => factory.CreateIndirectSignatureFromHash(hashStream, coseSigningKeyProvider, string.Empty));
        hashStream.Seek(0, SeekOrigin.Begin);

        CoseSign1Message IndirectSignatureStreamCurrent = factory.CreateIndirectSignatureFromHash(hashStream, coseSigningKeyProvider, "application/test.payload");
        IndirectSignatureStreamCurrent.IsIndirectSignature().Should().BeTrue();
        IndirectSignatureStreamCurrent.SignatureMatches(randomBytes).Should().BeTrue();
        IndirectSignatureStreamCurrent.TryGetPreImageContentType(out payloadType).Should().Be(true);
        payloadType!.Should().Be("application/test.payload");
        IndirectSignatureStreamCurrent.TryGetPayloadHashAlgorithm(out algo).Should().BeTrue();
        algo!.Should().Be(CoseHashAlgorithm.SHA256);
        hashStream.Seek(0, SeekOrigin.Begin);

#pragma warning disable CS0618 // Type or member is obsolete
        CoseSign1Message IndirectSignature2 = factory.CreateIndirectSignatureFromHash(hashStream, coseSigningKeyProvider, "application/test.payload", IndirectSignatureFactory.IndirectSignatureVersion.CoseHashV);
#pragma warning restore CS0618 // Type or member is obsolete
        IndirectSignature2.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature2.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature2.SignatureMatches(randomBytes).Should().BeTrue();
        hashStream.Seek(0, SeekOrigin.Begin);

        // test the async methods
        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateIndirectSignatureFromHashAsync(hash, coseSigningKeyProvider, string.Empty));

        CoseSign1Message IndirectSignatureCurrentAsync = factory.CreateIndirectSignatureFromHash(hash, coseSigningKeyProvider, "application/test.payload");
        IndirectSignatureCurrentAsync.IsIndirectSignature().Should().BeTrue();
        IndirectSignatureCurrentAsync.SignatureMatches(randomBytes).Should().BeTrue();
        IndirectSignatureCurrentAsync.TryGetPreImageContentType(out payloadType).Should().Be(true);
        payloadType!.Should().Be("application/test.payload");
        IndirectSignatureCurrentAsync.TryGetPayloadHashAlgorithm(out algo).Should().BeTrue();
        algo!.Should().Be(CoseHashAlgorithm.SHA256);
        hashStream.Seek(0, SeekOrigin.Begin);

#pragma warning disable CS0618 // Type or member is obsolete
        CoseSign1Message IndirectSignature3 = await factory.CreateIndirectSignatureFromHashAsync(hash, coseSigningKeyProvider, "application/test.payload", IndirectSignatureFactory.IndirectSignatureVersion.CoseHashV);
#pragma warning restore CS0618 // Type or member is obsolete
        IndirectSignature3.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature3.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature3.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateIndirectSignatureFromHashAsync(hashStream, coseSigningKeyProvider, string.Empty));
        hashStream.Seek(0, SeekOrigin.Begin);

        CoseSign1Message IndirectSignatureCurrentStreamAsync = factory.CreateIndirectSignatureFromHash(hash, coseSigningKeyProvider, "application/test.payload");
        IndirectSignatureCurrentStreamAsync.IsIndirectSignature().Should().BeTrue();
        IndirectSignatureCurrentStreamAsync.SignatureMatches(randomBytes).Should().BeTrue();
        IndirectSignatureCurrentStreamAsync.TryGetPreImageContentType(out payloadType).Should().Be(true);
        payloadType!.Should().Be("application/test.payload");
        IndirectSignatureCurrentStreamAsync.TryGetPayloadHashAlgorithm(out algo).Should().BeTrue();
        algo!.Should().Be(CoseHashAlgorithm.SHA256);
        hashStream.Seek(0, SeekOrigin.Begin);

#pragma warning disable CS0618 // Type or member is obsolete
        CoseSign1Message IndirectSignature4 = await factory.CreateIndirectSignatureFromHashAsync(hashStream, coseSigningKeyProvider, "application/test.payload", IndirectSignatureFactory.IndirectSignatureVersion.CoseHashV);
#pragma warning restore CS0618 // Type or member is obsolete
        IndirectSignature4.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature4.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature4.SignatureMatches(randomBytes).Should().BeTrue();
        hashStream.Seek(0, SeekOrigin.Begin);
    }

    [Test]
    public async Task TestCreateIndirectSignatureBytesAsync()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = TestUtils.SetupMockSigningKeyProvider();
        using IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        using MemoryStream memStream = new(randomBytes);

        // test the sync method
        Assert.Throws<ArgumentNullException>(() => factory.CreateIndirectSignatureBytes(randomBytes, coseSigningKeyProvider, string.Empty));

        CoseSign1Message IndirectSignatureCurrent = CoseMessage.DecodeSign1(factory.CreateIndirectSignatureBytes(randomBytes, coseSigningKeyProvider, "application/test.payload").ToArray());
        IndirectSignatureCurrent.IsIndirectSignature().Should().BeTrue();
        IndirectSignatureCurrent.SignatureMatches(randomBytes).Should().BeTrue();
        IndirectSignatureCurrent.TryGetPreImageContentType(out string? payloadType).Should().Be(true);
        payloadType!.Should().Be("application/test.payload");
        IndirectSignatureCurrent.TryGetPayloadHashAlgorithm(out CoseHashAlgorithm? algo).Should().BeTrue();
        algo!.Should().Be(CoseHashAlgorithm.SHA256);

#pragma warning disable CS0618 // Type or member is obsolete
        CoseSign1Message IndirectSignature = CoseMessage.DecodeSign1(factory.CreateIndirectSignatureBytes(randomBytes, coseSigningKeyProvider, "application/test.payload", IndirectSignatureFactory.IndirectSignatureVersion.CoseHashV).ToArray());
#pragma warning restore CS0618 // Type or member is obsolete
        IndirectSignature.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.Throws<ArgumentNullException>(() => factory.CreateIndirectSignatureBytes(memStream, coseSigningKeyProvider, string.Empty));
        memStream.Seek(0, SeekOrigin.Begin);

        CoseSign1Message IndirectSignatureStreamCurrent = CoseMessage.DecodeSign1(factory.CreateIndirectSignatureBytes(memStream, coseSigningKeyProvider, "application/test.payload").ToArray());
        IndirectSignatureStreamCurrent.IsIndirectSignature().Should().BeTrue();
        IndirectSignatureStreamCurrent.SignatureMatches(randomBytes).Should().BeTrue();
        IndirectSignatureStreamCurrent.TryGetPreImageContentType(out payloadType).Should().Be(true);
        payloadType!.Should().Be("application/test.payload");
        IndirectSignatureStreamCurrent.TryGetPayloadHashAlgorithm(out algo).Should().BeTrue();
        algo!.Should().Be(CoseHashAlgorithm.SHA256);
        memStream.Seek(0, SeekOrigin.Begin);

#pragma warning disable CS0618 // Type or member is obsolete
        CoseSign1Message IndirectSignature2 = CoseMessage.DecodeSign1(factory.CreateIndirectSignatureBytes(memStream, coseSigningKeyProvider, "application/test.payload", IndirectSignatureFactory.IndirectSignatureVersion.CoseHashV).ToArray());
#pragma warning restore CS0618 // Type or member is obsolete
        IndirectSignature2.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature2.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature2.SignatureMatches(randomBytes).Should().BeTrue();
        memStream.Seek(0, SeekOrigin.Begin);

        // test the async methods
        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateIndirectSignatureBytesAsync(randomBytes, coseSigningKeyProvider, string.Empty));

        CoseSign1Message IndirectSignatureCurrentAsync = CoseMessage.DecodeSign1(factory.CreateIndirectSignatureBytes(randomBytes, coseSigningKeyProvider, "application/test.payload").ToArray());
        IndirectSignatureCurrentAsync.IsIndirectSignature().Should().BeTrue();
        IndirectSignatureCurrentAsync.SignatureMatches(randomBytes).Should().BeTrue();
        IndirectSignatureCurrentAsync.TryGetPreImageContentType(out payloadType).Should().Be(true);
        payloadType!.Should().Be("application/test.payload");
        IndirectSignatureCurrentAsync.TryGetPayloadHashAlgorithm(out algo).Should().BeTrue();
        algo!.Should().Be(CoseHashAlgorithm.SHA256);

#pragma warning disable CS0618 // Type or member is obsolete
        CoseSign1Message IndirectSignature3 = CoseMessage.DecodeSign1((await factory.CreateIndirectSignatureBytesAsync(randomBytes, coseSigningKeyProvider, "application/test.payload", IndirectSignatureFactory.IndirectSignatureVersion.CoseHashV)).ToArray());
#pragma warning restore CS0618 // Type or member is obsolete
        IndirectSignature3.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature3.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature3.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateIndirectSignatureBytesAsync(memStream, coseSigningKeyProvider, string.Empty));
        memStream.Seek(0, SeekOrigin.Begin);

        CoseSign1Message IndirectSignatureCurrentStreamAsync = CoseMessage.DecodeSign1((await factory.CreateIndirectSignatureBytesAsync(memStream, coseSigningKeyProvider, "application/test.payload")).ToArray());
        IndirectSignatureCurrentStreamAsync.IsIndirectSignature().Should().BeTrue();
        IndirectSignatureCurrentStreamAsync.SignatureMatches(randomBytes).Should().BeTrue();
        IndirectSignatureCurrentStreamAsync.TryGetPreImageContentType(out payloadType).Should().Be(true);
        payloadType!.Should().Be("application/test.payload");
        IndirectSignatureCurrentStreamAsync.TryGetPayloadHashAlgorithm(out algo).Should().BeTrue();
        algo!.Should().Be(CoseHashAlgorithm.SHA256);
        memStream.Seek(0, SeekOrigin.Begin);

#pragma warning disable CS0618 // Type or member is obsolete
        CoseSign1Message IndirectSignature4 = CoseMessage.DecodeSign1((await factory.CreateIndirectSignatureBytesAsync(memStream, coseSigningKeyProvider, "application/test.payload", IndirectSignatureFactory.IndirectSignatureVersion.CoseHashV)).ToArray());
#pragma warning restore CS0618 // Type or member is obsolete
        IndirectSignature4.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature4.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        memStream.Seek(0, SeekOrigin.Begin);
        IndirectSignature4.SignatureMatches(memStream).Should().BeTrue();
    }

    [Test]
    public async Task TestCreateIndirectSignatureBytesHashProvidedAsync()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = TestUtils.SetupMockSigningKeyProvider();
        using IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        using HashAlgorithm hasher = CoseSign1MessageIndirectSignatureExtensions.CreateHashAlgorithmFromName(factory.HashAlgorithmName)
                 ?? throw new Exception($"Failed to get hash algorithm from {nameof(CoseSign1MessageIndirectSignatureExtensions.CreateHashAlgorithmFromName)}");
        byte[] hash = hasher!.ComputeHash(randomBytes);
        using MemoryStream hashStream = new(hash);

        // test the sync method
        Assert.Throws<ArgumentNullException>(() => factory.CreateIndirectSignatureBytesFromHash(hash, coseSigningKeyProvider, string.Empty));

        CoseSign1Message IndirectSignatureCurrent = CoseMessage.DecodeSign1(factory.CreateIndirectSignatureBytesFromHash(hash, coseSigningKeyProvider, "application/test.payload").ToArray());
        IndirectSignatureCurrent.IsIndirectSignature().Should().BeTrue();
        IndirectSignatureCurrent.SignatureMatches(randomBytes).Should().BeTrue();
        IndirectSignatureCurrent.TryGetPreImageContentType(out string? payloadType).Should().Be(true);
        payloadType!.Should().Be("application/test.payload");
        IndirectSignatureCurrent.TryGetPayloadHashAlgorithm(out CoseHashAlgorithm? algo).Should().BeTrue();
        algo!.Should().Be(CoseHashAlgorithm.SHA256);

#pragma warning disable CS0618 // Type or member is obsolete
        CoseSign1Message IndirectSignature = CoseMessage.DecodeSign1(factory.CreateIndirectSignatureBytesFromHash(hash, coseSigningKeyProvider, "application/test.payload", IndirectSignatureFactory.IndirectSignatureVersion.CoseHashV).ToArray());
#pragma warning restore CS0618 // Type or member is obsolete
        IndirectSignature.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.Throws<ArgumentNullException>(() => factory.CreateIndirectSignatureBytesFromHash(hashStream, coseSigningKeyProvider, string.Empty));
        hashStream.Seek(0, SeekOrigin.Begin);

        CoseSign1Message IndirectSignatureStreamCurrent = CoseMessage.DecodeSign1(factory.CreateIndirectSignatureBytesFromHash(hashStream, coseSigningKeyProvider, "application/test.payload").ToArray());
        IndirectSignatureStreamCurrent.IsIndirectSignature().Should().BeTrue();
        IndirectSignatureStreamCurrent.SignatureMatches(randomBytes).Should().BeTrue();
        IndirectSignatureStreamCurrent.TryGetPreImageContentType(out payloadType).Should().Be(true);
        payloadType!.Should().Be("application/test.payload");
        IndirectSignatureStreamCurrent.TryGetPayloadHashAlgorithm(out algo).Should().BeTrue();
        algo!.Should().Be(CoseHashAlgorithm.SHA256);
        hashStream.Seek(0, SeekOrigin.Begin);

#pragma warning disable CS0618 // Type or member is obsolete
        CoseSign1Message IndirectSignature2 = CoseMessage.DecodeSign1(factory.CreateIndirectSignatureBytesFromHash(hashStream, coseSigningKeyProvider, "application/test.payload", IndirectSignatureFactory.IndirectSignatureVersion.CoseHashV).ToArray());
#pragma warning restore CS0618 // Type or member is obsolete
        IndirectSignature2.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature2.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature2.SignatureMatches(randomBytes).Should().BeTrue();
        hashStream.Seek(0, SeekOrigin.Begin);

        // test the async methods
        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateIndirectSignatureBytesFromHashAsync(hash, coseSigningKeyProvider, string.Empty));

        CoseSign1Message IndirectSignatureHashCurrent = CoseMessage.DecodeSign1(factory.CreateIndirectSignatureBytesFromHash(hash, coseSigningKeyProvider, "application/test.payload").ToArray());
        IndirectSignatureHashCurrent.IsIndirectSignature().Should().BeTrue();
        IndirectSignatureHashCurrent.SignatureMatches(randomBytes).Should().BeTrue();
        IndirectSignatureHashCurrent.TryGetPreImageContentType(out payloadType).Should().Be(true);
        payloadType!.Should().Be("application/test.payload");
        IndirectSignatureHashCurrent.TryGetPayloadHashAlgorithm(out algo).Should().BeTrue();
        algo!.Should().Be(CoseHashAlgorithm.SHA256);

#pragma warning disable CS0618 // Type or member is obsolete
        CoseSign1Message IndirectSignature3 = CoseMessage.DecodeSign1((await factory.CreateIndirectSignatureBytesFromHashAsync(hash, coseSigningKeyProvider, "application/test.payload", IndirectSignatureFactory.IndirectSignatureVersion.CoseHashV)).ToArray());
#pragma warning restore CS0618 // Type or member is obsolete
        IndirectSignature3.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature3.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        IndirectSignature3.SignatureMatches(randomBytes).Should().BeTrue();

        Assert.ThrowsAsync<ArgumentNullException>(() => factory.CreateIndirectSignatureBytesFromHashAsync(hashStream, coseSigningKeyProvider, string.Empty));
        hashStream.Seek(0, SeekOrigin.Begin);

        CoseSign1Message IndirectSignatureHashCurrentAsync = CoseMessage.DecodeSign1((await factory.CreateIndirectSignatureBytesFromHashAsync(hashStream, coseSigningKeyProvider, "application/test.payload")).ToArray());
        IndirectSignatureHashCurrentAsync.IsIndirectSignature().Should().BeTrue();
        IndirectSignatureHashCurrentAsync.SignatureMatches(randomBytes).Should().BeTrue();
        IndirectSignatureHashCurrentAsync.TryGetPreImageContentType(out payloadType).Should().Be(true);
        payloadType!.Should().Be("application/test.payload");
        IndirectSignatureHashCurrentAsync.TryGetPayloadHashAlgorithm(out algo).Should().BeTrue();
        algo!.Should().Be(CoseHashAlgorithm.SHA256);
        hashStream.Seek(0, SeekOrigin.Begin);

#pragma warning disable CS0618 // Type or member is obsolete
        CoseSign1Message IndirectSignature4 = CoseMessage.DecodeSign1((await factory.CreateIndirectSignatureBytesFromHashAsync(hashStream, coseSigningKeyProvider, "application/test.payload", IndirectSignatureFactory.IndirectSignatureVersion.CoseHashV)).ToArray());
#pragma warning restore CS0618 // Type or member is obsolete
        IndirectSignature4.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType).Should().BeTrue();
        IndirectSignature4.ProtectedHeaders[CoseHeaderLabel.ContentType].GetValueAsString().Should().Be("application/test.payload+cose-hash-v");
        hashStream.Seek(0, SeekOrigin.Begin);
        IndirectSignature4.SignatureMatches(randomBytes).Should().BeTrue();
    }

    [Test]
    public void TestCreateIndirectSignatureUnsupportedAlgorithmFailure()
    {
        Action act = () => { IndirectSignatureFactory factory = new(HashAlgorithmName.SHA3_256); };
        act.Should().Throw<ArgumentException>();
    }

    [Test]
    public void TestCreateIndirectSignatureAlreadyProvided()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = TestUtils.SetupMockSigningKeyProvider();
        using IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        using HashAlgorithm hasher = CoseSign1MessageIndirectSignatureExtensions.CreateHashAlgorithmFromName(factory.HashAlgorithmName)
                                     ?? throw new Exception($"Failed to get hash algorithm from {nameof(CoseSign1MessageIndirectSignatureExtensions.CreateHashAlgorithmFromName)}");
        ReadOnlyMemory<byte> hash = hasher!.ComputeHash(randomBytes);

        // test the sync method
        Assert.Throws<ArgumentNullException>(() => factory.CreateIndirectSignature(hash, coseSigningKeyProvider, string.Empty));
        CoseSign1Message IndirectSignature = CoseMessage.DecodeSign1(factory.CreateIndirectSignatureBytes(randomBytes, coseSigningKeyProvider, "application/test.payload").ToArray());
        IndirectSignature.IsIndirectSignature().Should().BeTrue();
        IndirectSignature.SignatureMatches(randomBytes).Should().BeTrue();
        IndirectSignature.TryGetPreImageContentType(out string? payloadType).Should().Be(true);
        payloadType!.Should().Be("application/test.payload");
        IndirectSignature.TryGetPayloadHashAlgorithm(out CoseHashAlgorithm? algo).Should().BeTrue();
        algo!.Should().Be(CoseHashAlgorithm.SHA256);
    }

    [Test]
    public async Task TestCreateIndirectSignatureAsyncWithPayloadLocation()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = TestUtils.SetupMockSigningKeyProvider();
        using IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);
        string testPayloadLocation = "https://example.com/payload/test.bin";

        using MemoryStream memStream = new(randomBytes);
        CoseSign1Message indirectSignature = await factory.CreateIndirectSignatureAsync(
            memStream,
            coseSigningKeyProvider,
            "application/test.payload",
            IndirectSignatureFactory.IndirectSignatureVersion.CoseHashEnvelope,
            payloadLocation: testPayloadLocation);

        // Verify it's an indirect signature
        indirectSignature.IsIndirectSignature().Should().BeTrue();
        indirectSignature.SignatureMatches(randomBytes).Should().BeTrue();

        // Verify PayloadLocation header is set correctly
        indirectSignature.TryGetPayloadLocation(out string? actualLocation).Should().BeTrue();
        actualLocation.Should().Be(testPayloadLocation);

        // Verify other headers are also correct
        indirectSignature.TryGetPreImageContentType(out string? payloadType).Should().Be(true);
        payloadType!.Should().Be("application/test.payload");
        indirectSignature.TryGetPayloadHashAlgorithm(out CoseHashAlgorithm? algo).Should().BeTrue();
        algo!.Should().Be(CoseHashAlgorithm.SHA256);
    }

    [Test]
    public async Task TestCreateIndirectSignatureAsyncWithoutPayloadLocation()
    {
        ICoseSigningKeyProvider coseSigningKeyProvider = TestUtils.SetupMockSigningKeyProvider();
        using IndirectSignatureFactory factory = new();
        byte[] randomBytes = new byte[50];
        new Random().NextBytes(randomBytes);

        using MemoryStream memStream = new(randomBytes);
        CoseSign1Message indirectSignature = await factory.CreateIndirectSignatureAsync(
            memStream,
            coseSigningKeyProvider,
            "application/test.payload",
            IndirectSignatureFactory.IndirectSignatureVersion.CoseHashEnvelope);

        // Verify it's an indirect signature
        indirectSignature.IsIndirectSignature().Should().BeTrue();
        indirectSignature.SignatureMatches(randomBytes).Should().BeTrue();

        // Verify PayloadLocation header is NOT set
        indirectSignature.TryGetPayloadLocation(out string? actualLocation).Should().BeFalse();
        actualLocation.Should().BeNull();

        // Verify other headers are correct
        indirectSignature.TryGetPreImageContentType(out string? payloadType).Should().Be(true);
        payloadType!.Should().Be("application/test.payload");
        indirectSignature.TryGetPayloadHashAlgorithm(out CoseHashAlgorithm? algo).Should().BeTrue();
        algo!.Should().Be(CoseHashAlgorithm.SHA256);
    }
}
