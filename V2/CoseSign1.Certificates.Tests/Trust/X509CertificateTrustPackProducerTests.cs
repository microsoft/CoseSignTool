// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Trust;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Trust;
using CoseSign1.Certificates.Trust.Facts;
using CoseSign1.Certificates.Trust.Facts.Producers;
using CoseSign1.Factories.Direct;
using CoseSign1.Tests.Common;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Ids;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Subjects;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

[TestFixture]
public class X509CertificateTrustPackProducerTests
{
    private static readonly byte[] Payload = "cert trust pack"u8.ToArray();

    private static CoseSign1Message CreateMessageWithoutCertificateHeaders()
    {
        using var service = new TestSigningService();
        using var factory = new DirectSignatureFactory(service);

        byte[] messageBytes = factory.CreateCoseSign1MessageBytes(Payload, "application/octet-stream");
        return CoseMessage.DecodeSign1(messageBytes);
    }

    private sealed class ThrowOnCreateEntryMemoryCache : IMemoryCache
    {
        public ICacheEntry CreateEntry(object key)
        {
            throw new InvalidOperationException("test cache create-entry failure");
        }

        public void Dispose()
        {
        }

        public void Remove(object key)
        {
        }

        public bool TryGetValue(object key, out object? value)
        {
            value = null;
            return false;
        }
    }

    private sealed class TestSigningService : ISigningService<SigningOptions>
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public CoseSigner GetCoseSigner(SigningContext context)
        {
            return new CoseSigner(_key, HashAlgorithmName.SHA256);
        }

        public SigningOptions CreateSigningOptions() => new();

        public bool IsRemote => false;

        public SigningServiceMetadata ServiceMetadata { get; } = new("TestSigningService");

        public bool VerifySignature(CoseSign1Message message, SigningContext context)
        {
            return true; // Default: verification passes for tests
        }

        public void Dispose()
        {
            _key.Dispose();
        }
    }

    [Test]
    public async Task ProduceAsync_WhenSubjectNotApplicable_ReturnsAvailableEmpty()
    {
        var trustPack = new X509CertificateTrustPack();
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes("msg"u8.ToArray());
        var context = new TrustFactContext(messageId, TrustSubject.Message(messageId), new TrustEvaluationOptions(), memoryCache: null, message: null);

        var set = await trustPack.ProduceAsync(context, typeof(X509SigningCertificateIdentityFact), CancellationToken.None);

        Assert.That(set.IsMissing, Is.False);
        Assert.That(set.Count, Is.EqualTo(0));
    }

    [Test]
    public void ProduceAsync_WhenContextNull_Throws()
    {
        var trustPack = new X509CertificateTrustPack();

        Assert.That(
            async () => await trustPack.ProduceAsync(null!, typeof(X509SigningCertificateIdentityFact), CancellationToken.None),
            Throws.ArgumentNullException);
    }

    [Test]
    public void ProduceAsync_WhenFactTypeNull_Throws()
    {
        var trustPack = new X509CertificateTrustPack();
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes("msg"u8.ToArray());
        var context = new TrustFactContext(messageId, TrustSubject.PrimarySigningKey(messageId), new TrustEvaluationOptions(), memoryCache: null, message: null);

        Assert.That(
            async () => await trustPack.ProduceAsync(context, null!, CancellationToken.None),
            Throws.ArgumentNullException);
    }

    [Test]
    public async Task ProduceAsync_WhenSubjectNotApplicable_CoversAllKnownFactTypes()
    {
        var trustPack = new X509CertificateTrustPack();
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes("msg"u8.ToArray());
        var context = new TrustFactContext(messageId, TrustSubject.Message(messageId), new TrustEvaluationOptions(), memoryCache: null, message: null);

        var supportedFactTypes = new[]
        {
            typeof(X509SigningCertificateIdentityFact),
            typeof(X509SigningCertificateIdentityAllowedFact),
            typeof(X509SigningCertificateEkuFact),
            typeof(X509SigningCertificateKeyUsageFact),
            typeof(X509SigningCertificateBasicConstraintsFact),
            typeof(X509X5ChainCertificateIdentityFact),
            typeof(X509ChainTrustedFact),
            typeof(X509ChainElementIdentityFact),
            typeof(CertificateSigningKeyTrustFact),
        };

        foreach (Type factType in supportedFactTypes)
        {
            var set = await trustPack.ProduceAsync(context, factType, CancellationToken.None);
            Assert.That(set.IsMissing, Is.False, $"Expected {factType.Name} to be Available for non-applicable subjects");
            Assert.That(set.Count, Is.EqualTo(0));
        }

        var unsupported = await trustPack.ProduceAsync(context, typeof(string), CancellationToken.None);
        Assert.That(unsupported.IsMissing, Is.True);
    }

    [Test]
    public async Task ProduceAsync_WhenMessageNull_ReturnsMissingForCertFacts()
    {
        var trustPack = new X509CertificateTrustPack();
        TrustSubjectId messageId = TrustIds.CreateMessageId(new byte[32]);
        var context = new TrustFactContext(messageId, TrustSubject.PrimarySigningKey(messageId), new TrustEvaluationOptions(), memoryCache: null, message: null);

        var identity = await trustPack.ProduceAsync(context, typeof(X509SigningCertificateIdentityFact), CancellationToken.None);
        Assert.That(identity.IsMissing, Is.True);

        var x5chain = await trustPack.ProduceAsync(context, typeof(X509X5ChainCertificateIdentityFact), CancellationToken.None);
        Assert.That(x5chain.IsMissing, Is.True);

        var identityAllowed = await trustPack.ProduceAsync(context, typeof(X509SigningCertificateIdentityAllowedFact), CancellationToken.None);
        Assert.That(identityAllowed.IsMissing, Is.True);

        var eku = await trustPack.ProduceAsync(context, typeof(X509SigningCertificateEkuFact), CancellationToken.None);
        Assert.That(eku.IsMissing, Is.True);

        var keyUsage = await trustPack.ProduceAsync(context, typeof(X509SigningCertificateKeyUsageFact), CancellationToken.None);
        Assert.That(keyUsage.IsMissing, Is.True);

        var basicConstraints = await trustPack.ProduceAsync(context, typeof(X509SigningCertificateBasicConstraintsFact), CancellationToken.None);
        Assert.That(basicConstraints.IsMissing, Is.True);

        var chainTrusted = await trustPack.ProduceAsync(context, typeof(X509ChainTrustedFact), CancellationToken.None);
        Assert.That(chainTrusted.IsMissing, Is.True);

        var chainElements = await trustPack.ProduceAsync(context, typeof(X509ChainElementIdentityFact), CancellationToken.None);
        Assert.That(chainElements.IsMissing, Is.True);

        var signingKeyTrust = await trustPack.ProduceAsync(context, typeof(CertificateSigningKeyTrustFact), CancellationToken.None);
        Assert.That(signingKeyTrust.IsMissing, Is.True);
    }

    [Test]
    public async Task ProduceSigningCertificateIdentity_WhenNoCertificateHeaders_ReturnsMissing()
    {
        using var service = new TestSigningService();
        using var factory = new DirectSignatureFactory(service);

        byte[] messageBytes = factory.CreateCoseSign1MessageBytes(Payload, "application/octet-stream");
        var message = CoseMessage.DecodeSign1(messageBytes);

        TrustSubjectId messageId = TrustIds.CreateMessageId(message);
        var context = new TrustFactContext(messageId, TrustSubject.PrimarySigningKey(messageId), new TrustEvaluationOptions(), memoryCache: null, message: message);

        var trustPack = new X509CertificateTrustPack();

        var result = await trustPack.ProduceAsync(context, typeof(X509SigningCertificateIdentityFact), CancellationToken.None);

        Assert.That(result.IsMissing, Is.True);
    }

    [Test]
    public async Task ProduceSigningCertificateFacts_WithCertificateHeaders_ProducesExpectedSetsAndCaches()
    {
        using var signingCertificate = TestCertificateUtils.CreateCertificate(subjectName: "TrustPack", customEkus: new[] { "1.3.6.1.5.5.7.3.3" });

        using var signingService = CertificateSigningService.Create(signingCertificate, new List<X509Certificate2> { signingCertificate });
        using var factory = new DirectSignatureFactory(signingService);

        byte[] messageBytes = factory.CreateCoseSign1MessageBytes(Payload, "application/octet-stream");
        var message = CoseMessage.DecodeSign1(messageBytes);

        TrustSubjectId messageId = TrustIds.CreateMessageId(message);
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var context = new TrustFactContext(messageId, TrustSubject.PrimarySigningKey(messageId), new TrustEvaluationOptions(), cache, message);

        var options = new CertificateTrustBuilder()
            .UseEmbeddedChainOnly()
            .WithRevocationMode(X509RevocationMode.NoCheck)
            .Options;

        var trustPack = new X509CertificateTrustPack(options);

        var identity1 = await trustPack.ProduceAsync(context, typeof(X509SigningCertificateIdentityFact), CancellationToken.None);
        var identity2 = await trustPack.ProduceAsync(context, typeof(X509SigningCertificateIdentityFact), CancellationToken.None);

        Assert.That(identity1.IsMissing, Is.False);
        Assert.That(ReferenceEquals(identity1, identity2), Is.True);

        var ekuSet = await trustPack.ProduceAsync(context, typeof(X509SigningCertificateEkuFact), CancellationToken.None);
        Assert.That(ekuSet.IsMissing, Is.False);
        Assert.That(ekuSet.Count, Is.GreaterThanOrEqualTo(1));

        var keyUsageSet = await trustPack.ProduceAsync(context, typeof(X509SigningCertificateKeyUsageFact), CancellationToken.None);
        Assert.That(keyUsageSet.IsMissing, Is.False);

        var constraintsSet = await trustPack.ProduceAsync(context, typeof(X509SigningCertificateBasicConstraintsFact), CancellationToken.None);
        Assert.That(constraintsSet.IsMissing, Is.False);

        var x5ChainSet = await trustPack.ProduceAsync(context, typeof(X509X5ChainCertificateIdentityFact), CancellationToken.None);
        Assert.That(x5ChainSet.IsMissing, Is.False);
        Assert.That(x5ChainSet.Count, Is.GreaterThanOrEqualTo(1));
    }

    [Test]
    public async Task ProduceAdditionalSigningCertificateFacts_WithCache_HitsCacheForEachFactType()
    {
        using var signingCertificate = TestCertificateUtils.CreateCertificate(subjectName: "TrustPackCache", customEkus: new[] { "1.3.6.1.5.5.7.3.3" });

        using var signingService = CertificateSigningService.Create(signingCertificate, new List<X509Certificate2> { signingCertificate });
        using var factory = new DirectSignatureFactory(signingService);

        byte[] messageBytes = factory.CreateCoseSign1MessageBytes(Payload, "application/octet-stream");
        var message = CoseMessage.DecodeSign1(messageBytes);

        TrustSubjectId messageId = TrustIds.CreateMessageId(message);
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var context = new TrustFactContext(messageId, TrustSubject.PrimarySigningKey(messageId), new TrustEvaluationOptions(), cache, message);

        var trustPack = new X509CertificateTrustPack();

        var factTypes = new[]
        {
            typeof(X509SigningCertificateEkuFact),
            typeof(X509SigningCertificateKeyUsageFact),
            typeof(X509SigningCertificateBasicConstraintsFact),
            typeof(X509X5ChainCertificateIdentityFact),
        };

        foreach (var factType in factTypes)
        {
            var first = await trustPack.ProduceAsync(context, factType, CancellationToken.None);
            var second = await trustPack.ProduceAsync(context, factType, CancellationToken.None);

            Assert.That(first.IsMissing, Is.False, $"Expected {factType.Name} to be produced");
            Assert.That(ReferenceEquals(first, second), Is.True, $"Expected {factType.Name} to be cached");
        }
    }

    [Test]
    public async Task ProduceAsync_WhenMessageHasNoCertificateHeaders_ReturnsMissingForCertificateFacts()
    {
        var message = CreateMessageWithoutCertificateHeaders();
        TrustSubjectId messageId = TrustIds.CreateMessageId(message);
        var context = new TrustFactContext(messageId, TrustSubject.PrimarySigningKey(messageId), new TrustEvaluationOptions(), memoryCache: null, message: message);

        var trustPack = new X509CertificateTrustPack();

        var factTypes = new[]
        {
            typeof(X509SigningCertificateIdentityAllowedFact),
            typeof(X509SigningCertificateEkuFact),
            typeof(X509SigningCertificateKeyUsageFact),
            typeof(X509SigningCertificateBasicConstraintsFact),
            typeof(X509X5ChainCertificateIdentityFact),
            typeof(X509ChainElementIdentityFact),
            typeof(CertificateSigningKeyTrustFact),
        };

        foreach (var factType in factTypes)
        {
            var set = await trustPack.ProduceAsync(context, factType, CancellationToken.None);
            Assert.That(set.IsMissing, Is.True, $"Expected {factType.Name} to be missing when no certificate headers are present");
            Assert.That(set.MissingReason, Is.Not.Null);
            Assert.That(set.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.InputUnavailable));
        }
    }

    [Test]
    public async Task ProduceAsync_WhenCacheThrowsOnSet_ReturnsProducerFailedMissing_ForAllFactTypes()
    {
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var leaf = chain[0];

        using var signingService = CertificateSigningService.Create(leaf, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new DirectSignatureFactory(signingService);

        byte[] messageBytes = factory.CreateCoseSign1MessageBytes(Payload, "application/octet-stream");
        var message = CoseMessage.DecodeSign1(messageBytes);

        TrustSubjectId messageId = TrustIds.CreateMessageId(message);

        var options = new CertificateTrustBuilder()
            .UseEmbeddedChainOnly()
            .WithRevocationMode(X509RevocationMode.NoCheck)
            .Options;

        var trustPack = new X509CertificateTrustPack(options);
        using var throwingCache = new ThrowOnCreateEntryMemoryCache();
        var context = new TrustFactContext(messageId, TrustSubject.PrimarySigningKey(messageId), new TrustEvaluationOptions(), throwingCache, message);

        foreach (var factType in trustPack.FactTypes)
        {
            var set = await trustPack.ProduceAsync(context, factType, CancellationToken.None);
            Assert.That(set.IsMissing, Is.True, $"Expected {factType.Name} to be missing due to producer failure");
            Assert.That(set.MissingReason, Is.Not.Null);
            Assert.That(set.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.ProducerFailed));
        }
    }

    [Test]
    public async Task ProduceAsync_WhenServicesProvided_ResolvesLogger_BothWithAndWithoutRegistration()
    {
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var leaf = chain[0];

        using var signingService = CertificateSigningService.Create(leaf, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new DirectSignatureFactory(signingService);

        byte[] messageBytes = factory.CreateCoseSign1MessageBytes(Payload, "application/octet-stream");
        var message = CoseMessage.DecodeSign1(messageBytes);

        TrustSubjectId messageId = TrustIds.CreateMessageId(message);

        // No logger registered.
        var emptyProvider = new ServiceCollection().BuildServiceProvider();
        var contextNoLogger = new TrustFactContext(messageId, TrustSubject.PrimarySigningKey(messageId), new TrustEvaluationOptions(), memoryCache: null, message: message, services: emptyProvider);

        var trustPack = new X509CertificateTrustPack();
        var identityNoLogger = await trustPack.ProduceAsync(contextNoLogger, typeof(X509SigningCertificateIdentityFact), CancellationToken.None);
        Assert.That(identityNoLogger.IsMissing, Is.False);

        // Logger registered.
        var providerWithLogger = new ServiceCollection()
            .AddLogging(b => b.SetMinimumLevel(LogLevel.Trace))
            .BuildServiceProvider();

        var contextWithLogger = new TrustFactContext(messageId, TrustSubject.PrimarySigningKey(messageId), new TrustEvaluationOptions(), memoryCache: null, message: message, services: providerWithLogger);

        var identityWithLogger = await trustPack.ProduceAsync(contextWithLogger, typeof(X509SigningCertificateIdentityFact), CancellationToken.None);
        Assert.That(identityWithLogger.IsMissing, Is.False);
    }

    [Test]
    public async Task ProduceKeyUsageAndBasicConstraints_CoversPresentAndAbsentBranches()
    {
        // Leaf from chain includes KeyUsage; BasicConstraints is typically absent on an end-entity cert.
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var leaf = chain[0];

        using var signingService = CertificateSigningService.Create(leaf, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new DirectSignatureFactory(signingService);

        byte[] messageBytes = factory.CreateCoseSign1MessageBytes(Payload, "application/octet-stream");
        var message = CoseMessage.DecodeSign1(messageBytes);

        TrustSubjectId messageId = TrustIds.CreateMessageId(message);
        var context = new TrustFactContext(messageId, TrustSubject.PrimarySigningKey(messageId), new TrustEvaluationOptions(), memoryCache: null, message: message);

        var options = new CertificateTrustBuilder()
            .UseEmbeddedChainOnly()
            .WithRevocationMode(X509RevocationMode.NoCheck)
            .Options;

        var trustPack = new X509CertificateTrustPack(options);

        var keyUsageSet = await trustPack.ProduceAsync(context, typeof(X509SigningCertificateKeyUsageFact), CancellationToken.None);
        Assert.That(keyUsageSet.IsMissing, Is.False);

        var basicConstraintsSet = await trustPack.ProduceAsync(context, typeof(X509SigningCertificateBasicConstraintsFact), CancellationToken.None);
        Assert.That(basicConstraintsSet.IsMissing, Is.False);
    }

    [Test]
    public async Task ProduceChainRelatedFacts_WithSourceKindNone_UsesX5ChainFallback_AndCaches()
    {
        // SourceKind=None means we won't build an X509Chain, but we can still surface identities
        // from the embedded x5chain header.
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var leaf = chain[0];

        using var signingService = CertificateSigningService.Create(leaf, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new DirectSignatureFactory(signingService);

        byte[] messageBytes = factory.CreateCoseSign1MessageBytes(Payload, "application/octet-stream");
        var message = CoseMessage.DecodeSign1(messageBytes);

        TrustSubjectId messageId = TrustIds.CreateMessageId(message);
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var context = new TrustFactContext(messageId, TrustSubject.PrimarySigningKey(messageId), new TrustEvaluationOptions(), cache, message);

        var options = new CertificateTrustBuilder()
            .WithRevocationMode(X509RevocationMode.NoCheck)
            .Options;

        var trustPack = new X509CertificateTrustPack(options);

        var elementFacts1 = await trustPack.ProduceAsync(context, typeof(X509ChainElementIdentityFact), CancellationToken.None);
        var elementFacts2 = await trustPack.ProduceAsync(context, typeof(X509ChainElementIdentityFact), CancellationToken.None);

        Assert.That(elementFacts1.IsMissing, Is.False);
        Assert.That(elementFacts1.Count, Is.GreaterThanOrEqualTo(1));
        Assert.That(ReferenceEquals(elementFacts1, elementFacts2), Is.True);

        var identityAllowed1 = await trustPack.ProduceAsync(context, typeof(X509SigningCertificateIdentityAllowedFact), CancellationToken.None);
        var identityAllowed2 = await trustPack.ProduceAsync(context, typeof(X509SigningCertificateIdentityAllowedFact), CancellationToken.None);

        Assert.That(identityAllowed1.IsMissing, Is.False);
        Assert.That(ReferenceEquals(identityAllowed1, identityAllowed2), Is.True);

        var keyTrust1 = await trustPack.ProduceAsync(context, typeof(CertificateSigningKeyTrustFact), CancellationToken.None);
        var keyTrust2 = await trustPack.ProduceAsync(context, typeof(CertificateSigningKeyTrustFact), CancellationToken.None);

        Assert.That(keyTrust1.IsMissing, Is.False);
        Assert.That(ReferenceEquals(keyTrust1, keyTrust2), Is.True);
    }

    [Test]
    public async Task ProduceChainTrusted_WithEmbeddedChainOnly_AllowsUnknownRoot_AndPopulatesStatus()
    {
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var leaf = chain[0];

        using var signingService = CertificateSigningService.Create(leaf, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new DirectSignatureFactory(signingService);

        byte[] messageBytes = factory.CreateCoseSign1MessageBytes(Payload, "application/octet-stream");
        var message = CoseMessage.DecodeSign1(messageBytes);

        TrustSubjectId messageId = TrustIds.CreateMessageId(message);
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var context = new TrustFactContext(messageId, TrustSubject.PrimarySigningKey(messageId), new TrustEvaluationOptions(), cache, message);

        var options = new CertificateTrustBuilder()
            .UseEmbeddedChainOnly()
            .WithRevocationMode(X509RevocationMode.NoCheck)
            .Options;

        var trustPack = new X509CertificateTrustPack(options);

        var set = await trustPack.ProduceAsync(context, typeof(X509ChainTrustedFact), CancellationToken.None);

        Assert.That(set.IsMissing, Is.False);
        Assert.That(set.Count, Is.EqualTo(1));
        Assert.That(((ITrustFactSet<X509ChainTrustedFact>)set).Values[0].ElementCount, Is.GreaterThanOrEqualTo(1));
    }

    [Test]
    public async Task ProduceChainTrusted_WithSystemTrust_DeniesUntrustedRoot_AndProvidesSummary()
    {
        // The in-memory test chain is not rooted in a system-trusted root.
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var leaf = chain[0];

        using var signingService = CertificateSigningService.Create(leaf, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new DirectSignatureFactory(signingService);

        byte[] messageBytes = factory.CreateCoseSign1MessageBytes(Payload, "application/octet-stream");
        var message = CoseMessage.DecodeSign1(messageBytes);

        TrustSubjectId messageId = TrustIds.CreateMessageId(message);
        var context = new TrustFactContext(messageId, TrustSubject.PrimarySigningKey(messageId), new TrustEvaluationOptions(), memoryCache: null, message: message);

        var options = new CertificateTrustBuilder()
            .UseSystemTrust()
            .WithRevocationMode(X509RevocationMode.NoCheck)
            .Options;

        var trustPack = new X509CertificateTrustPack(options);

        var set = await trustPack.ProduceAsync(context, typeof(X509ChainTrustedFact), CancellationToken.None);

        Assert.That(set.IsMissing, Is.False);
        var fact = ((ITrustFactSet<X509ChainTrustedFact>)set).Values[0];
        Assert.That(fact.IsTrusted, Is.False);
        Assert.That(fact.StatusSummary, Is.Not.Null);
    }

    [Test]
    public async Task ProduceChainTrusted_WithSourceKindNone_ReturnsMissing()
    {
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var leaf = chain[0];

        using var signingService = CertificateSigningService.Create(leaf, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new DirectSignatureFactory(signingService);

        byte[] messageBytes = factory.CreateCoseSign1MessageBytes(Payload, "application/octet-stream");
        var message = CoseMessage.DecodeSign1(messageBytes);

        TrustSubjectId messageId = TrustIds.CreateMessageId(message);
        var context = new TrustFactContext(messageId, TrustSubject.PrimarySigningKey(messageId), new TrustEvaluationOptions(), memoryCache: null, message: message);

        // No trust source configured.
        var options = new CertificateTrustBuilder()
            .WithRevocationMode(X509RevocationMode.NoCheck)
            .Options;

        var trustPack = new X509CertificateTrustPack(options);

        var set = await trustPack.ProduceAsync(context, typeof(X509ChainTrustedFact), CancellationToken.None);
        Assert.That(set.IsMissing, Is.True);
    }

    [Test]
    public async Task ProduceChainTrusted_WithCustomRootTrust_TrustsChain_AndSurfacesChainElements()
    {
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var leaf = chain[0];
        using var root = chain[^1];

        using var signingService = CertificateSigningService.Create(leaf, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new DirectSignatureFactory(signingService);

        byte[] messageBytes = factory.CreateCoseSign1MessageBytes(Payload, "application/octet-stream");
        var message = CoseMessage.DecodeSign1(messageBytes);

        TrustSubjectId messageId = TrustIds.CreateMessageId(message);
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var context = new TrustFactContext(messageId, TrustSubject.PrimarySigningKey(messageId), new TrustEvaluationOptions(), cache, message);

        var roots = new X509Certificate2Collection { root };
        var options = new CertificateTrustBuilder()
            .UseCustomRootTrust(roots)
            .WithRevocationMode(X509RevocationMode.NoCheck)
            .Options;

        var trustPack = new X509CertificateTrustPack(options);

        var chainTrusted = await trustPack.ProduceAsync(context, typeof(X509ChainTrustedFact), CancellationToken.None);
        Assert.That(chainTrusted.IsMissing, Is.False);
        var chainTrustedFact = ((ITrustFactSet<X509ChainTrustedFact>)chainTrusted).Values[0];
        Assert.That(chainTrustedFact.IsTrusted, Is.True);

        var chainElements = await trustPack.ProduceAsync(context, typeof(X509ChainElementIdentityFact), CancellationToken.None);
        Assert.That(chainElements.IsMissing, Is.False);
        Assert.That(chainElements.Count, Is.GreaterThanOrEqualTo(1));
    }

    [Test]
    public async Task ProduceSigningCertificateIdentityAllowed_WhenThumbprintNotPinned_ReturnsFalse()
    {
        using var signingCertificate = TestCertificateUtils.CreateCertificate(subjectName: "TrustPackPinned");

        using var signingService = CertificateSigningService.Create(signingCertificate, new List<X509Certificate2> { signingCertificate });
        using var factory = new DirectSignatureFactory(signingService);

        byte[] messageBytes = factory.CreateCoseSign1MessageBytes(Payload, "application/octet-stream");
        var message = CoseMessage.DecodeSign1(messageBytes);

        TrustSubjectId messageId = TrustIds.CreateMessageId(message);
        var context = new TrustFactContext(messageId, TrustSubject.PrimarySigningKey(messageId), new TrustEvaluationOptions(), memoryCache: null, message: message);

        var options = new CertificateTrustBuilder()
            .EnableCertificateIdentityPinning(p => p.AllowThumbprint("DEADBEEF"))
            .WithRevocationMode(X509RevocationMode.NoCheck)
            .Options;

        var trustPack = new X509CertificateTrustPack(options);

        var set = await trustPack.ProduceAsync(context, typeof(X509SigningCertificateIdentityAllowedFact), CancellationToken.None);

        Assert.That(set.IsMissing, Is.False);
        var fact = ((ITrustFactSet<X509SigningCertificateIdentityAllowedFact>)set).Values[0];
        Assert.That(fact.IsAllowed, Is.False);
    }
}
