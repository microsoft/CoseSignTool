// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Facts;
using CoseSign1.Validation.Trust.Ids;
using CoseSign1.Validation.Trust.Facts.Producers;
using CoseSign1.Validation.Trust.Subjects;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Verifies that <see cref="CoreMessageFactsProducer"/> produces counter-signature related facts
/// from <see cref="ICounterSignatureResolver"/> results (not via header decoding).
/// </summary>
[TestFixture]
[Category("Validation")]
public sealed class CoreMessageFactsProducerCounterSignatureTests
{
    private static readonly byte[] Payload = "payload"u8.ToArray();

    private sealed class EcdsaSigningKey : ISigningKey
    {
        private readonly ECDsa Key;

        public EcdsaSigningKey(ECDsa key)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
        }

        public CoseKey GetCoseKey()
        {
            return new CoseKey(Key, HashAlgorithmName.SHA256);
        }

        public void Dispose()
        {
            // Test-owned.
        }
    }

    private sealed class TestCounterSignature : ICounterSignature
    {
        public TestCounterSignature(byte[] rawCounterSignatureBytes, bool isProtectedHeader, ISigningKey signingKey)
        {
            RawCounterSignatureBytes = rawCounterSignatureBytes ?? throw new ArgumentNullException(nameof(rawCounterSignatureBytes));
            IsProtectedHeader = isProtectedHeader;
            SigningKey = signingKey ?? throw new ArgumentNullException(nameof(signingKey));
        }

        public byte[] RawCounterSignatureBytes { get; }

        public bool IsProtectedHeader { get; }

        public ISigningKey SigningKey { get; }
    }

    private sealed class FixedCounterSignatureResolver : ICounterSignatureResolver
    {
        private readonly IReadOnlyList<CounterSignatureResolutionResult> Results;

        public FixedCounterSignatureResolver(params CounterSignatureResolutionResult[] results)
        {
            Results = results ?? throw new ArgumentNullException(nameof(results));
        }

        public IReadOnlyList<CounterSignatureResolutionResult> Resolve(CoseSign1Message message)
        {
            return Results;
        }

        public Task<IReadOnlyList<CounterSignatureResolutionResult>> ResolveAsync(CoseSign1Message message, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Results);
        }
    }

    private sealed class CountingCounterSignatureResolver : ICounterSignatureResolver
    {
        private readonly IReadOnlyList<CounterSignatureResolutionResult> Results;

        public CountingCounterSignatureResolver(params CounterSignatureResolutionResult[] results)
        {
            Results = results ?? throw new ArgumentNullException(nameof(results));
        }

        public int ResolveCalls { get; private set; }

        public int ResolveAsyncCalls { get; private set; }

        public IReadOnlyList<CounterSignatureResolutionResult> Resolve(CoseSign1Message message)
        {
            ResolveCalls++;
            return Results;
        }

        public Task<IReadOnlyList<CounterSignatureResolutionResult>> ResolveAsync(CoseSign1Message message, CancellationToken cancellationToken = default)
        {
            ResolveAsyncCalls++;
            return Task.FromResult(Results);
        }
    }

    private static CoseSign1Message CreateSignedMessage()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(signingKey, HashAlgorithmName.SHA256);
        byte[] messageBytes = CoseSign1Message.SignEmbedded(Payload, signer);
        return CoseMessage.DecodeSign1(messageBytes);
    }

    [Test]
    public async Task CounterSignatureSubjectFact_WhenNoResolvers_ReturnsMissing()
    {
        var message = CreateSignedMessage();
        var messageSubject = TrustSubject.Message(message);

        var services = new ServiceCollection().BuildServiceProvider();
        var engine = new TrustFactEngine(
            messageSubject.Id,
            message,
            producers: new IMultiTrustFactProducer[] { new CoreMessageFactsProducer() },
            services: services);

        var factSet = await engine.GetFactsAsync<CounterSignatureSubjectFact>(messageSubject);

        Assert.That(factSet.IsMissing, Is.True);
    }

    [Test]
    public async Task CounterSignatureSubjectFact_WhenResolverReturnsCounterSignature_EmitsFact()
    {
        var message = CreateSignedMessage();
        var messageSubject = TrustSubject.Message(message);

        byte[] counterSigBytes = [1, 2, 3];
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var counterSignature = new TestCounterSignature(counterSigBytes, isProtectedHeader: true, new EcdsaSigningKey(signingKey));

        var resolver = new CountingCounterSignatureResolver(CounterSignatureResolutionResult.Success(counterSignature));

        var services = new ServiceCollection()
            .AddSingleton<ICounterSignatureResolver>(resolver)
            .BuildServiceProvider();

        var engine = new TrustFactEngine(
            messageSubject.Id,
            message,
            producers: new IMultiTrustFactProducer[] { new CoreMessageFactsProducer() },
            services: services);

        var factSet = await engine.GetFactsAsync<CounterSignatureSubjectFact>(messageSubject);

        Assert.That(factSet.IsMissing, Is.False);
        Assert.That(factSet.Values, Has.Count.EqualTo(1));

        var fact = factSet.Values[0];
        Assert.Multiple(() =>
        {
            Assert.That(fact.IsProtectedHeader, Is.True);
            Assert.That(fact.Subject.Kind, Is.EqualTo(TrustSubjectKind.CounterSignature));
            Assert.That(fact.Subject.Id, Is.EqualTo(TrustIds.CreateCounterSignatureId(counterSigBytes)));
        });
    }

    [Test]
    public async Task CounterSignatureSubjectFact_WhenResolverReturnsFailure_ReturnsMissingProducerFailed()
    {
        var message = CreateSignedMessage();
        var messageSubject = TrustSubject.Message(message);

        var resolver = new FixedCounterSignatureResolver(CounterSignatureResolutionResult.Failure("bad"));

        var services = new ServiceCollection()
            .AddSingleton<ICounterSignatureResolver>(resolver)
            .BuildServiceProvider();

        var engine = new TrustFactEngine(
            messageSubject.Id,
            message,
            producers: new IMultiTrustFactProducer[] { new CoreMessageFactsProducer() },
            services: services);

        var factSet = await engine.GetFactsAsync<CounterSignatureSubjectFact>(messageSubject);

        Assert.That(factSet.IsMissing, Is.True);
        Assert.That(factSet.MissingReason, Is.Not.Null);
        Assert.That(factSet.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.ProducerFailed));
    }

    [Test]
    public async Task CounterSignatureSubjectFact_UsesCrossEvaluationCache()
    {
        var message = CreateSignedMessage();
        var messageSubject = TrustSubject.Message(message);

        byte[] counterSigBytes = [1, 2, 3];
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var counterSignature = new TestCounterSignature(counterSigBytes, isProtectedHeader: true, new EcdsaSigningKey(signingKey));

        var resolver = new CountingCounterSignatureResolver(CounterSignatureResolutionResult.Success(counterSignature));

        var services = new ServiceCollection()
            .AddSingleton<ICounterSignatureResolver>(resolver)
            .BuildServiceProvider();

        using var cache = new MemoryCache(new MemoryCacheOptions());

        var engine1 = new TrustFactEngine(
            messageSubject.Id,
            message,
            producers: new IMultiTrustFactProducer[] { new CoreMessageFactsProducer() },
            memoryCache: cache,
            services: services);

        var first = await engine1.GetFactsAsync<CounterSignatureSubjectFact>(messageSubject);

        var engine2 = new TrustFactEngine(
            messageSubject.Id,
            message,
            producers: new IMultiTrustFactProducer[] { new CoreMessageFactsProducer() },
            memoryCache: cache,
            services: services);

        var second = await engine2.GetFactsAsync<CounterSignatureSubjectFact>(messageSubject);

        Assert.Multiple(() =>
        {
            Assert.That(resolver.ResolveAsyncCalls, Is.EqualTo(1));
            Assert.That(first.IsMissing, Is.False);
            Assert.That(second.IsMissing, Is.False);
            Assert.That(first.Values, Has.Count.EqualTo(1));
            Assert.That(second.Values, Has.Count.EqualTo(1));
            Assert.That(first.Values[0].Subject.Id, Is.EqualTo(second.Values[0].Subject.Id));
            Assert.That(first.Values[0].IsProtectedHeader, Is.EqualTo(second.Values[0].IsProtectedHeader));
        });
    }

    [Test]
    public async Task UnknownCounterSignatureBytesFact_WhenResolverReturnsCounterSignature_EmitsBytesFact()
    {
        var message = CreateSignedMessage();
        var messageSubject = TrustSubject.Message(message);

        byte[] counterSigBytes = [9, 9, 9];
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var counterSignature = new TestCounterSignature(counterSigBytes, isProtectedHeader: false, new EcdsaSigningKey(signingKey));

        var resolver = new CountingCounterSignatureResolver(CounterSignatureResolutionResult.Success(counterSignature));

        var services = new ServiceCollection()
            .AddSingleton<ICounterSignatureResolver>(resolver)
            .BuildServiceProvider();

        var engine = new TrustFactEngine(
            messageSubject.Id,
            message,
            producers: new IMultiTrustFactProducer[] { new CoreMessageFactsProducer() },
            services: services);

        var factSet = await engine.GetFactsAsync<UnknownCounterSignatureBytesFact>(messageSubject);

        Assert.That(factSet.IsMissing, Is.False);
        Assert.That(factSet.Values, Has.Count.EqualTo(1));

        var fact = factSet.Values[0];
        Assert.Multiple(() =>
        {
            Assert.That(fact.RawCounterSignatureBytes, Is.EqualTo(counterSigBytes));
            Assert.That(fact.CounterSignatureId, Is.EqualTo(TrustIds.CreateCounterSignatureId(counterSigBytes)));
        });
    }

    [Test]
    public async Task UnknownCounterSignatureBytesFact_DeduplicatesByCounterSignatureId()
    {
        var message = CreateSignedMessage();
        var messageSubject = TrustSubject.Message(message);

        byte[] counterSigBytes = [9, 9, 9];
        using var signingKey1 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signingKey2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var counterSignature1 = new TestCounterSignature(counterSigBytes, isProtectedHeader: false, new EcdsaSigningKey(signingKey1));
        var counterSignature2 = new TestCounterSignature(counterSigBytes, isProtectedHeader: true, new EcdsaSigningKey(signingKey2));

        var resolver = new FixedCounterSignatureResolver(
            CounterSignatureResolutionResult.Success(counterSignature1),
            CounterSignatureResolutionResult.Success(counterSignature2));

        var services = new ServiceCollection()
            .AddSingleton<ICounterSignatureResolver>(resolver)
            .BuildServiceProvider();

        var engine = new TrustFactEngine(
            messageSubject.Id,
            message,
            producers: new IMultiTrustFactProducer[] { new CoreMessageFactsProducer() },
            services: services);

        var factSet = await engine.GetFactsAsync<UnknownCounterSignatureBytesFact>(messageSubject);

        Assert.That(factSet.IsMissing, Is.False);
        Assert.That(factSet.Values, Has.Count.EqualTo(1));
        Assert.That(factSet.Values[0].CounterSignatureId, Is.EqualTo(TrustIds.CreateCounterSignatureId(counterSigBytes)));
    }

    [Test]
    public async Task UnknownCounterSignatureBytesFact_WhenResolverReturnsFailure_ReturnsMissingProducerFailed()
    {
        var message = CreateSignedMessage();
        var messageSubject = TrustSubject.Message(message);

        var resolver = new FixedCounterSignatureResolver(CounterSignatureResolutionResult.Failure("bad"));

        var services = new ServiceCollection()
            .AddSingleton<ICounterSignatureResolver>(resolver)
            .BuildServiceProvider();

        var engine = new TrustFactEngine(
            messageSubject.Id,
            message,
            producers: new IMultiTrustFactProducer[] { new CoreMessageFactsProducer() },
            services: services);

        var factSet = await engine.GetFactsAsync<UnknownCounterSignatureBytesFact>(messageSubject);

        Assert.That(factSet.IsMissing, Is.True);
        Assert.That(factSet.MissingReason, Is.Not.Null);
        Assert.That(factSet.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.ProducerFailed));
    }

    [Test]
    public async Task UnknownCounterSignatureBytesFact_UsesCrossEvaluationCache()
    {
        var message = CreateSignedMessage();
        var messageSubject = TrustSubject.Message(message);

        byte[] counterSigBytes = [9, 9, 9];
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var counterSignature = new TestCounterSignature(counterSigBytes, isProtectedHeader: false, new EcdsaSigningKey(signingKey));

        var resolver = new CountingCounterSignatureResolver(CounterSignatureResolutionResult.Success(counterSignature));

        var services = new ServiceCollection()
            .AddSingleton<ICounterSignatureResolver>(resolver)
            .BuildServiceProvider();

        using var cache = new MemoryCache(new MemoryCacheOptions());

        var engine1 = new TrustFactEngine(
            messageSubject.Id,
            message,
            producers: new IMultiTrustFactProducer[] { new CoreMessageFactsProducer() },
            memoryCache: cache,
            services: services);

        var first = await engine1.GetFactsAsync<UnknownCounterSignatureBytesFact>(messageSubject);

        var engine2 = new TrustFactEngine(
            messageSubject.Id,
            message,
            producers: new IMultiTrustFactProducer[] { new CoreMessageFactsProducer() },
            memoryCache: cache,
            services: services);

        var second = await engine2.GetFactsAsync<UnknownCounterSignatureBytesFact>(messageSubject);

        Assert.Multiple(() =>
        {
            Assert.That(resolver.ResolveAsyncCalls, Is.EqualTo(1));
            Assert.That(first.IsMissing, Is.False);
            Assert.That(second.IsMissing, Is.False);
            Assert.That(first.Values, Has.Count.EqualTo(1));
            Assert.That(second.Values, Has.Count.EqualTo(1));
            Assert.That(first.Values[0].CounterSignatureId, Is.EqualTo(second.Values[0].CounterSignatureId));
            Assert.That(first.Values[0].RawCounterSignatureBytes, Is.EqualTo(counterSigBytes));
            Assert.That(second.Values[0].RawCounterSignatureBytes, Is.EqualTo(counterSigBytes));
        });
    }
}
