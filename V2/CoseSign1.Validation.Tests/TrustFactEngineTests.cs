// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using Microsoft.Extensions.Caching.Memory;

[TestFixture]
[Category("Validation")]
public class TrustFactEngineTests
{
    private sealed class TestFact
    {
        public TestFact(string value)
        {
            Value = value;
        }

        public string Value { get; }
    }

    private sealed class CountingProducer : IMultiTrustFactProducer
    {
        private int callCount;

        public int CallCount => callCount;

        public IReadOnlyCollection<Type> FactTypes => new[] { typeof(TestFact) };

        public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref callCount);
            return ValueTask.FromResult<ITrustFactSet>(TrustFactSet<TestFact>.Available(new TestFact("v")));
        }
    }

    private sealed class CrossValidationCacheProducer : IMultiTrustFactProducer
    {
        private int computeCount;

        public int ComputeCount => computeCount;

        public IReadOnlyCollection<Type> FactTypes => new[] { typeof(TestFact) };

        public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
        {
            if (context.MemoryCache == null)
            {
                return ValueTask.FromResult<ITrustFactSet>(
                    TrustFactSet<TestFact>.Missing(TrustFactMissingCodes.NoProducers, "cache required"));
            }

            var key = context.CreateCacheKey(typeof(TestFact));
            if (context.MemoryCache.TryGetValue(key, out ITrustFactSet? cached) && cached != null)
            {
                return ValueTask.FromResult(cached);
            }

            Interlocked.Increment(ref computeCount);
            ITrustFactSet produced = TrustFactSet<TestFact>.Available(new TestFact("cached"));
            context.MemoryCache.Set(key, produced);
            return ValueTask.FromResult(produced);
        }
    }

    private sealed class SlowProducer : IMultiTrustFactProducer
    {
        public IReadOnlyCollection<Type> FactTypes => new[] { typeof(TestFact) };

        public async ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
        {
            await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
            return TrustFactSet<TestFact>.Available(new TestFact("slow"));
        }
    }

    private sealed class MissingProducer : IMultiTrustFactProducer
    {
        public IReadOnlyCollection<Type> FactTypes => new[] { typeof(TestFact) };

        public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
        {
            return ValueTask.FromResult<ITrustFactSet>(
                TrustFactSet<TestFact>.Missing(TrustFactMissingCodes.AllProducersMissing, "missing"));
        }
    }

    private sealed class ThrowingProducer : IMultiTrustFactProducer
    {
        public IReadOnlyCollection<Type> FactTypes => new[] { typeof(TestFact) };

        public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("boom");
        }
    }

    private sealed class NullProducer : IMultiTrustFactProducer
    {
        public IReadOnlyCollection<Type> FactTypes => new[] { typeof(TestFact) };

        public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
        {
            return ValueTask.FromResult<ITrustFactSet>(null!);
        }
    }

    private sealed class WrongTypeProducer : IMultiTrustFactProducer
    {
        public IReadOnlyCollection<Type> FactTypes => new[] { typeof(TestFact) };

        public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
        {
            // Contract violation: claims TestFact but returns object.
            return ValueTask.FromResult<ITrustFactSet>(TrustFactSet<object>.Available(new object()));
        }
    }

    private sealed class CancellingProducer : IMultiTrustFactProducer
    {
        private readonly CancellationTokenSource cts;

        public CancellingProducer(CancellationTokenSource cts)
        {
            this.cts = cts;
        }

        public IReadOnlyCollection<Type> FactTypes => new[] { typeof(TestFact) };

        public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
        {
            cts.Cancel();
            throw new OperationCanceledException("cancelled by producer");
        }
    }

    [Test]
    public async Task GetFactsAsync_Memoizes_PerValidation()
    {
        using var key = ECDsa.Create();
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        byte[] signedBytes = CoseSign1Message.SignEmbedded("payload"u8.ToArray(), signer);
        var message = CoseMessage.DecodeSign1(signedBytes);

        var messageId = TrustIds.CreateMessageId(message);
        var subject = TrustSubject.Message(message);

        var producer = new CountingProducer();
        var engine = new TrustFactEngine(messageId, new[] { producer });

        var facts1 = await engine.GetFactsAsync<TestFact>(subject);
        var facts2 = await engine.GetFactsAsync<TestFact>(subject);

        Assert.Multiple(() =>
        {
            Assert.That(facts1.IsMissing, Is.False);
            Assert.That(facts2.IsMissing, Is.False);
            Assert.That(producer.CallCount, Is.EqualTo(1));
            Assert.That(facts1.Values, Has.Count.EqualTo(1));
        });
    }

    [Test]
    public async Task GetFactsAsync_AllowsProducerOwnedCrossValidationCaching()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());

        var messageId = TrustSubjectId.FromSha256OfBytes("m"u8);
        var subject = TrustSubject.CounterSignature(messageId, "cs"u8);

        var producer = new CrossValidationCacheProducer();

        var engine1 = new TrustFactEngine(messageId, new[] { producer }, memoryCache: cache);
        var engine2 = new TrustFactEngine(messageId, new[] { producer }, memoryCache: cache);

        var r1 = await engine1.GetFactsAsync<TestFact>(subject);
        var r2 = await engine2.GetFactsAsync<TestFact>(subject);

        Assert.Multiple(() =>
        {
            Assert.That(r1.IsMissing, Is.False);
            Assert.That(r2.IsMissing, Is.False);
            Assert.That(producer.ComputeCount, Is.EqualTo(1));
        });
    }

    [Test]
    public async Task GetFactsAsync_WhenProducerTimesOut_ReturnsMissingBudgetExceeded()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes("m"u8);
        var subject = TrustSubject.CounterSignature(messageId, "cs"u8);

        var options = new TrustEvaluationOptions
        {
            PerProducerTimeout = TimeSpan.FromMilliseconds(1)
        };

        var engine = new TrustFactEngine(messageId, new[] { new SlowProducer() }, options);

        var result = await engine.GetFactsAsync<TestFact>(subject);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsMissing, Is.True);
            Assert.That(result.MissingReason, Is.Not.Null);
            Assert.That(result.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.BudgetExceeded));
        });
    }

    [Test]
    public async Task GetFactsAsync_WhenCancelled_ReturnsMissingCancelled()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var messageId = TrustSubjectId.FromSha256OfBytes("m"u8);
        var subject = TrustSubject.CounterSignature(messageId, "cs"u8);

        var engine = new TrustFactEngine(messageId, new[] { new SlowProducer() }, cancellationToken: cts.Token);

        var result = await engine.GetFactsAsync<TestFact>(subject);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsMissing, Is.True);
            Assert.That(result.MissingReason, Is.Not.Null);
            Assert.That(result.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.Cancelled));
        });
    }

    [Test]
    public async Task GetFactsAsync_WhenNoProducers_ReturnsMissingNoProducers()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes("m"u8);
        var subject = TrustSubject.CounterSignature(messageId, "cs"u8);

        var engine = new TrustFactEngine(messageId, Array.Empty<IMultiTrustFactProducer>());

        var result = await engine.GetFactsAsync<TestFact>(subject);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsMissing, Is.True);
            Assert.That(result.MissingReason, Is.Not.Null);
            Assert.That(result.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.NoProducers));
        });
    }

    [Test]
    public async Task GetFactsAsync_WhenAllProducersReturnMissing_ReturnsMissingAllProducersMissing()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes("m"u8);
        var subject = TrustSubject.CounterSignature(messageId, "cs"u8);

        var engine = new TrustFactEngine(messageId, new[] { new MissingProducer() });

        var result = await engine.GetFactsAsync<TestFact>(subject);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsMissing, Is.True);
            Assert.That(result.MissingReason, Is.Not.Null);
            Assert.That(result.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.AllProducersMissing));
        });
    }

    [Test]
    public async Task GetFactsAsync_WhenOverallBudgetIsZero_ReturnsMissingBudgetExceeded()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes("m"u8);
        var subject = TrustSubject.CounterSignature(messageId, "cs"u8);

        var options = new TrustEvaluationOptions
        {
            OverallTimeout = TimeSpan.Zero
        };

        var engine = new TrustFactEngine(messageId, new[] { new CountingProducer() }, options);

        var result = await engine.GetFactsAsync<TestFact>(subject);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsMissing, Is.True);
            Assert.That(result.MissingReason, Is.Not.Null);
            Assert.That(result.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.BudgetExceeded));
        });
    }

    [Test]
    public async Task GetFactsAsync_WhenProducerThrowsAndNoOtherAvailable_ReturnsMissingProducerFailed()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes("m"u8);
        var subject = TrustSubject.CounterSignature(messageId, "cs"u8);

        var engine = new TrustFactEngine(messageId, new[] { new ThrowingProducer() });

        var result = await engine.GetFactsAsync<TestFact>(subject);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsMissing, Is.True);
            Assert.That(result.MissingReason, Is.Not.Null);
            Assert.That(result.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.ProducerFailed));
        });
    }

    [Test]
    public async Task GetFactsAsync_WhenOneProducerThrowsButOneSucceeds_ReturnsAvailable()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes("m"u8);
        var subject = TrustSubject.CounterSignature(messageId, "cs"u8);

        var engine = new TrustFactEngine(messageId, new IMultiTrustFactProducer[] { new CountingProducer(), new ThrowingProducer() });

        var result = await engine.GetFactsAsync<TestFact>(subject);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsMissing, Is.False);
            Assert.That(result.Values, Has.Count.GreaterThanOrEqualTo(1));
        });
    }

    [Test]
    public async Task GetFactsAsync_WhenProducerReturnsNull_IgnoresResultAndContinues()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes("m"u8);
        var subject = TrustSubject.CounterSignature(messageId, "cs"u8);

        var engine = new TrustFactEngine(messageId, new IMultiTrustFactProducer[] { new NullProducer(), new CountingProducer() });

        var result = await engine.GetFactsAsync<TestFact>(subject);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsMissing, Is.False);
            Assert.That(result.Values, Has.Count.GreaterThanOrEqualTo(1));
        });
    }

    [Test]
    public async Task GetFactsAsync_WhenAllProducersReturnNull_ReturnsMissingAllProducersMissing()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes("m"u8);
        var subject = TrustSubject.CounterSignature(messageId, "cs"u8);

        var engine = new TrustFactEngine(messageId, new IMultiTrustFactProducer[] { new NullProducer() });

        var result = await engine.GetFactsAsync<TestFact>(subject);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsMissing, Is.True);
            Assert.That(result.MissingReason, Is.Not.Null);
            Assert.That(result.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.AllProducersMissing));
        });
    }

    [Test]
    public async Task GetFactsAsync_WhenProducerReturnsWrongFactSetType_ReturnsMissingProducerFailed()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes("m"u8);
        var subject = TrustSubject.CounterSignature(messageId, "cs"u8);

        var engine = new TrustFactEngine(messageId, new IMultiTrustFactProducer[] { new WrongTypeProducer() });

        var result = await engine.GetFactsAsync<TestFact>(subject);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsMissing, Is.True);
            Assert.That(result.MissingReason, Is.Not.Null);
            Assert.That(result.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.ProducerFailed));
        });
    }

    [Test]
    public async Task GetFactsAsync_WhenProducerCancelsEngineToken_ReturnsMissingCancelled()
    {
        using var cts = new CancellationTokenSource();

        var messageId = TrustSubjectId.FromSha256OfBytes("m"u8);
        var subject = TrustSubject.CounterSignature(messageId, "cs"u8);

        var engine = new TrustFactEngine(messageId, new[] { new CancellingProducer(cts) }, cancellationToken: cts.Token);
        var result = await engine.GetFactsAsync<TestFact>(subject);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsMissing, Is.True);
            Assert.That(result.MissingReason, Is.Not.Null);
            Assert.That(result.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.Cancelled));
        });
    }

    [Test]
    public void MessageId_ReturnsEngineMessageId()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes("m"u8);
        var engine = new TrustFactEngine(messageId, Array.Empty<IMultiTrustFactProducer>());
        Assert.That(engine.MessageId, Is.EqualTo(messageId));
    }

    [Test]
    public void Ctor_NullProducers_ThrowsArgumentNullException()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes("m"u8);
        Assert.That(() => _ = new TrustFactEngine(messageId, (IEnumerable<IMultiTrustFactProducer>)null!), Throws.ArgumentNullException);
    }

    [Test]
    public void GetFactsAsync_NullSubject_ThrowsArgumentNullException()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes("m"u8);
        var engine = new TrustFactEngine(messageId, Array.Empty<IMultiTrustFactProducer>());
        Assert.That(() => engine.GetFactsAsync<TestFact>(null!), Throws.ArgumentNullException);
    }

    [Test]
    public void TrustFactContext_CreateCacheKey_NullFactType_Throws()
    {
        var context = new TrustFactContext(
            TrustSubjectId.FromSha256OfBytes("m"u8),
            TrustSubject.CounterSignature(TrustSubjectId.FromSha256OfBytes("m"u8), "cs"u8),
            new TrustEvaluationOptions(),
            memoryCache: null,
            message: null);

        Assert.That(() => context.CreateCacheKey(null!), Throws.ArgumentNullException);
    }

    [Test]
    public void TrustFactSet_ImplementsBaseInterfaceAndCount()
    {
        ITrustFactSet set = TrustFactSet<TestFact>.Available(new TestFact("v"));

        Assert.Multiple(() =>
        {
            Assert.That(set.FactType, Is.EqualTo(typeof(TestFact)));
            Assert.That(set.IsMissing, Is.False);
            Assert.That(set.Count, Is.EqualTo(1));
        });
    }

    [Test]
    public void TrustFactCacheKey_Equality_IsStable()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes("m"u8);
        var subjectId = TrustSubjectId.FromSha256OfBytes("s"u8);

        var k1 = new TrustFactCacheKey(messageId, subjectId, typeof(TestFact));
        var k2 = new TrustFactCacheKey(messageId, subjectId, typeof(TestFact));
        var k3 = new TrustFactCacheKey(messageId, TrustSubjectId.FromSha256OfBytes("s2"u8), typeof(TestFact));

        Assert.Multiple(() =>
        {
            Assert.That(k1.Equals(k2), Is.True);
            Assert.That(k1 == k2, Is.True);
            Assert.That(k1 != k2, Is.False);
            Assert.That(k1.Equals(k3), Is.False);
            Assert.That(k1.GetHashCode(), Is.Not.EqualTo(0));
        });
    }

    [Test]
    public async Task GetFactsAsync_WhenPerFactTimeoutIsZero_ReturnsMissingBudgetExceeded_AndSkipsProducers()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes("m"u8);
        var subject = TrustSubject.CounterSignature(messageId, "cs"u8);

        var producer = new CountingProducer();
        var options = new TrustEvaluationOptions
        {
            PerFactTimeout = TimeSpan.Zero
        };

        var engine = new TrustFactEngine(messageId, new[] { producer }, options);

        var result = await engine.GetFactsAsync<TestFact>(subject);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsMissing, Is.True);
            Assert.That(result.MissingReason, Is.Not.Null);
            Assert.That(result.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.BudgetExceeded));
            Assert.That(producer.CallCount, Is.EqualTo(0));
        });
    }

    [Test]
    public async Task GetFactsAsync_WhenOverallTimeoutIsSet_StillProducesWithinBudget()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes("m"u8);
        var subject = TrustSubject.CounterSignature(messageId, "cs"u8);

        var options = new TrustEvaluationOptions
        {
            OverallTimeout = TimeSpan.FromSeconds(1)
        };

        var engine = new TrustFactEngine(messageId, new[] { new CountingProducer() }, options);

        var result = await engine.GetFactsAsync<TestFact>(subject);

        Assert.That(result.IsMissing, Is.False);
    }

    [Test]
    public async Task GetFactsAsync_WhenRequestedBudgetExceedsOverall_UsesOverallBudget()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes("m"u8);
        var subject = TrustSubject.CounterSignature(messageId, "cs"u8);

        var options = new TrustEvaluationOptions
        {
            OverallTimeout = TimeSpan.FromMilliseconds(5),
            PerFactTimeout = TimeSpan.FromSeconds(10),
            PerProducerTimeout = TimeSpan.FromSeconds(10)
        };

        var engine = new TrustFactEngine(messageId, new[] { new SlowProducer() }, options);

        var result = await engine.GetFactsAsync<TestFact>(subject);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsMissing, Is.True);
            Assert.That(result.MissingReason, Is.Not.Null);
            Assert.That(result.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.BudgetExceeded));
        });
    }
}
