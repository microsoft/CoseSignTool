// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Engine;

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Subjects;
using Microsoft.Extensions.Caching.Memory;

/// <summary>
/// Produces and memoizes facts during a single trust evaluation.
/// </summary>
public sealed class TrustFactEngine
{
    private readonly IReadOnlyDictionary<Type, IReadOnlyList<IMultiTrustFactProducer>> ProducersByFactType;
    // Per-evaluation memoization to prevent duplicate fact production when multiple rules
    // ask for the same fact type/subject (including concurrent requests).
    // This is intentionally separate from producer-owned IMemoryCache usage, which may persist
    // across evaluations and is controlled by each producer.
    private readonly ConcurrentDictionary<FactKey, Lazy<Task<ITrustFactSet>>> MemoizedFactSets;
    private readonly Stopwatch OverallStopwatch;
    private readonly TrustSubjectId MessageIdValue;
    private readonly TrustEvaluationOptions Options;
    private readonly IMemoryCache? MemoryCache;
    private readonly CancellationToken CancellationTokenValue;
    private readonly CoseSign1Message? Message;
    private readonly IServiceProvider? Services;

    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string MissingNoProducersMessage = "No producers were registered for this fact type";
        public const string MissingCancelledMessage = "Fact production was cancelled";
        public const string MissingBudgetExceededMessage = "Fact production exceeded the configured budget";
        public const string MissingProducerFailedMessage = "Fact producer failed";
        public const string MissingAllProducersMissingMessage = "All producers returned missing";
        public const string ErrorNullFactType = "Fact type must not be null";
    }

    private readonly struct FactKey : IEquatable<FactKey>
    {
        public FactKey(TrustSubjectId subjectId, Type factType)
        {
            SubjectId = subjectId;
            FactType = factType;
        }

        public TrustSubjectId SubjectId { get; }

        public Type FactType { get; }

        public bool Equals(FactKey other)
        {
            return SubjectId.Equals(other.SubjectId) && FactType == other.FactType;
        }

        public override bool Equals(object? obj)
        {
            return obj is FactKey other && Equals(other);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hash = 17;
                hash = (hash * 31) + SubjectId.GetHashCode();
                hash = (hash * 31) + FactType.GetHashCode();
                return hash;
            }
        }
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TrustFactEngine"/> class.
    /// </summary>
    /// <param name="messageId">The stable message ID for the current evaluation.</param>
    /// <param name="producers">The fact producers available for this evaluation.</param>
    /// <param name="options">Evaluation options including budgets.</param>
    /// <param name="memoryCache">Optional producer-owned cross-validation cache.</param>
    /// <param name="cancellationToken">A cancellation token for fact production.</param>
    /// <param name="services">Optional service provider for resolving producer dependencies.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="producers"/> is null.</exception>
    public TrustFactEngine(
        TrustSubjectId messageId,
        IEnumerable<IMultiTrustFactProducer> producers,
        TrustEvaluationOptions? options = null,
        IMemoryCache? memoryCache = null,
        CancellationToken cancellationToken = default,
        IServiceProvider? services = null)
        : this(messageId, message: null, producers, options, memoryCache, cancellationToken, services)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TrustFactEngine"/> class.
    /// </summary>
    /// <param name="messageId">The stable message ID for the current evaluation.</param>
    /// <param name="message">The current message (optional, but required for some fact producers).</param>
    /// <param name="producers">The fact producers available for this evaluation.</param>
    /// <param name="options">Evaluation options including budgets.</param>
    /// <param name="memoryCache">Optional producer-owned cross-evaluation cache (used by fact producers).</param>
    /// <param name="cancellationToken">A cancellation token for fact production.</param>
    /// <param name="services">Optional service provider for resolving producer dependencies.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="producers"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when a producer advertises a null fact type.</exception>
    public TrustFactEngine(
        TrustSubjectId messageId,
        CoseSign1Message? message,
        IEnumerable<IMultiTrustFactProducer> producers,
        TrustEvaluationOptions? options = null,
        IMemoryCache? memoryCache = null,
        CancellationToken cancellationToken = default,
        IServiceProvider? services = null)
    {
        Guard.ThrowIfNull(producers);

        MessageIdValue = messageId;
        Options = options ?? new TrustEvaluationOptions();
        MemoryCache = memoryCache;
        CancellationTokenValue = cancellationToken;
        Message = message;
        Services = services;

        var byType = new Dictionary<Type, List<IMultiTrustFactProducer>>();
        foreach (var producer in producers)
        {
            if (producer == null)
            {
                continue;
            }

            foreach (var factType in producer.FactTypes ?? Array.Empty<Type>())
            {
                if (factType == null)
                {
                    throw new InvalidOperationException(ClassStrings.ErrorNullFactType);
                }

                if (!byType.TryGetValue(factType, out var list))
                {
                    list = new List<IMultiTrustFactProducer>();
                    byType.Add(factType, list);
                }

                if (!list.Contains(producer))
                {
                    list.Add(producer);
                }
            }
        }

        ProducersByFactType = byType.ToDictionary(
            kvp => kvp.Key,
            kvp => (IReadOnlyList<IMultiTrustFactProducer>)kvp.Value.ToArray());

        MemoizedFactSets = new ConcurrentDictionary<FactKey, Lazy<Task<ITrustFactSet>>>();
        OverallStopwatch = Stopwatch.StartNew();
    }

    /// <summary>
    /// Gets the message ID for the current evaluation.
    /// </summary>
    public TrustSubjectId MessageId => MessageIdValue;

    /// <summary>
    /// Retrieves the specified fact set for the subject.
    /// </summary>
    /// <param name="subject">The subject.</param>
    /// <returns>The fact set.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="subject"/> is null.</exception>
    public ValueTask<ITrustFactSet<TFact>> GetFactsAsync<TFact>(TrustSubject subject)
    {
        Guard.ThrowIfNull(subject);

        var factType = typeof(TFact);
        var key = new FactKey(subject.Id, factType);

        var lazy = MemoizedFactSets.GetOrAdd(
            key,
            _ => new Lazy<Task<ITrustFactSet>>(() => ProduceFactsAsync<TFact>(subject)));

        return new ValueTask<ITrustFactSet<TFact>>(AwaitAndCastAsync<TFact>(lazy.Value));
    }

    private static async Task<ITrustFactSet<TFact>> AwaitAndCastAsync<TFact>(Task<ITrustFactSet> task)
    {
        var set = await task.ConfigureAwait(false);
        if (set is ITrustFactSet<TFact> typed)
        {
            return typed;
        }

        // Producer contract violation: wrong fact set type.
        return TrustFactSet<TFact>.Missing(
            TrustFactMissingCodes.ProducerFailed,
            ClassStrings.MissingProducerFailedMessage);
    }

    private async Task<ITrustFactSet> ProduceFactsAsync<TFact>(TrustSubject subject)
    {
        var factType = typeof(TFact);

        if (CancellationTokenValue.IsCancellationRequested)
        {
            return TrustFactSet<TFact>.Missing(TrustFactMissingCodes.Cancelled, ClassStrings.MissingCancelledMessage);
        }

        if (!ProducersByFactType.TryGetValue(factType, out var producers) || producers.Count == 0)
        {
            return TrustFactSet<TFact>.Missing(TrustFactMissingCodes.NoProducers, ClassStrings.MissingNoProducersMessage);
        }

        if (Options.OverallTimeout is TimeSpan overallTimeout)
        {
            var remaining = overallTimeout - OverallStopwatch.Elapsed;
            if (remaining <= TimeSpan.Zero)
            {
                return TrustFactSet<TFact>.Missing(TrustFactMissingCodes.BudgetExceeded, ClassStrings.MissingBudgetExceededMessage);
            }
        }

        using var factCts = CreateBudgetCts(Options.PerFactTimeout);
        var factToken = factCts?.Token ?? CancellationTokenValue;

        if (factToken.IsCancellationRequested)
        {
            return CancellationTokenValue.IsCancellationRequested
                ? TrustFactSet<TFact>.Missing(TrustFactMissingCodes.Cancelled, ClassStrings.MissingCancelledMessage)
                : TrustFactSet<TFact>.Missing(TrustFactMissingCodes.BudgetExceeded, ClassStrings.MissingBudgetExceededMessage);
        }

        var context = new TrustFactContext(MessageIdValue, subject, Options, MemoryCache, Message, Services);

        var allValues = new List<TFact>();
        var anyAvailable = false;
        TrustFactMissing? firstMissing = null;

        foreach (var producer in producers)
        {
            try
            {
                if (factToken.IsCancellationRequested)
                {
                    return CancellationTokenValue.IsCancellationRequested
                        ? TrustFactSet<TFact>.Missing(TrustFactMissingCodes.Cancelled, ClassStrings.MissingCancelledMessage)
                        : TrustFactSet<TFact>.Missing(TrustFactMissingCodes.BudgetExceeded, ClassStrings.MissingBudgetExceededMessage);
                }

                using var producerCts = CreateBudgetCts(Options.PerProducerTimeout, factToken);
                var token = producerCts?.Token ?? factToken;

                var result = await producer.ProduceAsync(context, factType, token).ConfigureAwait(false);

                if (result == null)
                {
                    continue;
                }

                if (!result.IsMissing)
                {
                    if (result is ITrustFactSet<TFact> typed)
                    {
                        anyAvailable = true;
                        allValues.AddRange(typed.Values);
                    }
                    else
                    {
                        // Producer contract violation: wrong fact set type.
                        if (!anyAvailable)
                        {
                            return TrustFactSet<TFact>.Missing(
                                TrustFactMissingCodes.ProducerFailed,
                                ClassStrings.MissingProducerFailedMessage);
                        }
                    }
                }
                else if (firstMissing == null)
                {
                    firstMissing = result.MissingReason;
                }
            }
            catch (OperationCanceledException oce)
            {
                if (CancellationTokenValue.IsCancellationRequested)
                {
                    return TrustFactSet<TFact>.Missing(TrustFactMissingCodes.Cancelled, ClassStrings.MissingCancelledMessage, oce);
                }

                return TrustFactSet<TFact>.Missing(TrustFactMissingCodes.BudgetExceeded, ClassStrings.MissingBudgetExceededMessage, oce);
            }
            catch (Exception ex)
            {
                // Treat producer failure as a missing fact. If other producers succeed, we still allow the fact.
                if (!anyAvailable)
                {
                    return TrustFactSet<TFact>.Missing(TrustFactMissingCodes.ProducerFailed, ClassStrings.MissingProducerFailedMessage, ex);
                }
            }
        }

        if (!anyAvailable)
        {
            if (firstMissing != null)
            {
                return TrustFactSet<TFact>.Missing(firstMissing.Code, firstMissing.Message, firstMissing.Exception);
            }

            return TrustFactSet<TFact>.Missing(TrustFactMissingCodes.AllProducersMissing, ClassStrings.MissingAllProducersMissingMessage);
        }

        return TrustFactSet<TFact>.Available(allValues.ToArray());
    }

    private CancellationTokenSource? CreateBudgetCts(TimeSpan? timeout, CancellationToken? linkedToken = null)
    {
        var effectiveTimeout = GetEffectiveTimeout(timeout);
        if (effectiveTimeout == null)
        {
            return linkedToken == null ? null : CancellationTokenSource.CreateLinkedTokenSource(linkedToken.Value);
        }

        CancellationTokenSource cts;
        if (linkedToken == null)
        {
            cts = CancellationTokenSource.CreateLinkedTokenSource(CancellationTokenValue);
        }
        else
        {
            cts = CancellationTokenSource.CreateLinkedTokenSource(CancellationTokenValue, linkedToken.Value);
        }

        if (effectiveTimeout.Value <= TimeSpan.Zero)
        {
            cts.Cancel();
        }
        else
        {
            cts.CancelAfter(effectiveTimeout.Value);
        }
        return cts;
    }

    private TimeSpan? GetEffectiveTimeout(TimeSpan? requested)
    {
        if (Options.OverallTimeout is not TimeSpan overallTimeout)
        {
            return requested;
        }

        var remaining = overallTimeout - OverallStopwatch.Elapsed;
        if (remaining <= TimeSpan.Zero)
        {
            return TimeSpan.Zero;
        }

        if (requested == null)
        {
            return remaining;
        }

        return requested.Value < remaining ? requested.Value : remaining;
    }
}
