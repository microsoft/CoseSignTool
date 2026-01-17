// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Facts.Producers;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using Microsoft.Extensions.Caching.Memory;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Ids;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Rules;
using CoseSign1.Validation.Trust.Subjects;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Produces core message-level facts.
/// </summary>
public sealed partial class CoreMessageFactsProducer : ITrustPack
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string MissingMessageUnavailable = "COSE message is not available";
        public const string MissingCounterSignatureDecodeFailed = "Failed to decode counter-signature header value";
        public const string MissingCounterSignatureDiscoveryUnavailable = "Counter-signature discovery not available";
        public const string ErrorUnsupportedFactType = "Unsupported fact type requested";

        public const string DenyByDefault = "No trust packs enabled; trust is denied by default.";
        public const string NoVetoes = "No core vetoes.";
    }

    #region LoggerMessage methods

    [LoggerMessage(
        EventId = 6000,
        Level = LogLevel.Trace,
        Message = "Producing message fact. FactType: {FactType}, SubjectKind: {SubjectKind}")]
    private static partial void LogProducing(ILogger logger, string factType, TrustSubjectKind subjectKind);

    [LoggerMessage(
        EventId = 6001,
        Level = LogLevel.Debug,
        Message = "Message fact not applicable for subject kind. FactType: {FactType}, SubjectKind: {SubjectKind}")]
    private static partial void LogNotApplicable(ILogger logger, string factType, TrustSubjectKind subjectKind);

    [LoggerMessage(
        EventId = 6002,
        Level = LogLevel.Debug,
        Message = "COSE message unavailable; returning missing message fact. FactType: {FactType}")]
    private static partial void LogMessageUnavailable(ILogger logger, string factType);

    [LoggerMessage(
        EventId = 6003,
        Level = LogLevel.Debug,
        Message = "Unsupported fact type requested by engine. FactType: {FactType}")]
    private static partial void LogUnsupportedFactType(ILogger logger, string factType);

    [LoggerMessage(
        EventId = 6004,
        Level = LogLevel.Debug,
        Message = "Message fact cache hit. FactType: {FactType}")]
    private static partial void LogCacheHit(ILogger logger, string factType);

    [LoggerMessage(
        EventId = 6005,
        Level = LogLevel.Error,
        Message = "Counter-signature fact production failed. FactType: {FactType}")]
    private static partial void LogCounterSignatureProducerFailed(ILogger logger, Exception ex, string factType);

    #endregion

    private static readonly Type[] SupportedTypes =
    {
        typeof(DetachedPayloadPresentFact),
        typeof(ContentTypeFact),
        typeof(CounterSignatureSubjectFact),
        typeof(UnknownCounterSignatureBytesFact),
    };

    /// <inheritdoc />
    public IReadOnlyCollection<Type> FactTypes => SupportedTypes;

    /// <inheritdoc />
    public TrustPlanDefaults GetDefaults()
    {
        // Secure-by-default: without explicit trust packs, the default plan must deny trust.
        return new TrustPlanDefaults(
            constraints: TrustRules.AllowAll(),
            trustSources: new[] { TrustRules.DenyAll(ClassStrings.DenyByDefault) },
            vetoes: TrustRules.DenyAll(ClassStrings.NoVetoes));
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="context"/> or <paramref name="factType"/> is null.</exception>
    public ValueTask<ITrustFactSet> ProduceAsync(TrustFactContext context, Type factType, CancellationToken cancellationToken)
    {
        Guard.ThrowIfNull(context);
        Guard.ThrowIfNull(factType);

        ILogger logger = ResolveLogger(context);
        LogProducing(logger, factType.FullName ?? factType.Name, context.Subject.Kind);

        if (context.Subject.Kind != TrustSubjectKind.Message)
        {
            // These facts only apply to the Message subject.
            LogNotApplicable(logger, factType.FullName ?? factType.Name, context.Subject.Kind);

            return factType switch
            {
                var t when t == typeof(DetachedPayloadPresentFact) => new ValueTask<ITrustFactSet>(TrustFactSet<DetachedPayloadPresentFact>.Available()),
                var t when t == typeof(ContentTypeFact) => new ValueTask<ITrustFactSet>(TrustFactSet<ContentTypeFact>.Available()),
                var t when t == typeof(CounterSignatureSubjectFact) => new ValueTask<ITrustFactSet>(TrustFactSet<CounterSignatureSubjectFact>.Available()),
                var t when t == typeof(UnknownCounterSignatureBytesFact) => new ValueTask<ITrustFactSet>(TrustFactSet<UnknownCounterSignatureBytesFact>.Available()),
                _ => new ValueTask<ITrustFactSet>(TrustFactSet<object>.Missing(TrustFactMissingCodes.InputUnavailable, ClassStrings.ErrorUnsupportedFactType)),
            };
        }

        if (context.Message == null)
        {
            // Map to the correct typed missing set.
            LogMessageUnavailable(logger, factType.FullName ?? factType.Name);
            return factType switch
            {
                var t when t == typeof(DetachedPayloadPresentFact) => new ValueTask<ITrustFactSet>(
                    TrustFactSet<DetachedPayloadPresentFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingMessageUnavailable)),
                var t when t == typeof(ContentTypeFact) => new ValueTask<ITrustFactSet>(
                    TrustFactSet<ContentTypeFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingMessageUnavailable)),
                var t when t == typeof(CounterSignatureSubjectFact) => new ValueTask<ITrustFactSet>(
                    TrustFactSet<CounterSignatureSubjectFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingMessageUnavailable)),
                var t when t == typeof(UnknownCounterSignatureBytesFact) => new ValueTask<ITrustFactSet>(
                    TrustFactSet<UnknownCounterSignatureBytesFact>.Missing(
                        TrustFactMissingCodes.InputUnavailable,
                        ClassStrings.MissingMessageUnavailable)),
                _ => new ValueTask<ITrustFactSet>(
                    TrustFactSet<object>.Missing(TrustFactMissingCodes.InputUnavailable, ClassStrings.ErrorUnsupportedFactType)),
            };
        }

        return factType switch
        {
            var t when t == typeof(DetachedPayloadPresentFact) => ProduceDetachedPayloadPresentFact(context, logger),
            var t when t == typeof(ContentTypeFact) => ProduceContentTypeFact(context, logger),
            var t when t == typeof(CounterSignatureSubjectFact) => ProduceCounterSignatureSubjectsFactAsync(context, logger, cancellationToken),
            var t when t == typeof(UnknownCounterSignatureBytesFact) => ProduceUnknownCounterSignatureBytesFactAsync(context, logger, cancellationToken),
            _ => Unsupported(factType, logger),
        };
    }

    private static ValueTask<ITrustFactSet> Unsupported(Type factType, ILogger logger)
    {
        LogUnsupportedFactType(logger, factType.FullName ?? factType.Name);
        return new ValueTask<ITrustFactSet>(
            TrustFactSet<object>.Missing(TrustFactMissingCodes.InputUnavailable, ClassStrings.ErrorUnsupportedFactType));
    }

    private static ILogger ResolveLogger(TrustFactContext context)
    {
        if (context.Services == null)
        {
            return NullLogger.Instance;
        }

        return (context.Services.GetService(typeof(ILogger<CoreMessageFactsProducer>)) as ILogger<CoreMessageFactsProducer>)
            ?? NullLogger<CoreMessageFactsProducer>.Instance;
    }

    private static ValueTask<ITrustFactSet> ProduceDetachedPayloadPresentFact(TrustFactContext context, ILogger logger)
    {
        TrustFactCacheKey cacheKey = context.CreateCacheKey(typeof(DetachedPayloadPresentFact));
        if (context.MemoryCache != null &&
            context.MemoryCache.TryGetValue(cacheKey, out TrustFactSet<DetachedPayloadPresentFact>? cached) &&
            cached != null)
        {
            LogCacheHit(logger, typeof(DetachedPayloadPresentFact).FullName ?? nameof(DetachedPayloadPresentFact));
            return new ValueTask<ITrustFactSet>(cached);
        }

        bool detachedPayloadPresent = !context.Message!.Content.HasValue;
        var result = TrustFactSet<DetachedPayloadPresentFact>.Available(
            new DetachedPayloadPresentFact(detachedPayloadPresent));

        context.MemoryCache?.Set(cacheKey, result);
        return new ValueTask<ITrustFactSet>(result);
    }

    private static ValueTask<ITrustFactSet> ProduceContentTypeFact(TrustFactContext context, ILogger logger)
    {
        TrustFactCacheKey cacheKey = context.CreateCacheKey(typeof(ContentTypeFact));
        if (context.MemoryCache != null &&
            context.MemoryCache.TryGetValue(cacheKey, out TrustFactSet<ContentTypeFact>? cached) &&
            cached != null)
        {
            LogCacheHit(logger, typeof(ContentTypeFact).FullName ?? nameof(ContentTypeFact));
            return new ValueTask<ITrustFactSet>(cached);
        }

        if (!context.Message!.TryGetContentType(out string? contentType) || string.IsNullOrEmpty(contentType))
        {
            var empty = TrustFactSet<ContentTypeFact>.Available();
            context.MemoryCache?.Set(cacheKey, empty);
            return new ValueTask<ITrustFactSet>(empty);
        }

        var result = TrustFactSet<ContentTypeFact>.Available(new ContentTypeFact(contentType));
        context.MemoryCache?.Set(cacheKey, result);
        return new ValueTask<ITrustFactSet>(result);
    }

    private static async ValueTask<ITrustFactSet> ProduceCounterSignatureSubjectsFactAsync(
        TrustFactContext context,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        TrustFactCacheKey cacheKey = context.CreateCacheKey(typeof(CounterSignatureSubjectFact));
        if (context.MemoryCache != null &&
            context.MemoryCache.TryGetValue(cacheKey, out TrustFactSet<CounterSignatureSubjectFact>? cached) &&
            cached != null)
        {
            LogCacheHit(logger, typeof(CounterSignatureSubjectFact).FullName ?? nameof(CounterSignatureSubjectFact));
            return cached;
        }

        try
        {
            var resolvers = GetCounterSignatureResolvers(context).ToArray();

            if (resolvers.Length == 0)
            {
                var missing = TrustFactSet<CounterSignatureSubjectFact>.Missing(
                    TrustFactMissingCodes.NoProducers,
                    ClassStrings.MissingCounterSignatureDiscoveryUnavailable);
                context.MemoryCache?.Set(cacheKey, missing);
                return missing;
            }

            var subjects = new List<CounterSignatureSubjectFact>();
            foreach (var resolver in resolvers)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var results = await resolver.ResolveAsync(context.Message!, cancellationToken).ConfigureAwait(false);
                foreach (var result in results)
                {
                    if (!result.IsSuccess || result.CounterSignature == null)
                    {
                        throw new InvalidOperationException(result.ErrorMessage ?? ClassStrings.MissingCounterSignatureDecodeFailed);
                    }

                    var counterSignature = result.CounterSignature;
                    var subject = TrustSubject.CounterSignature(context.MessageId, counterSignature.RawCounterSignatureBytes);
                    subjects.Add(new CounterSignatureSubjectFact(subject, counterSignature.IsProtectedHeader));
                }
            }

            var factSet = TrustFactSet<CounterSignatureSubjectFact>.Available(subjects.ToArray());
            context.MemoryCache?.Set(cacheKey, factSet);
            return factSet;
        }
        catch (Exception ex)
        {
            LogCounterSignatureProducerFailed(logger, ex, typeof(CounterSignatureSubjectFact).FullName ?? nameof(CounterSignatureSubjectFact));
            return TrustFactSet<CounterSignatureSubjectFact>.Missing(
                TrustFactMissingCodes.ProducerFailed,
                ClassStrings.MissingCounterSignatureDecodeFailed,
                ex);
        }
    }

    private static async ValueTask<ITrustFactSet> ProduceUnknownCounterSignatureBytesFactAsync(
        TrustFactContext context,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        TrustFactCacheKey cacheKey = context.CreateCacheKey(typeof(UnknownCounterSignatureBytesFact));
        if (context.MemoryCache != null &&
            context.MemoryCache.TryGetValue(cacheKey, out TrustFactSet<UnknownCounterSignatureBytesFact>? cached) &&
            cached != null)
        {
            LogCacheHit(logger, typeof(UnknownCounterSignatureBytesFact).FullName ?? nameof(UnknownCounterSignatureBytesFact));
            return cached;
        }

        try
        {
            var resolvers = GetCounterSignatureResolvers(context).ToArray();

            if (resolvers.Length == 0)
            {
                var missing = TrustFactSet<UnknownCounterSignatureBytesFact>.Missing(
                    TrustFactMissingCodes.NoProducers,
                    ClassStrings.MissingCounterSignatureDiscoveryUnavailable);
                context.MemoryCache?.Set(cacheKey, missing);
                return missing;
            }

            var facts = new List<UnknownCounterSignatureBytesFact>();
            var seen = new HashSet<TrustSubjectId>();

            foreach (var resolver in resolvers)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var results = await resolver.ResolveAsync(context.Message!, cancellationToken).ConfigureAwait(false);
                foreach (var result in results)
                {
                    if (!result.IsSuccess || result.CounterSignature == null)
                    {
                        throw new InvalidOperationException(result.ErrorMessage ?? ClassStrings.MissingCounterSignatureDecodeFailed);
                    }

                    var rawCounterSignatureBytes = result.CounterSignature.RawCounterSignatureBytes;
                    var counterSignatureId = TrustIds.CreateCounterSignatureId(rawCounterSignatureBytes);
                    if (seen.Add(counterSignatureId))
                    {
                        facts.Add(new UnknownCounterSignatureBytesFact(counterSignatureId, rawCounterSignatureBytes));
                    }
                }
            }

            var factSet = TrustFactSet<UnknownCounterSignatureBytesFact>.Available(facts.ToArray());
            context.MemoryCache?.Set(cacheKey, factSet);
            return factSet;
        }
        catch (Exception ex)
        {
            LogCounterSignatureProducerFailed(logger, ex, typeof(UnknownCounterSignatureBytesFact).FullName ?? nameof(UnknownCounterSignatureBytesFact));
            return TrustFactSet<UnknownCounterSignatureBytesFact>.Missing(
                TrustFactMissingCodes.ProducerFailed,
                ClassStrings.MissingCounterSignatureDecodeFailed,
                ex);
        }
    }

    private static IEnumerable<ICounterSignatureResolver> GetCounterSignatureResolvers(TrustFactContext context)
    {
        return (context.Services?.GetService(typeof(IEnumerable<ICounterSignatureResolver>)) as IEnumerable<ICounterSignatureResolver>)
            ?? Array.Empty<ICounterSignatureResolver>();
    }
}
